// Package ocitest provides a small in-memory OCI registry for tests. It
// implements just enough of the distribution spec for beagle: catalog, tag
// listing, manifest and blob reads, and optionally the referrers API.
package ocitest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Registry is an in-memory registry.
type Registry struct {
	// ReferrersAPI enables /v2/<name>/referrers/<digest>. When disabled,
	// PushManifest maintains the OCI 1.1 referrers tag schema instead.
	ReferrersAPI bool
	// ReferrersDisabledStatus is the HTTP status returned for the referrers
	// endpoint when ReferrersAPI is false. Defaults to 404.
	ReferrersDisabledStatus int
	// Catalog enables /v2/_catalog.
	Catalog bool
	// Harbor enables a fake Harbor v2.0 API next to the registry API.
	Harbor *HarborAPI
	// Username and Password, if set, are required (basic auth) for every
	// registry API request.
	Username string
	Password string

	mu    sync.Mutex
	repos map[string]*repo
}

type stored struct {
	mediaType string
	data      []byte
}

type repo struct {
	manifests map[digest.Digest]stored
	blobs     map[digest.Digest][]byte
	tags      map[string]digest.Digest
}

// New returns an empty registry with the catalog and referrers API enabled.
func New() *Registry {
	return &Registry{ReferrersAPI: true, Catalog: true, repos: map[string]*repo{}}
}

// Start serves the registry until the test ends and returns its host:port.
func (r *Registry) Start(t testing.TB) string {
	t.Helper()
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func (r *Registry) repo(name string) *repo {
	rp, ok := r.repos[name]
	if !ok {
		rp = &repo{
			manifests: map[digest.Digest]stored{},
			blobs:     map[digest.Digest][]byte{},
			tags:      map[string]digest.Digest{},
		}
		r.repos[name] = rp
	}
	return rp
}

// PushBlob stores a blob and returns its descriptor.
func (r *Registry) PushBlob(repoName, mediaType string, data []byte) ocispec.Descriptor {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := digest.FromBytes(data)
	r.repo(repoName).blobs[d] = data
	return ocispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(data))}
}

// PushManifest stores a manifest (any JSON-marshalable value), tags it if tag
// is not empty, and returns its descriptor. Manifests with a subject are
// added to the referrers tag schema when the referrers API is disabled.
func (r *Registry) PushManifest(repoName, tag, mediaType string, manifest any) ocispec.Descriptor {
	data, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rp := r.repo(repoName)
	d := digest.FromBytes(data)
	rp.manifests[d] = stored{mediaType: mediaType, data: data}
	if tag != "" {
		rp.tags[tag] = d
	}
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(data))}

	if !r.ReferrersAPI {
		if ref, ok := referrerDescriptor(desc, data); ok {
			r.addToFallbackIndex(rp, ref)
		}
	}
	return desc
}

// Tag points tag at an existing manifest.
func (r *Registry) Tag(repoName, tag string, d digest.Digest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repo(repoName).tags[tag] = d
}

type subjectManifest struct {
	ArtifactType string              `json:"artifactType"`
	Config       *ocispec.Descriptor `json:"config"`
	Subject      *ocispec.Descriptor `json:"subject"`
	Annotations  map[string]string   `json:"annotations"`
}

type referrer struct {
	subject digest.Digest
	desc    ocispec.Descriptor
}

func referrerDescriptor(desc ocispec.Descriptor, data []byte) (referrer, bool) {
	var m subjectManifest
	if json.Unmarshal(data, &m) != nil || m.Subject == nil {
		return referrer{}, false
	}
	desc.ArtifactType = m.ArtifactType
	if desc.ArtifactType == "" && m.Config != nil {
		desc.ArtifactType = m.Config.MediaType
	}
	desc.Annotations = m.Annotations
	return referrer{subject: m.Subject.Digest, desc: desc}, true
}

func (r *Registry) addToFallbackIndex(rp *repo, ref referrer) {
	tag := strings.Replace(ref.subject.String(), ":", "-", 1)
	idx := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex}
	idx.SchemaVersion = 2
	if old, ok := rp.tags[tag]; ok {
		_ = json.Unmarshal(rp.manifests[old].data, &idx)
	}
	idx.Manifests = append(idx.Manifests, ref.desc)
	data, _ := json.Marshal(idx)
	d := digest.FromBytes(data)
	rp.manifests[d] = stored{mediaType: ocispec.MediaTypeImageIndex, data: data}
	rp.tags[tag] = d
}

func (r *Registry) referrers(rp *repo, subject digest.Digest, artifactType string) []ocispec.Descriptor {
	out := []ocispec.Descriptor{}
	for d, s := range rp.manifests {
		ref, ok := referrerDescriptor(ocispec.Descriptor{MediaType: s.mediaType, Digest: d, Size: int64(len(s.data))}, s.data)
		if !ok || ref.subject != subject {
			continue
		}
		if artifactType != "" && ref.desc.ArtifactType != artifactType {
			continue
		}
		out = append(out, ref.desc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out
}

// ServeHTTP implements the subset of the distribution API beagle uses.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if strings.HasPrefix(req.URL.Path, "/api/v2.0/") && r.Harbor != nil {
		r.serveHarbor(w, req)
		return
	}

	if r.Username != "" {
		if user, pass, ok := req.BasicAuth(); !ok || user != r.Username || pass != r.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="ocitest"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
			return
		}
	}

	path := strings.TrimPrefix(req.URL.Path, "/v2/")
	switch {
	case req.URL.Path == "/v2/" || req.URL.Path == "/v2":
		w.WriteHeader(http.StatusOK)
		return
	case path == "_catalog":
		if !r.Catalog {
			writeError(w, http.StatusNotFound, "UNSUPPORTED", "catalog disabled")
			return
		}
		names := make([]string, 0, len(r.repos))
		for n := range r.repos {
			names = append(names, n)
		}
		sort.Strings(names)
		writeJSON(w, "application/json", map[string]any{"repositories": names})
		return
	}

	if i := strings.LastIndex(path, "/tags/list"); i > 0 && strings.HasSuffix(path, "/tags/list") {
		name := path[:i]
		rp, ok := r.repos[name]
		if !ok {
			writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository not found")
			return
		}
		tags := make([]string, 0, len(rp.tags))
		for t := range rp.tags {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		writeJSON(w, "application/json", map[string]any{"name": name, "tags": tags})
		return
	}

	for _, kind := range []string{"/manifests/", "/blobs/", "/referrers/"} {
		i := strings.LastIndex(path, kind)
		if i <= 0 {
			continue
		}
		name, ref := path[:i], path[i+len(kind):]
		rp, ok := r.repos[name]
		if !ok {
			writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository not found")
			return
		}
		switch kind {
		case "/manifests/":
			r.serveManifest(w, req, rp, ref)
		case "/blobs/":
			data, ok := rp.blobs[digest.Digest(ref)]
			if !ok {
				writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob not found")
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Docker-Content-Digest", ref)
			w.Header().Set("Content-Length", fmt.Sprint(len(data)))
			if req.Method != http.MethodHead {
				_, _ = w.Write(data)
			}
		case "/referrers/":
			if !r.ReferrersAPI {
				status := r.ReferrersDisabledStatus
				if status == 0 {
					status = http.StatusNotFound
				}
				writeError(w, status, "UNSUPPORTED", "referrers API disabled")
				return
			}
			idx := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: r.referrers(rp, digest.Digest(ref), req.URL.Query().Get("artifactType"))}
			idx.SchemaVersion = 2
			writeJSON(w, ocispec.MediaTypeImageIndex, idx)
		}
		return
	}
	writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown endpoint")
}

func (r *Registry) serveManifest(w http.ResponseWriter, req *http.Request, rp *repo, ref string) {
	d := digest.Digest(ref)
	if d.Validate() != nil {
		var ok bool
		d, ok = rp.tags[ref]
		if !ok {
			writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "tag not found")
			return
		}
	}
	s, ok := rp.manifests[d]
	if !ok {
		writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest not found")
		return
	}
	w.Header().Set("Content-Type", s.mediaType)
	w.Header().Set("Docker-Content-Digest", d.String())
	w.Header().Set("Content-Length", fmt.Sprint(len(s.data)))
	if req.Method != http.MethodHead {
		_, _ = w.Write(s.data)
	}
}

func writeJSON(w http.ResponseWriter, contentType string, v any) {
	data, _ := json.Marshal(v)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"code": code, "message": msg}}})
}
