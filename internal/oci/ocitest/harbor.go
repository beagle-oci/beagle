package ocitest

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// HarborAPI configures the fake Harbor v2.0 API. Projects are derived from
// the first path segment of the stored repositories.
type HarborAPI struct {
	Version string
	// Private marks projects that require Username/Password.
	Private map[string]bool
	// ProxyCache marks proxy cache projects.
	ProxyCache map[string]bool
	Username   string
	Password   string
	// PushTimes and PullTimes set tag times, keyed by "repo:tag". Tags
	// without an entry get a fixed push time and were never pulled.
	PushTimes map[string]time.Time
	PullTimes map[string]time.Time
	// Vulns sets the scan summary (severity -> count) per repository.
	Vulns map[string]map[string]int
}

var harborTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func (h *HarborAPI) authorized(req *http.Request) bool {
	user, pass, ok := req.BasicAuth()
	return ok && user == h.Username && pass == h.Password
}

// serveHarbor handles /api/v2.0/*. Callers hold r.mu.
func (r *Registry) serveHarbor(w http.ResponseWriter, req *http.Request) {
	h := r.Harbor
	if _, _, ok := req.BasicAuth(); ok && !h.authorized(req) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}
	authed := h.authorized(req)
	path := strings.TrimPrefix(req.URL.Path, "/api/v2.0")

	projects := map[string][]string{}
	for name := range r.repos {
		project, _, _ := strings.Cut(name, "/")
		projects[project] = append(projects[project], name)
	}

	switch {
	case path == "/systeminfo":
		info := map[string]any{"auth_mode": "db_auth"}
		if authed {
			// Like Harbor, only reveal the version to authenticated users.
			info["harbor_version"] = h.Version
		}
		writeJSON(w, "application/json", info)
	case path == "/projects":
		var names []string
		for p := range projects {
			if h.Private[p] && !authed {
				continue
			}
			names = append(names, p)
		}
		sort.Strings(names)
		var items []map[string]any
		for i, p := range names {
			public := "true"
			if h.Private[p] {
				public = "false"
			}
			item := map[string]any{
				"project_id":    i + 1,
				"name":          p,
				"repo_count":    len(projects[p]),
				"creation_time": harborTime,
				"update_time":   harborTime,
				"metadata":      map[string]string{"public": public},
			}
			if h.ProxyCache[p] {
				item["registry_id"] = 1
			}
			items = append(items, item)
		}
		writePage(w, req, items)
	case strings.HasPrefix(path, "/projects/") && strings.HasSuffix(path, "/artifacts"):
		r.serveHarborArtifacts(w, req)
	case strings.HasPrefix(path, "/projects/") && strings.HasSuffix(path, "/repositories"):
		project, err := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(path, "/projects/"), "/repositories"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		repos, ok := projects[project]
		if !ok {
			writeError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("project %s not found", project))
			return
		}
		if h.Private[project] && !authed {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
			return
		}
		sort.Strings(repos)
		var items []map[string]any
		for i, name := range repos {
			items = append(items, map[string]any{
				"id":             i + 1,
				"name":           name,
				"artifact_count": len(r.repos[name].tags),
				"pull_count":     42,
				"creation_time":  harborTime,
				"update_time":    harborTime,
			})
		}
		writePage(w, req, items)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown endpoint")
	}
}

// writePage applies Harbor's page/page_size pagination and sets X-Total-Count.
func writePage(w http.ResponseWriter, req *http.Request, items []map[string]any) {
	page, _ := strconv.Atoi(req.URL.Query().Get("page"))
	size, _ := strconv.Atoi(req.URL.Query().Get("page_size"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}
	start := min((page-1)*size, len(items))
	end := min(start+size, len(items))
	w.Header().Set("X-Total-Count", strconv.Itoa(len(items)))
	out := items[start:end]
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, "application/json", out)
}

// serveHarborArtifacts implements
// GET /api/v2.0/projects/{project}/repositories/{name}/artifacts where name
// is URL-encoded twice, like Harbor expects.
func (r *Registry) serveHarborArtifacts(w http.ResponseWriter, req *http.Request) {
	h := r.Harbor
	parts := strings.Split(strings.TrimPrefix(req.URL.EscapedPath(), "/api/v2.0/projects/"), "/")
	if len(parts) != 4 || parts[1] != "repositories" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unexpected path")
		return
	}
	project, err1 := url.PathUnescape(parts[0])
	once, err2 := url.PathUnescape(parts[2])
	name, err3 := url.PathUnescape(once)
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "bad encoding")
		return
	}
	repoName := project + "/" + name
	rp, ok := r.repos[repoName]
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "repository not found")
		return
	}
	if h.Private[project] && !h.authorized(req) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
		return
	}

	byDigest := map[string][]string{}
	for tag, d := range rp.tags {
		byDigest[d.String()] = append(byDigest[d.String()], tag)
	}
	digests := make([]string, 0, len(byDigest))
	for d := range byDigest {
		digests = append(digests, d)
	}
	sort.Strings(digests)

	never := time.Time{}
	var items []map[string]any
	for _, d := range digests {
		tags := byDigest[d]
		sort.Strings(tags)
		var tagItems []map[string]any
		for _, t := range tags {
			push, ok := h.PushTimes[repoName+":"+t]
			if !ok {
				push = harborTime
			}
			pull, ok := h.PullTimes[repoName+":"+t]
			if !ok {
				pull = never
			}
			tagItems = append(tagItems, map[string]any{"name": t, "push_time": push, "pull_time": pull})
		}
		var accessories []map[string]any
		for _, ref := range r.referrers(rp, digest.Digest(d), "") {
			accessories = append(accessories, map[string]any{"type": accessoryType(ref), "digest": ref.Digest})
		}
		item := map[string]any{
			"digest":      d,
			"push_time":   harborTime,
			"pull_time":   never,
			"tags":        tagItems,
			"accessories": accessories,
		}
		if summary, ok := h.Vulns[repoName]; ok {
			item["scan_overview"] = map[string]any{
				"application/vnd.security.vulnerability.report; version=1.1": map[string]any{
					"scan_status": "Success",
					"summary":     map[string]any{"total": 0, "summary": summary},
					"scanner":     map[string]any{"name": "Trivy"},
				},
			}
		}
		items = append(items, item)
	}
	writePage(w, req, items)
}

// isCosignSignature tells signature bundles (cosign v3 predicate or none)
// from attestations.
func isCosignSignature(predicateType string) bool {
	return predicateType == "" || predicateType == "https://sigstore.dev/cosign/sign/v1"
}

// accessoryType mimics Harbor's accessory types for referrers.
func accessoryType(d ocispec.Descriptor) string {
	t := strings.ToLower(d.ArtifactType)
	switch {
	case strings.Contains(t, "notary.signature"):
		return "signature.notation"
	case strings.Contains(t, "sigstore.bundle") && isCosignSignature(d.Annotations["dev.sigstore.bundle.predicateType"]),
		strings.Contains(t, "cosign.artifact.sig"):
		return "signature.cosign"
	case strings.Contains(t, "spdx"), strings.Contains(t, "cyclonedx"):
		return "harbor.sbom"
	}
	return "subject.accessory"
}
