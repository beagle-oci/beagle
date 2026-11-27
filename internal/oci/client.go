// Package oci is beagle's read-only view of an OCI registry. It wraps
// oras-go so the UI never has to deal with transports, auth or the
// differences between the referrers API and its tag fallback.
package oci

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/errcode"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const (
	// MaxManifestSize is the largest manifest beagle will download.
	MaxManifestSize = 4 << 20
	// DefaultMaxBlobSize is the largest blob beagle shows in the raw viewer.
	DefaultMaxBlobSize = 1 << 20

	dockerHubHost    = "docker.io"
	dockerHubAPIHost = "registry-1.docker.io"
)

var (
	// ErrCatalogUnavailable is returned when the registry does not expose
	// (or does not allow) the /v2/_catalog endpoint.
	ErrCatalogUnavailable = errors.New("catalog API not available")
	// ErrTooLarge is returned when content exceeds the configured size limit.
	ErrTooLarge = errors.New("content too large")

	errStop = errors.New("stop listing")
)

// Options configures how beagle talks to a registry.
type Options struct {
	// PlainHTTP uses HTTP instead of HTTPS.
	PlainHTTP bool
	// Insecure skips TLS certificate verification.
	Insecure bool
	// UserAgent is sent with every request.
	UserAgent string
	// Credential overrides the Docker credential store lookup. Mainly used
	// by tests.
	Credential auth.CredentialFunc
}

// Client is a read-only registry client. It is safe for concurrent use.
type Client struct {
	host       string
	apiHost    string
	plainHTTP  bool
	authSource string
	registry   *remote.Registry
	httpClient *http.Client
	cred       auth.CredentialFunc

	mu    sync.Mutex
	repos map[string]*remote.Repository
}

// New creates a client for the registry at host (for example "ghcr.io",
// "localhost:5000" or "docker.io").
func New(host string, opts Options) (*Client, error) {
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/")
	if host == "" {
		return nil, errors.New("registry host must not be empty")
	}
	apiHost := host
	if host == dockerHubHost {
		apiHost = dockerHubAPIHost
	}

	reg, err := remote.NewRegistry(apiHost)
	if err != nil {
		return nil, fmt.Errorf("invalid registry %q: %w", host, err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicitly requested via --insecure
	}

	cred := opts.Credential
	authSource := "custom"
	if cred == nil {
		authSource = "anonymous"
		store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
		if err == nil {
			cred = credentials.Credential(store)
			authSource = "docker credentials"
		}
	}

	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = "beagle"
	}

	httpClient := &http.Client{Transport: retry.NewTransport(transport)}
	authClient := &auth.Client{
		Client:     httpClient,
		Cache:      auth.NewCache(),
		Credential: cred,
		Header:     http.Header{"User-Agent": {userAgent}},
	}
	if IsLoopbackHost(apiHost) {
		// oras-go refuses token realms on loopback addresses by default
		// (SSRF protection). When the registry itself runs on localhost,
		// its token service usually does too.
		authClient.BlockedRealmPrefixes = withoutLoopback(auth.DefaultBlockedRealmPrefixes())
	}

	reg.Client = authClient
	reg.PlainHTTP = opts.PlainHTTP

	return &Client{
		host:       host,
		apiHost:    apiHost,
		plainHTTP:  opts.PlainHTTP,
		authSource: authSource,
		registry:   reg,
		httpClient: httpClient,
		cred:       cred,
		repos:      map[string]*remote.Repository{},
	}, nil
}

// Host returns the registry host as given by the user.
func (c *Client) Host() string { return c.host }

// PlainHTTP reports whether the client talks plain HTTP.
func (c *Client) PlainHTTP() bool { return c.plainHTTP }

// AuthSource describes where credentials come from, e.g. "docker credentials".
func (c *Client) AuthSource() string { return c.authSource }

// BaseURL returns the registry's base URL, e.g. "https://ghcr.io".
func (c *Client) BaseURL() string {
	if c.plainHTTP {
		return "http://" + c.apiHost
	}
	return "https://" + c.apiHost
}

// HTTPClient returns an HTTP client with beagle's transport settings (TLS,
// retries) but without registry token handling. Used for vendor APIs such as
// Harbor's.
func (c *Client) HTTPClient() *http.Client { return c.httpClient }

// Credential returns the stored credential for the registry, which may be
// empty. Never log or display it.
func (c *Client) Credential(ctx context.Context) (auth.Credential, error) {
	if c.cred == nil {
		return auth.EmptyCredential, nil
	}
	return c.cred(ctx, c.apiHost)
}

// Ping checks that the registry speaks the distribution API.
func (c *Client) Ping(ctx context.Context) error {
	return c.registry.Ping(ctx)
}

// IsUnauthorized reports whether err means the registry wants credentials:
// an HTTP 401 or 403, or a basic auth challenge without stored credentials.
func IsUnauthorized(err error) bool {
	if errors.Is(err, auth.ErrBasicCredentialNotFound) {
		return true
	}
	var resp *errcode.ErrorResponse
	return errors.As(err, &resp) && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden)
}

// Repositories lists repository names via the catalog API. A limit <= 0
// lists everything.
func (c *Client) Repositories(ctx context.Context, limit int) ([]string, error) {
	var out []string
	err := c.registry.Repositories(ctx, "", func(repos []string) error {
		out = append(out, repos...)
		if limit > 0 && len(out) >= limit {
			return errStop
		}
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	if err != nil {
		var resp *errcode.ErrorResponse
		if errors.As(err, &resp) {
			switch resp.StatusCode {
			case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden, http.StatusMethodNotAllowed:
				return nil, fmt.Errorf("%w (HTTP %d)", ErrCatalogUnavailable, resp.StatusCode)
			}
		}
		return nil, err
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Tags lists all tags of a repository.
func (c *Client) Tags(ctx context.Context, repo string) ([]string, error) {
	r, err := c.repository(repo)
	if err != nil {
		return nil, err
	}
	var out []string
	err = r.Tags(ctx, "", func(tags []string) error {
		out = append(out, tags...)
		return nil
	})
	return out, err
}

// Resolve resolves a tag or digest to a manifest descriptor.
func (c *Client) Resolve(ctx context.Context, repo, reference string) (ocispec.Descriptor, error) {
	r, err := c.repository(repo)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return r.Resolve(ctx, reference)
}

// FetchManifest downloads and parses the manifest described by desc.
func (c *Client) FetchManifest(ctx context.Context, repo string, desc ocispec.Descriptor) (*Manifest, error) {
	if desc.Size > MaxManifestSize {
		return nil, fmt.Errorf("%w: manifest is %d bytes", ErrTooLarge, desc.Size)
	}
	r, err := c.repository(repo)
	if err != nil {
		return nil, err
	}
	raw, err := content.FetchAll(ctx, r.Manifests(), desc)
	if err != nil {
		return nil, err
	}
	return ParseManifest(desc, raw)
}

// FetchManifestReference resolves reference (tag or digest) and downloads
// the manifest in one round trip.
func (c *Client) FetchManifestReference(ctx context.Context, repo, reference string) (*Manifest, error) {
	r, err := c.repository(repo)
	if err != nil {
		return nil, err
	}
	desc, rc, err := r.FetchReference(ctx, reference)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if desc.Size > MaxManifestSize {
		return nil, fmt.Errorf("%w: manifest is %d bytes", ErrTooLarge, desc.Size)
	}
	raw, err := content.ReadAll(rc, desc)
	if err != nil {
		return nil, err
	}
	return ParseManifest(desc, raw)
}

// FetchBlob downloads a blob if it is not larger than maxSize bytes.
func (c *Client) FetchBlob(ctx context.Context, repo string, desc ocispec.Descriptor, maxSize int64) ([]byte, error) {
	if maxSize > 0 && desc.Size > maxSize {
		return nil, fmt.Errorf("%w: blob is %d bytes (limit %d)", ErrTooLarge, desc.Size, maxSize)
	}
	r, err := c.repository(repo)
	if err != nil {
		return nil, err
	}
	rc, err := r.Blobs().Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return content.ReadAll(io.LimitReader(rc, desc.Size+1), desc)
}

// Referrers lists the manifests that reference desc as their subject. oras-go
// uses the referrers API when the registry supports it and falls back to the
// referrers tag schema (sha256-<hex>) otherwise.
func (c *Client) Referrers(ctx context.Context, repo string, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	r, err := c.repository(repo)
	if err != nil {
		return nil, err
	}
	var out []ocispec.Descriptor
	collect := func(referrers []ocispec.Descriptor) error {
		out = append(out, referrers...)
		return nil
	}
	err = r.Referrers(ctx, desc, "", collect)
	if isReferrersAPIMissing(err) {
		// oras-go only falls back to the tag schema on 404. Some registries
		// answer 405 or 501 when the referrers API is disabled.
		if r.SetReferrersCapability(false) == nil {
			out = nil
			err = r.Referrers(ctx, desc, "", collect)
		}
	}
	return out, err
}

func isReferrersAPIMissing(err error) bool {
	var resp *errcode.ErrorResponse
	if !errors.As(err, &resp) {
		return false
	}
	switch resp.StatusCode {
	case http.StatusMethodNotAllowed, http.StatusNotImplemented, http.StatusBadRequest:
		return true
	}
	return false
}

// repository returns a cached repository client so oras-go remembers
// whether the registry supports the referrers API.
func (c *Client) repository(name string) (*remote.Repository, error) {
	name = c.NormalizeRepository(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.repos[name]; ok {
		return r, nil
	}
	repo, err := c.registry.Repository(context.Background(), name)
	if err != nil {
		return nil, fmt.Errorf("invalid repository %q: %w", name, err)
	}
	r, ok := repo.(*remote.Repository)
	if !ok {
		return nil, fmt.Errorf("unexpected repository type %T", repo)
	}
	c.repos[name] = r
	return r, nil
}

// NormalizeRepository applies Docker Hub's implicit "library/" namespace.
func (c *Client) NormalizeRepository(name string) string {
	name = strings.Trim(name, "/")
	if c.apiHost == dockerHubAPIHost && !strings.Contains(name, "/") {
		return "library/" + name
	}
	return name
}

// IsLoopbackHost reports whether host (optionally with port) points to the
// local machine.
func IsLoopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func withoutLoopback(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if p.Addr().IsLoopback() {
			continue
		}
		out = append(out, p)
	}
	return out
}
