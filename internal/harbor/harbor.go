// Package harbor is a small read-only client for the Harbor v2.0 API. beagle
// uses it to list projects and repositories, because Harbor only allows
// system administrators to use the registry catalog API.
package harbor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	apiPrefix = "/api/v2.0"
	// DefaultPageSize is the largest page size Harbor accepts.
	DefaultPageSize = 100
	maxPages        = 1000
)

var (
	// ErrNotHarbor is returned by Detect when the registry is not Harbor.
	ErrNotHarbor = errors.New("not a Harbor registry")
	// ErrUnauthorized is returned for HTTP 401/403 responses.
	ErrUnauthorized = errors.New("unauthorized")
)

// CredentialFunc returns the username and password for the Harbor API. Empty
// values mean anonymous access.
type CredentialFunc func(ctx context.Context) (username, password string, err error)

// SystemInfo is the public part of GET /api/v2.0/systeminfo.
type SystemInfo struct {
	HarborVersion string `json:"harbor_version"`
	AuthMode      string `json:"auth_mode"`
}

// Project is a Harbor project.
type Project struct {
	ID           int64     `json:"project_id"`
	Name         string    `json:"name"`
	RepoCount    int64     `json:"repo_count"`
	CreationTime time.Time `json:"creation_time"`
	UpdateTime   time.Time `json:"update_time"`
	// RegistryID is set for proxy cache projects.
	RegistryID *int64 `json:"registry_id"`
	Metadata   struct {
		Public string `json:"public"`
	} `json:"metadata"`
}

// Public reports whether anonymous users can pull from the project.
func (p Project) Public() bool { return p.Metadata.Public == "true" }

// ProxyCache reports whether the project is a pull-through cache.
func (p Project) ProxyCache() bool { return p.RegistryID != nil && *p.RegistryID != 0 }

// Repository is a repository inside a project. Name includes the project,
// e.g. "library/nginx".
type Repository struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	ProjectID     int64     `json:"project_id"`
	ArtifactCount int64     `json:"artifact_count"`
	PullCount     int64     `json:"pull_count"`
	CreationTime  time.Time `json:"creation_time"`
	UpdateTime    time.Time `json:"update_time"`
	Description   string    `json:"description"`
}

// Client talks to the Harbor API of one registry.
type Client struct {
	baseURL  string
	http     *http.Client
	cred     CredentialFunc
	info     SystemInfo
	PageSize int
	// UserAgent is sent with every request.
	UserAgent string
}

// Detect checks whether baseURL (e.g. "https://harbor.example.com") is a
// Harbor instance and returns a client for it. It returns ErrNotHarbor for
// other registries.
func Detect(ctx context.Context, baseURL string, httpClient *http.Client, cred CredentialFunc) (*Client, error) {
	c := &Client{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		http:     httpClient,
		cred:     cred,
		PageSize: DefaultPageSize,
	}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	// systeminfo is readable anonymously, but Harbor only reveals its
	// version to authenticated users. Try with credentials first and fall
	// back to anonymous access if they are rejected.
	var info SystemInfo
	_, err := c.do(ctx, "/systeminfo", nil, &info, true, nil)
	if errors.Is(err, ErrUnauthorized) {
		info = SystemInfo{}
		_, err = c.do(ctx, "/systeminfo", nil, &info, false, nil)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// 404s, HTML pages and other unexpected answers all mean the same:
		// this is not Harbor (or not one we can talk to).
		return nil, ErrNotHarbor
	}
	if info.AuthMode == "" && info.HarborVersion == "" {
		return nil, ErrNotHarbor
	}
	c.info = info
	return c, nil
}

// Version returns the Harbor version, e.g. "v2.12.2-73072d0d". It is empty
// for anonymous users, because Harbor hides it from them.
func (c *Client) Version() string { return c.info.HarborVersion }

// Projects lists all projects visible to the current user.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	return list[Project](ctx, c, "/projects", nil, nil)
}

// Repositories lists the repositories of a project.
func (c *Client) Repositories(ctx context.Context, project string) ([]Repository, error) {
	return list[Repository](ctx, c, "/projects/"+url.PathEscape(project)+"/repositories", nil, nil)
}

func list[T any](ctx context.Context, c *Client, path string, extra url.Values, headers map[string]string) ([]T, error) {
	pageSize := c.PageSize
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	var all []T
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)}}
		for k, v := range extra {
			q[k] = v
		}
		var batch []T
		total, err := c.do(ctx, path, q, &batch, true, headers)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < pageSize || (total >= 0 && len(all) >= total) {
			break
		}
	}
	return all, nil
}

type statusError struct {
	status  int
	message string
}

func (e *statusError) Error() string {
	if e.message != "" {
		return fmt.Sprintf("harbor API: HTTP %d: %s", e.status, e.message)
	}
	return fmt.Sprintf("harbor API: HTTP %d", e.status)
}

// do performs a GET request and decodes the JSON response into out. It
// returns the X-Total-Count header (-1 if absent).
func (c *Client) do(ctx context.Context, path string, query url.Values, out any, withAuth bool, headers map[string]string) (int, error) {
	u := c.baseURL + apiPrefix + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("Accept", "application/json")
	// Treat project names that look like numbers as names, not IDs.
	req.Header.Set("X-Is-Resource-Name", "true")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if withAuth && c.cred != nil {
		user, pass, err := c.cred(ctx)
		if err == nil && user != "" {
			req.SetBasicAuth(user, pass)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := errorMessage(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return -1, fmt.Errorf("%w: %s", ErrUnauthorized, (&statusError{resp.StatusCode, msg}).Error())
		}
		return -1, &statusError{status: resp.StatusCode, message: msg}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
		return -1, err
	}
	total := -1
	if v := resp.Header.Get("X-Total-Count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			total = n
		}
	}
	return total, nil
}

// errorMessage extracts the message of a Harbor error response:
// {"errors":[{"code":"...","message":"..."}]}.
func errorMessage(r io.Reader) string {
	var body struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	data, _ := io.ReadAll(io.LimitReader(r, 64<<10))
	if json.Unmarshal(data, &body) == nil && len(body.Errors) > 0 {
		return body.Errors[0].Message
	}
	return strings.TrimSpace(string(data))
}
