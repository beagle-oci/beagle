// Package dockerhub reads tag metadata (push and pull times) from the
// Docker Hub API, which the registry API does not expose.
package dockerhub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beagle-oci/beagle/internal/meta"
)

// DefaultBaseURL is the Docker Hub API endpoint.
const DefaultBaseURL = "https://hub.docker.com"

// Client is a read-only, anonymous Docker Hub API client.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
	// MaxPages caps pagination (100 tags per page). Defaults to 20.
	MaxPages int
}

// New returns a client for hub.docker.com.
func New(httpClient *http.Client) *Client {
	return &Client{BaseURL: DefaultBaseURL, HTTP: httpClient}
}

// Name implements meta.Provider.
func (c *Client) Name() string { return "docker-hub" }

// Capabilities implements meta.Provider.
func (c *Client) Capabilities() meta.Capabilities {
	return meta.Capabilities{Pushed: true, Pulled: true}
}

type tagPage struct {
	Next    string `json:"next"`
	Results []struct {
		Name          string     `json:"name"`
		Digest        string     `json:"digest"`
		LastUpdated   *time.Time `json:"last_updated"`
		TagLastPushed *time.Time `json:"tag_last_pushed"`
		TagLastPulled *time.Time `json:"tag_last_pulled"`
	} `json:"results"`
}

// Tags implements meta.Provider. repo is "namespace/name"; single names use
// the "library" namespace.
func (c *Client) Tags(ctx context.Context, repo string) (map[string]meta.TagInfo, error) {
	ns, name, ok := strings.Cut(repo, "/")
	if !ok {
		ns, name = "library", repo
	}
	base := strings.TrimSuffix(c.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	next := fmt.Sprintf("%s/v2/namespaces/%s/repositories/%s/tags?page_size=100", base, url.PathEscape(ns), url.PathEscape(name))
	maxPages := c.MaxPages
	if maxPages <= 0 {
		maxPages = 20
	}

	out := map[string]meta.TagInfo{}
	for page := 0; next != "" && page < maxPages; page++ {
		// Only follow pagination links that stay on the API host.
		if !strings.HasPrefix(next, base+"/") {
			return out, fmt.Errorf("docker hub: unexpected pagination link %q", next)
		}
		var p tagPage
		if err := c.get(ctx, next, &p); err != nil {
			return out, err
		}
		for _, r := range p.Results {
			info := meta.TagInfo{Digest: r.Digest}
			switch {
			case r.TagLastPushed != nil:
				info.Pushed = *r.TagLastPushed
			case r.LastUpdated != nil:
				info.Pushed = *r.LastUpdated
			}
			if r.TagLastPulled != nil {
				info.Pulled = *r.TagLastPulled
			}
			out[r.Name] = info
		}
		next = p.Next
	}
	return out, nil
}

func (c *Client) get(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker hub API: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}
