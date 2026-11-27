package ocitest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Hub is a fake of the Docker Hub tags API
// (GET /v2/namespaces/{ns}/repositories/{name}/tags) backed by a Registry.
type Hub struct {
	Registry *Registry
	// PushTimes and PullTimes are keyed by "namespace/name:tag". Missing pull
	// times are reported as null (never pulled).
	PushTimes map[string]time.Time
	PullTimes map[string]time.Time
	// PageSize overrides the requested page size to test pagination.
	PageSize int
}

// Start serves the fake Hub API until the test ends and returns its base URL.
func (h *Hub) Start(t testing.TB) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// ServeHTTP implements the tags endpoint with page/page_size pagination and
// absolute "next" links.
func (h *Hub) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "v2" || parts[1] != "namespaces" || parts[3] != "repositories" || parts[5] != "tags" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown endpoint")
		return
	}
	repo := parts[2] + "/" + parts[4]

	h.Registry.mu.Lock()
	rp, ok := h.Registry.repos[repo]
	type tag struct {
		name   string
		digest string
	}
	var tags []tag
	if ok {
		for name, d := range rp.tags {
			tags = append(tags, tag{name, d.String()})
		}
	}
	h.Registry.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "object not found")
		return
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].name < tags[j].name })

	page, _ := strconv.Atoi(req.URL.Query().Get("page"))
	size, _ := strconv.Atoi(req.URL.Query().Get("page_size"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}
	if h.PageSize > 0 {
		size = h.PageSize
	}
	start := min((page-1)*size, len(tags))
	end := min(start+size, len(tags))

	results := []map[string]any{}
	for _, t := range tags[start:end] {
		key := repo + ":" + t.name
		push, ok := h.PushTimes[key]
		if !ok {
			push = harborTime
		}
		var pulled any
		if p, ok := h.PullTimes[key]; ok {
			pulled = p
		}
		results = append(results, map[string]any{
			"name":            t.name,
			"digest":          t.digest,
			"last_updated":    push,
			"tag_last_pushed": push,
			"tag_last_pulled": pulled,
		})
	}
	var next any
	if end < len(tags) {
		next = fmt.Sprintf("http://%s%s?page=%d&page_size=%d", req.Host, req.URL.Path, page+1, size)
	}
	writeJSON(w, "application/json", map[string]any{"count": len(tags), "next": next, "results": results})
}
