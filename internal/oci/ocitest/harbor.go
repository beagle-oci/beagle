package ocitest

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
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
