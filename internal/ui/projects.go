package ui

import (
	"errors"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/beagle-oci/beagle/internal/harbor"
)

// projectsView lists Harbor projects. It is the root view on Harbor.
type projectsView struct {
	baseView
	list *list[harbor.Project]
}

type projectsLoadedMsg struct {
	viewID   int
	projects []harbor.Project
	err      error
}

func (m projectsLoadedMsg) target() int { return m.viewID }

func newProjectsView() *projectsView {
	return &projectsView{
		list: newList(
			[]column{{title: "NAME", flex: 1}, {title: "ACCESS", max: 7}, {title: "TYPE", max: 11}, {title: "REPOS", max: 6, right: true}, {title: "AGE", max: 5, right: true}},
			func(p harbor.Project) []string {
				access, kind := "private", "project"
				if p.Public() {
					access = "public"
				}
				if p.ProxyCache() {
					kind = "proxy cache"
				}
				return []string{p.Name, access, kind, fmt.Sprint(p.RepoCount), age(p.CreationTime.Format(time.RFC3339))}
			},
			func(p harbor.Project) lipgloss.Style {
				if p.ProxyCache() {
					return styleMuted
				}
				return styleRow
			},
		),
	}
}

func (v *projectsView) crumb() string { return "projects" }
func (v *projectsView) title() string { return "projects" }
func (v *projectsView) count() int    { return v.list.count() }

func (v *projectsView) hints() []hint {
	return []hint{{"enter", "repositories"}, hintOf(keys.Reload)}
}

func (v *projectsView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	v.list.setSize(w, h)
}

func (v *projectsView) setFilter(f string) { v.list.setFilter(f) }
func (v *projectsView) filter() string     { return v.list.filter }

func (v *projectsView) names() []string {
	out := make([]string, len(v.list.items))
	for i, p := range v.list.items {
		out[i] = p.Name
	}
	return out
}

func (v *projectsView) init(e *env) tea.Cmd {
	v.busy, v.err = true, nil
	id := v.id()
	return func() tea.Msg {
		ctx, cancel := e.timeout()
		defer cancel()
		projects, err := e.harbor.Projects(ctx)
		return projectsLoadedMsg{viewID: id, projects: projects, err: err}
	}
}

func (v *projectsView) update(e *env, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case projectsLoadedMsg:
		v.busy = false
		if msg.err != nil {
			v.err = msg.err
			return flashErr(msg.err)
		}
		v.list.setItems(msg.projects)
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Reload):
			return v.init(e)
		case key.Matches(msg, keys.Open):
			if p, ok := v.list.selected(); ok {
				return push(newProjectReposView(p.Name))
			}
		default:
			v.list.update(msg)
		}
	}
	return nil
}

func (v *projectsView) render() string {
	switch {
	case errors.Is(v.err, harbor.ErrUnauthorized) && len(v.list.items) == 0:
		return centered(v.width, v.height,
			styleError.Render("Harbor rejected the stored credentials."),
			"",
			styleValue.Render("Check ")+stylePrompt.Render("docker login <registry>")+styleValue.Render(" or start with --no-harbor."),
		)
	case v.err != nil && len(v.list.items) == 0:
		return centered(v.width, v.height, styleError.Render(v.err.Error()))
	case v.busy && len(v.list.items) == 0:
		return centered(v.width, v.height, styleMuted.Render("Loading projects…"))
	case len(v.list.items) == 0:
		return centered(v.width, v.height,
			styleMuted.Render("No projects visible."),
			"",
			styleValue.Render("Private projects need ")+stylePrompt.Render("docker login <registry>")+styleValue.Render("."),
		)
	}
	return v.list.view()
}
