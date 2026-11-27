package ui

import (
	"errors"
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/beagle-oci/beagle/internal/harbor"
	"github.com/beagle-oci/beagle/internal/oci"
)

// maxRepositories caps the catalog listing.
const maxRepositories = 10000

type repoItem struct {
	name      string
	artifacts int64
	pulls     int64
	updated   time.Time
}

// reposView lists repositories, either from the registry catalog or, on
// Harbor, from the repositories API of one project.
type reposView struct {
	baseView
	project     string
	list        *list[repoItem]
	unavailable bool
}

type reposLoadedMsg struct {
	viewID int
	repos  []repoItem
	err    error
}

func (m reposLoadedMsg) target() int { return m.viewID }

// newReposView lists repositories via the catalog API.
func newReposView() *reposView {
	return &reposView{
		list: newList([]column{{title: "NAME", flex: 1}},
			func(r repoItem) []string { return []string{r.name} }, nil),
	}
}

// newProjectReposView lists the repositories of a Harbor project.
func newProjectReposView(project string) *reposView {
	return &reposView{
		project: project,
		list: newList(
			[]column{{title: "NAME", flex: 1}, {title: "ARTIFACTS", max: 9, right: true}, {title: "PULLS", max: 9, right: true}, {title: "UPDATED", max: 19}},
			func(r repoItem) []string {
				return []string{r.name, fmt.Sprint(r.artifacts), fmt.Sprint(r.pulls), timestamp(r.updated, "-")}
			}, nil),
	}
}

func (v *reposView) crumb() string   { return "repositories" }
func (v *reposView) title() string   { return "repositories" }
func (v *reposView) subject() string { return v.project }
func (v *reposView) count() int {
	if v.unavailable {
		return -1
	}
	return v.list.count()
}

func (v *reposView) hints() []hint {
	return []hint{{"enter", "tags"}, hintOf(keys.Reload)}
}

func (v *reposView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	v.list.setSize(w, h)
}

func (v *reposView) setFilter(f string) { v.list.setFilter(f) }
func (v *reposView) filter() string     { return v.list.filter }

// names returns the loaded repository names, used for command completion.
func (v *reposView) names() []string {
	out := make([]string, len(v.list.items))
	for i, r := range v.list.items {
		out[i] = r.name
	}
	return out
}

func (v *reposView) init(e *env) tea.Cmd {
	v.busy, v.err = true, nil
	id, project := v.id(), v.project
	return func() tea.Msg {
		ctx, cancel := e.timeout()
		defer cancel()
		msg := reposLoadedMsg{viewID: id}
		if project != "" && e.harbor != nil {
			repos, err := e.harbor.Repositories(ctx, project)
			msg.err = err
			for _, r := range repos {
				msg.repos = append(msg.repos, repoItem{name: r.Name, artifacts: r.ArtifactCount, pulls: r.PullCount, updated: r.UpdateTime})
			}
			return msg
		}
		names, err := e.client.Repositories(ctx, maxRepositories)
		msg.err = err
		for _, n := range names {
			msg.repos = append(msg.repos, repoItem{name: n})
		}
		return msg
	}
}

func (v *reposView) update(e *env, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case reposLoadedMsg:
		v.busy = false
		v.unavailable = errors.Is(msg.err, oci.ErrCatalogUnavailable)
		if msg.err != nil && !v.unavailable {
			v.err = msg.err
			return flashErr(msg.err)
		}
		v.list.setItems(msg.repos)
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Reload):
			return v.init(e)
		case key.Matches(msg, keys.Open):
			if repo, ok := v.list.selected(); ok {
				return push(newTagsView(repo.name))
			}
		default:
			v.list.update(msg)
		}
	}
	return nil
}

func (v *reposView) render() string {
	switch {
	case v.unavailable:
		return centered(v.width, v.height,
			styleWarn.Render("This registry does not expose the catalog API."),
			"",
			styleValue.Render("Open a repository with ")+stylePrompt.Render(":repo <name>"),
			styleValue.Render("or start beagle with ")+stylePrompt.Render("beagle <registry>/<repository>"),
		)
	case errors.Is(v.err, harbor.ErrUnauthorized) && len(v.list.items) == 0:
		return centered(v.width, v.height,
			styleError.Render("Not allowed to list the repositories of project "+v.project+"."),
			"",
			styleValue.Render("Log in with ")+stylePrompt.Render("docker login <registry>")+styleValue.Render(" and restart beagle."),
		)
	case v.err != nil && len(v.list.items) == 0:
		return centered(v.width, v.height, styleError.Render(v.err.Error()))
	case v.busy && len(v.list.items) == 0:
		return centered(v.width, v.height, styleMuted.Render("Loading repositories…"))
	case len(v.list.items) == 0:
		return centered(v.width, v.height, styleMuted.Render("No repositories."))
	}
	return v.list.view()
}

// centered places lines in the middle of a w×h area.
func centered(w, h int, lines ...string) string {
	block := lipgloss.JoinVertical(lipgloss.Center, lines...)
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, block)
}
