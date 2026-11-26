package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
)

const (
	// maxResolvedTags caps how many tags are resolved in the background.
	maxResolvedTags = 500
	// resolveConcurrency limits parallel manifest requests per view.
	resolveConcurrency = 8
)

type tagItem struct {
	name     string
	resolved bool
	desc     ocispec.Descriptor
	kind     oci.Kind
	info     string
	err      error
	subject  *oci.SubjectTag
}

type tagsView struct {
	baseView
	repo         string
	all          []*tagItem
	list         *list[*tagItem]
	showAttached bool
	pending      int
	gen          int
	sem          chan struct{}
}

type tagsLoadedMsg struct {
	viewID, gen int
	tags        []string
	err         error
}

type tagResolvedMsg struct {
	viewID, gen int
	item        *tagItem
	desc        ocispec.Descriptor
	kind        oci.Kind
	info        string
	err         error
}

func (m tagsLoadedMsg) target() int  { return m.viewID }
func (m tagResolvedMsg) target() int { return m.viewID }

func newTagsView(repo string) *tagsView {
	v := &tagsView{repo: repo, showAttached: true, sem: make(chan struct{}, resolveConcurrency)}
	v.list = newList(
		[]column{{title: "TAG", flex: 2}, {title: "KIND", max: 12}, {title: "DIGEST", max: 19}, {title: "INFO", flex: 3}},
		func(t *tagItem) []string {
			digest, info := "…", t.info
			if t.resolved {
				digest = shortDigest(t.desc.Digest)
			}
			if t.err != nil {
				digest, info = "error", t.err.Error()
			}
			kind := ""
			if t.resolved || t.subject != nil {
				kind = t.kind.String()
			}
			return []string{displayTag(t.name), kind, digest, info}
		},
		func(t *tagItem) lipgloss.Style {
			if t.err != nil {
				return styleError
			}
			return kindStyle(t.kind)
		},
	)
	return v
}

func (v *tagsView) crumb() string   { return "tags" }
func (v *tagsView) title() string   { return "tags" }
func (v *tagsView) subject() string { return v.repo }
func (v *tagsView) count() int      { return v.list.count() }
func (v *tagsView) loading() bool   { return v.busy || v.pending > 0 }

func (v *tagsView) hints() []hint {
	return []hint{{"enter", "manifest"}, hintOf(keys.Referrers), hintOf(keys.Raw), hintOf(keys.ToggleAll), hintOf(keys.Copy)}
}

func (v *tagsView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	v.list.setSize(w, h)
}

func (v *tagsView) setFilter(f string) { v.list.setFilter(f) }
func (v *tagsView) filter() string     { return v.list.filter }

func (v *tagsView) init(e *env) tea.Cmd {
	v.gen++
	v.busy, v.err, v.pending = true, nil, 0
	id, gen, repo := v.id(), v.gen, v.repo
	return func() tea.Msg {
		ctx, cancel := e.timeout()
		defer cancel()
		tags, err := e.client.Tags(ctx, repo)
		return tagsLoadedMsg{viewID: id, gen: gen, tags: tags, err: err}
	}
}

func (v *tagsView) update(e *env, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tagsLoadedMsg:
		if msg.gen != v.gen {
			return nil
		}
		v.busy = false
		if msg.err != nil {
			v.err = msg.err
			return flashErr(msg.err)
		}
		return v.setTags(e, msg.tags)
	case tagResolvedMsg:
		if msg.gen != v.gen {
			return nil
		}
		v.pending--
		it := msg.item
		it.resolved, it.desc, it.err = msg.err == nil, msg.desc, msg.err
		if it.subject == nil {
			it.kind, it.info = msg.kind, msg.info
		}
		v.list.refresh()
	case tea.KeyMsg:
		return v.handleKey(e, msg)
	}
	return nil
}

func (v *tagsView) handleKey(e *env, msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, keys.Reload):
		return v.init(e)
	case key.Matches(msg, keys.ToggleAll):
		v.showAttached = !v.showAttached
		v.applyVisibility()
		if v.showAttached {
			return flash(flashInfo, "Showing sha256-* tags")
		}
		return flash(flashInfo, "Hiding sha256-* tags (cosign legacy and referrers fallback)")
	}

	t, ok := v.list.selected()
	if !ok {
		v.list.update(msg)
		return nil
	}
	var desc *ocispec.Descriptor
	if t.resolved {
		desc = &t.desc
	}
	switch {
	case key.Matches(msg, keys.Open):
		return push(newManifestView(v.repo, t.name, desc))
	case key.Matches(msg, keys.Referrers):
		return push(newReferrersView(v.repo, t.name, desc))
	case key.Matches(msg, keys.Raw):
		return push(newRawManifestView(v.repo, t.name, desc))
	case key.Matches(msg, keys.Copy):
		ref := fmt.Sprintf("%s/%s:%s", e.client.Host(), v.repo, t.name)
		termenv.Copy(ref)
		return flash(flashInfo, "Copied %s", ref)
	default:
		v.list.update(msg)
	}
	return nil
}

func (v *tagsView) setTags(e *env, tags []string) tea.Cmd {
	var regular, attached []*tagItem
	for _, name := range tags {
		it := &tagItem{name: name}
		if st, ok := oci.ParseSubjectTag(name); ok {
			it.subject = &st
			it.kind = st.Kind
			it.info = fmt.Sprintf("→ %s (%s)", shortDigest(st.Subject), st.Scheme)
			attached = append(attached, it)
			continue
		}
		regular = append(regular, it)
	}
	v.all = append(regular, attached...)
	v.applyVisibility()

	detailed := e.client.Host() != "docker.io"
	var cmds []tea.Cmd
	for i, it := range v.all {
		if i >= maxResolvedTags {
			break
		}
		cmds = append(cmds, v.resolve(e, it, detailed))
	}
	v.pending = len(cmds)
	if len(v.all) > maxResolvedTags {
		cmds = append(cmds, flash(flashWarn, "Resolving the first %d of %d tags", maxResolvedTags, len(v.all)))
	}
	return tea.Batch(cmds...)
}

func (v *tagsView) applyVisibility() {
	items := v.all
	if !v.showAttached {
		items = nil
		for _, it := range v.all {
			if it.subject == nil {
				items = append(items, it)
			}
		}
	}
	v.list.setItems(items)
}

// resolve fetches a tag's manifest. On Docker Hub only a HEAD request is
// made, because manifest GETs count against the pull rate limit.
func (v *tagsView) resolve(e *env, it *tagItem, detailed bool) tea.Cmd {
	id, gen, repo, sem := v.id(), v.gen, v.repo, v.sem
	return func() tea.Msg {
		sem <- struct{}{}
		defer func() { <-sem }()
		ctx, cancel := e.timeout()
		defer cancel()
		res := tagResolvedMsg{viewID: id, gen: gen, item: it}
		if !detailed {
			res.desc, res.err = e.client.Resolve(ctx, repo, it.name)
			res.kind = oci.ClassifyDescriptor(res.desc)
			res.info = shortMediaType(res.desc.MediaType)
			return res
		}
		m, err := e.client.FetchManifestReference(ctx, repo, it.name)
		if err != nil {
			res.err = err
			return res
		}
		res.desc, res.kind, res.info = m.Descriptor, oci.ClassifyManifest(m), manifestInfo(m)
		return res
	}
}

// displayTag shortens digest tags (sha256-<hex>[.sig]) so the suffix stays
// visible in narrow columns.
func displayTag(tag string) string {
	st, ok := oci.ParseSubjectTag(tag)
	if !ok {
		return tag
	}
	short := strings.Replace(shortDigest(st.Subject), ":", "-", 1) + "…"
	if _, suffix, found := strings.Cut(tag, "."); found {
		short += "." + suffix
	}
	return short
}

// manifestInfo summarizes a manifest in one line for the INFO column.
func manifestInfo(m *oci.Manifest) string {
	if m.IsIndex() {
		var platforms []string
		attestations := 0
		for _, d := range m.Manifests {
			if d.Annotations[oci.AnnotationDockerReferenceType] == "attestation-manifest" {
				attestations++
				continue
			}
			if p := oci.PlatformString(d.Platform); p != "" {
				platforms = append(platforms, p)
			}
		}
		s := strings.Join(platforms, ", ")
		if attestations > 0 {
			s += fmt.Sprintf(" (+%d attestation manifests)", attestations)
		}
		if s == "" {
			s = fmt.Sprintf("%d manifests", len(m.Manifests))
		}
		return s
	}
	if at := m.EffectiveArtifactType(); at != "" {
		return at
	}
	layers := "layers"
	if len(m.Layers) == 1 {
		layers = "layer"
	}
	return fmt.Sprintf("%d %s, %s", len(m.Layers), layers, humanSize(m.ContentSize()))
}

func (v *tagsView) render() string {
	switch {
	case v.err != nil && len(v.all) == 0:
		return centered(v.width, v.height, styleError.Render(v.err.Error()))
	case v.busy && len(v.all) == 0:
		return centered(v.width, v.height, styleMuted.Render("Loading tags…"))
	case len(v.all) == 0:
		return centered(v.width, v.height, styleMuted.Render("No tags."))
	}
	return v.list.view()
}
