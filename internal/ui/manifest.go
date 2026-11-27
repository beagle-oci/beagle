package ui

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
)

// kindLabel names a kind in a table cell; unknown kinds stay blank because the
// media type next to it says more.
func kindLabel(k oci.Kind) string {
	if k == oci.KindUnknown {
		return ""
	}
	return k.String()
}

// entry is a row in the manifest view: an index entry, the config or a layer.
type entry struct {
	role string // platform, "config" or "layer N"
	desc ocispec.Descriptor
	kind oci.Kind
}

type manifestView struct {
	baseView
	repo      string
	reference string
	desc      *ocispec.Descriptor
	manifest  *oci.Manifest
	kind      oci.Kind
	list      *list[entry]
}

type manifestLoadedMsg struct {
	viewID   int
	manifest *oci.Manifest
	err      error
}

func (m manifestLoadedMsg) target() int { return m.viewID }

// newManifestView shows the manifest identified by reference (tag or
// digest). desc may be nil if the reference has not been resolved yet.
func newManifestView(repo, reference string, desc *ocispec.Descriptor) *manifestView {
	v := &manifestView{repo: repo, reference: reference, desc: desc}
	v.list = newList(
		[]column{{title: "NAME", max: 24}, {title: "KIND", max: 12}, {title: "DIGEST", max: 19}, {title: "MEDIA TYPE", flex: 3}, {title: "SIZE", max: 10, right: true}, {title: "TITLE", flex: 1}},
		func(e entry) []string {
			return []string{e.role, kindLabel(e.kind), shortDigest(e.desc.Digest), e.desc.MediaType, humanSize(e.desc.Size), e.desc.Annotations[ocispec.AnnotationTitle]}
		},
		func(e entry) lipgloss.Style { return kindStyle(e.kind) },
	)
	return v
}

func (v *manifestView) crumb() string   { return "manifest" }
func (v *manifestView) title() string   { return "manifest" }
func (v *manifestView) subject() string { return refString(v.repo, v.reference) }
func (v *manifestView) count() int      { return v.list.count() }

func (v *manifestView) hints() []hint {
	h := []hint{{"enter", "open"}, hintOf(keys.Referrers), hintOf(keys.Raw), hintOf(keys.Copy)}
	if v.manifest != nil && v.manifest.Subject != nil {
		h = append(h, hintOf(keys.Subject))
	}
	return h
}

func (v *manifestView) setFilter(f string) { v.list.setFilter(f) }
func (v *manifestView) filter() string     { return v.list.filter }

func (v *manifestView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	v.layout()
}

func (v *manifestView) layout() {
	v.list.setSize(v.width, max(v.height-lipgloss.Height(v.summary())-1, 3))
}

func (v *manifestView) init(e *env) tea.Cmd {
	v.busy, v.err = true, nil
	id, repo, ref, desc := v.id(), v.repo, v.reference, v.desc
	return func() tea.Msg {
		ctx, cancel := e.timeout()
		defer cancel()
		var m *oci.Manifest
		var err error
		if desc != nil {
			m, err = e.client.FetchManifest(ctx, repo, *desc)
		} else {
			m, err = e.client.FetchManifestReference(ctx, repo, ref)
		}
		return manifestLoadedMsg{viewID: id, manifest: m, err: err}
	}
}

func (v *manifestView) update(e *env, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case manifestLoadedMsg:
		v.busy = false
		if msg.err != nil {
			v.err = msg.err
			return flashErr(msg.err)
		}
		v.setManifest(msg.manifest)
	case tea.KeyMsg:
		return v.handleKey(e, msg)
	}
	return nil
}

func (v *manifestView) setManifest(m *oci.Manifest) {
	v.manifest = m
	d := m.Descriptor
	v.desc = &d
	v.kind = oci.ClassifyManifest(m)

	var entries []entry
	if m.IsIndex() {
		for _, d := range m.Manifests {
			role := oci.PlatformString(d.Platform)
			if d.Annotations[oci.AnnotationDockerReferenceType] == "attestation-manifest" {
				role = "attestation"
			}
			if role == "" {
				role = "-"
			}
			entries = append(entries, entry{role: role, desc: d, kind: oci.ClassifyDescriptor(d)})
		}
	} else {
		if m.Config != nil {
			entries = append(entries, entry{role: "config", desc: *m.Config, kind: oci.ClassifyMediaType(m.Config.MediaType)})
		}
		for i, l := range m.Layers {
			entries = append(entries, entry{role: fmt.Sprintf("layer %d", i+1), desc: l, kind: oci.ClassifyMediaType(l.MediaType)})
		}
	}
	v.list.setItems(entries)
	v.layout()
}

func (v *manifestView) handleKey(e *env, msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, keys.Reload):
		return v.init(e)
	case v.manifest == nil:
		return nil
	case key.Matches(msg, keys.Referrers):
		return push(newReferrersView(v.repo, v.reference, v.desc))
	case key.Matches(msg, keys.Raw):
		return push(newRawManifestView(v.repo, v.reference, v.desc))
	case key.Matches(msg, keys.Subject):
		if s := v.manifest.Subject; s != nil {
			d := *s
			return push(newManifestView(v.repo, d.Digest.String(), &d))
		}
		return flash(flashWarn, "This manifest has no subject")
	case key.Matches(msg, keys.Copy):
		ref := fmt.Sprintf("%s/%s@%s", e.client.Host(), v.repo, v.manifest.Descriptor.Digest)
		copyToClipboard(ref)
		return flash(flashInfo, "Copied %s", ref)
	case key.Matches(msg, keys.Open):
		sel, ok := v.list.selected()
		if !ok {
			return nil
		}
		d := sel.desc
		if v.manifest.IsIndex() || oci.IsManifestMediaType(d.MediaType) {
			return push(newManifestView(v.repo, d.Digest.String(), &d))
		}
		if !isTextual(d.MediaType) {
			return flash(flashWarn, "%s is binary content (%s), not shown", sel.role, humanSize(d.Size))
		}
		return push(newRawBlobView(v.repo, sel.role, d))
	default:
		v.list.update(msg)
	}
	return nil
}

// isTextual reports whether a blob of this media type is worth showing in
// the raw viewer.
func isTextual(mediaType string) bool {
	mt := strings.ToLower(mediaType)
	if strings.Contains(mt, "tar") || strings.Contains(mt, "gzip") || strings.Contains(mt, "zstd") {
		return false
	}
	for _, s := range []string{"json", "text/", "yaml", "xml", "spdx", "cyclonedx", "jose"} {
		if strings.Contains(mt, s) {
			return true
		}
	}
	return false
}

func (v *manifestView) summary() string {
	if v.manifest == nil {
		return ""
	}
	m := v.manifest
	type field struct{ label, value string }
	fields := []field{
		{"Reference", refString(v.repo, v.reference)},
		{"Digest", m.Descriptor.Digest.String()},
		{"Media type", m.MediaType},
		{"Kind", v.kind.String()},
	}
	if at := m.EffectiveArtifactType(); at != "" {
		fields = append(fields, field{"Artifact type", at})
	}
	size := humanSize(m.Descriptor.Size) + " manifest"
	if !m.IsIndex() {
		size += ", " + humanSize(m.ContentSize()) + " content"
	}
	fields = append(fields, field{"Size", size})
	if m.Subject != nil {
		fields = append(fields, field{"Subject", m.Subject.Digest.String() + "  (press s)"})
	}
	annKeys := slices.Sorted(maps.Keys(m.Annotations))
	for i, k := range annKeys {
		if i == 4 {
			fields = append(fields, field{"", fmt.Sprintf("… %d more (press y)", len(annKeys)-4)})
			break
		}
		label := ""
		if i == 0 {
			label = "Annotations"
		}
		fields = append(fields, field{label, k + "=" + m.Annotations[k]})
	}

	lines := make([]string, 0, len(fields))
	for _, f := range fields {
		label := f.label
		if label != "" {
			label += ":"
		}
		line := " " + styleLabel.Render(fmt.Sprintf("%-15s", label)) + styleValue.Render(f.value)
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (v *manifestView) render() string {
	switch {
	case v.err != nil && v.manifest == nil:
		return centered(v.width, v.height, styleError.Render(v.err.Error()))
	case v.manifest == nil:
		return centered(v.width, v.height, styleMuted.Render("Loading manifest…"))
	}
	return v.summary() + "\n\n" + v.list.view()
}

// refString renders repo:tag or repo@digest.
func refString(repo, reference string) string {
	if strings.Contains(reference, ":") {
		return repo + "@" + reference
	}
	return repo + ":" + reference
}
