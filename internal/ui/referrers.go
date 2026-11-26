package ui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
)

type referrersView struct {
	baseView
	repo      string
	reference string
	desc      *ocispec.Descriptor
	tree      *oci.TreeNode
	list      *list[oci.FlatNode]
}

type treeLoadedMsg struct {
	viewID int
	desc   ocispec.Descriptor
	tree   *oci.TreeNode
	err    error
}

func (m treeLoadedMsg) target() int { return m.viewID }

// newReferrersView shows everything attached to the manifest identified by
// reference. desc may be nil if the reference has not been resolved yet.
func newReferrersView(repo, reference string, desc *ocispec.Descriptor) *referrersView {
	v := &referrersView{repo: repo, reference: reference, desc: desc}
	v.list = newList(
		[]column{{title: "ARTIFACT", flex: 3}, {title: "KIND", max: 12}, {title: "DIGEST", max: 19}, {title: "SOURCE", max: 11}, {title: "AGE", max: 6, right: true}},
		func(n oci.FlatNode) []string {
			node := n.Node
			label := nodeLabel(node, v.reference)
			if node.Err != nil {
				label += "  ✗ " + node.Err.Error()
			}
			dgst := ""
			if node.Descriptor.Digest != "" {
				dgst = shortDigest(node.Descriptor.Digest)
			}
			return []string{n.Prefix + label, node.Kind.String(), dgst, sourceLabel(node.Source), age(node.Descriptor.Annotations[ocispec.AnnotationCreated])}
		},
		func(n oci.FlatNode) lipgloss.Style {
			if n.Node.Err != nil {
				return styleError
			}
			if n.Node.Source == oci.SourceSubject {
				return styleTitle
			}
			return kindStyle(n.Node.Kind)
		},
	)
	return v
}

func nodeLabel(n *oci.TreeNode, reference string) string {
	switch n.Source {
	case oci.SourceSubject:
		return reference
	case oci.SourceCosignTag:
		return displayTag(n.Label)
	case oci.SourcePlatform:
		return n.Label
	}
	if n.Descriptor.ArtifactType != "" {
		return n.Descriptor.ArtifactType
	}
	return n.Descriptor.MediaType
}

func sourceLabel(s string) string {
	switch s {
	case oci.SourceCosignTag:
		return "cosign tag"
	case oci.SourceSubject:
		return ""
	}
	return s
}

func (v *referrersView) crumb() string   { return "referrers" }
func (v *referrersView) title() string   { return "referrers" }
func (v *referrersView) subject() string { return refString(v.repo, v.reference) }
func (v *referrersView) count() int {
	if v.tree == nil {
		return -1
	}
	return v.tree.Count()
}

func (v *referrersView) hints() []hint {
	return []hint{{"enter", "manifest"}, hintOf(keys.Raw), hintOf(keys.Copy), hintOf(keys.Reload)}
}

func (v *referrersView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	v.list.setSize(w, h)
}

func (v *referrersView) setFilter(f string) { v.list.setFilter(f) }
func (v *referrersView) filter() string     { return v.list.filter }

func (v *referrersView) init(e *env) tea.Cmd {
	v.busy, v.err = true, nil
	id, repo, ref, desc := v.id(), v.repo, v.reference, v.desc
	return func() tea.Msg {
		ctx, cancel := e.timeout()
		defer cancel()
		res := treeLoadedMsg{viewID: id}
		if desc != nil {
			res.desc = *desc
		} else {
			res.desc, res.err = e.client.Resolve(ctx, repo, ref)
			if res.err != nil {
				return res
			}
		}
		res.tree, res.err = e.client.ReferrerTree(ctx, repo, res.desc, oci.TreeOptions{})
		return res
	}
}

func (v *referrersView) update(e *env, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case treeLoadedMsg:
		v.busy = false
		if msg.err != nil {
			v.err = msg.err
			return flashErr(msg.err)
		}
		d := msg.desc
		v.desc, v.tree = &d, msg.tree
		v.list.setItems(msg.tree.Flatten())
		if msg.tree.Count() == 0 {
			return flash(flashInfo, "No referrers or cosign tags found")
		}
	case tea.KeyMsg:
		return v.handleKey(e, msg)
	}
	return nil
}

func (v *referrersView) handleKey(e *env, msg tea.KeyMsg) tea.Cmd {
	if key.Matches(msg, keys.Reload) {
		return v.init(e)
	}
	sel, ok := v.list.selected()
	if !ok {
		v.list.update(msg)
		return nil
	}
	d := sel.Node.Descriptor
	switch {
	case key.Matches(msg, keys.Open):
		if d.Digest == "" {
			return nil
		}
		return push(newManifestView(v.repo, d.Digest.String(), &d))
	case key.Matches(msg, keys.Raw):
		if d.Digest == "" {
			return nil
		}
		return push(newRawManifestView(v.repo, d.Digest.String(), &d))
	case key.Matches(msg, keys.Copy):
		if d.Digest == "" {
			return nil
		}
		ref := fmt.Sprintf("%s/%s@%s", e.client.Host(), v.repo, d.Digest)
		termenv.Copy(ref)
		return flash(flashInfo, "Copied %s", ref)
	default:
		v.list.update(msg)
	}
	return nil
}

func (v *referrersView) render() string {
	switch {
	case v.err != nil && v.tree == nil:
		return centered(v.width, v.height, styleError.Render(v.err.Error()))
	case v.tree == nil:
		return centered(v.width, v.height, styleMuted.Render("Walking referrers…"))
	}
	return v.list.view()
}
