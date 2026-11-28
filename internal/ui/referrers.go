package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/sigverify"
)

type referrersView struct {
	baseView
	repo      string
	reference string
	desc      *ocispec.Descriptor
	tree      *oci.TreeNode
	list      *list[oci.FlatNode]

	// verified and verifying track the signature checks of tree nodes.
	verified  map[*oci.TreeNode]*sigverify.Result
	verifying map[*oci.TreeNode]bool
	sem       chan struct{}
}

type treeVerifiedMsg struct {
	viewID int
	tree   *oci.TreeNode
	node   *oci.TreeNode
	result sigverify.Result
}

func (m treeVerifiedMsg) target() int { return m.viewID }

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
	v := &referrersView{repo: repo, reference: reference, desc: desc, sem: make(chan struct{}, resolveConcurrency)}
	v.list = newList(
		[]column{{title: "ARTIFACT", flex: 3}, {title: "KIND", max: 12}, {title: "DIGEST", max: 19}, {title: "SOURCE", max: 11}, {title: "CREATED", max: 19}},
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
			return []string{n.Prefix + label, node.Kind.String(), dgst, sourceLabel(node.Source), annotationTime(node.Descriptor.Annotations[ocispec.AnnotationCreated]), v.mark(node)}
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
	v.list.cell = func(n oci.FlatNode, col int) *lipgloss.Style {
		if col == verifiedColumn {
			return verificationStyle(v.verified[n.Node])
		}
		return nil
	}
	return v
}

// verifiedColumn is the index of the VERIFIED column, which is only shown
// when verification is on.
const verifiedColumn = 5

// mark shows the verification state of a node.
func (v *referrersView) mark(n *oci.TreeNode) string {
	if r := v.verified[n]; r != nil {
		switch r.Status {
		case sigverify.Verified:
			return "✓"
		case sigverify.Invalid:
			return "✗"
		}
		return "?"
	}
	if v.verifying[n] {
		return "…"
	}
	return ""
}

// verifyRef tells whether beagle can verify a node and how to fetch it:
// signatures, and attestations stored as Sigstore bundles.
func verifyRef(n *oci.TreeNode) (oci.SignatureRef, bool) {
	switch {
	case n.Source == oci.SourceCosignTag && n.Kind == oci.KindSignature:
		return oci.SignatureRef{Format: oci.FormatCosign, Tag: n.Label}, true
	case n.Source != oci.SourceReferrer:
		return oci.SignatureRef{}, false
	case n.Kind == oci.KindSignature:
		return oci.SignatureRef{Format: oci.SignatureFormat(n.Descriptor), Descriptor: n.Descriptor}, true
	case n.Kind == oci.KindAttestation && strings.HasPrefix(n.Descriptor.ArtifactType, "application/vnd.dev.sigstore.bundle"):
		return oci.SignatureRef{Format: oci.FormatCosign, Descriptor: n.Descriptor}, true
	}
	return oci.SignatureRef{}, false
}

// verifyTree starts verifying every signature and signed attestation in
// the tree against its parent.
func (v *referrersView) verifyTree(e *env) tea.Cmd {
	if e.verifier == nil || v.tree == nil {
		return nil
	}
	v.verified, v.verifying = map[*oci.TreeNode]*sigverify.Result{}, map[*oci.TreeNode]bool{}
	var cmds []tea.Cmd
	var walk func(parent, n *oci.TreeNode)
	walk = func(parent, n *oci.TreeNode) {
		if parent != nil && parent.Descriptor.Digest != "" {
			if ref, ok := verifyRef(n); ok {
				cmds = append(cmds, v.verifyNode(e, parent.Descriptor.Digest, n, ref))
			}
		}
		for _, c := range n.Children {
			walk(n, c)
		}
	}
	walk(nil, v.tree)
	return tea.Batch(cmds...)
}

func (v *referrersView) verifyNode(e *env, subject digest.Digest, n *oci.TreeNode, ref oci.SignatureRef) tea.Cmd {
	v.verifying[n] = true
	id, repo, tree, sem := v.id(), v.repo, v.tree, v.sem
	signature := n.Kind == oci.KindSignature
	return func() tea.Msg {
		sem <- struct{}{}
		defer func() { <-sem }()
		ctx, cancel := e.timeout()
		defer cancel()
		var r sigverify.Result
		if signature {
			r = e.verifier.Signature(ctx, e.client, repo, subject, ref)
		} else {
			r = e.verifier.Attached(ctx, e.client, repo, subject, ref)
		}
		return treeVerifiedMsg{viewID: id, tree: tree, node: n, result: r}
	}
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
	switch {
	case v.tree == nil:
		return -1
	case v.list.filter != "":
		return v.list.count()
	}
	return v.tree.Count()
}

func (v *referrersView) refreshRows() { v.list.refresh() }

func (v *referrersView) hints() []hint {
	return []hint{{"enter", "manifest"}, hintOf(keys.Raw), hintOf(keys.Copy), hintOf(keys.Reload)}
}

func (v *referrersView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	v.list.setSize(w, h)
}

func (v *referrersView) setFilter(f string) { v.list.setFilter(f) }
func (v *referrersView) filter() string     { return v.list.filter }

func (v *referrersView) loading() bool { return v.busy || len(v.verifying) > 0 }

func (v *referrersView) init(e *env) tea.Cmd {
	if e.verifier != nil && len(v.list.cols) == verifiedColumn {
		v.list.cols = append(v.list.cols, column{title: "VERIFIED", max: 8})
	}
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
		return v.verifyTree(e)
	case treeVerifiedMsg:
		if msg.tree != v.tree {
			return nil
		}
		delete(v.verifying, msg.node)
		v.verified[msg.node] = &msg.result
		v.list.refresh()
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
		copyToClipboard(ref)
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
