package ui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/meta"
	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/sigverify"
)

const (
	// resolveConcurrency limits parallel registry requests per view.
	resolveConcurrency = 8
	// detailBuffer is how many rows above and below the visible window are
	// loaded ahead of scrolling.
	detailBuffer = 10
)

type loadState int

const (
	stateIdle loadState = iota
	stateLoading
	stateDone
)

type sortMode int

const (
	sortDefault sortMode = iota
	sortNewest
	sortName
)

type tagItem struct {
	name    string
	subject *oci.SubjectTag
	order   int

	state loadState
	desc  ocispec.Descriptor
	kind  oci.Kind
	info  string
	err   error

	// Details are loaded lazily for visible rows and work on every registry.
	attach    *oci.Attachments
	attachErr error
	created   time.Time

	// meta comes from a vendor API (Harbor, Docker Hub) when available.
	meta *meta.TagInfo

	// verify is the verification outcome of the attached signatures.
	verify      *sigverify.Result
	verifyState loadState
}

// signatureMark shows how far the signatures check out: ✓ verified,
// ✗ invalid, ? not verifiable, … being verified, • not verified.
func (t *tagItem) signatureMark() string {
	switch {
	case t.verify != nil:
		switch t.verify.Status {
		case sigverify.Verified:
			return "✓"
		case sigverify.Invalid:
			return "✗"
		}
		return "?"
	case t.verifyState == stateLoading:
		return "…"
	}
	return "•"
}

// verificationStyle colors a verification result.
func verificationStyle(r *sigverify.Result) *lipgloss.Style {
	switch {
	case r == nil:
		return nil
	case r.Status == sigverify.Verified:
		return &styleSigned
	case r.Status == sigverify.Invalid:
		return &styleCritical
	}
	return &styleHigh
}

func (t *tagItem) resolved() bool { return t.state == stateDone && t.err == nil }

// signatures merges what the referrers and the vendor API report.
func (t *tagItem) signatures() []string {
	var out []string
	if t.attach != nil {
		out = append(out, t.attach.Signatures...)
	}
	if t.meta != nil {
		out = append(out, t.meta.Signatures...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (t *tagItem) attachedLabels() []string {
	var out []string
	if t.attach != nil {
		for _, k := range []struct {
			kind  oci.Kind
			label string
		}{{oci.KindSBOM, "sbom"}, {oci.KindAttestation, "att"}, {oci.KindVEX, "vex"}, {oci.KindVulnReport, "vuln"}, {oci.KindArtifact, "other"}} {
			if t.attach.Kinds[k.kind] > 0 {
				out = append(out, k.label)
			}
		}
	}
	if t.meta != nil {
		for _, a := range t.meta.Attached {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// newest is the time used for "newest first" sorting.
func (t *tagItem) newest() time.Time {
	if t.meta != nil && !t.meta.Pushed.IsZero() {
		return t.meta.Pushed
	}
	return t.created
}

// tagColumn is a column of the tag list.
type tagColumn struct {
	column
	value func(*tagItem) string
	style func(*tagItem) *lipgloss.Style
}

type tagsView struct {
	baseView
	repo         string
	all          []*tagItem
	names        []string
	list         *list[*tagItem]
	columns      []tagColumn
	caps         meta.Capabilities
	provider     string
	showAttached bool
	sort         sortMode
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
	attach      *oci.Attachments
	attachErr   error
	created     time.Time
}

type tagMetaMsg struct {
	viewID, gen int
	infos       map[string]meta.TagInfo
	err         error
}

type tagVerifiedMsg struct {
	viewID, gen int
	item        *tagItem
	result      sigverify.Result
}

func (m tagsLoadedMsg) target() int  { return m.viewID }
func (m tagResolvedMsg) target() int { return m.viewID }
func (m tagMetaMsg) target() int     { return m.viewID }
func (m tagVerifiedMsg) target() int { return m.viewID }

func newTagsView(repo string) *tagsView {
	v := &tagsView{repo: repo, showAttached: true, sem: make(chan struct{}, resolveConcurrency)}
	v.list = newList(nil,
		func(t *tagItem) []string {
			row := make([]string, len(v.columns))
			for i, c := range v.columns {
				row[i] = c.value(t)
			}
			return row
		},
		func(t *tagItem) lipgloss.Style {
			if t.err != nil {
				return styleError
			}
			return kindStyle(t.kind)
		},
	)
	v.list.cell = func(t *tagItem, col int) *lipgloss.Style {
		if col < len(v.columns) && v.columns[col].style != nil {
			return v.columns[col].style(t)
		}
		return nil
	}
	v.setColumns(meta.Capabilities{})
	return v
}

var (
	styleSigned   = lipgloss.NewStyle().Foreground(lipgloss.Color("114")).Bold(true)
	styleCritical = lipgloss.NewStyle().Foreground(colorError).Bold(true)
	styleHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	styleClean    = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
)

// setColumns picks the columns: push/pull times and vulnerabilities only when
// a vendor API provides them, the build time otherwise.
func (v *tagsView) setColumns(caps meta.Capabilities) {
	v.caps = caps
	loading := func(t *tagItem) bool { return t.subject == nil && t.state != stateDone }

	cols := []tagColumn{
		{column: column{title: "TAG", flex: 2}, value: func(t *tagItem) string { return displayTag(t.name) }},
		{column: column{title: "KIND", max: 12}, value: func(t *tagItem) string {
			if t.state == stateDone || t.subject != nil {
				return t.kind.String()
			}
			return ""
		}},
		{column: column{title: "DIGEST", max: 12}, value: func(t *tagItem) string {
			switch {
			case t.err != nil:
				return "error"
			case t.resolved():
				return t.desc.Digest.Encoded()[:12]
			}
			return "…"
		}},
		{
			column: column{title: "SIGNED", max: 16},
			value: func(t *tagItem) string {
				if t.subject != nil {
					return ""
				}
				if sigs := t.signatures(); len(sigs) > 0 {
					return t.signatureMark() + " " + strings.Join(sigs, ",")
				}
				switch {
				case t.attachErr != nil:
					return "?"
				case t.attach == nil && loading(t):
					return "…"
				}
				return "-"
			},
			style: func(t *tagItem) *lipgloss.Style {
				if t.subject != nil || len(t.signatures()) == 0 {
					return nil
				}
				return verificationStyle(t.verify)
			},
		},
		{column: column{title: "ATTACHED", max: 16}, value: func(t *tagItem) string {
			if t.subject != nil {
				return ""
			}
			if labels := t.attachedLabels(); len(labels) > 0 {
				return strings.Join(labels, " ")
			}
			if t.attach == nil && loading(t) {
				return "…"
			}
			return "-"
		}},
	}
	if caps.Pushed {
		cols = append(cols, tagColumn{column: column{title: "PUSHED", max: 19}, value: func(t *tagItem) string {
			if t.meta == nil {
				return ""
			}
			return formatTime(t.meta.Pushed, "-")
		}})
	}
	if caps.Pulled {
		cols = append(cols, tagColumn{column: column{title: "PULLED", max: 19}, value: func(t *tagItem) string {
			if t.meta == nil {
				return ""
			}
			return formatTime(t.meta.Pulled, "never")
		}})
	}
	if caps.Vulns {
		cols = append(cols, tagColumn{
			column: column{title: "VULNS", max: 16},
			value: func(t *tagItem) string {
				if t.meta == nil || t.subject != nil {
					return ""
				}
				return t.meta.Vulns.String()
			},
			style: func(t *tagItem) *lipgloss.Style {
				if t.meta == nil || t.subject != nil || !t.meta.Vulns.Done() {
					return nil
				}
				switch v := t.meta.Vulns; {
				case v.Critical > 0:
					return &styleCritical
				case v.High > 0:
					return &styleHigh
				case v.Medium+v.Low+v.Unknown == 0:
					return &styleClean
				}
				return nil
			},
		})
	}
	if !caps.Pushed {
		cols = append(cols, tagColumn{column: column{title: "CREATED", max: 19}, value: func(t *tagItem) string {
			switch {
			case t.subject != nil:
				return ""
			case loading(t):
				return "…"
			}
			return formatTime(t.created, "-")
		}})
	}
	cols = append(cols, tagColumn{column: column{title: "INFO", flex: 3}, value: func(t *tagItem) string {
		if t.err != nil {
			return t.err.Error()
		}
		return t.info
	}})

	v.columns = cols
	v.list.cols = make([]column, len(cols))
	for i, c := range cols {
		v.list.cols[i] = c.column
	}
	v.list.refresh()
}

func (v *tagsView) crumb() string { return "tags" }

func (v *tagsView) refreshRows()  { v.list.refresh() }
func (v *tagsView) title() string { return "tags" }
func (v *tagsView) subject() string {
	if v.provider != "" {
		return v.repo + " · " + v.provider
	}
	return v.repo
}
func (v *tagsView) count() int    { return v.list.count() }
func (v *tagsView) loading() bool { return v.busy || v.pending > 0 }

func (v *tagsView) hints() []hint {
	return []hint{{"enter", "manifest"}, hintOf(keys.Referrers), hintOf(keys.Raw), hintOf(keys.Sort), hintOf(keys.ToggleAll), hintOf(keys.Copy)}
}

func (v *tagsView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	v.list.setSize(w, h)
}

func (v *tagsView) setFilter(f string) { v.list.setFilter(f) }
func (v *tagsView) filter() string     { return v.list.filter }

func (v *tagsView) init(e *env) tea.Cmd {
	if e.meta != nil {
		v.provider = e.meta.Name()
		v.setColumns(e.meta.Capabilities())
	}
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
		it.state, it.desc, it.err = stateDone, msg.desc, msg.err
		if it.subject == nil {
			it.kind, it.info = msg.kind, msg.info
		}
		it.attach, it.attachErr, it.created = msg.attach, msg.attachErr, msg.created
		v.list.refresh()
		return v.verify(e, it)
	case tagVerifiedMsg:
		if msg.gen != v.gen {
			return nil
		}
		v.pending--
		msg.item.verify, msg.item.verifyState = &msg.result, stateDone
		v.list.refresh()
	case tagMetaMsg:
		if msg.gen != v.gen {
			return nil
		}
		v.pending--
		if msg.err != nil {
			return flash(flashWarn, "%s metadata unavailable: %v", v.provider, msg.err)
		}
		for _, it := range v.all {
			if info, ok := msg.infos[it.name]; ok {
				it.meta = &info
			}
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
	case key.Matches(msg, keys.Sort):
		v.sort = (v.sort + 1) % 3
		v.applyVisibility()
		switch v.sort {
		case sortNewest:
			if v.caps.Pushed {
				return flash(flashInfo, "Sorted by push time, newest first")
			}
			return flash(flashInfo, "Sorted by build time, newest first (loaded tags only)")
		case sortName:
			return flash(flashInfo, "Sorted by name")
		}
		return flash(flashInfo, "Registry order")
	}

	t, ok := v.list.selected()
	if !ok {
		v.list.update(msg)
		return nil
	}
	var desc *ocispec.Descriptor
	if t.resolved() {
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
		copyToClipboard(ref)
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
	for i, it := range v.all {
		it.order = i
	}
	v.names = tags
	v.applyVisibility()

	var cmds []tea.Cmd
	if e.meta != nil {
		v.pending++
		id, gen, repo, provider := v.id(), v.gen, v.repo, e.meta
		cmds = append(cmds, func() tea.Msg {
			ctx, cancel := e.timeout()
			defer cancel()
			infos, err := provider.Tags(ctx, repo)
			return tagMetaMsg{viewID: id, gen: gen, infos: infos, err: err}
		})
	}
	cmds = append(cmds, v.loadVisible(e))
	return tea.Batch(cmds...)
}

func (v *tagsView) applyVisibility() {
	items := make([]*tagItem, 0, len(v.all))
	for _, it := range v.all {
		if v.showAttached || it.subject == nil {
			items = append(items, it)
		}
	}
	switch v.sort {
	case sortNewest:
		slices.SortStableFunc(items, func(a, b *tagItem) int {
			// Unknown times sort last; newer first.
			ta, tb := a.newest(), b.newest()
			if ta.IsZero() != tb.IsZero() {
				if ta.IsZero() {
					return 1
				}
				return -1
			}
			return tb.Compare(ta)
		})
	case sortName:
		slices.SortStableFunc(items, func(a, b *tagItem) int { return cmp.Compare(a.name, b.name) })
	default:
		slices.SortStableFunc(items, func(a, b *tagItem) int { return cmp.Compare(a.order, b.order) })
	}
	v.list.setItems(items)
}

// loadVisible starts loading details for the rows around the visible window
// that have not been requested yet. The app calls it after every update, so
// scrolling, filtering and resizing load what comes into view.
func (v *tagsView) loadVisible(e *env) tea.Cmd {
	start := max(v.list.offset-detailBuffer, 0)
	end := min(v.list.offset+v.list.bodyHeight()+detailBuffer, len(v.list.visible))
	var cmds []tea.Cmd
	for i := start; i < end; i++ {
		it := v.list.items[v.list.visible[i]]
		if it.state != stateIdle {
			continue
		}
		it.state = stateLoading
		v.pending++
		cmds = append(cmds, v.resolve(e, it))
	}
	return tea.Batch(cmds...)
}

// resolve fetches a tag's manifest and, for regular tags, its attachments
// and build time. On Docker Hub only a HEAD request is made for the manifest
// because manifest GETs count against the pull rate limit.
func (v *tagsView) resolve(e *env, it *tagItem) tea.Cmd {
	id, gen, repo, sem, names := v.id(), v.gen, v.repo, v.sem, v.names
	wantCreated := !v.caps.Pushed
	dockerHub := isDockerHub(e)
	return func() tea.Msg {
		sem <- struct{}{}
		defer func() { <-sem }()
		ctx, cancel := e.timeout()
		defer cancel()
		res := tagResolvedMsg{viewID: id, gen: gen, item: it}

		var m *oci.Manifest
		if dockerHub {
			res.desc, res.err = e.client.Resolve(ctx, repo, it.name)
			res.kind = oci.ClassifyDescriptor(res.desc)
			res.info = shortMediaType(res.desc.MediaType)
		} else {
			m, res.err = e.client.FetchManifestReference(ctx, repo, it.name)
			if m != nil {
				res.desc, res.kind, res.info = m.Descriptor, oci.ClassifyManifest(m), manifestInfo(m)
			}
		}
		if res.err != nil || it.subject != nil {
			return res
		}

		a, err := e.client.Attachments(ctx, repo, res.desc, names)
		res.attach, res.attachErr = &a, err
		if wantCreated && m != nil {
			res.created, _ = e.client.Created(ctx, repo, m)
		}
		return res
	}
}

// isDockerHub reports whether beagle talks to Docker Hub, where manifest
// GETs count against the pull rate limit.
func isDockerHub(e *env) bool { return e.client.Host() == "docker.io" }

// verify starts verifying the signatures attached to a resolved tag. On
// Docker Hub it waits until the user opens the manifest, because fetching
// signature manifests counts against the pull rate limit.
func (v *tagsView) verify(e *env, it *tagItem) tea.Cmd {
	if e.verifier == nil || isDockerHub(e) || it.err != nil || it.attach == nil ||
		len(it.attach.SignatureRefs) == 0 || it.verifyState != stateIdle {
		return nil
	}
	it.verifyState = stateLoading
	v.pending++
	id, gen, repo, sem := v.id(), v.gen, v.repo, v.sem
	refs, subject := it.attach.SignatureRefs, it.desc.Digest
	return func() tea.Msg {
		sem <- struct{}{}
		defer func() { <-sem }()
		ctx, cancel := e.timeout()
		defer cancel()
		results := e.verifier.Signatures(ctx, e.client, repo, subject, refs)
		return tagVerifiedMsg{viewID: id, gen: gen, item: it, result: sigverify.Best(results)}
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
