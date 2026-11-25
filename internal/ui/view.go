package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/opencontainers/go-digest"

	"github.com/reichertan/beagle-cli/internal/harbor"
	"github.com/reichertan/beagle-cli/internal/oci"
)

// requestTimeout bounds every registry call issued by a view.
const requestTimeout = 60 * time.Second

// view is one screen on the navigation stack (repositories, tags, ...).
type view interface {
	// id identifies the view so async results reach the right screen even
	// after the user navigated away.
	id() int
	setID(int)
	// crumb is the short name shown in the breadcrumb bar.
	crumb() string
	// title, subject and count make up the frame title,
	// e.g. "tags(demo/app)[12]". count < 0 hides the counter.
	title() string
	subject() string
	count() int

	init(env *env) tea.Cmd
	update(env *env, msg tea.Msg) tea.Cmd
	render() string
	setSize(w, h int)
	hints() []hint
	loading() bool
}

// filterable views support "/" filtering.
type filterable interface {
	setFilter(string)
	filter() string
}

// env gives views access to shared state.
type env struct {
	ctx    context.Context
	client *oci.Client
	// harbor is set when the registry is a Harbor instance.
	harbor *harbor.Client
}

func (e *env) timeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(e.ctx, requestTimeout)
}

// baseView holds the fields every view needs.
type baseView struct {
	vid    int
	width  int
	height int
	busy   bool
	err    error
}

func (b *baseView) id() int          { return b.vid }
func (b *baseView) setID(id int)     { b.vid = id }
func (b *baseView) loading() bool    { return b.busy }
func (b *baseView) setSize(w, h int) { b.width, b.height = w, h }
func (b *baseView) count() int       { return -1 }
func (b *baseView) subject() string  { return "" }
func (b *baseView) hints() []hint    { return nil }

// Messages exchanged between views and the app.

// targeted messages are routed to the view with the given id.
type targeted interface{ target() int }

type pushMsg struct{ v view }
type popMsg struct{}

type flashLevel int

const (
	flashInfo flashLevel = iota
	flashWarn
	flashError
)

type flashMsg struct {
	text  string
	level flashLevel
}

type clearFlashMsg struct{ seq int }

func push(v view) tea.Cmd { return func() tea.Msg { return pushMsg{v: v} } }

func flash(level flashLevel, format string, args ...any) tea.Cmd {
	text := fmt.Sprintf(format, args...)
	return func() tea.Msg { return flashMsg{text: text, level: level} }
}

func flashErr(err error) tea.Cmd {
	return flash(flashError, "%s", err)
}

// Formatting helpers.

func shortDigest(d digest.Digest) string {
	s := d.String()
	if alg, enc, ok := strings.Cut(s, ":"); ok && len(enc) > 12 {
		return alg + ":" + enc[:12]
	}
	return s
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// shortMediaType turns well-known media types into compact labels.
func shortMediaType(mt string) string {
	switch mt {
	case "application/vnd.oci.image.index.v1+json":
		return "oci index"
	case "application/vnd.oci.image.manifest.v1+json":
		return "oci manifest"
	case oci.MediaTypeDockerManifestList:
		return "docker list"
	case oci.MediaTypeDockerManifest:
		return "docker v2"
	case oci.MediaTypeArtifactManifest:
		return "oci artifact"
	case "":
		return ""
	}
	return mt
}

// age renders an RFC 3339 timestamp relative to now, k9s style.
func age(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	d := time.Since(t)
	switch {
	case d < 0:
		return t.Format("2006-01-02")
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	default:
		return fmt.Sprintf("%dy", int(d.Hours()/24/365))
	}
}
