package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"
	"github.com/opencontainers/go-digest"

	"github.com/beagle-oci/beagle/internal/harbor"
	"github.com/beagle-oci/beagle/internal/meta"
	"github.com/beagle-oci/beagle/internal/oci"
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
	// meta provides vendor tag metadata (push/pull times, scans). Optional.
	meta meta.Provider
}

// lazyLoader views load data for what is currently visible. The app calls
// loadVisible after every update of the top view.
type lazyLoader interface {
	loadVisible(e *env) tea.Cmd
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

// copyToClipboard copies text via OSC 52, which works in most terminals and
// over SSH. Tests replace it.
var copyToClipboard = func(s string) { termenv.Copy(s) }

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

// timeLayout is how beagle renders points in time: local time, to the second.
const timeLayout = "2006-01-02 15:04:05"

// relativeTimes switches time columns from timestamps to ages, k9s style.
// The t key and the :time command toggle it for the whole app.
var relativeTimes bool

// formatTime renders t as a local timestamp or, with relativeTimes, as an
// age; zero times render as unknown.
func formatTime(t time.Time, unknown string) string {
	switch {
	case t.IsZero():
		return unknown
	case relativeTimes:
		return age(t)
	}
	return t.Local().Format(timeLayout)
}

// annotationTime renders an RFC 3339 annotation value like formatTime and
// returns anything else unchanged.
func annotationTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return formatTime(t, "")
}

// age renders t relative to now, e.g. "5m" or "3d".
func age(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 0:
		return t.Local().Format("2006-01-02")
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

// rowRefresher is implemented by views whose rows depend on display
// settings such as relativeTimes.
type rowRefresher interface {
	refreshRows()
}
