package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/beagle-oci/beagle/internal/oci"
)

// rawView shows a manifest or blob as (highlighted) JSON or text.
type rawView struct {
	baseView
	name     string
	label    string
	load     func(ctx context.Context, e *env) ([]byte, error)
	content  string
	plain    string
	viewport viewport.Model
	ready    bool
}

type rawLoadedMsg struct {
	viewID int
	data   []byte
	err    error
}

func (m rawLoadedMsg) target() int { return m.viewID }

func newRawManifestView(repo, reference string, desc *ocispec.Descriptor) *rawView {
	return &rawView{
		name:  "raw",
		label: refString(repo, reference),
		load: func(ctx context.Context, e *env) ([]byte, error) {
			var m *oci.Manifest
			var err error
			if desc != nil {
				m, err = e.client.FetchManifest(ctx, repo, *desc)
			} else {
				m, err = e.client.FetchManifestReference(ctx, repo, reference)
			}
			if err != nil {
				return nil, err
			}
			return m.Raw, nil
		},
	}
}

func newRawBlobView(repo, role string, desc ocispec.Descriptor) *rawView {
	return &rawView{
		name:  "blob",
		label: fmt.Sprintf("%s %s", role, shortDigest(desc.Digest)),
		load: func(ctx context.Context, e *env) ([]byte, error) {
			return e.client.FetchBlob(ctx, repo, desc, oci.DefaultMaxBlobSize)
		},
	}
}

func (v *rawView) crumb() string   { return v.name }
func (v *rawView) title() string   { return v.name }
func (v *rawView) subject() string { return v.label }

func (v *rawView) hints() []hint {
	return []hint{{"↑/↓", "scroll"}, {"←/→", "pan"}, {"g/G", "top/bottom"}}
}

func (v *rawView) setSize(w, h int) {
	v.baseView.setSize(w, h)
	if !v.ready {
		v.viewport = viewport.New(w, h)
		v.viewport.KeyMap.Down = keys.Down
		v.viewport.KeyMap.Up = keys.Up
		v.viewport.KeyMap.PageDown = keys.PageDown
		v.viewport.KeyMap.PageUp = keys.PageUp
		v.viewport.KeyMap.Left = key.NewBinding(key.WithKeys("left", "h"))
		v.viewport.KeyMap.Right = key.NewBinding(key.WithKeys("right", "l"))
		v.viewport.SetHorizontalStep(8)
		v.ready = true
		if v.content != "" {
			v.viewport.SetContent(v.content)
		}
		return
	}
	v.viewport.Width, v.viewport.Height = w, h
}

func (v *rawView) init(e *env) tea.Cmd {
	v.busy, v.err = true, nil
	id, load := v.id(), v.load
	return func() tea.Msg {
		ctx, cancel := e.timeout()
		defer cancel()
		data, err := load(ctx, e)
		return rawLoadedMsg{viewID: id, data: data, err: err}
	}
}

func (v *rawView) update(e *env, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case rawLoadedMsg:
		v.busy = false
		if msg.err != nil {
			v.err = msg.err
			return flashErr(msg.err)
		}
		v.plain, v.content = formatContent(msg.data)
		if v.ready {
			v.viewport.SetContent(v.content)
		}
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Reload):
			return v.init(e)
		case key.Matches(msg, keys.Copy):
			copyToClipboard(v.plain)
			return flash(flashInfo, "Copied %s to the clipboard", v.name)
		case key.Matches(msg, keys.Top):
			v.viewport.GotoTop()
		case key.Matches(msg, keys.Bottom):
			v.viewport.GotoBottom()
		default:
			var cmd tea.Cmd
			v.viewport, cmd = v.viewport.Update(msg)
			return cmd
		}
	}
	return nil
}

func (v *rawView) render() string {
	switch {
	case v.err != nil && v.content == "":
		return centered(v.width, v.height, styleError.Render(v.err.Error()))
	case v.content == "":
		return centered(v.width, v.height, styleMuted.Render("Loading…"))
	}
	return v.viewport.View()
}

// formatContent pretty-prints JSON with syntax highlighting, shows other
// UTF-8 text as is, and summarizes binary data. It returns the plain text
// (for copying) and the rendered text.
func formatContent(data []byte) (plain, rendered string) {
	var buf bytes.Buffer
	if json.Indent(&buf, data, "", "  ") == nil {
		plain = buf.String()
		return plain, highlightJSON(plain)
	}
	if utf8.Valid(data) {
		plain = strings.ReplaceAll(string(data), "\t", "    ")
		return plain, plain
	}
	plain = fmt.Sprintf("binary content, %s", humanSize(int64(len(data))))
	return plain, styleMuted.Render(plain)
}

// painter returns a cheap function that wraps text in the ANSI sequences of
// style. Rendering every JSON token through lipgloss would be slow for large
// documents.
func painter(style lipgloss.Style) func(string) string {
	prefix, suffix, _ := strings.Cut(style.Render("\x00"), "\x00")
	return func(s string) string { return prefix + s + suffix }
}

// highlightJSON colors keys, strings, numbers and literals of indented JSON.
func highlightJSON(s string) string {
	keyStyle := painter(lipgloss.NewStyle().Foreground(lipgloss.Color("39")))
	strStyle := painter(lipgloss.NewStyle().Foreground(lipgloss.Color("114")))
	numStyle := painter(lipgloss.NewStyle().Foreground(lipgloss.Color("215")))
	litStyle := painter(lipgloss.NewStyle().Foreground(lipgloss.Color("177")))
	punctStyle := painter(lipgloss.NewStyle().Foreground(lipgloss.Color("245")))

	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j+1, len(s))
			token := s[i:j]
			k := j
			for k < len(s) && s[k] == ' ' {
				k++
			}
			if k < len(s) && s[k] == ':' {
				b.WriteString(keyStyle(token))
			} else {
				b.WriteString(strStyle(token))
			}
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(s) && strings.IndexByte("0123456789.eE+-", s[j]) >= 0 {
				j++
			}
			b.WriteString(numStyle(s[i:j]))
			i = j
		case strings.HasPrefix(s[i:], "true"), strings.HasPrefix(s[i:], "null"):
			b.WriteString(litStyle(s[i : i+4]))
			i += 4
		case strings.HasPrefix(s[i:], "false"):
			b.WriteString(litStyle(s[i : i+5]))
			i += 5
		case strings.IndexByte("{}[],:", c) >= 0:
			b.WriteString(punctStyle(string(c)))
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}
