// Package ui implements beagle's k9s-style terminal user interface on top
// of Bubble Tea.
package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/reichertan/beagle-cli/internal/harbor"
	"github.com/reichertan/beagle-cli/internal/oci"
)

// Options configure the app.
type Options struct {
	Client *oci.Client
	// Harbor enables project browsing via the Harbor API. Optional.
	Harbor  *harbor.Client
	Version string
	// Repository and Reference optionally select where beagle starts.
	Repository string
	Reference  string
}

type inputMode int

const (
	modeNone inputMode = iota
	modeCommand
	modeFilter
)

// chrome is the number of lines used around the main frame:
// prompt, crumbs and status line.
const chrome = 3

const flashDuration = 4 * time.Second

// App is the root Bubble Tea model.
type App struct {
	env     *env
	cancel  context.CancelFunc
	opts    Options
	stack   []view
	nextID  int
	width   int
	height  int
	mode    inputMode
	input   textinput.Model
	spinner spinner.Model
	spin    bool
	help    bool

	flashText  string
	flashLevel flashLevel
	flashSeq   int
}

// New creates the app.
func New(opts Options) *App {
	ctx, cancel := context.WithCancel(context.Background())
	in := textinput.New()
	in.ShowSuggestions = true
	in.PromptStyle = stylePrompt
	in.CompletionStyle = styleMuted
	return &App{
		env:     &env{ctx: ctx, client: opts.Client, harbor: opts.Harbor},
		cancel:  cancel,
		opts:    opts,
		input:   in,
		spinner: spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(styleLogo)),
	}
}

// Init implements tea.Model.
func (a *App) Init() tea.Cmd {
	var cmds []tea.Cmd
	if a.env.harbor != nil {
		cmds = append(cmds, a.pushView(newProjectsView()))
	} else {
		cmds = append(cmds, a.pushView(newReposView()))
	}
	if a.opts.Repository != "" {
		repo := a.env.client.NormalizeRepository(a.opts.Repository)
		if a.env.harbor != nil {
			project, _, _ := strings.Cut(repo, "/")
			cmds = append(cmds, a.pushView(newProjectReposView(project)))
		}
		cmds = append(cmds, a.pushView(newTagsView(repo)))
		if a.opts.Reference != "" {
			cmds = append(cmds, a.pushView(newManifestView(repo, a.opts.Reference, nil)))
		}
	}
	cmds = append(cmds, a.startSpinner())
	return tea.Batch(cmds...)
}

func (a *App) top() view { return a.stack[len(a.stack)-1] }

func (a *App) headerHeight() int {
	if a.height < 24 {
		return 1
	}
	return len(logo)
}

// contentSize is the area inside the main frame.
func (a *App) contentSize() (int, int) {
	frameHeight := a.height - a.headerHeight() - chrome
	return max(a.width-2, 1), max(frameHeight-2, 1)
}

func (a *App) pushView(v view) tea.Cmd {
	a.nextID++
	v.setID(a.nextID)
	v.setSize(a.contentSize())
	a.stack = append(a.stack, v)
	a.help = false
	return v.init(a.env)
}

func (a *App) pop() {
	if len(a.stack) > 1 {
		a.stack = a.stack[:len(a.stack)-1]
		a.top().setSize(a.contentSize())
	}
}

func (a *App) anyLoading() bool {
	for _, v := range a.stack {
		if v.loading() {
			return true
		}
	}
	return false
}

func (a *App) startSpinner() tea.Cmd {
	if a.spin || !a.anyLoading() {
		return nil
	}
	a.spin = true
	return a.spinner.Tick
}

// Update implements tea.Model.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		w, h := a.contentSize()
		for _, v := range a.stack {
			v.setSize(w, h)
		}
	case tea.KeyMsg:
		var quit bool
		cmd, quit = a.handleKey(msg)
		if quit {
			a.cancel()
			return a, tea.Quit
		}
	case pushMsg:
		cmd = a.pushView(msg.v)
	case popMsg:
		a.pop()
	case flashMsg:
		a.flashSeq++
		a.flashText, a.flashLevel = msg.text, msg.level
		seq := a.flashSeq
		cmd = tea.Tick(flashDuration, func(time.Time) tea.Msg { return clearFlashMsg{seq: seq} })
	case clearFlashMsg:
		if msg.seq == a.flashSeq {
			a.flashText = ""
		}
	case spinner.TickMsg:
		if !a.anyLoading() {
			a.spin = false
			return a, nil
		}
		a.spinner, cmd = a.spinner.Update(msg)
		return a, cmd
	case targeted:
		for _, v := range a.stack {
			if v.id() == msg.target() {
				cmd = v.update(a.env, msg)
				break
			}
		}
	}
	return a, tea.Batch(cmd, a.startSpinner())
}

func (a *App) handleKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	if key.Matches(msg, keys.ForceQuit) {
		return nil, true
	}
	if a.mode != modeNone {
		return a.handleInput(msg), false
	}
	if a.help {
		if key.Matches(msg, keys.Back, keys.Help, keys.Quit) {
			a.help = false
		}
		return nil, false
	}

	top := a.top()
	f, canFilter := top.(filterable)
	switch {
	case key.Matches(msg, keys.Command):
		a.mode = modeCommand
		a.input.Prompt = ":"
		a.input.Reset()
		a.input.SetSuggestions(a.suggestions())
		return a.input.Focus(), false
	case key.Matches(msg, keys.Filter) && canFilter:
		a.mode = modeFilter
		a.input.Prompt = "/"
		a.input.SetSuggestions(nil)
		a.input.SetValue(f.filter())
		a.input.CursorEnd()
		return a.input.Focus(), false
	case key.Matches(msg, keys.Help):
		a.help = true
		return nil, false
	case key.Matches(msg, keys.Back):
		if canFilter && f.filter() != "" {
			f.setFilter("")
			return nil, false
		}
		a.pop()
		return nil, false
	case key.Matches(msg, keys.Quit):
		if len(a.stack) == 1 {
			return nil, true
		}
		a.pop()
		return nil, false
	}
	return top.update(a.env, msg), false
}

func (a *App) handleInput(msg tea.KeyMsg) tea.Cmd {
	switch msg.Type {
	case tea.KeyEsc:
		if a.mode == modeFilter {
			if f, ok := a.top().(filterable); ok {
				f.setFilter("")
			}
		}
		a.mode = modeNone
		a.input.Blur()
		return nil
	case tea.KeyEnter:
		mode, value := a.mode, strings.TrimSpace(a.input.Value())
		a.mode = modeNone
		a.input.Blur()
		if mode == modeCommand {
			return a.runCommand(value)
		}
		return nil
	}
	var cmd tea.Cmd
	a.input, cmd = a.input.Update(msg)
	if a.mode == modeFilter {
		if f, ok := a.top().(filterable); ok {
			f.setFilter(a.input.Value())
		}
	}
	return cmd
}

var commandNames = []string{"repos", "repo ", "open ", "referrers ", "help", "quit"}

func (a *App) suggestions() []string {
	out := append([]string{}, commandNames...)
	if a.env.harbor != nil {
		out = append(out, "projects", "project ")
	}
	seen := map[string]bool{}
	for _, v := range a.stack {
		switch v := v.(type) {
		case *projectsView:
			for _, n := range v.names() {
				out = append(out, "project "+n)
			}
		case *reposView:
			for _, n := range v.names() {
				if !seen[n] {
					seen[n] = true
					out = append(out, "repo "+n)
				}
			}
		}
	}
	return out
}

func (a *App) runCommand(line string) tea.Cmd {
	cmd, arg, _ := strings.Cut(line, " ")
	arg = strings.TrimSpace(arg)
	switch cmd {
	case "":
		return nil
	case "q", "q!", "quit", "exit":
		a.cancel()
		return tea.Quit
	case "help", "h", "?":
		a.help = true
		return nil
	case "repos", "repositories", "catalog", "projects":
		if cmd == "projects" && a.env.harbor == nil {
			return flash(flashError, "not a Harbor registry, use :repos")
		}
		a.stack = a.stack[:1]
		a.top().setSize(a.contentSize())
		return a.top().init(a.env)
	case "project", "p":
		if a.env.harbor == nil {
			return flash(flashError, "not a Harbor registry")
		}
		if arg == "" {
			return flash(flashError, "usage: :project <name>")
		}
		return a.pushView(newProjectReposView(arg))
	case "repo", "tags", "cd":
		if arg == "" {
			return flash(flashError, "usage: :repo <name>")
		}
		repo, _, _ := a.splitReference(arg)
		return a.pushView(newTagsView(repo))
	case "open", "o", "manifest":
		repo, ref, err := a.splitReference(arg)
		if err != nil {
			return flashErr(err)
		}
		return a.pushView(newManifestView(repo, ref, nil))
	case "referrers", "ref", "tree":
		repo, ref, err := a.splitReference(arg)
		if err != nil {
			return flashErr(err)
		}
		return a.pushView(newReferrersView(repo, ref, nil))
	}
	// Bare references are a shortcut: ":demo/app" or ":demo/app:v1".
	if arg == "" && strings.ContainsAny(cmd, "/:@") {
		repo, ref, err := a.splitReference(cmd)
		if err != nil {
			return a.pushView(newTagsView(repo))
		}
		return a.pushView(newManifestView(repo, ref, nil))
	}
	return flash(flashError, "unknown command %q, press ? for help", cmd)
}

// splitReference parses repo:tag or repo@digest, optionally prefixed with
// the registry host. err is set when no tag or digest is present.
func (a *App) splitReference(s string) (repo, ref string, err error) {
	s = strings.TrimPrefix(s, a.env.client.Host()+"/")
	if i := strings.Index(s, "@"); i >= 0 {
		return a.env.client.NormalizeRepository(s[:i]), s[i+1:], nil
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		return a.env.client.NormalizeRepository(s[:i]), s[i+1:], nil
	}
	return a.env.client.NormalizeRepository(s), "", fmt.Errorf("%q has no tag or digest", s)
}

// View implements tea.Model.
func (a *App) View() string {
	if a.width == 0 || a.height == 0 || len(a.stack) == 0 {
		return ""
	}
	top := a.top()
	cw, ch := a.contentSize()

	title, content := a.frameContent(top, cw, ch)
	sections := []string{
		a.renderHeader(top),
		a.renderPrompt(),
		frame(title, content, a.width, ch+2),
		crumbs(a.crumbNames()),
		a.renderStatus(),
	}
	return strings.Join(sections, "\n")
}

func (a *App) frameContent(top view, w, h int) (string, string) {
	if a.help {
		return frameTitle("help", "", -1, ""), renderHelp(w, h)
	}
	filter := ""
	if f, ok := top.(filterable); ok {
		filter = f.filter()
	}
	return frameTitle(top.title(), top.subject(), top.count(), filter), top.render()
}

func (a *App) crumbNames() []string {
	names := make([]string, len(a.stack))
	for i, v := range a.stack {
		names[i] = v.crumb()
	}
	return names
}

func (a *App) renderHeader(top view) string {
	c := a.env.client
	transport := "https"
	if c.PlainHTTP() {
		transport = "http (plain)"
	}
	if a.headerHeight() == 1 {
		line := styleLogo.Render(" beagle ") + styleLabel.Render("registry: ") + styleValue.Render(c.Host()) +
			styleLabel.Render("  transport: ") + styleValue.Render(transport) + styleMuted.Render("  ? help")
		return ansi.Truncate(line, a.width, "")
	}
	info := [][2]string{
		{"Registry", c.Host()},
		{"Transport", transport},
		{"Auth", c.AuthSource()},
	}
	if h := a.env.harbor; h != nil {
		version := h.Version()
		if version == "" {
			version = "detected (version hidden)"
		}
		info = append(info, [2]string{"Harbor", version})
	}
	info = append(info, [2]string{"beagle", a.opts.Version})
	hints := append(top.hints(), hintOf(keys.Command))
	if _, ok := top.(filterable); ok {
		hints = append(hints, hintOf(keys.Filter))
	}
	hints = append(hints, hintOf(keys.Help), hint{"esc", "back"}, hint{"ctrl-c", "quit"})
	return header(info, hints, a.width)
}

func (a *App) renderPrompt() string {
	if a.mode == modeNone {
		return ""
	}
	return " " + a.input.View()
}

func (a *App) renderStatus() string {
	left := ""
	if a.flashText != "" {
		style := styleInfo
		switch a.flashLevel {
		case flashWarn:
			style = styleWarn
		case flashError:
			style = styleError
		}
		left = " " + style.Render(a.flashText)
	}
	right := ""
	if a.anyLoading() {
		right = a.spinner.View() + styleMuted.Render(" loading ")
	}
	gap := a.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return ansi.Truncate(left, a.width, "…")
	}
	return left + strings.Repeat(" ", gap) + right
}
