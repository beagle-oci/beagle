package ui

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Quit      key.Binding
	ForceQuit key.Binding
	Back      key.Binding
	Help      key.Binding
	Command   key.Binding
	Filter    key.Binding
	Reload    key.Binding
	Time      key.Binding

	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Top      key.Binding
	Bottom   key.Binding
	Left     key.Binding
	Right    key.Binding

	Open      key.Binding
	Referrers key.Binding
	Raw       key.Binding
	Subject   key.Binding
	Copy      key.Binding
	ToggleAll key.Binding
	Sort      key.Binding
}

var keys = keyMap{
	Quit:      key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "back / quit")),
	ForceQuit: key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl-c", "quit")),
	Back:      key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back / clear filter")),
	Help:      key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Command:   key.NewBinding(key.WithKeys(":"), key.WithHelp(":", "command")),
	Filter:    key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Reload:    key.NewBinding(key.WithKeys("ctrl+r"), key.WithHelp("ctrl-r", "reload")),
	Time:      key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "timestamps / age")),

	Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	PageUp:   key.NewBinding(key.WithKeys("pgup", "ctrl+b"), key.WithHelp("pgup", "page up")),
	PageDown: key.NewBinding(key.WithKeys("pgdown", "ctrl+f", " "), key.WithHelp("pgdn", "page down")),
	Top:      key.NewBinding(key.WithKeys("home", "g"), key.WithHelp("g", "top")),
	Bottom:   key.NewBinding(key.WithKeys("end", "G"), key.WithHelp("G", "bottom")),
	Left:     key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "scroll left")),
	Right:    key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→/l", "scroll right")),

	Open:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
	Referrers: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "referrers")),
	Raw:       key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "raw JSON")),
	Subject:   key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "go to subject")),
	Copy:      key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "copy reference")),
	ToggleAll: key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "toggle sha256-* tags")),
	Sort:      key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "sort: registry/newest/name")),
}

// hint is a key shown in the header.
type hint struct {
	key  string
	desc string
}

func hintOf(b key.Binding) hint {
	h := b.Help()
	return hint{key: h.Key, desc: h.Desc}
}
