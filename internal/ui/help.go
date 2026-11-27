package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/lipgloss"
)

type helpSection struct {
	title string
	items []hint
}

func helpSections() []helpSection {
	b := func(bs ...key.Binding) []hint {
		out := make([]hint, len(bs))
		for i, x := range bs {
			out[i] = hintOf(x)
		}
		return out
	}
	return []helpSection{
		{"GENERAL", b(keys.Command, keys.Filter, keys.Help, keys.Back, keys.Quit, keys.ForceQuit, keys.Reload, keys.Time)},
		{"NAVIGATION", b(keys.Up, keys.Down, keys.PageUp, keys.PageDown, keys.Top, keys.Bottom, keys.Left, keys.Right)},
		{"RESOURCE", b(keys.Open, keys.Referrers, keys.Raw, keys.Subject, keys.Copy, keys.ToggleAll, keys.Sort)},
		{"COMMANDS", []hint{
			{":repos", "back to the start view"},
			{":projects", "Harbor projects"},
			{":project <name>", "repositories of a Harbor project"},
			{":repo <name>", "open a repository"},
			{":open <repo:tag|@digest>", "open a manifest"},
			{":referrers <ref>", "referrer tree of a manifest"},
			{":time [age|timestamp]", "switch the time format"},
			{":q", "quit"},
		}},
	}
}

func renderHelp(w, h int) string {
	var cols []string
	for _, s := range helpSections() {
		keyWidth := 0
		for _, it := range s.items {
			keyWidth = max(keyWidth, len([]rune(it.key))+2)
		}
		lines := []string{styleLabel.Render(s.title), ""}
		for _, it := range s.items {
			lines = append(lines, styleKey.Render(fmt.Sprintf("%-*s", keyWidth, "<"+it.key+">"))+" "+styleHintDesc.Render(it.desc))
		}
		cols = append(cols, lipgloss.NewStyle().PaddingRight(4).Render(strings.Join(lines, "\n")))
	}
	// All sections side by side, else two per row, else one below the other.
	body := lipgloss.JoinHorizontal(lipgloss.Top, cols...)
	if lipgloss.Width(body) > w {
		var rows []string
		for i := 0; i < len(cols); i += 2 {
			rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, cols[i:min(i+2, len(cols))]...))
		}
		body = strings.Join(rows, "\n\n")
	}
	if lipgloss.Width(body) > w {
		body = lipgloss.JoinVertical(lipgloss.Left, cols...)
	}
	return lipgloss.NewStyle().Padding(1, 2).Render(body)
}
