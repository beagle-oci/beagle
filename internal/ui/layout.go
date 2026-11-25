package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var logo = []string{
	`    __                     __   `,
	`   / /_  ___  ____ _____ _/ /__ `,
	`  / __ \/ _ \/ __ ` + "`" + `/ __ ` + "`" + `/ / _ \`,
	` / /_/ /  __/ /_/ / /_/ / /  __/`,
	`/_.___/\___/\__,_/\__, /_/\___/ `,
	`                 /____/         `,
}

// frame draws a k9s style box with the title embedded in the top border.
// content is clipped or padded to fit.
func frame(title, content string, w, h int) string {
	if w < 4 || h < 2 {
		return ""
	}
	inner := w - 2
	titleWidth := ansi.StringWidth(title)
	if titleWidth > inner-2 {
		title = ansi.Truncate(title, inner-2, "…")
		titleWidth = ansi.StringWidth(title)
	}
	left := (inner - titleWidth) / 2
	right := inner - titleWidth - left

	var b strings.Builder
	b.WriteString(styleFrame.Render("┌" + strings.Repeat("─", left)))
	b.WriteString(title)
	b.WriteString(styleFrame.Render(strings.Repeat("─", right) + "┐"))

	lines := strings.Split(content, "\n")
	side := styleFrame.Render("│")
	for i := 0; i < h-2; i++ {
		line := ""
		if i < len(lines) {
			line = ansi.Truncate(lines[i], inner, "")
		}
		pad := max(inner-ansi.StringWidth(line), 0)
		b.WriteString("\n" + side + line + strings.Repeat(" ", pad) + side)
	}
	b.WriteString("\n" + styleFrame.Render("└"+strings.Repeat("─", inner)+"┘"))
	return b.String()
}

// frameTitle renders "title(subject)[count]" with a filter suffix.
func frameTitle(title, subject string, count int, filter string) string {
	s := " " + styleTitle.Render(title)
	if subject != "" {
		s += styleTitle.Render("(") + styleSubject.Render(subject) + styleTitle.Render(")")
	}
	if count >= 0 {
		s += styleTitle.Render("[") + styleCounter.Render(fmt.Sprint(count)) + styleTitle.Render("]")
	}
	if filter != "" {
		s += styleTitle.Render(" </") + styleSubject.Render(filter) + styleTitle.Render(">")
	}
	return s + " "
}

// header renders registry info, key hints and the logo side by side.
func header(info [][2]string, hints []hint, w int) string {
	infoLines := make([]string, len(logo))
	labelWidth := 0
	for _, kv := range info {
		labelWidth = max(labelWidth, len(kv[0])+1)
	}
	for i := range infoLines {
		if i < len(info) {
			infoLines[i] = " " + styleLabel.Render(fmt.Sprintf("%-*s", labelWidth, info[i][0]+":")) + " " + styleValue.Render(info[i][1])
		}
	}
	infoCol := lipgloss.NewStyle().Width(lipgloss.Width(strings.Join(infoLines, "\n")) + 4).Render(strings.Join(infoLines, "\n"))

	// Hints flow into columns of len(logo) rows.
	var cols []string
	rows := len(logo)
	for start := 0; start < len(hints); start += rows {
		end := min(start+rows, len(hints))
		var lines []string
		keyWidth := 0
		for _, h := range hints[start:end] {
			keyWidth = max(keyWidth, ansi.StringWidth(h.key)+2)
		}
		for _, h := range hints[start:end] {
			lines = append(lines, styleKey.Render(fmt.Sprintf("%-*s", keyWidth, "<"+h.key+">"))+" "+styleHintDesc.Render(h.desc))
		}
		cols = append(cols, lipgloss.NewStyle().PaddingRight(3).Render(strings.Join(lines, "\n")))
	}
	hintBlock := lipgloss.JoinHorizontal(lipgloss.Top, cols...)
	logoBlock := styleLogo.Render(strings.Join(logo, "\n"))

	left := lipgloss.JoinHorizontal(lipgloss.Top, infoCol, hintBlock)
	gap := w - lipgloss.Width(left) - lipgloss.Width(logoBlock)
	var out string
	if gap >= 1 {
		out = lipgloss.JoinHorizontal(lipgloss.Top, left, strings.Repeat(" ", gap), logoBlock)
	} else {
		out = left
	}
	return lipgloss.NewStyle().Height(len(logo)).MaxHeight(len(logo)).MaxWidth(w).Render(out)
}

// crumbs renders the navigation breadcrumbs.
func crumbs(names []string) string {
	parts := make([]string, len(names))
	for i, n := range names {
		if i == len(names)-1 {
			parts[i] = styleCrumbLast.Render("<" + n + ">")
		} else {
			parts[i] = styleCrumb.Render("<" + n + ">")
		}
	}
	return " " + strings.Join(parts, " ")
}
