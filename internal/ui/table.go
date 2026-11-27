package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// column describes a table column. Columns with flex > 0 share the space
// left over by the fixed columns.
type column struct {
	title string
	// max caps the natural width of a fixed column (0 = no cap).
	max  int
	flex int
	// right aligns the column content to the right.
	right bool
}

const cellGap = 2

// table is a minimal table widget. Unlike bubbles/table it supports a style
// per row, which beagle uses to color rows by artifact kind.
type table struct {
	cols   []column
	rows   [][]string
	styles []lipgloss.Style
	// cellStyles optionally overrides the row style per cell (nil = row style).
	cellStyles [][]*lipgloss.Style

	cursor int
	offset int
	width  int
	height int // including the header line
}

func (t *table) setSize(w, h int) {
	t.width, t.height = w, h
	t.clamp()
}

func (t *table) setRows(rows [][]string, styles []lipgloss.Style, cellStyles [][]*lipgloss.Style) {
	t.rows, t.styles, t.cellStyles = rows, styles, cellStyles
	t.clamp()
}

func (t *table) bodyHeight() int { return max(t.height-1, 1) }

func (t *table) clamp() {
	t.cursor = min(max(t.cursor, 0), max(len(t.rows)-1, 0))
	body := t.bodyHeight()
	if t.cursor < t.offset {
		t.offset = t.cursor
	}
	if t.cursor >= t.offset+body {
		t.offset = t.cursor - body + 1
	}
	t.offset = min(max(t.offset, 0), max(len(t.rows)-body, 0))
}

func (t *table) move(delta int) {
	t.cursor += delta
	t.clamp()
}

// update handles navigation keys and reports whether the key was consumed.
func (t *table) update(msg tea.KeyMsg) bool {
	switch {
	case key.Matches(msg, keys.Up):
		t.move(-1)
	case key.Matches(msg, keys.Down):
		t.move(1)
	case key.Matches(msg, keys.PageUp):
		t.move(-t.bodyHeight())
	case key.Matches(msg, keys.PageDown):
		t.move(t.bodyHeight())
	case key.Matches(msg, keys.Top):
		t.cursor = 0
		t.clamp()
	case key.Matches(msg, keys.Bottom):
		t.cursor = len(t.rows) - 1
		t.clamp()
	default:
		return false
	}
	return true
}

// widths computes column widths from the content and the available width.
func (t *table) widths() []int {
	natural := make([]int, len(t.cols))
	for i, c := range t.cols {
		natural[i] = ansi.StringWidth(c.title)
	}
	for _, r := range t.rows {
		for i := range t.cols {
			if i < len(r) {
				natural[i] = max(natural[i], ansi.StringWidth(r[i]))
			}
		}
	}

	avail := t.width - 2 - cellGap*(len(t.cols)-1)
	out := make([]int, len(t.cols))
	used, flexTotal := 0, 0
	for i, c := range t.cols {
		if c.flex > 0 {
			flexTotal += c.flex
			continue
		}
		w := natural[i]
		if c.max > 0 {
			w = min(w, c.max)
		}
		out[i] = w
		used += w
	}
	rest := max(avail-used, 0)
	for i, c := range t.cols {
		if c.flex > 0 {
			out[i] = max(rest*c.flex/flexTotal, min(natural[i], 8))
		}
	}
	return out
}

func (t *table) view() string {
	if t.width <= 0 || t.height <= 0 {
		return ""
	}
	widths := t.widths()
	var b strings.Builder

	titles := make([]string, len(t.cols))
	for i, c := range t.cols {
		titles[i] = c.title
	}
	b.WriteString(styleTableHeader.Render(t.renderRow(titles, widths)))

	end := min(t.offset+t.bodyHeight(), len(t.rows))
	for i := t.offset; i < end; i++ {
		b.WriteByte('\n')
		if i == t.cursor {
			b.WriteString(styleSelected.Render(t.renderRow(t.rows[i], widths)))
			continue
		}
		rowStyle := styleRow
		if i < len(t.styles) {
			rowStyle = t.styles[i]
		}
		var cells []*lipgloss.Style
		if i < len(t.cellStyles) {
			cells = t.cellStyles[i]
		}
		b.WriteString(t.renderStyledRow(t.rows[i], widths, rowStyle, cells))
	}
	return b.String()
}

// renderStyledRow renders a row with the row style, letting individual cells
// override it.
func (t *table) renderStyledRow(cells []string, widths []int, rowStyle lipgloss.Style, cellStyles []*lipgloss.Style) string {
	if len(cellStyles) == 0 {
		return rowStyle.Render(t.renderRow(cells, widths))
	}
	var b strings.Builder
	used := 1
	b.WriteString(rowStyle.Render(" "))
	for i, w := range widths {
		if i > 0 {
			b.WriteString(rowStyle.Render(strings.Repeat(" ", cellGap)))
			used += cellGap
		}
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		cell = ansi.Truncate(cell, w, "…")
		pad := strings.Repeat(" ", max(w-ansi.StringWidth(cell), 0))
		text := cell + pad
		if t.cols[i].right {
			text = pad + cell
		}
		style := rowStyle
		if i < len(cellStyles) && cellStyles[i] != nil {
			style = *cellStyles[i]
		}
		b.WriteString(style.Render(text))
		used += w
	}
	if used < t.width {
		b.WriteString(rowStyle.Render(strings.Repeat(" ", t.width-used)))
	}
	return ansi.Truncate(b.String(), t.width, "")
}

func (t *table) renderRow(cells []string, widths []int) string {
	var b strings.Builder
	b.WriteByte(' ')
	for i, w := range widths {
		if i > 0 {
			b.WriteString(strings.Repeat(" ", cellGap))
		}
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		cell = ansi.Truncate(cell, w, "…")
		pad := strings.Repeat(" ", max(w-ansi.StringWidth(cell), 0))
		if t.cols[i].right {
			b.WriteString(pad + cell)
		} else {
			b.WriteString(cell + pad)
		}
	}
	line := b.String()
	if lw := ansi.StringWidth(line); lw < t.width {
		line += strings.Repeat(" ", t.width-lw)
	}
	return ansi.Truncate(line, t.width, "")
}

// list is a filterable table of items.
type list[T any] struct {
	table
	items   []T
	visible []int
	filter  string
	row     func(T) []string
	style   func(T) lipgloss.Style
	// cell optionally styles single cells (return nil for the row style).
	cell func(item T, col int) *lipgloss.Style
}

func newList[T any](cols []column, row func(T) []string, style func(T) lipgloss.Style) *list[T] {
	return &list[T]{table: table{cols: cols}, row: row, style: style}
}

func (l *list[T]) setItems(items []T) {
	l.items = items
	l.refresh()
}

func (l *list[T]) setFilter(f string) {
	if f == l.filter {
		return
	}
	l.filter = f
	l.cursor = 0
	l.refresh()
}

// refresh re-renders rows, e.g. after items changed in place.
func (l *list[T]) refresh() {
	needle := strings.ToLower(l.filter)
	l.visible = l.visible[:0]
	rows := make([][]string, 0, len(l.items))
	styles := make([]lipgloss.Style, 0, len(l.items))
	var cellStyles [][]*lipgloss.Style
	for i, it := range l.items {
		r := l.row(it)
		if needle != "" && !strings.Contains(strings.ToLower(strings.Join(r, " ")), needle) {
			continue
		}
		l.visible = append(l.visible, i)
		rows = append(rows, r)
		if l.style != nil {
			styles = append(styles, l.style(it))
		} else {
			styles = append(styles, styleRow)
		}
		if l.cell != nil {
			cs := make([]*lipgloss.Style, len(l.cols))
			for c := range l.cols {
				cs[c] = l.cell(it, c)
			}
			cellStyles = append(cellStyles, cs)
		}
	}
	l.setRows(rows, styles, cellStyles)
}

func (l *list[T]) selected() (T, bool) {
	var zero T
	if l.cursor < 0 || l.cursor >= len(l.visible) {
		return zero, false
	}
	return l.items[l.visible[l.cursor]], true
}

func (l *list[T]) selectedIndex() int {
	if l.cursor < 0 || l.cursor >= len(l.visible) {
		return -1
	}
	return l.visible[l.cursor]
}

func (l *list[T]) count() int { return len(l.visible) }
