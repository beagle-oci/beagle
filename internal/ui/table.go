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
	// xoff is the first scrollable column shown while the columns do not fit
	// the width. Column 0 always stays visible.
	xoff int
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
	case key.Matches(msg, keys.Left):
		t.scrollX(-1)
	case key.Matches(msg, keys.Right):
		t.scrollX(1)
	default:
		return false
	}
	return true
}

// scrollX shifts the scrollable columns by delta while they do not fit.
func (t *table) scrollX(delta int) {
	l := t.layout()
	if !l.scroll {
		return
	}
	t.xoff = min(max(l.cols[1]+delta, 1), l.maxOff)
}

// colLayout is the result of table.layout.
type colLayout struct {
	// cols are the visible column indexes, widths their widths.
	cols, widths []int
	// scroll reports that the columns do not fit and scroll horizontally;
	// maxOff is then the largest useful scroll offset.
	scroll bool
	maxOff int
}

// hiddenLeft and hiddenRight report columns scrolled out of view.
func (l colLayout) hiddenLeft() bool { return l.scroll && len(l.cols) > 1 && l.cols[1] > 1 }
func (l colLayout) hiddenRight(n int) bool {
	return len(l.cols) > 0 && l.cols[len(l.cols)-1] < n-1
}

// naturalWidths returns the width of the widest title or cell per column.
func (t *table) naturalWidths() []int {
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
	return natural
}

// layout picks the visible columns and their widths. When all columns fit,
// flex columns share the space left over by the fixed ones. Otherwise column
// 0 stays in place and the other columns scroll horizontally, k9s style,
// starting at xoff.
func (t *table) layout() colLayout {
	n := len(t.cols)
	natural := t.naturalWidths()
	minW := make([]int, n)
	need := cellGap * max(n-1, 0)
	for i, c := range t.cols {
		switch {
		case c.flex > 0:
			minW[i] = min(natural[i], 8)
		case c.max > 0:
			minW[i] = min(natural[i], c.max)
		default:
			minW[i] = natural[i]
		}
		need += minW[i]
	}
	avail := t.width - 2
	if need <= avail || n < 2 {
		return t.fitLayout(natural, minW, avail)
	}

	first := minW[0]
	if t.cols[0].flex > 0 {
		first = min(natural[0], max(minW[0], avail/3))
	}
	first = max(min(first, avail-cellGap-1), 1)
	rest := avail - first

	// The largest offset is the one that brings the last column into view.
	maxOff, used := n-1, cellGap+minW[n-1]
	for i := n - 2; i >= 1; i-- {
		used += cellGap + minW[i]
		if used > rest {
			break
		}
		maxOff = i
	}

	l := colLayout{cols: []int{0}, widths: []int{first}, scroll: true, maxOff: maxOff}
	used = 0
	for i := min(max(t.xoff, 1), maxOff); i < n; i++ {
		w := minW[i]
		if used+cellGap+w > rest {
			if len(l.cols) > 1 {
				break
			}
			w = max(rest-cellGap, 1) // too wide even on its own
		}
		l.cols = append(l.cols, i)
		l.widths = append(l.widths, w)
		used += cellGap + w
	}

	// Flex columns, including column 0, grow into what is left.
	left := rest - used
	for j := len(l.cols) - 1; j >= 0 && left > 0; j-- {
		if i := l.cols[j]; t.cols[i].flex > 0 && natural[i] > l.widths[j] {
			grow := min(natural[i]-l.widths[j], left)
			l.widths[j] += grow
			left -= grow
		}
	}
	return l
}

// fitLayout lays out all columns when they fit the available width.
func (t *table) fitLayout(natural, minW []int, avail int) colLayout {
	l := colLayout{cols: make([]int, len(t.cols)), widths: make([]int, len(t.cols))}
	avail -= cellGap * max(len(t.cols)-1, 0)
	used, flexTotal := 0, 0
	for i, c := range t.cols {
		l.cols[i] = i
		if c.flex > 0 {
			flexTotal += c.flex
			continue
		}
		l.widths[i] = minW[i]
		used += minW[i]
	}
	rest := max(avail-used, 0)
	for i, c := range t.cols {
		if c.flex > 0 {
			l.widths[i] = max(rest*c.flex/flexTotal, minW[i])
		}
	}
	return l
}

func (t *table) view() string {
	if t.width <= 0 || t.height <= 0 {
		return ""
	}
	l := t.layout()
	var b strings.Builder

	titles := make([]string, len(t.cols))
	for i, c := range t.cols {
		titles[i] = c.title
	}
	header := t.renderRow(titles, l)
	// Arrows mark columns scrolled out of view.
	if l.hiddenLeft() {
		header = overlay(header, 1+l.widths[0], "◀")
	}
	if l.hiddenRight(len(t.cols)) {
		header = overlay(header, t.width-1, "▶")
	}
	b.WriteString(styleTableHeader.Render(header))

	end := min(t.offset+t.bodyHeight(), len(t.rows))
	for i := t.offset; i < end; i++ {
		b.WriteByte('\n')
		if i == t.cursor {
			b.WriteString(styleSelected.Render(t.renderRow(t.rows[i], l)))
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
		b.WriteString(t.renderStyledRow(t.rows[i], l, rowStyle, cells))
	}
	return b.String()
}

// overlay replaces the cell at column x of a plain line with s.
func overlay(line string, x int, s string) string {
	if x < 0 || x >= ansi.StringWidth(line) {
		return line
	}
	return ansi.Cut(line, 0, x) + s + ansi.Cut(line, x+ansi.StringWidth(s), ansi.StringWidth(line))
}

// renderStyledRow renders a row with the row style, letting individual cells
// override it.
func (t *table) renderStyledRow(cells []string, l colLayout, rowStyle lipgloss.Style, cellStyles []*lipgloss.Style) string {
	if len(cellStyles) == 0 {
		return rowStyle.Render(t.renderRow(cells, l))
	}
	var b strings.Builder
	used := 1
	b.WriteString(rowStyle.Render(" "))
	for j, i := range l.cols {
		w := l.widths[j]
		if j > 0 {
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

func (t *table) renderRow(cells []string, l colLayout) string {
	var b strings.Builder
	b.WriteByte(' ')
	for j, i := range l.cols {
		w := l.widths[j]
		if j > 0 {
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

func (l *list[T]) count() int { return len(l.visible) }
