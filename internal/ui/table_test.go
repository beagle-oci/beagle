package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func scrollTable(width int) *table {
	tb := &table{cols: []column{
		{title: "NAME", flex: 1},
		{title: "A", max: 10},
		{title: "B", max: 10},
		{title: "C", max: 10},
		{title: "INFO", flex: 1},
	}}
	tb.setRows([][]string{{"first", "aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc", "some info text"}}, nil, nil)
	tb.setSize(width, 5)
	return tb
}

func headerLine(tb *table) string { return strings.SplitN(tb.view(), "\n", 2)[0] }

func TestTableFitsWithoutScrolling(t *testing.T) {
	tb := scrollTable(80)
	l := tb.layout()
	if l.scroll || len(l.cols) != 5 {
		t.Fatalf("all columns should fit into 80 cells: %+v", l)
	}
	tb.scrollX(1)
	if tb.xoff != 0 {
		t.Fatalf("scrolling without overflow moved the offset to %d", tb.xoff)
	}
	if h := headerLine(tb); strings.ContainsAny(h, "◀▶") {
		t.Fatalf("header without overflow shows arrows: %q", h)
	}
}

func TestTableScrollsColumns(t *testing.T) {
	tb := scrollTable(40)
	for _, step := range []struct {
		delta       int
		cols        []int
		left, right bool
	}{
		{0, []int{0, 1, 2}, false, true},
		{1, []int{0, 2, 3}, true, true},
		{1, []int{0, 3, 4}, true, false},
		{1, []int{0, 3, 4}, true, false}, // the last column is in view: stop
		{-5, []int{0, 1, 2}, false, true},
	} {
		tb.scrollX(step.delta)
		l := tb.layout()
		if !l.scroll || !equalInts(l.cols, step.cols) {
			t.Fatalf("after scrolling by %d: columns %v, want %v", step.delta, l.cols, step.cols)
		}
		h := headerLine(tb)
		if strings.Contains(h, "◀") != step.left || strings.Contains(h, "▶") != step.right {
			t.Fatalf("after scrolling by %d: header %q, want left=%v right=%v", step.delta, h, step.left, step.right)
		}
		for _, line := range strings.Split(tb.view(), "\n") {
			if w := ansi.StringWidth(line); w != 40 {
				t.Fatalf("line width %d, want 40: %q", w, line)
			}
		}
	}

	// At the right end the flex column grows into the free space.
	tb.scrollX(10)
	if v := tb.view(); !strings.Contains(v, "some info text") || !strings.Contains(v, "first") {
		t.Fatalf("scrolled view lacks the frozen or the last column:\n%s", v)
	}
}

func TestTableTooNarrowForOneColumn(t *testing.T) {
	tb := scrollTable(12)
	l := tb.layout()
	if len(l.cols) != 2 || l.cols[0] != 0 {
		t.Fatalf("columns %v, want the frozen column and one more", l.cols)
	}
	for _, line := range strings.Split(tb.view(), "\n") {
		if w := ansi.StringWidth(line); w > 12 {
			t.Fatalf("line wider than the table (%d): %q", w, line)
		}
	}
}

func TestStyledRowsScroll(t *testing.T) {
	tb := scrollTable(40)
	rows := [][]string{{"x"}, tb.rows[0]}
	tb.setRows(rows, nil, [][]*lipgloss.Style{nil, {nil, nil, nil, nil, &styleSigned}})
	tb.scrollX(10)
	lines := strings.Split(tb.view(), "\n")
	if !strings.Contains(lines[2], "some info text") || strings.Contains(lines[2], "aaaa") {
		t.Fatalf("styled row does not follow the scroll offset: %q", lines[2])
	}
	if w := ansi.StringWidth(lines[2]); w != 40 {
		t.Fatalf("styled row width %d, want 40", w)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
