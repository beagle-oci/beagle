package ui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/reichertan/beagle-cli/internal/oci"
)

// Palette, loosely following k9s' default skin.
var (
	colorFrame     = lipgloss.Color("33")  // dodger blue
	colorTitle     = lipgloss.Color("51")  // aqua
	colorSubject   = lipgloss.Color("213") // fuchsia
	colorCounter   = lipgloss.Color("230") // papaya whip
	colorLogo      = lipgloss.Color("208") // orange
	colorLabel     = lipgloss.Color("214") // gold
	colorValue     = lipgloss.Color("255") // white
	colorKey       = lipgloss.Color("33")
	colorHintDesc  = lipgloss.Color("249")
	colorMuted     = lipgloss.Color("244")
	colorSelectBg  = lipgloss.Color("51")
	colorSelectFg  = lipgloss.Color("16")
	colorCrumbBg   = lipgloss.Color("39")
	colorCrumbLast = lipgloss.Color("208")
	colorError     = lipgloss.Color("196")
	colorInfo      = lipgloss.Color("48")
	colorWarn      = lipgloss.Color("220")
	colorPrompt    = lipgloss.Color("51")
)

var (
	styleFrame       = lipgloss.NewStyle().Foreground(colorFrame)
	styleTitle       = lipgloss.NewStyle().Foreground(colorTitle).Bold(true)
	styleSubject     = lipgloss.NewStyle().Foreground(colorSubject).Bold(true)
	styleCounter     = lipgloss.NewStyle().Foreground(colorCounter).Bold(true)
	styleLogo        = lipgloss.NewStyle().Foreground(colorLogo).Bold(true)
	styleLabel       = lipgloss.NewStyle().Foreground(colorLabel).Bold(true)
	styleValue       = lipgloss.NewStyle().Foreground(colorValue)
	styleKey         = lipgloss.NewStyle().Foreground(colorKey).Bold(true)
	styleHintDesc    = lipgloss.NewStyle().Foreground(colorHintDesc)
	styleMuted       = lipgloss.NewStyle().Foreground(colorMuted)
	styleTableHeader = lipgloss.NewStyle().Foreground(colorValue).Bold(true)
	styleSelected    = lipgloss.NewStyle().Background(colorSelectBg).Foreground(colorSelectFg).Bold(true)
	styleCrumb       = lipgloss.NewStyle().Background(colorCrumbBg).Foreground(colorSelectFg).Bold(true).Padding(0, 1)
	styleCrumbLast   = lipgloss.NewStyle().Background(colorCrumbLast).Foreground(colorSelectFg).Bold(true).Padding(0, 1)
	styleError       = lipgloss.NewStyle().Foreground(colorError).Bold(true)
	styleInfo        = lipgloss.NewStyle().Foreground(colorInfo)
	styleWarn        = lipgloss.NewStyle().Foreground(colorWarn)
	stylePrompt      = lipgloss.NewStyle().Foreground(colorPrompt).Bold(true)
	styleRow         = lipgloss.NewStyle().Foreground(colorValue)
)

// kindStyle colors table rows by what they contain, the way k9s colors
// rows by resource status.
func kindStyle(k oci.Kind) lipgloss.Style {
	switch k {
	case oci.KindIndex:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	case oci.KindImage:
		return styleRow
	case oci.KindSignature:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	case oci.KindAttestation:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("177"))
	case oci.KindSBOM:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("117"))
	case oci.KindVulnReport, oci.KindVEX:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("221"))
	case oci.KindHelmChart:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	case oci.KindArtifact:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("152"))
	case oci.KindReferrersIndex:
		return styleMuted
	default:
		return styleRow
	}
}
