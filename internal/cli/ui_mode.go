package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/batu3384/ironsentinel/internal/preferences"
)

type uiMode string

const (
	uiModeStandard uiMode = "standard"
	uiModePlain    uiMode = "plain"
	uiModeCompact  uiMode = "compact"
)

var selectableUIModes = []uiMode{
	uiModeStandard,
	uiModePlain,
	uiModeCompact,
}

func parseUIMode(value string) (uiMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(uiModeStandard):
		return uiModeStandard, nil
	case string(uiModePlain):
		return uiModePlain, nil
	case string(uiModeCompact):
		return uiModeCompact, nil
	default:
		return "", fmt.Errorf("invalid ui mode: %s", value)
	}
}

func (a *App) currentUIMode() uiMode {
	if a != nil && a.colorDisabled() {
		return uiModePlain
	}
	if a == nil || a.uiMode == "" {
		return uiModeStandard
	}
	return a.uiMode
}

func (a *App) SetUIMode(mode string) error {
	parsed, err := parseUIMode(mode)
	if err != nil {
		return fmt.Errorf("%s", a.catalog.T("ui_mode_invalid", mode))
	}
	a.uiMode = parsed
	return nil
}

func (a *App) SaveUIMode(mode string) error {
	if err := a.SetUIMode(mode); err != nil {
		return err
	}
	a.preferences.UIMode = string(a.uiMode)
	return preferences.Save(a.cfg, a.preferences)
}

type tuiTheme struct {
	mode uiMode
}

func newTUITheme(mode uiMode) tuiTheme {
	return tuiTheme{mode: mode}
}

func (a *App) tuiTheme() tuiTheme {
	return newTUITheme(a.currentUIMode())
}

func (t tuiTheme) plain() bool {
	return t.mode == uiModePlain
}

func (t tuiTheme) compact() bool {
	return t.mode == uiModeCompact
}

func (t tuiTheme) docStyle() lipgloss.Style {
	paddingY := 0
	paddingX := 2
	if t.compact() {
		paddingY = 0
		paddingX = 1
	}
	if t.plain() {
		paddingY = 0
		paddingX = 1
	}
	return lipgloss.NewStyle().Padding(paddingY, paddingX)
}

func (t tuiTheme) titleStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Bold(true)
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("153"))
	}
	return style
}

func (t tuiTheme) heroTitleStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Bold(true)
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("123"))
	}
	return style
}

func (t tuiTheme) subtitleStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("250"))
	}
	return style
}

func (t tuiTheme) tabActiveStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	if t.plain() {
		return style.Underline(true)
	}
	if t.compact() {
		return style.Foreground(lipgloss.Color("123")).Underline(true)
	}
	return style.
		Foreground(lipgloss.Color("231")).
		Background(lipgloss.Color("31"))
}

func (t tuiTheme) tabIdleStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Padding(0, 1)
	if t.plain() {
		return style
	}
	if t.compact() {
		return style.Foreground(lipgloss.Color("250"))
	}
	return style.Foreground(lipgloss.Color("245"))
}

func (t tuiTheme) panelStyle(width int) lipgloss.Style {
	paddingY := 0
	paddingX := 1
	var border lipgloss.Border
	style := lipgloss.NewStyle().Width(width)
	if t.compact() {
		paddingX = 0
	}
	if t.plain() {
		border = lipgloss.NormalBorder()
	} else {
		border = lipgloss.RoundedBorder()
	}
	style = style.Border(border).Padding(paddingY, paddingX)
	if !t.plain() {
		style = style.BorderForeground(lipgloss.Color("62")).Background(lipgloss.Color("235"))
	}
	return style
}

func (t tuiTheme) metricCardStyle(width int) lipgloss.Style {
	style := lipgloss.NewStyle().Width(width).Padding(0, 1)
	if t.plain() {
		return style
	}
	if t.compact() {
		return style.Foreground(lipgloss.Color("252"))
	}
	return style.
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.Color("67")).
		Foreground(lipgloss.Color("255")).
		Background(lipgloss.Color("236"))
}

func (t tuiTheme) heroPanelStyle(width int) lipgloss.Style {
	style := lipgloss.NewStyle().Width(width).Padding(1, 2)
	if t.plain() {
		return style.Border(lipgloss.RoundedBorder())
	}
	if t.compact() {
		return style.Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("67"))
	}
	return style.
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("81")).
		Background(lipgloss.Color("233"))
}

func (t tuiTheme) gap() string {
	if t.compact() {
		return " "
	}
	return "   "
}

func (t tuiTheme) blockGap() string {
	if t.compact() || t.plain() {
		return "\n"
	}
	return "\n\n"
}

func (t tuiTheme) sectionTitleStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Bold(true)
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("117"))
	}
	return style
}

func (t tuiTheme) sectionBodyStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("252"))
	}
	return style
}

func (t tuiTheme) eyebrowStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Bold(true)
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("75"))
	}
	return style
}

func (t tuiTheme) chipStyle(active bool) lipgloss.Style {
	style := lipgloss.NewStyle().Padding(0, 1)
	if t.plain() {
		if active {
			return style.Underline(true).Bold(true)
		}
		return style
	}
	if active {
		return style.Foreground(lipgloss.Color("231")).Background(lipgloss.Color("37")).Bold(true)
	}
	return style.Foreground(lipgloss.Color("250")).Background(lipgloss.Color("237"))
}

func (t tuiTheme) rowStyle(selected bool) lipgloss.Style {
	style := lipgloss.NewStyle()
	if selected {
		style = style.Bold(true).Padding(0, 1).Border(lipgloss.NormalBorder(), false, false, false, true)
		if !t.plain() {
			style = style.Foreground(lipgloss.Color("231")).Background(lipgloss.Color("239")).BorderForeground(lipgloss.Color("117"))
		}
		return style
	}
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("252")).PaddingLeft(1)
	}
	return style
}

func (t tuiTheme) rowHintStyle(selected bool) lipgloss.Style {
	if selected {
		style := lipgloss.NewStyle().Padding(0, 1).PaddingLeft(3)
		if !t.plain() {
			return style.Foreground(lipgloss.Color("153")).Background(lipgloss.Color("239"))
		}
		return style
	}
	return t.mutedStyle()
}

func (t tuiTheme) mutedStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("243"))
	}
	return style
}

func (t tuiTheme) helpStyle() lipgloss.Style {
	return t.mutedStyle()
}

func (t tuiTheme) routeRibbonStyle(width int) lipgloss.Style {
	style := lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Padding(0, 1)
	if t.plain() {
		return style
	}
	return style.
		Background(lipgloss.Color("233")).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(lipgloss.Color("238"))
}

func (t tuiTheme) commandRibbonStyle(width int) lipgloss.Style {
	style := lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Padding(0, 1)
	if t.plain() {
		return style
	}
	return style.
		Background(lipgloss.Color("232")).
		Border(lipgloss.NormalBorder(), true, false, false, false).
		BorderForeground(lipgloss.Color("236"))
}

func (t tuiTheme) noticeStyle(alert bool) lipgloss.Style {
	style := lipgloss.NewStyle()
	if alert {
		style = style.Bold(true)
		if !t.plain() {
			style = style.Foreground(lipgloss.Color("203"))
		}
		return style
	}
	if !t.plain() {
		style = style.Foreground(lipgloss.Color("86"))
	}
	return style
}
