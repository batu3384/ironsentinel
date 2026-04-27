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

type colorTheme string

const (
	colorThemeDark  colorTheme = "dark"
	colorThemeLight colorTheme = "light"
)

var selectableColorThemes = []colorTheme{
	colorThemeDark,
	colorThemeLight,
}

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

func parseColorTheme(value string) (colorTheme, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(colorThemeDark):
		return colorThemeDark, nil
	case string(colorThemeLight):
		return colorThemeLight, nil
	default:
		return "", fmt.Errorf("invalid color theme: %s", value)
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

func (a *App) SetColorTheme(theme string) error {
	parsed, err := parseColorTheme(theme)
	if err != nil {
		return fmt.Errorf("%s", a.catalog.T("color_theme_invalid", theme))
	}
	a.colorTheme = parsed
	return nil
}

func (a *App) SaveColorTheme(theme string) error {
	if err := a.SetColorTheme(theme); err != nil {
		return err
	}
	a.preferences.ColorTheme = string(a.colorTheme)
	return preferences.Save(a.cfg, a.preferences)
}

type tuiTheme struct {
	mode         uiMode
	colorTheme   colorTheme
}

func newTUITheme(mode uiMode, theme colorTheme) tuiTheme {
	if theme == "" {
		theme = colorThemeDark
	}
	return tuiTheme{mode: mode, colorTheme: theme}
}

func (a *App) tuiTheme() tuiTheme {
	return newTUITheme(a.currentUIMode(), a.currentColorTheme())
}

func (a *App) currentColorTheme() colorTheme {
	if a != nil && a.colorTheme != "" {
		return a.colorTheme
	}
	return colorThemeDark
}

func (a *App) decorativeMotionEnabled() bool {
	if a == nil {
		return false
	}
	return !a.tuiTheme().plain() && !a.reducedMotion()
}

func (t tuiTheme) plain() bool {
	return t.mode == uiModePlain
}

func (t tuiTheme) compact() bool {
	return t.mode == uiModeCompact
}

func (t tuiTheme) dark() bool {
	return t.colorTheme == colorThemeDark
}

// colorPalette defines the color scheme for a theme
type colorPalette struct {
	primary      string
	secondary    string
	accent       string
	warning      string
	error        string
	success      string
	muted        string
	highlight    string
	tabActiveBG  string
	tabActiveFG  string
	panelBorder  string
	panelBG      string
	heroBG       string
}

// Dark theme palette (default)
var darkPalette = colorPalette{
	primary:     "153", // Light blue
	secondary:   "117", // Cyan
	accent:      "81",  // Teal
	warning:     "214", // Orange
	error:       "203", // Red
	success:     "86",  // Green
	muted:       "243", // Gray
	highlight:   "117", // Cyan
	tabActiveBG: "31",  // Blue bg
	tabActiveFG: "231", // White text
	panelBorder: "62",  // Gray border
	panelBG:     "235", // Dark gray bg
	heroBG:      "233", // Darker bg
}

// Light theme palette
var lightPalette = colorPalette{
	primary:     "26",  // Dark blue
	secondary:   "31",  // Blue
	accent:      "36",  // Teal
	warning:     "208", // Orange
	error:       "196", // Red
	success:     "34",  // Green
	muted:       "247", // Gray
	highlight:   "32",  // Green
	tabActiveBG: "21",   // Dark blue bg
	tabActiveFG: "231", // White text
	panelBorder: "250", // Light gray border
	panelBG:     "255", // White bg
	heroBG:      "252", // Light gray bg
}

func (t tuiTheme) palette() colorPalette {
	if t.dark() {
		return darkPalette
	}
	return lightPalette
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
		style = style.Foreground(lipgloss.Color(t.palette().primary))
	}
	return style
}

func (t tuiTheme) heroTitleStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Bold(true)
	if !t.plain() {
		style = style.Foreground(lipgloss.Color(t.palette().accent))
	}
	return style
}

func (t tuiTheme) subtitleStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !t.plain() {
		style = style.Foreground(lipgloss.Color(t.palette().muted))
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
		p := t.palette()
		style = style.BorderForeground(lipgloss.Color(p.panelBorder)).Background(lipgloss.Color(p.panelBG))
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
	p := t.palette()
	if t.compact() {
		return style.Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(p.accent))
	}
	return style.
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(p.accent)).
		Background(lipgloss.Color(p.heroBG))
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
		style = style.Foreground(lipgloss.Color(t.palette().secondary))
	}
	return style
}

func (t tuiTheme) sectionBodyStyle() lipgloss.Style {
	style := lipgloss.NewStyle()
	if !t.plain() {
		style = style.Foreground(lipgloss.Color(t.palette().muted))
	}
	return style
}

func (t tuiTheme) eyebrowStyle() lipgloss.Style {
	style := lipgloss.NewStyle().Bold(true)
	if !t.plain() {
		style = style.Foreground(lipgloss.Color(t.palette().success))
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
		style = style.Foreground(lipgloss.Color(t.palette().muted))
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
	p := t.palette()
	return style.
		Background(lipgloss.Color(p.heroBG)).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(lipgloss.Color(p.panelBorder))
}

func (t tuiTheme) commandRibbonStyle(width int) lipgloss.Style {
	style := lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Padding(0, 1)
	if t.plain() {
		return style
	}
	p := t.palette()
	return style.
		Background(lipgloss.Color(p.heroBG)).
		Border(lipgloss.NormalBorder(), true, false, false, false).
		BorderForeground(lipgloss.Color(p.panelBorder))
}

func (t tuiTheme) noticeStyle(alert bool) lipgloss.Style {
	style := lipgloss.NewStyle()
	if alert {
		style = style.Bold(true)
		if !t.plain() {
			style = style.Foreground(lipgloss.Color(t.palette().error))
		}
		return style
	}
	if !t.plain() {
		style = style.Foreground(lipgloss.Color(t.palette().success))
	}
	return style
}
