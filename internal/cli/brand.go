package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

const (
	brandProductName   = "IronSentinel"
	brandPrimaryBinary = "ironsentinel"
)

var brandGlyphs = map[rune][]string{
	'I': {"███", " █ ", " █ ", " █ ", " █ ", "███"},
	'R': {"████ ", "█   █", "████ ", "█  █ ", "█   █", "█   █"},
	'O': {" ███ ", "█   █", "█   █", "█   █", "█   █", " ███ "},
	'N': {"█   █", "██  █", "█ █ █", "█  ██", "█   █", "█   █"},
	'S': {" ████", "█    ", " ███ ", "    █", "    █", "████ "},
	'E': {"█████", "█    ", "████ ", "█    ", "█    ", "█████"},
	'T': {"█████", "  █  ", "  █  ", "  █  ", "  █  ", "  █  "},
	'L': {"█    ", "█    ", "█    ", "█    ", "█    ", "█████"},
	' ': {"  ", "  ", "  ", "  ", "  ", "  "},
}

type brandMascotProfile struct {
	title  string
	hint   string
	frames [][]string
}

func (a *App) primaryCommandName() string {
	return brandPrimaryBinary
}

func (a *App) commandHint(parts ...string) string {
	tokens := append([]string{a.primaryCommandName()}, parts...)
	return fmt.Sprintf("`%s`", strings.Join(tokens, " "))
}

func isConfigLanguageCommandPath(path string) bool {
	path = strings.TrimSpace(path)
	return path == "config language" || strings.HasSuffix(path, " config language")
}

func (a *App) staticRenderWidth() int {
	if !a.isInteractiveTerminal() {
		return 120
	}
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return 120
	}
	return width
}

func initialTerminalViewport() (int, int) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		width = 120
	}
	if err != nil || height <= 0 {
		height = 36
	}
	return width, height
}

func composeBrandBanner(text string) []string {
	text = strings.ToUpper(strings.TrimSpace(text))
	lines := make([]string, 6)
	for _, r := range text {
		glyph, ok := brandGlyphs[r]
		if !ok {
			glyph = brandGlyphs[' ']
		}
		for i := range lines {
			if lines[i] != "" {
				lines[i] += "  "
			}
			lines[i] += glyph[i]
		}
	}
	return lines
}

func (a *App) renderBrandHero(width, frame int, subtitle string) string {
	return a.renderBrandHeroForRoute(width, frame, subtitle, appRouteHome)
}

func (a *App) renderBrandHeroForRoute(width, frame int, subtitle string, route appRoute) string {
	if width <= 0 {
		width = 120
	}
	theme := a.tuiTheme()
	banner := strings.Join(a.renderBrandBannerLines(frame), "\n")
	mascot := strings.Join(a.brandMascotLines(route, frame), "\n")
	commandDeck := theme.chipStyle(true).Render("SNTL // " + a.catalog.T("app_sidebar_title"))
	paletteHint := theme.chipStyle(false).Render(a.catalog.T("app_sidebar_palette_hint"))
	subtitleBlock := lipgloss.JoinVertical(
		lipgloss.Left,
		theme.heroTitleStyle().Render(strings.ToUpper(brandProductName)),
		theme.subtitleStyle().Render(subtitle),
		theme.mutedStyle().Render(a.catalog.T("brand_tagline")),
		lipgloss.JoinHorizontal(lipgloss.Left, commandDeck, " ", paletteHint),
	)
	signal := theme.mutedStyle().Render(a.brandSignalLine(frame))
	statusLines := []string{
		fmt.Sprintf("%s // %s", strings.ToUpper(a.routeMascotProfile(route).title), a.routeMascotProfile(route).hint),
		a.catalog.T("brand_tagline"),
		signal,
	}

	if width < 88 {
		return lipgloss.JoinVertical(
			lipgloss.Left,
			subtitleBlock,
			theme.panelStyle(width).Width(width).Render(strings.Join([]string{mascot, "", signal}, "\n")),
		)
	}

	if width < 138 {
		left := lipgloss.JoinVertical(
			lipgloss.Left,
			banner,
			"",
			subtitleBlock,
		)
		right := theme.panelStyle(minInt(34, maxInt(28, width/3))).Render(strings.Join([]string{
			mascot,
			"",
			strings.Join(statusLines, "\n"),
		}, "\n"))
		return lipgloss.JoinHorizontal(lipgloss.Top, left, theme.gap(), right)
	}

	rightWidth := 34
	leftWidth := width - rightWidth - len(theme.gap())
	if leftWidth < 72 {
		leftWidth = 72
	}
	left := lipgloss.NewStyle().Width(leftWidth).Render(strings.Join([]string{
		banner,
		"",
		theme.titleStyle().Render(strings.ToUpper(brandProductName)),
		theme.subtitleStyle().Render(subtitle),
		theme.mutedStyle().Render(a.catalog.T("brand_tagline")),
		signal,
	}, "\n"))
	right := theme.panelStyle(rightWidth).Width(rightWidth).Render(strings.Join([]string{
		mascot,
		"",
		strings.Join(statusLines, "\n"),
	}, "\n"))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, theme.gap(), right)
}

func (a *App) renderBrandMastheadForRoute(width, frame int, subtitle string, route appRoute) string {
	if width <= 0 {
		width = 120
	}
	theme := a.tuiTheme()
	title := strings.ToUpper(brandProductName)
	if width < 74 {
		return lipgloss.JoinVertical(
			lipgloss.Left,
			lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(theme.heroTitleStyle().Bold(true).Render(title)),
			lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(theme.subtitleStyle().Render(trimForSelect(subtitle, maxInt(18, width-4)))),
		)
	}

	bannerLines := 0
	if width >= 108 && width < 148 {
		bannerLines = 1
	}
	if width >= 148 {
		bannerLines = 2
	}

	mascotWidth := 16
	if width >= 132 {
		mascotWidth = 18
	}
	if width >= 152 {
		mascotWidth = 20
	}
	contentWidth := maxInt(42, width-mascotWidth-2)
	mascotPanel := theme.panelStyle(mascotWidth).Width(mascotWidth).Render(strings.Join(a.brandMascotBadgeLines(route, frame), "\n"))
	contentParts := []string{}
	if bannerLines > 0 {
		contentParts = append(contentParts, a.renderBannerBlock(contentWidth, frame, bannerLines))
	}
	contentParts = append(contentParts,
		lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Center).Render(theme.heroTitleStyle().Bold(true).Render(title)),
		lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Center).Render(theme.subtitleStyle().Render(trimForSelect(subtitle, maxInt(18, contentWidth-4)))),
		lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Center).Render(theme.mutedStyle().Render(
			fmt.Sprintf("%s • %s", strings.ToUpper(a.routeMascotProfile(route).title), trimForSelect(a.catalog.T("brand_tagline"), maxInt(18, contentWidth-16))),
		)),
	)
	if width >= 132 {
		contentParts = append(contentParts,
			lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Center).Render(theme.mutedStyle().Render(a.brandSignalLine(frame))),
		)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, mascotPanel, "  ", lipgloss.JoinVertical(lipgloss.Left, contentParts...))
}

func (a *App) renderBrandHeaderCompactForRoute(width, frame int, subtitle string, route appRoute) string {
	if width <= 0 {
		width = 120
	}
	theme := a.tuiTheme()
	profile := a.routeMascotProfile(route)
	title := strings.ToUpper(brandProductName)
	subtitleLine := trimForSelect(subtitle, maxInt(18, width-4))
	mascotLine := strings.ToUpper(profile.title)
	if width < 88 {
		return lipgloss.JoinVertical(
			lipgloss.Left,
			lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(theme.heroTitleStyle().Bold(true).Render(title)),
			lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(theme.mutedStyle().Render(trimForSelect(mascotLine+" • "+subtitleLine, maxInt(18, width-4)))),
		)
	}

	titleLine := lipgloss.JoinHorizontal(
		lipgloss.Left,
		lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true).Render(mascotLine),
		"  ",
		theme.heroTitleStyle().Bold(true).Render(title),
	)
	return lipgloss.JoinVertical(
		lipgloss.Left,
		lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(titleLine),
		lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(theme.mutedStyle().Render(subtitleLine)),
	)
}

func (a *App) renderBrandConsoleHeaderForRoute(width, frame int, subtitle string, route appRoute) string {
	if width <= 0 {
		width = 120
	}
	theme := a.tuiTheme()
	if width < 92 {
		return lipgloss.JoinVertical(
			lipgloss.Left,
			a.renderBannerBlock(width, frame, 2),
			lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(theme.heroTitleStyle().Render(strings.ToUpper(brandProductName))),
			lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(theme.subtitleStyle().Render(trimForSelect(subtitle, maxInt(18, width-4)))),
		)
	}

	mascotWidth := 20
	contentWidth := width - mascotWidth - 2
	bannerLines := 2
	if width >= 132 {
		bannerLines = 3
	}
	mascot := theme.panelStyle(mascotWidth).Width(mascotWidth).Render(strings.Join(a.brandMascotCompactLines(route, frame), "\n"))
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		a.renderBannerBlock(contentWidth, frame, bannerLines),
		lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Center).Render(theme.heroTitleStyle().Render(strings.ToUpper(brandProductName))),
		lipgloss.NewStyle().Width(contentWidth).Align(lipgloss.Center).Render(theme.subtitleStyle().Render(trimForSelect(subtitle, maxInt(24, contentWidth-4)))),
	)
	return lipgloss.JoinHorizontal(lipgloss.Top, mascot, "  ", content)
}

func (a *App) renderStaticBrandHero(subtitle string) string {
	return a.renderBrandHero(a.staticRenderWidth()-4, 0, subtitle)
}

func (a *App) renderBrandBannerLines(frame int) []string {
	if a.tuiTheme().plain() {
		return composeBrandBanner(brandProductName)
	}
	palette := []lipgloss.Color{
		lipgloss.Color("87"),
		lipgloss.Color("81"),
		lipgloss.Color("51"),
		lipgloss.Color("45"),
		lipgloss.Color("39"),
		lipgloss.Color("111"),
	}
	raw := composeBrandBanner(brandProductName)
	lines := make([]string, 0, len(raw))
	for index, line := range raw {
		color := palette[(index+frame)%len(palette)]
		style := lipgloss.NewStyle().Bold(true).Foreground(color)
		lines = append(lines, style.Render(line))
	}
	return lines
}

func (a *App) renderBannerBlock(width, frame, lines int) string {
	bannerLines := a.renderBrandBannerLines(frame)
	if lines > 0 && len(bannerLines) > lines {
		bannerLines = bannerLines[:lines]
	}
	rendered := make([]string, 0, len(bannerLines))
	for _, line := range bannerLines {
		rendered = append(rendered, lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(line))
	}
	return strings.Join(rendered, "\n")
}

func (a *App) routeMascotProfile(route appRoute) brandMascotProfile {
	switch route {
	case appRouteScanReview, appRouteRuntime:
		return brandMascotProfile{
			title: a.catalog.T("brand_mascot_warden"),
			hint:  a.catalog.T("brand_mascot_warden_hint"),
			frames: [][]string{
				{"   .===.", "  [ 0 0 ]", "  |  ^  |", "  | [#] |", "   `-=-`"},
				{"   .===.", "  [ 0 0 ]", "  |  -  |", "  | [#] |", "   `-=-`"},
			},
		}
	case appRouteLiveScan:
		return brandMascotProfile{
			title: a.catalog.T("brand_mascot_pulse"),
			hint:  a.catalog.T("brand_mascot_pulse_hint"),
			frames: [][]string{
				{"   .~~~.", "  ( o o )", "  | /|\\\\ |", "  | |_| |", "   `-=-`"},
				{"   .~~~.", "  ( o o )", "  | \\\\|/ |", "  | |_| |", "   `-=-`"},
			},
		}
	case appRouteRuns:
		return brandMascotProfile{
			title: a.catalog.T("brand_mascot_courier"),
			hint:  a.catalog.T("brand_mascot_courier_hint"),
			frames: [][]string{
				{"   .-.-.", "  ( o o )>", "  |  v  |", "  | [_] |", "   `---`"},
				{"   .-.-.", " <( o o )", "  |  v  |", "  | [_] |", "   `---`"},
			},
		}
	case appRouteFindings:
		return brandMascotProfile{
			title: a.catalog.T("brand_mascot_oracle"),
			hint:  a.catalog.T("brand_mascot_oracle_hint"),
			frames: [][]string{
				{"   .***.", "  ( -O- )", "  |  ~  |", "  | [_] |", "   `---`"},
				{"   .***.", "  ( oOo )", "  |  ~  |", "  | [_] |", "   `---`"},
			},
		}
	default:
		return brandMascotProfile{
			title: a.catalog.T("brand_mascot_scout"),
			hint:  a.catalog.T("brand_mascot_scout_hint"),
			frames: [][]string{
				{"   .-^-.", "  ( o o )", "  |  >  |", "  | /_\\\\ |", "   `---`"},
				{"   .-.-.", "  ( o o )", "  |  >  |", "  | /_\\\\ |", "   `---`"},
			},
		}
	}
}

func (a *App) mascotFrame(route appRoute, frame int) []string {
	profile := a.routeMascotProfile(route)
	if len(profile.frames) == 0 {
		return []string{profile.title}
	}
	if a.reducedMotion() {
		return profile.frames[0]
	}
	return profile.frames[frame%len(profile.frames)]
}

func (a *App) brandMascotLines(route appRoute, frame int) []string {
	profile := a.routeMascotProfile(route)
	lines := append([]string{}, a.mascotFrame(route, frame)...)
	lines = append(lines, "", fmt.Sprintf("  %s // %s", strings.ToUpper(profile.title), profile.hint))
	return lines
}

func (a *App) brandMascotBadgeLines(route appRoute, frame int) []string {
	profile := a.routeMascotProfile(route)
	lines := append([]string{}, a.mascotFrame(route, frame)...)
	lines = append(lines, "", "  "+strings.ToUpper(profile.title), "  "+profile.hint)
	return lines
}

func (a *App) brandMascotCompactLines(route appRoute, frame int) []string {
	profile := a.routeMascotProfile(route)
	frameLines := a.mascotFrame(route, frame)
	lines := append([]string{}, frameLines...)
	lines = append(lines, strings.ToUpper(profile.title))
	return lines
}

func (a *App) brandSignalLine(frame int) string {
	if a.tuiTheme().plain() {
		return strings.Join([]string{
			a.catalog.T("brand_signal_local"),
			a.catalog.T("brand_signal_bilingual"),
			a.catalog.T("brand_signal_trust"),
			a.catalog.T("brand_signal_evidence"),
		}, " | ")
	}
	signals := []struct {
		label string
		color lipgloss.Color
	}{
		{label: a.catalog.T("brand_signal_local"), color: lipgloss.Color("45")},
		{label: a.catalog.T("brand_signal_bilingual"), color: lipgloss.Color("39")},
		{label: a.catalog.T("brand_signal_trust"), color: lipgloss.Color("81")},
		{label: a.catalog.T("brand_signal_evidence"), color: lipgloss.Color("111")},
	}

	rendered := make([]string, 0, len(signals))
	for index, signal := range signals {
		style := lipgloss.NewStyle().
			Bold(true).
			Padding(0, 1).
			Foreground(lipgloss.Color("235")).
			Background(signal.color)
		if frame%2 == index%2 {
			style = style.Foreground(lipgloss.Color("255"))
		}
		rendered = append(rendered, style.Render(signal.label))
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, rendered...)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
