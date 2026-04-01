package cli

import (
	"regexp"
	"strings"

	"github.com/pterm/pterm"
)

var ptermMarkupPattern = regexp.MustCompile(`\[(?:[-a-zA-Z0-9_#;]+)\]`)

func (a *App) stripStyledText(value string) string {
	cleaned := pterm.RemoveColorFromString(value)
	return ptermMarkupPattern.ReplaceAllString(cleaned, "")
}

func (a *App) ptermSprintf(format string, args ...any) string {
	rendered := pterm.Sprintf(format, args...)
	if a == nil || !a.colorDisabled() {
		return rendered
	}
	return a.stripStyledText(rendered)
}

func (a *App) plainBadge(label string) string {
	label = strings.TrimSpace(strings.ToUpper(label))
	if label == "" {
		return "-"
	}
	return "[" + label + "]"
}
