package cli

import "github.com/batu3384/ironsentinel/internal/domain"

type tuiSnapshot struct {
	Portfolio portfolioSnapshot
	Runtime   domain.RuntimeStatus
}

type tuiMetricCard struct {
	Title string
	Value string
	Hint  string
}

var runFindingSeverityFilters = []string{"all", "critical", "high", "medium", "low", "info"}
var runFindingStatusFilters = []string{"all", "open", "investigating", "accepted_risk", "false_positive", "fixed"}
var runFindingCategoryFilters = []string{"all", "secret", "vulnerability", "compliance", "configuration", "license"}

func (a *App) buildTUISnapshot() tuiSnapshot {
	return tuiSnapshot{
		Portfolio: a.buildPortfolioSnapshot(),
		Runtime:   a.runtimeStatus(false),
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
