package cli

import (
	"context"
	"fmt"

	"github.com/pterm/pterm"
)

func (a *App) runPrimarySurface(ctx context.Context) error {
	if a.isInteractiveTerminal() {
		return a.launchTUI(ctx)
	}
	return a.renderOverviewSurface()
}

func (a *App) renderOverviewSurface() error {
	snapshot := a.buildPortfolioSnapshot()
	if a.shellSafeSurfaceOutput() {
		return a.renderOverviewSurfacePlain(snapshot)
	}
	a.renderDashboardHeader(snapshot)
	if err := a.renderRecentRunsOverview(snapshot); err != nil {
		return err
	}
	if err := a.renderRecentFindingsOverview(snapshot); err != nil {
		return err
	}
	pterm.Println()
	pterm.Info.Println(a.catalog.T("runs_saved"))
	if a.isInteractiveTerminal() {
		pterm.Info.Println(a.catalog.T("primary_surface_hint"))
	}
	return nil
}

func (a *App) renderHome() error {
	return a.renderOverviewSurface()
}

func (a *App) requireInteractiveSurface() error {
	if !a.isInteractiveTerminal() {
		return fmt.Errorf("%s", a.catalog.T("interactive_required"))
	}
	return nil
}
