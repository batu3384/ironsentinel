package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"

	"github.com/batu3384/ironsentinel/internal/agent"
	"github.com/batu3384/ironsentinel/internal/domain"
)

type daemonOptions struct {
	Interval         time.Duration
	ProjectIDs       []string
	PresetID         domain.CompliancePreset
	Mode             domain.ScanMode
	Coverage         domain.CoverageProfile
	AutoUpdateBundle bool
	DriftDetection   bool
	SlackWebhook     string
	WebhookURL       string
}

type daemonNotifier struct {
	app  *App
	opts daemonOptions
	mu   sync.Mutex
	runs map[string]struct{}
}

func newDaemonNotifier(app *App, opts daemonOptions) *daemonNotifier {
	return &daemonNotifier{
		app:  app,
		opts: opts,
		runs: make(map[string]struct{}),
	}
}

func (n *daemonNotifier) Track(run domain.ScanRun) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.runs[run.ID] = struct{}{}
}

func (n *daemonNotifier) shouldHandle(run domain.ScanRun) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.runs[run.ID]; ok {
		delete(n.runs, run.ID)
		return true
	}
	return run.ExecutionMode == "scheduled"
}

func (n *daemonNotifier) Handle(event domain.StreamEvent) {
	switch event.Type {
	case "run.completed", "run.failed", "run.canceled":
	default:
		return
	}
	if !n.shouldHandle(event.Run) {
		return
	}

	projectLabel := n.app.projectLabel(event.Run.ProjectID)
	message := fmt.Sprintf("IronSentinel scheduled run %s finished with status %s for %s.", event.Run.ID, strings.ToUpper(string(event.Run.Status)), projectLabel)
	payload := map[string]any{
		"type":    event.Type,
		"run":     event.Run,
		"project": projectLabel,
		"status":  event.Run.Status,
	}
	if n.opts.DriftDetection && event.Run.Status == domain.ScanCompleted {
		if delta, _, baseline, err := n.app.service.GetRunDelta(event.Run.ID, ""); err == nil {
			payload["delta"] = delta
			if baseline != nil {
				payload["baselineRunId"] = baseline.ID
			}
			message = fmt.Sprintf(
				"IronSentinel scheduled run %s for %s completed. New=%d Existing=%d Resolved=%d Total=%d.",
				event.Run.ID,
				projectLabel,
				delta.CountsByChange[domain.FindingNew],
				delta.CountsByChange[domain.FindingExisting],
				delta.CountsByChange[domain.FindingResolved],
				event.Run.Summary.TotalFindings,
			)
		}
	}
	if n.opts.SlackWebhook != "" {
		if err := postJSON(n.opts.SlackWebhook, map[string]any{"text": message}); err == nil {
			_ = agent.UpdateDaemonNotification(n.app.cfg, time.Now().UTC(), "scheduled notification delivered")
		}
	}
	if n.opts.WebhookURL != "" {
		payload["message"] = message
		if err := postJSON(n.opts.WebhookURL, payload); err == nil {
			_ = agent.UpdateDaemonNotification(n.app.cfg, time.Now().UTC(), "scheduled notification delivered")
		}
	}
}

func postJSON(target string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("webhook returned %s", resp.Status)
}

func (a *App) startDaemonScheduler(ctx context.Context, opts daemonOptions, notifier *daemonNotifier) {
	if opts.Interval <= 0 {
		return
	}
	queue := func() {
		if opts.AutoUpdateBundle {
			updateMode := "safe"
			if opts.Coverage == domain.CoverageFull {
				updateMode = "full"
			}
			if _, err := agent.UpdateManagedBundle(a.cfg, updateMode, a.runInstallBundle); err != nil {
				pterm.Warning.Printf("%s\n", a.catalog.T("daemon_bundle_update_failed", err.Error()))
			}
		}
		count, err := a.enqueueScheduledScans(opts, notifier)
		if err != nil {
			pterm.Warning.Printf("%s\n", a.catalog.T("daemon_schedule_failed", err.Error()))
			return
		}
		if count > 0 {
			pterm.Info.Printf("%s\n", a.catalog.T("daemon_schedule_enqueued", count))
		}
	}

	queue()
	ticker := time.NewTicker(opts.Interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				queue()
			}
		}
	}()
}

func (a *App) enqueueScheduledScans(opts daemonOptions, notifier *daemonNotifier) (int, error) {
	projects := a.scheduledProjects(opts.ProjectIDs)
	if len(projects) == 0 {
		return 0, nil
	}

	active := make(map[string]struct{})
	for _, run := range a.service.ListRuns() {
		if run.Status == domain.ScanQueued || run.Status == domain.ScanRunning {
			active[run.ProjectID] = struct{}{}
		}
	}

	enqueued := 0
	for _, project := range projects {
		if _, busy := active[project.ID]; busy {
			continue
		}
		profile := a.buildScheduledProfile(project, opts)
		if err := a.enforceRequiredRuntime(project, profile, true, false); err != nil {
			pterm.Warning.Printf("%s\n", a.catalog.T("daemon_schedule_skip_project", project.DisplayName, err.Error()))
			continue
		}
		run, err := a.service.ScheduleScan(project.ID, profile)
		if err != nil {
			return enqueued, err
		}
		notifier.Track(run)
		active[project.ID] = struct{}{}
		enqueued++
	}
	if enqueued > 0 {
		_ = agent.UpdateDaemonSchedule(a.cfg, time.Now().UTC(), fmt.Sprintf("scheduled %d scan(s)", enqueued))
	}
	return enqueued, nil
}

func (a *App) scheduledProjects(ids []string) []domain.Project {
	all := a.service.ListProjects()
	if len(ids) == 0 {
		return all
	}
	index := make(map[string]domain.Project, len(all))
	for _, project := range all {
		index[project.ID] = project
	}
	selected := make([]domain.Project, 0, len(ids))
	for _, id := range ids {
		if project, ok := index[id]; ok {
			selected = append(selected, project)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].DisplayName < selected[j].DisplayName })
	return selected
}

func (a *App) buildScheduledProfile(project domain.Project, opts daemonOptions) domain.ScanProfile {
	profile := a.quickScanProfile(project)
	if opts.Mode != "" {
		profile.Mode = opts.Mode
	}
	if opts.Coverage != "" {
		profile.Coverage = opts.Coverage
	}
	if opts.PresetID != "" {
		profile.PresetID = opts.PresetID
	}
	profile = a.applyCompliancePreset(project, profile, opts.Mode != "", opts.Coverage != "", false, false, false, false, false)
	profile.Modules = a.resolveModulesForProject(project, profile)
	return profile
}
