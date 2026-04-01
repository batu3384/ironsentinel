package reports

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func Export(format string, run domain.ScanRun, baseline *domain.ScanRun, findings []domain.Finding, delta domain.RunDelta, trends []domain.RunTrendPoint) (string, error) {
	run.Summary = domain.RecalculateSummary(findings, run.Profile.SeverityGate)
	changeByFingerprint := buildChangeIndex(delta)
	switch strings.ToLower(format) {
	case "sarif":
		return exportSARIF(run, baseline, findings, delta, changeByFingerprint, trends)
	case "csv":
		return exportCSV(findings, changeByFingerprint)
	case "html":
		return exportHTML(run, baseline, findings, delta, changeByFingerprint, trends), nil
	default:
		return "", fmt.Errorf("unsupported export format: %s", format)
	}
}

func exportSARIF(run domain.ScanRun, baseline *domain.ScanRun, findings []domain.Finding, delta domain.RunDelta, changeByFingerprint map[string]domain.FindingChange, trends []domain.RunTrendPoint) (string, error) {
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Properties map[string]any `json:"properties,omitempty"`
		Locations  []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}

	payload := map[string]any{
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name": "IronSentinel AppSec",
					},
				},
				"automationDetails": map[string]any{
					"id": run.ID,
				},
				"properties": map[string]any{
					"baselineRunId":    baselineID(baseline),
					"newFindings":      delta.CountsByChange[domain.FindingNew],
					"existingFindings": delta.CountsByChange[domain.FindingExisting],
					"resolvedFindings": delta.CountsByChange[domain.FindingResolved],
					"moduleExecution":  moduleExecutionStats(run.ModuleResults),
					"trend":            trends,
					"moduleResultSummaries": func() []map[string]any {
						items := make([]map[string]any, 0, len(run.ModuleResults))
						for _, module := range run.ModuleResults {
							items = append(items, map[string]any{
								"name":         module.Name,
								"status":       module.Status,
								"findingCount": module.FindingCount,
								"attempts":     displayModuleAttempts(module),
								"durationMs":   module.DurationMs,
								"timedOut":     module.TimedOut,
								"failureKind":  string(module.FailureKind),
								"summary":      module.Summary,
							})
						}
						return items
					}(),
				},
				"results": func() []result {
					items := make([]result, 0, len(findings))
					for _, finding := range findings {
						entry := result{
							RuleID: string(finding.RuleID),
							Level:  string(finding.Severity),
							Properties: map[string]any{
								"category":     finding.Category,
								"module":       finding.Module,
								"triageStatus": defaultStatus(finding.Status),
								"tags":         finding.Tags,
								"owner":        finding.Owner,
								"note":         finding.Note,
								"fingerprint":  finding.Fingerprint,
								"change":       defaultChange(changeByFingerprint[finding.Fingerprint]),
								"cvss31":       finding.CVSS31,
								"cvss40":       finding.CVSS40,
								"epssScore":    finding.EPSSScore,
								"epssPercent":  finding.EPSSPercent,
								"kev":          finding.KEV,
								"cwes":         finding.CWEs,
								"compliance":   finding.Compliance,
								"priority":     finding.Priority,
								"attackChain":  finding.AttackChain,
								"related":      finding.Related,
							},
						}
						entry.Message.Text = finding.Title
						if finding.Location != "" {
							entry.Locations = append(entry.Locations, struct {
								PhysicalLocation struct {
									ArtifactLocation struct {
										URI string `json:"uri"`
									} `json:"artifactLocation"`
								} `json:"physicalLocation"`
							}{})
							entry.Locations[0].PhysicalLocation.ArtifactLocation.URI = finding.Location
						}
						items = append(items, entry)
					}
					return items
				}(),
			},
		},
	}

	bytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func exportCSV(findings []domain.Finding, changeByFingerprint map[string]domain.FindingChange) (string, error) {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	if err := writer.Write([]string{"severity", "change", "triage_status", "category", "module", "rule_id", "title", "location", "cvss31", "cvss40", "epss_score", "epss_percent", "kev", "cwes", "compliance", "priority", "owner", "tags", "note", "remediation"}); err != nil {
		return "", err
	}
	for _, finding := range findings {
		if err := writer.Write([]string{
			string(finding.Severity),
			string(defaultChange(changeByFingerprint[finding.Fingerprint])),
			string(defaultStatus(finding.Status)),
			string(finding.Category),
			finding.Module,
			finding.RuleID,
			finding.Title,
			finding.Location,
			formatScore(finding.CVSS31),
			formatScore(finding.CVSS40),
			formatScore(finding.EPSSScore),
			formatScore(finding.EPSSPercent),
			fmt.Sprintf("%t", finding.KEV),
			strings.Join(finding.CWEs, "|"),
			strings.Join(finding.Compliance, "|"),
			formatScore(finding.Priority),
			finding.Owner,
			strings.Join(finding.Tags, "|"),
			finding.Note,
			finding.Remediation,
		}); err != nil {
			return "", err
		}
	}
	writer.Flush()
	return builder.String(), writer.Error()
}

func exportHTML(run domain.ScanRun, baseline *domain.ScanRun, findings []domain.Finding, delta domain.RunDelta, changeByFingerprint map[string]domain.FindingChange, trends []domain.RunTrendPoint) string {
	priorityFindings := append([]domain.Finding(nil), findings...)
	sort.Slice(priorityFindings, func(i, j int) bool {
		if priorityFindings[i].Priority == priorityFindings[j].Priority {
			return domain.SeverityRank(priorityFindings[i].Severity) < domain.SeverityRank(priorityFindings[j].Severity)
		}
		return priorityFindings[i].Priority > priorityFindings[j].Priority
	})

	rows := make([]string, 0, len(findings))
	for _, finding := range findings {
		tagOwner := strings.Join(finding.Tags, ", ")
		if strings.TrimSpace(finding.Owner) != "" {
			if tagOwner != "" {
				tagOwner += " / "
			}
			tagOwner += finding.Owner
		}
		rows = append(rows, fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%.2f</td><td>%t</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s / %s</td><td>%s</td></tr>`,
			finding.Severity,
			htmlEscape(string(defaultChange(changeByFingerprint[finding.Fingerprint]))),
			htmlEscape(string(defaultStatus(finding.Status))),
			finding.CVSS31,
			finding.EPSSScore,
			finding.KEV,
			finding.Category,
			finding.Module,
			htmlEscape(finding.RuleID),
			htmlEscape(finding.Title),
			htmlEscape(finding.Location),
			htmlEscape(strings.Join(finding.CWEs, ", ")),
			htmlEscape(strings.Join(finding.Compliance, ", ")),
			htmlEscape(tagOwner),
		))
	}

	resolvedRows := make([]string, 0, len(delta.ResolvedFindings))
	for _, finding := range delta.ResolvedFindings {
		resolvedRows = append(resolvedRows, fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
			finding.Severity,
			htmlEscape(finding.Title),
			htmlEscape(finding.Location),
		))
	}

	moduleRows := make([]string, 0, len(run.ModuleResults))
	for _, module := range run.ModuleResults {
		moduleRows = append(moduleRows, fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%d</td><td>%dms</td><td>%s</td><td>%t</td><td>%d</td><td>%s</td></tr>`,
			htmlEscape(module.Name),
			htmlEscape(string(module.Status)),
			displayModuleAttempts(module),
			module.DurationMs,
			htmlEscape(defaultModuleFailure(module.FailureKind)),
			module.TimedOut,
			module.FindingCount,
			htmlEscape(module.Summary),
		))
	}
	moduleStats := moduleExecutionStats(run.ModuleResults)
	moduleSection := renderModuleSection(moduleRows)
	executiveSummary := renderExecutiveSummary(priorityFindings)
	severityOverview := renderSeverityOverview(run)
	trendChart := renderTrendChart(run, trends)
	heatmap := renderHeatmap(findings)
	complianceSection := renderComplianceSection(findings)
	drilldown := renderFindingDrilldown(priorityFindings, changeByFingerprint)
	resolvedSection := renderResolvedSection(resolvedRows)

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>%s</title>
  <style>
    :root { color-scheme: dark; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; background:#081017; color:#eaf5ef; padding:32px; }
    table { width:100%%; border-collapse:collapse; margin-top:20px; }
    td, th { border:1px solid rgba(255,255,255,0.12); padding:12px; text-align:left; vertical-align:top; }
    th { background:#10202b; }
    .meta { color:#97aaa8; }
    .grid { display:grid; grid-template-columns: 1.2fr 1fr; gap:24px; margin-top:24px; }
    .card { border:1px solid rgba(255,255,255,0.12); border-radius:18px; padding:20px; background:rgba(16,32,43,0.72); }
    .cards { display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:16px; margin-top:24px; }
    .big { font-size:2rem; font-weight:700; }
    .pie { width:220px; height:220px; border-radius:50%%; margin:0 auto 18px auto; }
    .legend { display:grid; gap:8px; }
    .legend-row { display:flex; justify-content:space-between; align-items:center; }
    .swatch { width:12px; height:12px; display:inline-block; border-radius:999px; margin-right:8px; }
    .timeline { display:flex; gap:10px; align-items:flex-end; height:180px; margin-top:16px; }
    .timeline-bar { flex:1; background:linear-gradient(180deg, rgba(94,234,212,0.95), rgba(15,118,110,0.55)); border-radius:12px 12px 6px 6px; position:relative; min-width:40px; }
    .timeline-bar span { position:absolute; bottom:-22px; left:50%%; transform:translateX(-50%%); font-size:11px; color:#97aaa8; white-space:nowrap; }
    .timeline-bar strong { position:absolute; top:8px; left:50%%; transform:translateX(-50%%); font-size:12px; color:#041015; }
    .heatmap { display:grid; gap:6px; margin-top:16px; }
    .heat-row { display:grid; grid-template-columns: 120px repeat(4, 1fr); gap:6px; align-items:center; }
    .heat-cell { padding:12px; border-radius:10px; text-align:center; }
    .finding-card { border:1px solid rgba(255,255,255,0.12); border-radius:14px; padding:14px; margin-top:14px; background:rgba(255,255,255,0.02); }
    details summary { cursor:pointer; font-weight:600; }
    .badge { display:inline-block; padding:4px 10px; border-radius:999px; margin-right:6px; font-size:12px; }
    .sev-critical { background:#4c0b1b; color:#ff8aa1; }
    .sev-high { background:#4a2508; color:#ffb067; }
    .sev-medium { background:#554108; color:#ffd166; }
    .sev-low { background:#06363f; color:#72f1da; }
    .sev-info { background:#10202b; color:#c8dde2; }
  </style>
</head>
<body>
  <h1>IronSentinel AppSec Report</h1>
  <p class="meta">Run: %s</p>
  <p class="meta">Baseline: %s</p>
  <p class="meta">Status: %s | Findings: %d</p>
  <p class="meta">Open: %d | Investigating: %d | Accepted Risk: %d | False Positive: %d | Fixed: %d</p>
  <p class="meta">New: %d | Existing: %d | Resolved: %d</p>
  <p class="meta">Failed modules: %d | Skipped modules: %d | Retried modules: %d</p>
  <div class="grid">
    <section class="card">
      <h2>Executive summary</h2>
      %s
    </section>
    <section class="card">
      <h2>Severity overview</h2>
      %s
    </section>
    <section class="card">
      <h2>Run trend</h2>
      %s
    </section>
    <section class="card">
      <h2>Heatmap</h2>
      %s
    </section>
  </div>
  <section class="card" style="margin-top:24px;">
    <h2>Compliance mapping</h2>
    %s
  </section>
  %s
  <table>
    <thead>
      <tr><th>Severity</th><th>Change</th><th>Triage</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Category</th><th>Module</th><th>Rule</th><th>Title</th><th>Location</th><th>CWE / Compliance</th><th>Tags / Owner</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>
  <section class="card" style="margin-top:24px;">
    <h2>Technical drill-down</h2>
    %s
  </section>
  %s
</body>
</html>`,
		htmlEscape(run.ID),
		htmlEscape(run.ID),
		htmlEscape(baselineID(baseline)),
		htmlEscape(string(run.Status)),
		len(findings),
		run.Summary.CountsByStatus[domain.FindingOpen],
		run.Summary.CountsByStatus[domain.FindingInvestigating],
		run.Summary.CountsByStatus[domain.FindingAcceptedRisk],
		run.Summary.CountsByStatus[domain.FindingFalsePositive],
		run.Summary.CountsByStatus[domain.FindingFixed],
		delta.CountsByChange[domain.FindingNew],
		delta.CountsByChange[domain.FindingExisting],
		delta.CountsByChange[domain.FindingResolved],
		moduleStats["failed"],
		moduleStats["skipped"],
		moduleStats["retried"],
		executiveSummary,
		severityOverview,
		trendChart,
		heatmap,
		complianceSection,
		moduleSection,
		strings.Join(rows, ""),
		drilldown,
		resolvedSection,
	)
}

func defaultStatus(status domain.FindingStatus) domain.FindingStatus {
	if status == "" {
		return domain.FindingOpen
	}
	return status
}

func defaultChange(change domain.FindingChange) domain.FindingChange {
	if change == "" {
		return domain.FindingNew
	}
	return change
}

func baselineID(baseline *domain.ScanRun) string {
	if baseline == nil {
		return "none"
	}
	return baseline.ID
}

func buildChangeIndex(delta domain.RunDelta) map[string]domain.FindingChange {
	index := make(map[string]domain.FindingChange, len(delta.NewFindings)+len(delta.ExistingFindings)+len(delta.ResolvedFindings))
	for _, finding := range delta.NewFindings {
		index[finding.Fingerprint] = domain.FindingNew
	}
	for _, finding := range delta.ExistingFindings {
		index[finding.Fingerprint] = domain.FindingExisting
	}
	for _, finding := range delta.ResolvedFindings {
		index[finding.Fingerprint] = domain.FindingResolved
	}
	return index
}

func renderResolvedSection(rows []string) string {
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf(`<h2>Resolved findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Title</th><th>Location</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>`, strings.Join(rows, ""))
}

func renderExecutiveSummary(findings []domain.Finding) string {
	if len(findings) == 0 {
		return `<p>No findings were recorded in this run.</p>`
	}
	top := findings[:min(3, len(findings))]
	items := make([]string, 0, len(top))
	for _, finding := range top {
		items = append(items, fmt.Sprintf(`<li><strong>%s</strong> (%s, priority %.1f)</li>`, htmlEscape(finding.Title), htmlEscape(string(finding.Severity)), finding.Priority))
	}
	return fmt.Sprintf(`<p class="big">%d findings</p><ul>%s</ul>`, len(findings), strings.Join(items, ""))
}

func renderSeverityOverview(run domain.ScanRun) string {
	critical := run.Summary.CountsBySeverity[domain.SeverityCritical]
	high := run.Summary.CountsBySeverity[domain.SeverityHigh]
	medium := run.Summary.CountsBySeverity[domain.SeverityMedium]
	low := run.Summary.CountsBySeverity[domain.SeverityLow]
	info := run.Summary.CountsBySeverity[domain.SeverityInfo]
	total := max(1, critical+high+medium+low+info)
	pie := fmt.Sprintf(`conic-gradient(
      #ff4d6d 0 %0.2f%%,
      #ff8c42 %0.2f%% %0.2f%%,
      #ffd166 %0.2f%% %0.2f%%,
      #5eead4 %0.2f%% %0.2f%%,
      #7dd3fc %0.2f%% 100%%)`,
		float64(critical)/float64(total)*100,
		float64(critical)/float64(total)*100,
		float64(critical+high)/float64(total)*100,
		float64(critical+high)/float64(total)*100,
		float64(critical+high+medium)/float64(total)*100,
		float64(critical+high+medium)/float64(total)*100,
		float64(critical+high+medium+low)/float64(total)*100,
		float64(critical+high+medium+low)/float64(total)*100,
	)
	legendRows := []string{
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#ff4d6d;"></span>Critical</span><strong>%d</strong></div>`, critical),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#ff8c42;"></span>High</span><strong>%d</strong></div>`, high),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#ffd166;"></span>Medium</span><strong>%d</strong></div>`, medium),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#5eead4;"></span>Low</span><strong>%d</strong></div>`, low),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#7dd3fc;"></span>Info</span><strong>%d</strong></div>`, info),
	}
	return fmt.Sprintf(`<div class="pie" style="background:%s;"></div><div class="legend">%s</div>`, pie, strings.Join(legendRows, ""))
}

func renderTrendChart(run domain.ScanRun, trends []domain.RunTrendPoint) string {
	if len(trends) == 0 {
		trends = []domain.RunTrendPoint{{
			RunID:         run.ID,
			StartedAt:     run.StartedAt,
			TotalFindings: run.Summary.TotalFindings,
			Critical:      run.Summary.CountsBySeverity[domain.SeverityCritical],
			High:          run.Summary.CountsBySeverity[domain.SeverityHigh],
			Medium:        run.Summary.CountsBySeverity[domain.SeverityMedium],
			Low:           run.Summary.CountsBySeverity[domain.SeverityLow],
		}}
	}
	maxTotal := 1
	for _, point := range trends {
		if point.TotalFindings > maxTotal {
			maxTotal = point.TotalFindings
		}
	}
	bars := make([]string, 0, len(trends))
	for _, point := range trends {
		height := 24
		if maxTotal > 0 {
			height = int((float64(point.TotalFindings) / float64(maxTotal)) * 150)
		}
		if height < 18 {
			height = 18
		}
		label := point.StartedAt.Format("02 Jan")
		if len(label) > 6 {
			label = label[:6]
		}
		bars = append(bars, fmt.Sprintf(`<div class="timeline-bar" style="height:%dpx" title="%s: %d findings"><strong>%d</strong><span>%s</span></div>`, height, htmlEscape(point.RunID), point.TotalFindings, point.TotalFindings, htmlEscape(label)))
	}
	return `<div class="timeline">` + strings.Join(bars, "") + `</div>`
}

func renderHeatmap(findings []domain.Finding) string {
	if len(findings) == 0 {
		return `<p>No findings were recorded in this run.</p>`
	}
	categories := []domain.FindingCategory{domain.CategorySAST, domain.CategorySCA, domain.CategoryIaC, domain.CategoryContainer, domain.CategoryDAST, domain.CategorySecret, domain.CategoryMalware, domain.CategoryCompliance}
	severities := []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow}
	counts := make(map[string]int)
	maxCount := 1
	for _, finding := range findings {
		key := string(finding.Category) + "|" + string(finding.Severity)
		counts[key]++
		if counts[key] > maxCount {
			maxCount = counts[key]
		}
	}
	rows := []string{`<div class="heat-row"><strong>Category</strong><strong>Critical</strong><strong>High</strong><strong>Medium</strong><strong>Low</strong></div>`}
	for _, category := range categories {
		cells := []string{fmt.Sprintf(`<div><strong>%s</strong></div>`, htmlEscape(string(category)))}
		for _, severity := range severities {
			value := counts[string(category)+"|"+string(severity)]
			opacity := 0.08
			if value > 0 {
				opacity = 0.18 + (float64(value)/float64(maxCount))*0.62
			}
			color := "#5eead4"
			switch severity {
			case domain.SeverityCritical:
				color = "#ff4d6d"
			case domain.SeverityHigh:
				color = "#ff8c42"
			case domain.SeverityMedium:
				color = "#ffd166"
			}
			cells = append(cells, fmt.Sprintf(`<div class="heat-cell" style="background:rgba(%s, %.2f);">%d</div>`, hexToRGB(color), opacity, value))
		}
		rows = append(rows, `<div class="heat-row">`+strings.Join(cells, "")+`</div>`)
	}
	return `<div class="heatmap">` + strings.Join(rows, "") + `</div>`
}

func renderComplianceSection(findings []domain.Finding) string {
	index := make(map[string]int)
	for _, finding := range findings {
		for _, mapping := range finding.Compliance {
			index[mapping]++
		}
	}
	if len(index) == 0 {
		return `<p>No compliance mappings were generated for this run.</p>`
	}
	keys := make([]string, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([]string, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, htmlEscape(key), index[key]))
	}
	return `<table><thead><tr><th>Control mapping</th><th>Finding count</th></tr></thead><tbody>` + strings.Join(rows, "") + `</tbody></table>`
}

func renderFindingDrilldown(findings []domain.Finding, changeByFingerprint map[string]domain.FindingChange) string {
	if len(findings) == 0 {
		return `<p>No findings were recorded in this run.</p>`
	}
	cards := make([]string, 0, len(findings))
	for _, finding := range findings {
		cards = append(cards, fmt.Sprintf(
			`<details class="finding-card"><summary><span class="badge sev-%s">%s</span>%s</summary><p><strong>Rule:</strong> %s</p><p><strong>Location:</strong> %s</p><p><strong>CVSS:</strong> %.1f / %.1f | <strong>EPSS:</strong> %.2f | <strong>Priority:</strong> %.1f | <strong>Change:</strong> %s</p><p><strong>CWE:</strong> %s</p><p><strong>Compliance:</strong> %s</p><p><strong>Remediation:</strong> %s</p>%s</details>`,
			htmlEscape(string(finding.Severity)),
			htmlEscape(strings.ToUpper(string(finding.Severity))),
			htmlEscape(finding.Title),
			htmlEscape(finding.RuleID),
			htmlEscape(finding.Location),
			finding.CVSS31,
			finding.CVSS40,
			finding.EPSSScore,
			finding.Priority,
			htmlEscape(string(defaultChange(changeByFingerprint[finding.Fingerprint]))),
			htmlEscape(strings.Join(finding.CWEs, ", ")),
			htmlEscape(strings.Join(finding.Compliance, ", ")),
			htmlEscape(finding.Remediation),
			renderAttackChainDetail(finding),
		))
	}
	return strings.Join(cards, "")
}

func renderAttackChainDetail(finding domain.Finding) string {
	if strings.TrimSpace(finding.AttackChain) == "" {
		return ""
	}
	return fmt.Sprintf(`<p><strong>Attack chain:</strong> %s</p><p><strong>Related findings:</strong> %s</p>`, htmlEscape(finding.AttackChain), htmlEscape(strings.Join(finding.Related, ", ")))
}

func renderModuleSection(rows []string) string {
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf(`<h2>Module execution</h2>
  <table>
    <thead>
      <tr><th>Module</th><th>Status</th><th>Attempts</th><th>Duration</th><th>Failure</th><th>Timed out</th><th>Findings</th><th>Summary</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>`, strings.Join(rows, ""))
}

func moduleExecutionStats(modules []domain.ModuleResult) map[string]int {
	stats := map[string]int{
		"failed":  0,
		"skipped": 0,
		"retried": 0,
	}
	for _, module := range modules {
		if module.Status == domain.ModuleFailed {
			stats["failed"]++
		}
		if module.Status == domain.ModuleSkipped {
			stats["skipped"]++
		}
		if module.Attempts > 1 {
			stats["retried"]++
		}
	}
	return stats
}

func displayModuleAttempts(module domain.ModuleResult) int {
	if module.Attempts > 0 {
		return module.Attempts
	}
	if module.Status == domain.ModuleSkipped {
		return 0
	}
	return 1
}

func defaultModuleFailure(kind domain.ModuleFailureKind) string {
	if kind == "" {
		return "-"
	}
	return string(kind)
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return replacer.Replace(value)
}

func formatScore(value float64) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%.2f", value)
}

func hexToRGB(hex string) string {
	value := strings.TrimPrefix(strings.TrimSpace(hex), "#")
	if len(value) != 6 {
		return "94,234,212"
	}
	return fmt.Sprintf("%d, %d, %d", hexToByte(value[0:2]), hexToByte(value[2:4]), hexToByte(value[4:6]))
}

func hexToByte(value string) int {
	parsed, err := strconv.ParseInt(value, 16, 64)
	if err != nil {
		return 0
	}
	return int(parsed)
}
