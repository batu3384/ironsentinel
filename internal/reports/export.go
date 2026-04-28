package reports

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/findingtext"
	"github.com/batu3384/ironsentinel/internal/i18n"
	"github.com/batu3384/ironsentinel/internal/sbom"
)

func Export(format string, report domain.RunReport) (string, error) {
	return ExportLocalized(format, report, i18n.EN)
}

func ExportLocalized(format string, report domain.RunReport, language i18n.Language) (string, error) {
	switch strings.ToLower(format) {
	case "sarif":
		return exportSARIF(report)
	case "csv":
		return exportCSV(report)
	case "html":
		return exportHTML(report, language), nil
	case "openvex":
		return exportOpenVEX(report)
	case "sbom-attestation":
		return exportSBOMAttestation(report)
	default:
		return "", fmt.Errorf("unsupported export format: %s", format)
	}
}

func reportFindings(report domain.RunReport) []domain.Finding {
	findings := make([]domain.Finding, 0, len(report.Findings))
	for _, item := range report.Findings {
		findings = append(findings, item.Finding)
	}
	return findings
}

func reportChangeIndex(report domain.RunReport) map[string]domain.FindingChange {
	index := make(map[string]domain.FindingChange, len(report.Findings))
	for _, item := range report.Findings {
		index[item.Finding.Fingerprint] = DefaultChange(item.Change)
	}
	return index
}

func exportSARIF(report domain.RunReport) (string, error) {
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
					"id": report.Run.ID,
				},
				"properties": map[string]any{
					"baselineRunId":    baselineID(report.Baseline),
					"newFindings":      report.Delta.CountsByChange[domain.FindingNew],
					"existingFindings": report.Delta.CountsByChange[domain.FindingExisting],
					"resolvedFindings": report.Delta.CountsByChange[domain.FindingResolved],
					"moduleExecution":  report.ModuleStats,
					"trend":            report.Trends,
					"moduleResultSummaries": func() []map[string]any {
						items := make([]map[string]any, 0, len(report.ModuleSummaries))
						for _, module := range report.ModuleSummaries {
							items = append(items, map[string]any{
								"name":         module.Name,
								"status":       module.Status,
								"findingCount": module.FindingCount,
								"attempts":     displayModuleSummaryAttempts(module),
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
					items := make([]result, 0, len(report.Findings))
					for _, reportFinding := range report.Findings {
						finding := reportFinding.Finding
						entry := result{
							RuleID: string(finding.RuleID),
							Level:  string(finding.Severity),
							Properties: map[string]any{
								"category":         finding.Category,
								"module":           finding.Module,
								"reachability":     finding.Reachability.String(),
								"triageStatus":     DefaultStatus(finding.Status),
								"tags":             finding.Tags,
								"owner":            finding.Owner,
								"note":             finding.Note,
								"vexStatus":        finding.VEXStatus,
								"vexJustification": finding.VEXJustification,
								"fingerprint":      finding.Fingerprint,
								"change":           DefaultChange(reportFinding.Change),
								"cvss31":           finding.CVSS31,
								"cvss40":           finding.CVSS40,
								"epssScore":        finding.EPSSScore,
								"epssPercent":      finding.EPSSPercent,
								"kev":              finding.KEV,
								"cwes":             finding.CWEs,
								"compliance":       finding.Compliance,
								"priority":         finding.Priority,
								"attackChain":      finding.AttackChain,
								"related":          finding.Related,
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

func exportCSV(report domain.RunReport) (string, error) {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	if err := writer.Write([]string{"severity", "change", "triage_status", "category", "module", "reachability", "vex_status", "vex_justification", "rule_id", "title", "location", "cvss31", "cvss40", "epss_score", "epss_percent", "kev", "cwes", "compliance", "priority", "owner", "tags", "note", "remediation"}); err != nil {
		return "", err
	}
	for _, reportFinding := range report.Findings {
		finding := reportFinding.Finding
		if err := writer.Write([]string{
			string(finding.Severity),
			string(DefaultChange(reportFinding.Change)),
			string(DefaultStatus(finding.Status)),
			string(finding.Category),
			finding.Module,
			finding.Reachability.String(),
			string(finding.VEXStatus),
			finding.VEXJustification,
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

func exportOpenVEX(report domain.RunReport) (string, error) {
	type product struct {
		ID string `json:"@id"`
	}
	type statement struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products      []product        `json:"products"`
		Status        domain.VEXStatus `json:"status"`
		Justification string           `json:"justification,omitempty"`
	}
	type document struct {
		Context    string      `json:"@context"`
		ID         string      `json:"@id"`
		Author     string      `json:"author"`
		Role       string      `json:"role"`
		Timestamp  time.Time   `json:"timestamp"`
		Version    int         `json:"version"`
		Statements []statement `json:"statements"`
	}

	productsByName := sbom.ProductsByComponentName(report.Run.ArtifactRefs)
	doc := document{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://github.com/batu3384/ironsentinel/openvex/%s", report.Run.ID),
		Author:     "IronSentinel",
		Role:       "Tool",
		Timestamp:  time.Now().UTC(),
		Version:    1,
		Statements: make([]statement, 0),
	}
	seen := make(map[string]struct{})
	for _, item := range report.Findings {
		finding := item.Finding
		if finding.Category != domain.CategorySCA || strings.TrimSpace(finding.RuleID) == "" {
			continue
		}
		key := finding.RuleID + "|" + strings.ToLower(strings.TrimSpace(finding.Location))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		entry := statement{
			Status:        finding.VEXStatus,
			Justification: finding.VEXJustification,
		}
		if entry.Status == "" {
			entry.Status = domain.VEXStatusUnderInvestigation
		}
		entry.Vulnerability.Name = finding.RuleID

		for _, purl := range productsByName[strings.ToLower(strings.TrimSpace(finding.Location))] {
			entry.Products = append(entry.Products, product{ID: purl})
		}
		if len(entry.Products) == 0 && strings.TrimSpace(finding.Location) != "" {
			entry.Products = append(entry.Products, product{ID: "pkg:generic/" + strings.ToLower(strings.TrimSpace(finding.Location))})
		}
		doc.Statements = append(doc.Statements, entry)
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func exportSBOMAttestation(report domain.RunReport) (string, error) {
	attestation, err := sbom.BuildAttestation(report.Run)
	if err != nil {
		return "", err
	}
	attestation.Timestamp = time.Now().UTC()
	body, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
}

type htmlReportText struct {
	lang                  string
	title                 string
	run                   string
	baseline              string
	status                string
	findings              string
	severity              string
	open                  string
	investigating         string
	acceptedRisk          string
	falsePositive         string
	fixed                 string
	newFindings           string
	existingFindings      string
	resolved              string
	failedModules         string
	skippedModules        string
	retriedModules        string
	executiveSummary      string
	severityOverview      string
	runTrend              string
	heatmap               string
	operationalDecision   string
	remediationPlan       string
	complianceMapping     string
	technicalDrilldown    string
	scopeBlockers         string
	execution             string
	coverage              string
	policy                string
	runtime               string
	validation            string
	createCampaign        string
	createCampaignBody    string
	closeCoverageBlockers string
	closeCoverageBody     string
	keepWatching          string
	keepWatchingBody      string
	moduleExecution       string
	resolvedFindings      string
	none                  string
	noFindingsRecorded    string
	noComplianceMappings  string
	completeCoverage      string
	trustedRuntime        string
	partialCoverageFormat string
	degradedRuntime       string
	policyPassed          string
	policyFailedFormat    string
	policyNeedsReviewFmt  string
	priority              string
	rule                  string
	location              string
	change                string
	triage                string
	category              string
	module                string
	reachability          string
	cweCompliance         string
	tagsOwner             string
	attempts              string
	duration              string
	failure               string
	timedOut              string
	summary               string
	controlMapping        string
	findingCount          string
	critical              string
	high                  string
	medium                string
	low                   string
	info                  string
	remediation           string
	attackChain           string
	relatedFindings       string
	reportTitle           string
}

func htmlText(language i18n.Language) htmlReportText {
	if language == i18n.TR {
		return htmlReportText{
			lang:                  "tr",
			title:                 "IronSentinel Uygulama Güvenliği Raporu",
			run:                   "Koşu",
			baseline:              "Referans",
			status:                "Durum",
			findings:              "Bulgular",
			severity:              "Şiddet",
			open:                  "Açık",
			investigating:         "İncelemede",
			acceptedRisk:          "Kabul edilmiş risk",
			falsePositive:         "Yanlış pozitif",
			fixed:                 "Düzeltildi",
			newFindings:           "Yeni",
			existingFindings:      "Mevcut",
			resolved:              "Çözülen",
			failedModules:         "Başarısız modüller",
			skippedModules:        "Atlanan modüller",
			retriedModules:        "Tekrarlanan modüller",
			executiveSummary:      "Yönetici özeti",
			severityOverview:      "Şiddet özeti",
			runTrend:              "Koşu trendi",
			heatmap:               "Isı haritası",
			operationalDecision:   "Operasyonel karar",
			remediationPlan:       "Düzeltme planı",
			complianceMapping:     "Uyumluluk eşlemesi",
			technicalDrilldown:    "Teknik detay",
			scopeBlockers:         "Kapsam blokörleri",
			execution:             "Çalıştırma",
			coverage:              "Kapsam",
			policy:                "Politika",
			runtime:               "Çalışma zamanı",
			validation:            "Doğrulama",
			createCampaign:        "Düzeltme kampanyası oluştur",
			createCampaignBody:    "Öne çıkan bulguları izlenebilir bir kampanyada gruplayın.",
			closeCoverageBlockers: "Kapsam blokörlerini kapat",
			closeCoverageBody:     "Bunlar tek başına güvenlik bulgusu değildir; ancak run güvenini azaltır.",
			keepWatching:          "İzlemeye devam et",
			keepWatchingBody:      "Düzeltme gerektiren bulgu yok. Anlamlı kod veya bağımlılık değişikliklerinden sonra tekrar tarayın.",
			moduleExecution:       "Modül çalıştırma",
			resolvedFindings:      "Çözülen bulgular",
			none:                  "yok",
			noFindingsRecorded:    "Bu koşuda bulgu kaydedilmedi.",
			noComplianceMappings:  "Bu koşu için uyumluluk eşlemesi üretilmedi.",
			completeCoverage:      "Seçili profil için tamamlandı",
			trustedRuntime:        "Seçili profil için güvenilir",
			partialCoverageFormat: "Kısmi kapsam - başarısız modül: %d, atlanan modül: %d",
			degradedRuntime:       "Sınırlı - tam kapsama güvenmeden önce modül blokörlerini inceleyin",
			policyPassed:          "Başarılı",
			policyFailedFormat:    "Başarısız - %d kritik/yüksek bulgu aksiyon gerektiriyor",
			policyNeedsReviewFmt:  "İnceleme gerekli - %d bulgu kaydedildi",
			priority:              "Öncelik",
			rule:                  "Kural",
			location:              "Konum",
			change:                "Değişim",
			triage:                "Triage",
			category:              "Kategori",
			module:                "Modül",
			reachability:          "Erişilebilirlik",
			cweCompliance:         "CWE / Uyumluluk",
			tagsOwner:             "Etiketler / Sahip",
			attempts:              "Deneme",
			duration:              "Süre",
			failure:               "Hata",
			timedOut:              "Zaman aşımı",
			summary:               "Özet",
			controlMapping:        "Kontrol eşlemesi",
			findingCount:          "Bulgu sayısı",
			critical:              "Kritik",
			high:                  "Yüksek",
			medium:                "Orta",
			low:                   "Düşük",
			info:                  "Bilgi",
			remediation:           "Düzeltme",
			attackChain:           "Saldırı zinciri",
			relatedFindings:       "İlişkili bulgular",
			reportTitle:           "Başlık",
		}
	}
	return htmlReportText{
		lang:                  "en",
		title:                 "IronSentinel AppSec Report",
		run:                   "Run",
		baseline:              "Baseline",
		status:                "Status",
		findings:              "Findings",
		severity:              "Severity",
		open:                  "Open",
		investigating:         "Investigating",
		acceptedRisk:          "Accepted Risk",
		falsePositive:         "False Positive",
		fixed:                 "Fixed",
		newFindings:           "New",
		existingFindings:      "Existing",
		resolved:              "Resolved",
		failedModules:         "Failed modules",
		skippedModules:        "Skipped modules",
		retriedModules:        "Retried modules",
		executiveSummary:      "Executive summary",
		severityOverview:      "Severity overview",
		runTrend:              "Run trend",
		heatmap:               "Heatmap",
		operationalDecision:   "Operational decision",
		remediationPlan:       "Remediation plan",
		complianceMapping:     "Compliance mapping",
		technicalDrilldown:    "Technical drill-down",
		scopeBlockers:         "Scope blockers",
		execution:             "Execution",
		coverage:              "Coverage",
		policy:                "Policy",
		runtime:               "Runtime",
		validation:            "Validation",
		createCampaign:        "Create remediation campaign",
		createCampaignBody:    "Group the top findings into a trackable campaign.",
		closeCoverageBlockers: "Close coverage blockers",
		closeCoverageBody:     "These are not security findings by themselves, but they reduce trust in the run.",
		keepWatching:          "Keep watching",
		keepWatchingBody:      "No findings require remediation. Re-run after meaningful code or dependency changes.",
		moduleExecution:       "Module execution",
		resolvedFindings:      "Resolved findings",
		none:                  "none",
		noFindingsRecorded:    "No findings were recorded in this run.",
		noComplianceMappings:  "No compliance mappings were generated for this run.",
		completeCoverage:      "Complete for selected profile",
		trustedRuntime:        "Trusted for selected profile",
		partialCoverageFormat: "Partial coverage - failed modules: %d, skipped modules: %d",
		degradedRuntime:       "Degraded - review module blockers before trusting full coverage",
		policyPassed:          "Passed",
		policyFailedFormat:    "Failed - %d critical/high findings require action",
		policyNeedsReviewFmt:  "Needs review - %d findings recorded",
		priority:              "Priority",
		rule:                  "Rule",
		location:              "Location",
		change:                "Change",
		triage:                "Triage",
		category:              "Category",
		module:                "Module",
		reachability:          "Reachability",
		cweCompliance:         "CWE / Compliance",
		tagsOwner:             "Tags / Owner",
		attempts:              "Attempts",
		duration:              "Duration",
		failure:               "Failure",
		timedOut:              "Timed out",
		summary:               "Summary",
		controlMapping:        "Control mapping",
		findingCount:          "Finding count",
		critical:              "Critical",
		high:                  "High",
		medium:                "Medium",
		low:                   "Low",
		info:                  "Info",
		remediation:           "Remediation",
		attackChain:           "Attack chain",
		relatedFindings:       "Related findings",
		reportTitle:           "Title",
	}
}

func exportHTML(report domain.RunReport, language i18n.Language) string {
	labels := htmlText(language)
	catalog := i18n.New(language)
	findings := reportFindings(report)
	changeByFingerprint := reportChangeIndex(report)
	priorityFindings := append([]domain.Finding(nil), findings...)
	sort.Slice(priorityFindings, func(i, j int) bool {
		if priorityFindings[i].Priority == priorityFindings[j].Priority {
			return domain.SeverityRank(priorityFindings[i].Severity) < domain.SeverityRank(priorityFindings[j].Severity)
		}
		return priorityFindings[i].Priority > priorityFindings[j].Priority
	})

	rows := make([]string, 0, len(priorityFindings))
	for _, finding := range priorityFindings {
		tagOwner := strings.Join(finding.Tags, ", ")
		if strings.TrimSpace(finding.Owner) != "" {
			if tagOwner != "" {
				tagOwner += " / "
			}
			tagOwner += finding.Owner
		}
		rows = append(rows, fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%.2f</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(reportSeverityLabel(labels, finding.Severity)),
			htmlEscape(reportChangeLabel(labels, DefaultChange(changeByFingerprint[finding.Fingerprint]))),
			htmlEscape(reportStatusLabel(labels, DefaultStatus(finding.Status))),
			finding.CVSS31,
			finding.EPSSScore,
			htmlEscape(reportBoolLabel(labels, finding.KEV)),
			htmlEscape(reportCategoryLabel(labels, finding.Category)),
			finding.Module,
			htmlEscape(reportReachabilityLabel(catalog, finding.Reachability)),
			htmlEscape(finding.RuleID),
			htmlEscape(findingtext.Title(catalog, finding)),
			htmlEscape(finding.Location),
			htmlEscape(reportJoinedLists(labels, finding.CWEs, finding.Compliance)),
			htmlEscape(tagOwner),
		))
	}

	resolvedRows := make([]string, 0, len(report.Delta.ResolvedFindings))
	for _, finding := range report.Delta.ResolvedFindings {
		resolvedRows = append(resolvedRows, fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(reportSeverityLabel(labels, finding.Severity)),
			htmlEscape(findingtext.Title(catalog, finding)),
			htmlEscape(finding.Location),
		))
	}

	moduleRows := make([]string, 0, len(report.ModuleSummaries))
	for _, module := range report.ModuleSummaries {
		moduleRows = append(moduleRows, fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%d</td><td>%dms</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`,
			htmlEscape(module.Name),
			htmlEscape(reportModuleStatusLabel(labels, module.Status)),
			displayModuleSummaryAttempts(module),
			module.DurationMs,
			htmlEscape(reportModuleFailure(labels, module.FailureKind)),
			htmlEscape(reportBoolLabel(labels, module.TimedOut)),
			module.FindingCount,
			htmlEscape(reportModuleSummary(catalog, module)),
		))
	}
	moduleStats := report.ModuleStats
	moduleSection := renderModuleSection(moduleRows, labels)
	executiveSummary := renderExecutiveSummary(priorityFindings, labels, catalog)
	operationalDecision := renderOperationalDecisionSection(report, findings, labels)
	remediationPlan := renderRemediationPlanSection(report, priorityFindings, labels, catalog)
	severityOverview := renderSeverityOverview(report.Run, labels)
	trendChart := renderTrendChart(report.Run, report.Trends)
	heatmap := renderHeatmap(findings, labels)
	complianceSection := renderComplianceSection(findings, labels)
	drilldown := renderFindingDrilldown(priorityFindings, changeByFingerprint, labels, catalog)
	resolvedSection := renderResolvedSection(resolvedRows, labels)

	return fmt.Sprintf(`<!doctype html>
<html lang="%s">
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
    .decision-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap:12px; }
    .decision-card { border:1px solid rgba(255,255,255,0.12); border-radius:14px; padding:14px; background:rgba(255,255,255,0.025); }
    .decision-card strong { display:block; color:#5eead4; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
    .decision-card span { display:block; margin-top:8px; }
    .plan-list { display:grid; gap:12px; }
    .plan-item { border:1px solid rgba(255,255,255,0.12); border-radius:14px; padding:14px; background:rgba(255,255,255,0.025); }
    .plan-item b { color:#ffd166; }
    code { color:#5eead4; background:rgba(94,234,212,0.08); border:1px solid rgba(94,234,212,0.16); padding:2px 6px; border-radius:8px; }
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
  <h1>%s</h1>
  <p class="meta">%s: %s</p>
  <p class="meta">%s: %s</p>
  <p class="meta">%s: %s | %s: %d</p>
  <p class="meta">%s: %d | %s: %d | %s: %d | %s: %d | %s: %d</p>
  <p class="meta">%s: %d | %s: %d | %s: %d</p>
  <p class="meta">%s: %d | %s: %d | %s: %d</p>
  <div class="grid">
    <section class="card">
      <h2>%s</h2>
      %s
    </section>
    <section class="card">
      <h2>%s</h2>
      %s
    </section>
    <section class="card">
      <h2>%s</h2>
      %s
    </section>
    <section class="card">
      <h2>%s</h2>
      %s
    </section>
  </div>
  <section class="card" style="margin-top:24px;">
    <h2>%s</h2>
    %s
  </section>
  <section class="card" style="margin-top:24px;">
    <h2>%s</h2>
    %s
  </section>
  <section class="card" style="margin-top:24px;">
    <h2>%s</h2>
    %s
  </section>
  %s
  <table>
    <thead>
      <tr><th>%s</th><th>%s</th><th>%s</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>
  <section class="card" style="margin-top:24px;">
    <h2>%s</h2>
    %s
  </section>
  %s
</body>
</html>`,
		htmlEscape(labels.lang),
		htmlEscape(labels.title),
		htmlEscape(labels.title),
		htmlEscape(labels.run),
		htmlEscape(report.Run.ID),
		htmlEscape(labels.baseline),
		htmlEscape(reportBaselineID(report.Baseline, labels)),
		htmlEscape(labels.status),
		htmlEscape(reportRunStatusLabel(labels, report.Run.Status)),
		htmlEscape(labels.findings),
		len(findings),
		htmlEscape(labels.open),
		report.Run.Summary.CountsByStatus[domain.FindingOpen],
		htmlEscape(labels.investigating),
		report.Run.Summary.CountsByStatus[domain.FindingInvestigating],
		htmlEscape(labels.acceptedRisk),
		report.Run.Summary.CountsByStatus[domain.FindingAcceptedRisk],
		htmlEscape(labels.falsePositive),
		report.Run.Summary.CountsByStatus[domain.FindingFalsePositive],
		htmlEscape(labels.fixed),
		report.Run.Summary.CountsByStatus[domain.FindingFixed],
		htmlEscape(labels.newFindings),
		report.Delta.CountsByChange[domain.FindingNew],
		htmlEscape(labels.existingFindings),
		report.Delta.CountsByChange[domain.FindingExisting],
		htmlEscape(labels.resolved),
		report.Delta.CountsByChange[domain.FindingResolved],
		htmlEscape(labels.failedModules),
		moduleStats["failed"],
		htmlEscape(labels.skippedModules),
		moduleStats["skipped"],
		htmlEscape(labels.retriedModules),
		moduleStats["retried"],
		htmlEscape(labels.executiveSummary),
		executiveSummary,
		htmlEscape(labels.severityOverview),
		severityOverview,
		htmlEscape(labels.runTrend),
		trendChart,
		htmlEscape(labels.heatmap),
		heatmap,
		htmlEscape(labels.operationalDecision),
		operationalDecision,
		htmlEscape(labels.remediationPlan),
		remediationPlan,
		htmlEscape(labels.complianceMapping),
		complianceSection,
		moduleSection,
		htmlEscape(labels.severity),
		htmlEscape(labels.change),
		htmlEscape(labels.triage),
		htmlEscape(labels.category),
		htmlEscape(labels.module),
		htmlEscape(labels.reachability),
		htmlEscape(labels.rule),
		htmlEscape(labels.reportTitle),
		htmlEscape(labels.location),
		htmlEscape(labels.cweCompliance),
		htmlEscape(labels.tagsOwner),
		strings.Join(rows, ""),
		htmlEscape(labels.technicalDrilldown),
		drilldown,
		resolvedSection,
	)
}

func DefaultStatus(status domain.FindingStatus) domain.FindingStatus {
	if status == "" {
		return domain.FindingOpen
	}
	return status
}

func DefaultChange(change domain.FindingChange) domain.FindingChange {
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

func reportBaselineID(baseline *domain.ScanRun, labels htmlReportText) string {
	if baseline == nil {
		return labels.none
	}
	return baseline.ID
}

func BuildChangeIndex(delta domain.RunDelta) map[string]domain.FindingChange {
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

func renderResolvedSection(rows []string, labels htmlReportText) string {
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf(`<h2>%s</h2>
  <table>
    <thead>
      <tr><th>%s</th><th>%s</th><th>%s</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>`, htmlEscape(labels.resolvedFindings), htmlEscape(labels.severity), htmlEscape(labels.reportTitle), htmlEscape(labels.location), strings.Join(rows, ""))
}

func renderOperationalDecisionSection(report domain.RunReport, findings []domain.Finding, labels htmlReportText) string {
	stats := ModuleExecutionStats(report.Run.ModuleResults)
	critical := report.Run.Summary.CountsBySeverity[domain.SeverityCritical]
	high := report.Run.Summary.CountsBySeverity[domain.SeverityHigh]
	coverage := labels.completeCoverage
	runtime := labels.trustedRuntime
	if stats["failed"] > 0 || stats["skipped"] > 0 {
		coverage = fmt.Sprintf(labels.partialCoverageFormat, stats["failed"], stats["skipped"])
		runtime = labels.degradedRuntime
	}
	policy := labels.policyPassed
	switch {
	case critical > 0 || high > 0:
		policy = fmt.Sprintf(labels.policyFailedFormat, critical+high)
	case len(findings) > 0:
		policy = fmt.Sprintf(labels.policyNeedsReviewFmt, len(findings))
	}
	cards := []string{
		renderDecisionCard(labels.execution, reportRunStatusLabel(labels, report.Run.Status)),
		renderDecisionCard(labels.coverage, coverage),
		renderDecisionCard(labels.policy, policy),
		renderDecisionCard(labels.runtime, runtime),
	}
	blockers := renderScopeBlockerList(report.Run.ModuleResults)
	if blockers != "" {
		cards = append(cards, `<div class="decision-card"><strong>`+htmlEscape(labels.scopeBlockers)+`</strong>`+blockers+`</div>`)
	}
	return `<div class="decision-grid">` + strings.Join(cards, "") + `</div>`
}

func renderDecisionCard(title, value string) string {
	return fmt.Sprintf(`<div class="decision-card"><strong>%s</strong><span>%s</span></div>`, htmlEscape(title), htmlEscape(value))
}

func renderScopeBlockerList(modules []domain.ModuleResult) string {
	items := make([]string, 0, 3)
	for _, module := range modules {
		if module.Status != domain.ModuleFailed && module.Status != domain.ModuleSkipped {
			continue
		}
		summary := strings.TrimSpace(module.Summary)
		if summary == "" {
			summary = string(module.FailureKind)
		}
		items = append(items, fmt.Sprintf(`<li><strong>%s</strong>: %s</li>`, htmlEscape(module.Name), htmlEscape(summary)))
		if len(items) >= 3 {
			break
		}
	}
	if len(items) == 0 {
		return ""
	}
	return `<ul>` + strings.Join(items, "") + `</ul>`
}

func renderRemediationPlanSection(report domain.RunReport, findings []domain.Finding, labels htmlReportText, catalog i18n.Catalog) string {
	items := make([]string, 0, 4)
	for index, finding := range findings[:min(2, len(findings))] {
		priority := "P1"
		if index == 0 && (finding.Severity == domain.SeverityCritical || finding.Severity == domain.SeverityHigh || finding.Category == domain.CategorySecret) {
			priority = "P0"
		}
		remediation := strings.TrimSpace(findingtext.Remediation(catalog, finding))
		if remediation == "" {
			remediation = labels.keepWatchingBody
		}
		items = append(items, fmt.Sprintf(
			`<div class="plan-item"><b>%s</b> %s<p>%s</p><p><strong>%s:</strong> <code>%s</code></p></div>`,
			htmlEscape(priority),
			htmlEscape(findingtext.Title(catalog, finding)),
			htmlEscape(remediation),
			htmlEscape(labels.validation),
			htmlEscape(reportValidationCommand(report.Run, finding)),
		))
	}
	if len(findings) > 0 {
		items = append(items, fmt.Sprintf(
			`<div class="plan-item"><b>P1</b> %s<p>%s</p><p><strong>%s:</strong> <code>%s</code></p></div>`,
			htmlEscape(labels.createCampaign),
			htmlEscape(labels.createCampaignBody),
			htmlEscape(labels.validation),
			htmlEscape(reportCampaignCreateCommand(report.Run, findings, labels)),
		))
	}
	if blockers := renderScopeBlockerList(report.Run.ModuleResults); blockers != "" {
		items = append(items, `<div class="plan-item"><b>P2</b> `+htmlEscape(labels.closeCoverageBlockers)+`<p>`+htmlEscape(labels.closeCoverageBody)+`</p>`+blockers+`<p><strong>`+htmlEscape(labels.validation)+`:</strong> <code>ironsentinel scan . --strict</code></p></div>`)
	}
	if len(items) == 0 {
		items = append(items, `<div class="plan-item"><b>P2</b> `+htmlEscape(labels.keepWatching)+`<p>`+htmlEscape(labels.keepWatchingBody)+`</p><p><strong>`+htmlEscape(labels.validation)+`:</strong> <code>ironsentinel scan . --strict</code></p></div>`)
	}
	return `<div class="plan-list">` + strings.Join(items, "") + `</div>`
}

func reportValidationCommand(run domain.ScanRun, finding domain.Finding) string {
	module := strings.TrimSpace(finding.Module)
	if module != "" {
		return fmt.Sprintf("ironsentinel scan . --module %s --strict", module)
	}
	if strings.TrimSpace(run.ID) != "" {
		return fmt.Sprintf("ironsentinel scan . --strict # after run %s", run.ID)
	}
	return "ironsentinel scan . --strict"
}

func reportCampaignCreateCommand(run domain.ScanRun, findings []domain.Finding, labels htmlReportText) string {
	projectID := strings.TrimSpace(run.ProjectID)
	if projectID == "" {
		projectID = "<project-id>"
	}
	runID := strings.TrimSpace(run.ID)
	if runID == "" {
		runID = "<run-id>"
	}
	fingerprint := "<finding-fingerprint>"
	for _, finding := range findings {
		if candidate := strings.TrimSpace(finding.Fingerprint); candidate != "" {
			fingerprint = candidate
			break
		}
	}
	title := "High-priority remediation"
	if labels.lang == "tr" {
		title = "Yüksek öncelikli düzeltme"
	}
	return fmt.Sprintf(
		`ironsentinel campaigns create --project %s --run %s --title "%s" --finding %s`,
		projectID,
		runID,
		title,
		fingerprint,
	)
}

func renderExecutiveSummary(findings []domain.Finding, labels htmlReportText, catalog i18n.Catalog) string {
	if len(findings) == 0 {
		return `<p>` + htmlEscape(labels.noFindingsRecorded) + `</p>`
	}
	top := findings[:min(3, len(findings))]
	items := make([]string, 0, len(top))
	for _, finding := range top {
		items = append(items, fmt.Sprintf(
			`<li><strong>%s</strong> (%s, %s %.1f)</li>`,
			htmlEscape(findingtext.Title(catalog, finding)),
			htmlEscape(reportSeverityLabel(labels, finding.Severity)),
			htmlEscape(labels.priority),
			finding.Priority,
		))
	}
	return fmt.Sprintf(`<p class="big">%s</p><ul>%s</ul>`, htmlEscape(reportFindingCountLabel(labels, len(findings))), strings.Join(items, ""))
}

func renderSeverityOverview(run domain.ScanRun, labels htmlReportText) string {
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
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#ff4d6d;"></span>%s</span><strong>%d</strong></div>`, htmlEscape(labels.critical), critical),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#ff8c42;"></span>%s</span><strong>%d</strong></div>`, htmlEscape(labels.high), high),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#ffd166;"></span>%s</span><strong>%d</strong></div>`, htmlEscape(labels.medium), medium),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#5eead4;"></span>%s</span><strong>%d</strong></div>`, htmlEscape(labels.low), low),
		fmt.Sprintf(`<div class="legend-row"><span><span class="swatch" style="background:#7dd3fc;"></span>%s</span><strong>%d</strong></div>`, htmlEscape(labels.info), info),
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

func renderHeatmap(findings []domain.Finding, labels htmlReportText) string {
	if len(findings) == 0 {
		return `<p>` + htmlEscape(labels.noFindingsRecorded) + `</p>`
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
	rows := []string{fmt.Sprintf(`<div class="heat-row"><strong>%s</strong><strong>%s</strong><strong>%s</strong><strong>%s</strong><strong>%s</strong></div>`, htmlEscape(labels.category), htmlEscape(labels.critical), htmlEscape(labels.high), htmlEscape(labels.medium), htmlEscape(labels.low))}
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

func renderComplianceSection(findings []domain.Finding, labels htmlReportText) string {
	index := make(map[string]int)
	for _, finding := range findings {
		for _, mapping := range finding.Compliance {
			index[mapping]++
		}
	}
	if len(index) == 0 {
		return `<p>` + htmlEscape(labels.noComplianceMappings) + `</p>`
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
	return `<table><thead><tr><th>` + htmlEscape(labels.controlMapping) + `</th><th>` + htmlEscape(labels.findingCount) + `</th></tr></thead><tbody>` + strings.Join(rows, "") + `</tbody></table>`
}

func renderFindingDrilldown(findings []domain.Finding, changeByFingerprint map[string]domain.FindingChange, labels htmlReportText, catalog i18n.Catalog) string {
	if len(findings) == 0 {
		return `<p>` + htmlEscape(labels.noFindingsRecorded) + `</p>`
	}
	cards := make([]string, 0, len(findings))
	for _, finding := range findings {
		cards = append(cards, fmt.Sprintf(
			`<details class="finding-card"><summary><span class="badge sev-%s">%s</span>%s</summary><p><strong>%s:</strong> %s</p><p><strong>%s:</strong> %s</p><p><strong>CVSS:</strong> %.1f / %.1f | <strong>EPSS:</strong> %.2f | <strong>%s:</strong> %.1f | <strong>%s:</strong> %s</p><p><strong>CWE:</strong> %s</p><p><strong>%s:</strong> %s</p><p><strong>%s:</strong> %s</p>%s</details>`,
			htmlEscape(string(finding.Severity)),
			htmlEscape(reportSeverityBadgeLabel(labels, finding.Severity)),
			htmlEscape(findingtext.Title(catalog, finding)),
			htmlEscape(labels.rule),
			htmlEscape(finding.RuleID),
			htmlEscape(labels.location),
			htmlEscape(finding.Location),
			finding.CVSS31,
			finding.CVSS40,
			finding.EPSSScore,
			htmlEscape(labels.priority),
			finding.Priority,
			htmlEscape(labels.change),
			htmlEscape(reportChangeLabel(labels, DefaultChange(changeByFingerprint[finding.Fingerprint]))),
			htmlEscape(reportJoinedStrings(labels, finding.CWEs)),
			htmlEscape(labels.cweCompliance),
			htmlEscape(reportJoinedStrings(labels, finding.Compliance)),
			htmlEscape(labels.remediation),
			htmlEscape(findingtext.Remediation(catalog, finding)),
			renderAttackChainDetail(finding, labels),
		))
	}
	return strings.Join(cards, "")
}

func renderAttackChainDetail(finding domain.Finding, labels htmlReportText) string {
	if strings.TrimSpace(finding.AttackChain) == "" {
		return ""
	}
	return fmt.Sprintf(`<p><strong>%s:</strong> %s</p><p><strong>%s:</strong> %s</p>`, htmlEscape(labels.attackChain), htmlEscape(finding.AttackChain), htmlEscape(labels.relatedFindings), htmlEscape(strings.Join(finding.Related, ", ")))
}

func renderModuleSection(rows []string, labels htmlReportText) string {
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf(`<h2>%s</h2>
  <table>
    <thead>
      <tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>`, htmlEscape(labels.moduleExecution), htmlEscape(labels.module), htmlEscape(labels.status), htmlEscape(labels.attempts), htmlEscape(labels.duration), htmlEscape(labels.failure), htmlEscape(labels.timedOut), htmlEscape(labels.findings), htmlEscape(labels.summary), strings.Join(rows, ""))
}

func reportSeverityLabel(labels htmlReportText, severity domain.Severity) string {
	switch severity {
	case domain.SeverityCritical:
		return labels.critical
	case domain.SeverityHigh:
		return labels.high
	case domain.SeverityMedium:
		return labels.medium
	case domain.SeverityLow:
		return labels.low
	case domain.SeverityInfo:
		return labels.info
	default:
		return string(severity)
	}
}

func reportSeverityBadgeLabel(labels htmlReportText, severity domain.Severity) string {
	if labels.lang != "tr" {
		return strings.ToUpper(string(severity))
	}
	switch severity {
	case domain.SeverityCritical:
		return "KRİTİK"
	case domain.SeverityHigh:
		return "YÜKSEK"
	case domain.SeverityMedium:
		return "ORTA"
	case domain.SeverityLow:
		return "DÜŞÜK"
	case domain.SeverityInfo:
		return "BİLGİ"
	default:
		return strings.ToUpper(string(severity))
	}
}

func reportCategoryLabel(labels htmlReportText, category domain.FindingCategory) string {
	if labels.lang != "tr" {
		switch category {
		case domain.CategorySecret:
			return "Secret"
		case domain.CategoryMalware:
			return "Malware"
		case domain.CategoryMaintainability:
			return "Maintainability"
		case domain.CategoryPlatform:
			return "Platform"
		case domain.CategorySCA:
			return "SCA"
		case domain.CategoryIaC:
			return "IaC"
		case domain.CategoryContainer:
			return "Container"
		case domain.CategoryDAST:
			return "DAST"
		case domain.CategoryCompliance:
			return "Compliance"
		default:
			return "SAST"
		}
	}
	switch category {
	case domain.CategorySecret:
		return "Gizli bilgi"
	case domain.CategoryMalware:
		return "Zararlı yazılım"
	case domain.CategoryMaintainability:
		return "Bakım"
	case domain.CategoryPlatform:
		return "Platform"
	case domain.CategorySCA:
		return "Bağımlılık"
	case domain.CategoryIaC:
		return "Altyapı"
	case domain.CategoryContainer:
		return "Konteyner"
	case domain.CategoryDAST:
		return "Dinamik"
	case domain.CategoryCompliance:
		return "Uyumluluk"
	default:
		return "Statik analiz"
	}
}

func reportReachabilityLabel(catalog i18n.Catalog, value domain.Reachability) string {
	switch domain.NormalizeReachability(value.String()) {
	case domain.ReachabilityReachable:
		return catalog.T("finding_reachability_reachable")
	case domain.ReachabilityPossible:
		return catalog.T("finding_reachability_possible")
	case domain.ReachabilityUnknown:
		return catalog.T("finding_reachability_unknown")
	case domain.ReachabilityRepository:
		return catalog.T("finding_reachability_repository")
	case domain.ReachabilityImage:
		return catalog.T("finding_reachability_image")
	case domain.ReachabilityInfrastructure:
		return catalog.T("finding_reachability_infrastructure")
	case domain.ReachabilityExecutionSurface:
		return catalog.T("finding_reachability_execution_surface")
	case domain.ReachabilityNotApplicable:
		return catalog.T("finding_reachability_not_applicable")
	default:
		return value.String()
	}
}

func reportChangeLabel(labels htmlReportText, change domain.FindingChange) string {
	switch change {
	case domain.FindingNew:
		return labels.newFindings
	case domain.FindingExisting:
		return labels.existingFindings
	case domain.FindingResolved:
		return labels.resolved
	default:
		return string(change)
	}
}

func reportStatusLabel(labels htmlReportText, status domain.FindingStatus) string {
	switch status {
	case domain.FindingOpen:
		return labels.open
	case domain.FindingInvestigating:
		return labels.investigating
	case domain.FindingAcceptedRisk:
		return labels.acceptedRisk
	case domain.FindingFalsePositive:
		return labels.falsePositive
	case domain.FindingFixed:
		return labels.fixed
	default:
		return string(status)
	}
}

func reportModuleStatusLabel(labels htmlReportText, status domain.ModuleStatus) string {
	if labels.lang != "tr" {
		return strings.ToUpper(string(status))
	}
	switch status {
	case domain.ModuleQueued:
		return "KUYRUKTA"
	case domain.ModuleRunning:
		return "ÇALIŞIYOR"
	case domain.ModuleCompleted:
		return "TAMAMLANDI"
	case domain.ModuleFailed:
		return "BAŞARISIZ"
	case domain.ModuleSkipped:
		return "ATLANDI"
	default:
		return strings.ToUpper(string(status))
	}
}

func reportModuleFailure(labels htmlReportText, kind domain.ModuleFailureKind) string {
	if kind == "" {
		return labels.none
	}
	return string(kind)
}

func reportModuleSummary(catalog i18n.Catalog, module domain.RunReportModuleSummary) string {
	switch module.Name {
	case "stack-detector":
		return catalog.T("report_module_summary_stack_detector")
	case "surface-inventory":
		return catalog.T("report_module_summary_surface_inventory")
	case "script-audit":
		return catalog.T("report_module_summary_script_audit")
	case "dependency-confusion":
		return catalog.T("report_module_summary_dependency_confusion")
	case "runtime-config-audit":
		return catalog.T("report_module_summary_runtime_config_audit")
	case "binary-entropy":
		return catalog.T("report_module_summary_binary_entropy")
	case "secret-heuristics":
		return catalog.T("report_module_summary_secret_heuristics")
	case "malware-signature":
		return catalog.T("report_module_summary_malware_signature")
	case "semgrep":
		return catalog.T("report_module_summary_semgrep", module.FindingCount)
	case "gitleaks":
		return catalog.T("report_module_summary_gitleaks", module.FindingCount)
	case "trivy":
		return catalog.T("report_module_summary_trivy", module.FindingCount)
	case "trivy-image":
		return catalog.T("report_module_summary_trivy_image", module.FindingCount)
	case "syft":
		return catalog.T("report_module_summary_syft")
	case "grype":
		return catalog.T("report_module_summary_grype", module.FindingCount)
	case "osv-scanner":
		return catalog.T("report_module_summary_osv_scanner", module.FindingCount)
	case "checkov":
		return catalog.T("report_module_summary_checkov", module.FindingCount)
	case "tfsec":
		return catalog.T("report_module_summary_tfsec", module.FindingCount)
	case "kics":
		return catalog.T("report_module_summary_kics", module.FindingCount)
	case "licensee":
		return catalog.T("report_module_summary_licensee", module.FindingCount)
	case "scancode":
		return catalog.T("report_module_summary_scancode", module.FindingCount)
	case "govulncheck":
		return catalog.T("report_module_summary_govulncheck", module.FindingCount)
	case "staticcheck":
		return catalog.T("report_module_summary_staticcheck", module.FindingCount)
	case "knip":
		return catalog.T("report_module_summary_knip", module.FindingCount)
	case "vulture":
		return catalog.T("report_module_summary_vulture", module.FindingCount)
	case "clamscan":
		return catalog.T("report_module_summary_clamscan", module.FindingCount)
	case "yara-x":
		return catalog.T("report_module_summary_yara_x", module.FindingCount)
	case "codeql":
		return catalog.T("report_module_summary_codeql", module.FindingCount)
	case "nuclei":
		return catalog.T("report_module_summary_nuclei", module.FindingCount)
	case "zaproxy":
		return catalog.T("report_module_summary_zaproxy", module.FindingCount)
	default:
		return module.Summary
	}
}

func reportBoolLabel(labels htmlReportText, value bool) string {
	if labels.lang != "tr" {
		if value {
			return "true"
		}
		return "false"
	}
	if value {
		return "evet"
	}
	return "hayır"
}

func reportRunStatusLabel(labels htmlReportText, status domain.ScanStatus) string {
	if labels.lang != "tr" {
		return strings.ToUpper(string(status))
	}
	switch status {
	case domain.ScanQueued:
		return "KUYRUKTA"
	case domain.ScanRunning:
		return "ÇALIŞIYOR"
	case domain.ScanCompleted:
		return "TAMAMLANDI"
	case domain.ScanFailed:
		return "BAŞARISIZ"
	case domain.ScanCanceled:
		return "İPTAL EDİLDİ"
	default:
		return strings.ToUpper(string(status))
	}
}

func reportJoinedLists(labels htmlReportText, left, right []string) string {
	leftText := reportJoinedStrings(labels, left)
	rightText := reportJoinedStrings(labels, right)
	if leftText == labels.none && rightText == labels.none {
		return labels.none
	}
	if leftText == labels.none {
		return rightText
	}
	if rightText == labels.none {
		return leftText
	}
	return leftText + " / " + rightText
}

func reportJoinedStrings(labels htmlReportText, values []string) string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}
	if len(filtered) == 0 {
		return labels.none
	}
	return strings.Join(filtered, ", ")
}

func reportFindingCountLabel(labels htmlReportText, count int) string {
	if labels.lang == "tr" {
		return fmt.Sprintf("%d bulgu", count)
	}
	if count == 1 {
		return "1 finding"
	}
	return fmt.Sprintf("%d findings", count)
}

func ModuleExecutionStats(modules []domain.ModuleResult) map[string]int {
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

func BuildModuleSummaries(modules []domain.ModuleResult) []domain.RunReportModuleSummary {
	summaries := make([]domain.RunReportModuleSummary, 0, len(modules))
	for _, module := range modules {
		summaries = append(summaries, domain.RunReportModuleSummary{
			Name:         module.Name,
			Status:       module.Status,
			FindingCount: module.FindingCount,
			Attempts:     displayModuleAttempts(module),
			DurationMs:   module.DurationMs,
			TimedOut:     module.TimedOut,
			FailureKind:  module.FailureKind,
			Summary:      module.Summary,
		})
	}
	return summaries
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

func displayModuleSummaryAttempts(module domain.RunReportModuleSummary) int {
	if module.Attempts > 0 {
		return module.Attempts
	}
	if module.Status == domain.ModuleSkipped {
		return 0
	}
	return 1
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
