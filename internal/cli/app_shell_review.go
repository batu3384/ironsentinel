package cli

import (
	"fmt"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (m appShellModel) scanReviewContext(project domain.Project) (domain.ScanProfile, domain.RuntimeDoctor, bool, []string) {
	ctx := m.reviewContextValue(project)
	return ctx.profile, ctx.doctor, ctx.ready, append([]string(nil), ctx.blockers...)
}

func (m appShellModel) reviewContextValue(project domain.Project) reviewContextCacheEntry {
	if m.reviewContext.projectID == project.ID &&
		m.reviewContext.review == m.review &&
		m.reviewContext.snapshotStamp.Equal(m.snapshotUpdatedAt) {
		return m.reviewContext
	}
	return m.buildReviewContext(project)
}

func (m appShellModel) buildReviewContext(project domain.Project) reviewContextCacheEntry {
	profile := m.resolvedReviewProfile(project)
	doctor := m.app.runtimeDoctor(profile, m.review.StrictVersions, m.review.RequireIntegrity)
	blockers := make([]string, 0, 3)
	if m.review.ActiveValidation && strings.TrimSpace(m.review.DASTTarget) == "" {
		blockers = append(blockers, m.app.catalog.T("app_scan_review_requires_target"))
	}
	if !doctor.Ready {
		blockers = append(blockers, doctorSummaryLine(m.app, doctor))
	}
	includedModules := make(map[string]struct{}, len(profile.Modules))
	for _, module := range profile.Modules {
		includedModules[module] = struct{}{}
	}
	laneDescriptors := m.app.scanLaneDescriptorsForProject(project, profile.Modules, m.snapshot.Portfolio.Runs)
	current, next, deferred := m.reviewLaneFlow(laneDescriptors)
	return reviewContextCacheEntry{
		projectID:       project.ID,
		snapshotStamp:   m.snapshotUpdatedAt,
		review:          m.review,
		profile:         profile,
		doctor:          doctor,
		ready:           len(blockers) == 0,
		blockers:        append([]string(nil), blockers...),
		includedModules: includedModules,
		laneDescriptors: append([]scanLaneDescriptor(nil), laneDescriptors...),
		flowCurrent:     current,
		flowNext:        next,
		flowDeferred:    deferred,
	}
}

func (m *appShellModel) refreshReviewContext() {
	project, ok := m.selectedProject()
	if !ok {
		m.reviewContext = reviewContextCacheEntry{}
		return
	}
	m.reviewContext = m.reviewContextValue(project)
}

func (m appShellModel) resolvedReviewProfile(project domain.Project) domain.ScanProfile {
	profile := domain.ScanProfile{
		Mode:         domain.ModeDeep,
		Isolation:    m.review.Isolation,
		Coverage:     domain.CoverageFull,
		SeverityGate: domain.SeverityHigh,
		AllowBuild:   false,
		AllowNetwork: false,
	}
	switch m.review.Preset {
	case reviewPresetQuickSafe:
		profile.Mode = domain.ModeSafe
		profile.Coverage = domain.CoveragePremium
	case reviewPresetCompliance:
		profile.PresetID = m.review.CompliancePreset
		profile = m.app.applyCompliancePreset(project, profile, false, false, false, false, true, true, false)
	default:
	}
	if m.review.ActiveValidation {
		profile.Mode = domain.ModeActive
		profile.AllowNetwork = true
		profile.DASTAuthProfiles = append([]domain.DastAuthProfile(nil), m.reviewAuthProfiles...)
		if len(m.reviewDASTTargets) > 0 {
			profile.DASTTargets = append([]domain.DastTarget(nil), m.reviewDASTTargets...)
			if strings.TrimSpace(m.review.DASTTarget) != "" {
				profile.DASTTargets[0].URL = strings.TrimSpace(m.review.DASTTarget)
			}
		} else if strings.TrimSpace(m.review.DASTTarget) != "" {
			profile.DASTTargets = []domain.DastTarget{{
				Name:     "primary",
				URL:      strings.TrimSpace(m.review.DASTTarget),
				AuthType: domain.DastAuthNone,
			}}
		}
	}
	profile.Modules = m.app.resolveModulesForProject(project, profile)
	return profile
}

func (m appShellModel) scanReviewRows(project domain.Project, profile domain.ScanProfile, ready bool) selectableRows {
	rows := selectableRows{
		{Label: m.app.catalog.T("app_scan_review_project"), Hint: fmt.Sprintf("%s • %s", project.DisplayName, m.app.catalog.T("app_projects_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_preset"), Hint: fmt.Sprintf("%s • %s", m.reviewPresetLabel(), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_compliance"), Hint: fmt.Sprintf("%s • %s", m.reviewComplianceLabel(), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_isolation"), Hint: fmt.Sprintf("%s • %s", strings.ToUpper(string(m.review.Isolation)), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_active_validation"), Hint: fmt.Sprintf("%s • %s", m.boolLabel(m.review.ActiveValidation), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_target"), Hint: fmt.Sprintf("%s • %s", coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty")), m.app.catalog.T("app_scan_review_keys_hint"))},
		{Label: m.app.catalog.T("app_action_start_scan"), Hint: m.scanStartHint(profile, ready)},
	}
	return rows
}

func (m appShellModel) reviewFocusLines(width int, project domain.Project, profile domain.ScanProfile, doctor domain.RuntimeDoctor, ready bool, blockers []string) []string {
	switch m.cursor {
	case 0:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 56)},
		), m.app.catalog.T("app_projects_enter_hint"))
	case 1:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.app.modeLabel(profile.Mode)},
			factPair{Label: m.app.catalog.T("app_label_coverage"), Value: m.app.coverageLabel(profile.Coverage)},
		)
	case 2:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewComplianceLabel()},
		), ternary(m.review.Preset == reviewPresetCompliance, m.app.catalog.T("app_scan_review_enter_hint"), m.app.catalog.T("app_scan_review_not_applicable")))
	case 3:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.review.Isolation))},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: strings.ToUpper(string(profile.Isolation))},
		), m.app.catalog.T("app_scan_review_enter_hint"))
	case 4:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.boolLabel(m.review.ActiveValidation)},
		), ternary(m.review.ActiveValidation, m.app.catalog.T("app_scan_review_requires_target"), m.app.catalog.T("app_scan_review_enter_hint")))
	case 5:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
		), m.app.catalog.T("app_scan_review_keys_hint"))
	default:
		lines := append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
		), m.scanStartHint(profile, ready), doctorSummaryLine(m.app, doctor))
		if len(blockers) > 0 {
			lines = append(lines, blockers...)
		}
		return lines
	}
}

func (m appShellModel) reviewLaneSectionsForWidth(project domain.Project, profile domain.ScanProfile, limit int) []string {
	ctx := m.reviewContextValue(project)
	modules := ctx.includedModules
	if len(modules) == 0 {
		modules = make(map[string]struct{}, len(profile.Modules))
		for _, module := range profile.Modules {
			modules[module] = struct{}{}
		}
	}
	lines := make([]string, 0, len(ctx.laneDescriptors))
	for _, lane := range ctx.laneDescriptors {
		parts := make([]string, 0, len(lane.Modules))
		for _, module := range lane.Modules {
			parts = append(parts, fmt.Sprintf("- %s • %s", module, m.reviewModuleState(project, profile, module, modules)))
		}
		lines = append(lines, lane.Title)
		if limit > 0 && len(parts) > limit {
			parts = append(parts[:limit], fmt.Sprintf("- … %d %s", len(parts)-limit, strings.ToLower(m.app.catalog.T("scan_modules"))))
		}
		lines = append(lines, parts...)
	}
	return lines
}

func (m appShellModel) reviewModuleState(project domain.Project, profile domain.ScanProfile, module string, included map[string]struct{}) string {
	if module == "nuclei" || module == "zaproxy" {
		if !m.review.ActiveValidation || strings.TrimSpace(m.review.DASTTarget) == "" {
			return m.app.catalog.T("app_scan_review_requires_target_short")
		}
	}
	if _, ok := included[module]; ok {
		return m.app.catalog.T("app_scan_review_ready")
	}
	if !moduleApplicableForProject(project, module) {
		return m.app.catalog.T("app_scan_review_not_applicable")
	}
	if profile.Mode != domain.ModeActive && (module == "nuclei" || module == "zaproxy") {
		return m.app.catalog.T("app_scan_review_requires_target_short")
	}
	return m.app.catalog.T("app_scan_review_waiting")
}

func moduleApplicableForProject(project domain.Project, module string) bool {
	switch module {
	case "govulncheck", "staticcheck":
		return hasAnyStack(project.DetectedStacks, "go")
	case "knip":
		return hasAnyStack(project.DetectedStacks, "javascript", "typescript")
	case "vulture":
		return hasAnyStack(project.DetectedStacks, "python")
	case "tfsec", "kics":
		return hasAnyStack(project.DetectedStacks, "terraform", "iac", "helm", "kubernetes")
	case "trivy-image", "checkov":
		return hasAnyStack(project.DetectedStacks, "docker", "container", "kubernetes", "terraform", "iac", "helm")
	default:
		return true
	}
}

func (m appShellModel) reviewPresetLabel() string {
	switch m.review.Preset {
	case reviewPresetQuickSafe:
		return m.app.catalog.T("app_preset_quick_safe")
	case reviewPresetCompliance:
		return m.app.catalog.T("app_preset_compliance")
	default:
		return m.app.catalog.T("app_preset_full_deep")
	}
}

func (m appShellModel) reviewComplianceLabel() string {
	if m.review.Preset != reviewPresetCompliance {
		return "-"
	}
	return m.app.compliancePresetLabel(m.review.CompliancePreset)
}

func (m appShellModel) boolLabel(value bool) string {
	if value {
		return m.app.catalog.T("boolean_yes")
	}
	return m.app.catalog.T("boolean_no")
}

func (m appShellModel) scanStartHint(profile domain.ScanProfile, ready bool) string {
	if !ready {
		return m.app.catalog.T("app_scan_review_start_blocked")
	}
	return fmt.Sprintf("%s • %s • %d %s", m.reviewPresetLabel(), m.app.modeLabel(profile.Mode), len(profile.Modules), strings.ToLower(m.app.catalog.T("scan_modules")))
}
