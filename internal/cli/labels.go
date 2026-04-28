package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pterm/pterm"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/findingtext"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func (a *App) phaseLabel() string {
	if a.lang == i18n.TR {
		return "Aşama"
	}
	return "Phase"
}

func (a *App) toolLabel() string {
	if a.lang == i18n.TR {
		return "Araç"
	}
	return "Tool"
}

func (a *App) consoleMissionSubtitle(done bool) string {
	if done {
		if a.lang == i18n.TR {
			return "Görev tamamlandı. Bu yüzey yalnızca görev durumu ve kanıt özetini gösteriyor."
		}
		return "Mission complete. This surface remains focused on mission status and evidence summary."
	}
	if a.lang == i18n.TR {
		return "Canlı tarama durumu, risk ve bulgular bu yüzeyde akıyor."
	}
	return "Live scan status, risk, and findings are flowing on this surface."
}

func (a *App) consoleMissionDoneNotice(status domain.ScanStatus, requiredErr error, findingCount int) string {
	switch {
	case status == domain.ScanFailed:
		if a.lang == i18n.TR {
			return "Görev başarısız sonlandı. Kanıt özeti bu yüzeyde korunuyor."
		}
		return "Mission failed. Evidence summary remains on this surface."
	case status == domain.ScanCanceled:
		if a.lang == i18n.TR {
			return "Görev iptal edildi. Toplanan kanıt özeti bu yüzeyde korunuyor."
		}
		return "Mission canceled. Collected evidence summary remains on this surface."
	case requiredErr != nil:
		if a.lang == i18n.TR {
			return "Görev tamamlandı. Zorunlu kapsama kontrolleri eksik olduğu için koşu kısmi kabul edilmeli."
		}
		return "Mission complete. Required coverage checks were incomplete, so treat this run as partial."
	case findingCount > 0:
		if a.lang == i18n.TR {
			return "Görev tamamlandı. Bulgular ve kanıt özeti bu yüzeyde korunuyor."
		}
		return "Mission complete. Findings and evidence summary remain on this surface."
	default:
		if a.lang == i18n.TR {
			return "Görev tamamlandı. Bu koşuda doğrulanmış bulgu üretilmedi."
		}
		return "Mission complete. No confirmed findings were raised in this run."
	}
}

func (a *App) consoleMissionFooter(done, aborting bool) string {
	switch {
	case !done && aborting:
		if a.lang == i18n.TR {
			return "iptal gönderildi, ajan temiz biçimde durduruluyor"
		}
		return "cancel requested, waiting for the agent to stop cleanly"
	case !done:
		if a.lang == i18n.TR {
			return "q iptal isteği gönder"
		}
		return "q request cancel"
	default:
		if a.lang == i18n.TR {
			return "q görevi kapat"
		}
		return "q close mission"
	}
}

func (a *App) languageLabel(language i18n.Language) string {
	switch language {
	case i18n.TR:
		if a.lang == i18n.TR {
			return "Türkçe (TR)"
		}
		return "Turkish (TR)"
	default:
		if a.lang == i18n.TR {
			return "İngilizce (EN)"
		}
		return "English (EN)"
	}
}

func (a *App) uiModeLabel(mode uiMode) string {
	switch mode {
	case uiModePlain:
		if a.lang == i18n.TR {
			return "Sade"
		}
		return "Plain"
	case uiModeCompact:
		if a.lang == i18n.TR {
			return "Kompakt"
		}
		return "Compact"
	default:
		if a.lang == i18n.TR {
			return "Standart"
		}
		return "Standard"
	}
}

func (a *App) coverageLabel(coverage domain.CoverageProfile) string {
	switch coverage {
	case domain.CoverageCore:
		return a.catalog.T("coverage_core")
	case domain.CoverageFull:
		return a.catalog.T("coverage_full")
	default:
		return a.catalog.T("coverage_premium")
	}
}

func (a *App) compliancePresetLabel(preset domain.CompliancePreset) string {
	switch preset {
	case domain.CompliancePresetPCIDSS:
		return a.catalog.T("preset_pci_dss")
	case domain.CompliancePresetSOC2:
		return a.catalog.T("preset_soc2")
	case domain.CompliancePresetOWASPTop10:
		return a.catalog.T("preset_owasp_top10")
	case domain.CompliancePresetSANSTop25:
		return a.catalog.T("preset_sans_top25")
	default:
		return a.catalog.T("preset_none")
	}
}

func (a *App) compliancePresetNote(preset domain.CompliancePreset) string {
	switch preset {
	case domain.CompliancePresetPCIDSS:
		return a.catalog.T("preset_note_pci_dss")
	case domain.CompliancePresetSOC2:
		return a.catalog.T("preset_note_soc2")
	case domain.CompliancePresetOWASPTop10:
		return a.catalog.T("preset_note_owasp_top10")
	case domain.CompliancePresetSANSTop25:
		return a.catalog.T("preset_note_sans_top25")
	default:
		return a.catalog.T("preset_note_none")
	}
}

func (a *App) runtimeSupportLevelLabel(level domain.RuntimeSupportLevel) string {
	switch level {
	case domain.RuntimeSupportPartial:
		if a.lang == i18n.TR {
			return "Kısmi"
		}
		return "Partial"
	case domain.RuntimeSupportUnsupported:
		if a.lang == i18n.TR {
			return "Desteklenmiyor"
		}
		return "Unsupported"
	default:
		if a.lang == i18n.TR {
			return "Destekleniyor"
		}
		return "Supported"
	}
}

func (a *App) modeLabel(mode domain.ScanMode) string {
	switch mode {
	case domain.ModeDeep:
		if a.lang == i18n.TR {
			return "Derin"
		}
		return "Deep"
	case domain.ModeActive:
		if a.lang == i18n.TR {
			return "Aktif"
		}
		return "Active"
	default:
		if a.lang == i18n.TR {
			return "Güvenli"
		}
		return "Safe"
	}
}

func (a *App) severityLabel(severity domain.Severity) string {
	switch severity {
	case domain.SeverityCritical:
		if a.lang == i18n.TR {
			return "Kritik"
		}
		return "Critical"
	case domain.SeverityHigh:
		if a.lang == i18n.TR {
			return "Yüksek"
		}
		return "High"
	case domain.SeverityMedium:
		if a.lang == i18n.TR {
			return "Orta"
		}
		return "Medium"
	case domain.SeverityLow:
		if a.lang == i18n.TR {
			return "Düşük"
		}
		return "Low"
	default:
		if a.lang == i18n.TR {
			return "Bilgi"
		}
		return "Info"
	}
}

func (a *App) categoryLabel(category domain.FindingCategory) string {
	switch category {
	case domain.CategorySecret:
		if a.lang == i18n.TR {
			return "Gizli bilgi"
		}
		return "Secret"
	case domain.CategoryMalware:
		if a.lang == i18n.TR {
			return "Zararlı yazılım"
		}
		return "Malware"
	case domain.CategoryMaintainability:
		if a.lang == i18n.TR {
			return "Bakım"
		}
		return "Maintainability"
	case domain.CategoryPlatform:
		if a.lang == i18n.TR {
			return "Platform"
		}
		return "Platform"
	case domain.CategorySCA:
		if a.lang == i18n.TR {
			return "Bağımlılık"
		}
		return "SCA"
	case domain.CategoryIaC:
		if a.lang == i18n.TR {
			return "Altyapı"
		}
		return "IaC"
	case domain.CategoryContainer:
		if a.lang == i18n.TR {
			return "Konteyner"
		}
		return "Container"
	case domain.CategoryDAST:
		if a.lang == i18n.TR {
			return "Dinamik"
		}
		return "DAST"
	case domain.CategoryCompliance:
		if a.lang == i18n.TR {
			return "Uyumluluk"
		}
		return "Compliance"
	default:
		if a.lang == i18n.TR {
			return "Statik analiz"
		}
		return "SAST"
	}
}

func (a *App) findingStatusLabel(status domain.FindingStatus) string {
	switch status {
	case domain.FindingInvestigating:
		if a.lang == i18n.TR {
			return "İnceleniyor"
		}
		return "Investigating"
	case domain.FindingAcceptedRisk:
		if a.lang == i18n.TR {
			return "Kabul edilmiş risk"
		}
		return "Accepted Risk"
	case domain.FindingFalsePositive:
		if a.lang == i18n.TR {
			return "Yanlış pozitif"
		}
		return "False Positive"
	case domain.FindingFixed:
		if a.lang == i18n.TR {
			return "Düzeltildi"
		}
		return "Fixed"
	default:
		if a.lang == i18n.TR {
			return "Açık"
		}
		return "Open"
	}
}

func (a *App) displayFindingTitle(finding domain.Finding) string {
	title := findingtext.Title(a.catalog, finding)
	if a.lang != i18n.TR || title == "" {
		return title
	}

	replacements := []struct {
		prefix string
		value  string
	}{
		{"Binary or opaque artifact committed to the repository", "Depoya ikili veya opak dosya eklenmiş"},
		{"Sensitive operational file committed to the repository", "Depoya hassas operasyon dosyası eklenmiş"},
		{"TLS verification disabled in fetch command", "İndirme komutunda TLS doğrulaması kapatılmış"},
		{"pip configuration uses extra-index-url, which can widen dependency confusion exposure", "pip ayarında extra-index-url kullanımı dependency confusion riskini artırıyor"},
	}
	for _, item := range replacements {
		if title == item.prefix {
			return item.value
		}
	}

	switch {
	case strings.HasPrefix(title, "Potential dependency confusion risk for npm package "):
		name := strings.Trim(strings.TrimPrefix(title, "Potential dependency confusion risk for npm package "), "\"")
		return fmt.Sprintf("npm paketi %q için dependency confusion riski", name)
	case strings.HasPrefix(title, "Potential dependency confusion risk for Python package "):
		name := strings.Trim(strings.TrimPrefix(title, "Potential dependency confusion risk for Python package "), "\"")
		return fmt.Sprintf("Python paketi %q için dependency confusion riski", name)
	case strings.HasPrefix(title, "High-entropy binary artifact detected"):
		return strings.Replace(title, "High-entropy binary artifact detected", "Yüksek entropili ikili dosya tespit edildi", 1)
	case strings.HasPrefix(title, "Possible packed or obfuscated binary artifact detected"):
		return strings.Replace(title, "Possible packed or obfuscated binary artifact detected", "Paketlenmiş veya gizlenmiş ikili dosya olasılığı tespit edildi", 1)
	case strings.HasPrefix(title, "YARA signature matched: "):
		return strings.Replace(title, "YARA signature matched: ", "YARA imzası eşleşti: ", 1)
	default:
		return title
	}
}

func (a *App) displayFindingRemediation(finding domain.Finding) string {
	return findingtext.Remediation(a.catalog, finding)
}

func (a *App) moduleNarrative(module string) string {
	switch strings.TrimSpace(module) {
	case "stack-detector":
		if a.lang == i18n.TR {
			return "depo yüzeyi ve teknoloji izi çıkarılıyor"
		}
		return "profiling repository surface and stack"
	case "surface-inventory":
		if a.lang == i18n.TR {
			return "depo maruziyeti, ikili dosyalar ve hassas dosya yüzeyi haritalanıyor"
		}
		return "mapping repository exposure, binaries, and sensitive file surface"
	case "script-audit":
		if a.lang == i18n.TR {
			return "betikler, çalışma akışları ve görev komutları riskli kalıplara karşı inceleniyor"
		}
		return "auditing scripts, workflows, and task runners for risky patterns"
	case "dependency-confusion":
		if a.lang == i18n.TR {
			return "özel paket isimleri ve registry pinleme bağımlılık karışıklığı için inceleniyor"
		}
		return "checking registry pinning and private package confusion exposure"
	case "runtime-config-audit":
		if a.lang == i18n.TR {
			return "çalışma zamanı konfigürasyonu ve izinler denetleniyor"
		}
		return "auditing runtime configuration and file permission exposure"
	case "binary-entropy":
		if a.lang == i18n.TR {
			return "ikili dosyalar paketlenmiş veya gizlenmiş içerik için analiz ediliyor"
		}
		return "inspecting binaries for packed or obfuscated content"
	case "secret-heuristics":
		if a.lang == i18n.TR {
			return "gizli bilgi sızıntısı izleri taranıyor"
		}
		return "sweeping for exposed secrets"
	case "malware-signature":
		if a.lang == i18n.TR {
			return "zararlı imzalar ve test yükleri inceleniyor"
		}
		return "inspecting malware signatures and test payloads"
	case "semgrep":
		if a.lang == i18n.TR {
			return "statik kod güvenlik kuralları çalıştırılıyor"
		}
		return "running static code security rules"
	case "gitleaks":
		if a.lang == i18n.TR {
			return "git geçmişi ve çalışma alanı gizli anahtarlar için taranıyor"
		}
		return "scanning git and workspace secrets"
	case "trivy":
		if a.lang == i18n.TR {
			return "bağımlılıklar ve dosya sistemi güvenlik için denetleniyor"
		}
		return "auditing dependencies and filesystem security"
	case "trivy-image":
		if a.lang == i18n.TR {
			return "tespit edilen container imajları güvenlik açıkları için taranıyor"
		}
		return "scanning discovered container images for vulnerabilities"
	case "syft":
		if a.lang == i18n.TR {
			return "SBOM envanteri üretiliyor"
		}
		return "building software inventory and SBOM"
	case "grype":
		if a.lang == i18n.TR {
			return "derlenmiş artefaktlar ve binary bileşenler zafiyetler için taranıyor"
		}
		return "inspecting compiled artifacts and binary components for vulnerabilities"
	case "osv-scanner":
		if a.lang == i18n.TR {
			return "güvenlik bültenleriyle eşleştirme yapılıyor"
		}
		return "correlating package advisories"
	case "checkov":
		if a.lang == i18n.TR {
			return "altyapı konfigürasyonu güvenlik için gözden geçiriliyor"
		}
		return "reviewing infrastructure misconfigurations"
	case "tfsec":
		if a.lang == i18n.TR {
			return "terraform güvenlik kontrolleri çalıştırılıyor"
		}
		return "running Terraform-focused security checks"
	case "kics":
		if a.lang == i18n.TR {
			return "IaC politikaları ve riskli altyapı desenleri analiz ediliyor"
		}
		return "analyzing IaC policy drift and risky infrastructure patterns"
	case "licensee":
		if a.lang == i18n.TR {
			return "depo lisansı ve dağıtım yükümlülükleri değerlendiriliyor"
		}
		return "evaluating repository license posture"
	case "scancode":
		if a.lang == i18n.TR {
			return "dosya bazlı lisans ve uyumluluk sinyalleri toplanıyor"
		}
		return "collecting file-level license compliance signals"
	case "govulncheck":
		if a.lang == i18n.TR {
			return "Go çağrı akışı ve güvenlik açıkları analiz ediliyor"
		}
		return "analyzing Go call paths and vulnerabilities"
	case "staticcheck":
		if a.lang == i18n.TR {
			return "Go kalite ve mantık kusurları denetleniyor"
		}
		return "checking Go correctness and quality issues"
	case "knip":
		if a.lang == i18n.TR {
			return "kullanılmayan JS/TS kodu ve bağımlılıklar bulunuyor"
		}
		return "finding unused JS/TS code and dependencies"
	case "vulture":
		if a.lang == i18n.TR {
			return "kullanılmayan Python kodu aranıyor"
		}
		return "finding unused Python code"
	case "clamscan":
		if a.lang == i18n.TR {
			return "ClamAV ile dosya imzaları taranıyor"
		}
		return "scanning file signatures with ClamAV"
	case "yara-x":
		if a.lang == i18n.TR {
			return "özel YARA kuralları ile malware ve tehdit imzaları eşleştiriliyor"
		}
		return "matching custom YARA rules against suspicious artifacts"
	case "codeql":
		if a.lang == i18n.TR {
			return "semantik kod akışı ve derin açık analizi yapılıyor"
		}
		return "running deep semantic code analysis"
	case "nuclei":
		if a.lang == i18n.TR {
			return "aktif HTTP imzaları ve güvenlik kontrolleri koşuluyor"
		}
		return "launching active HTTP signatures"
	case "zaproxy":
		if a.lang == i18n.TR {
			return "dinamik uygulama güvenlik testleri yürütülüyor"
		}
		return "executing dynamic application probes"
	default:
		return module
	}
}

func (a *App) phaseDisplayText(phase, module string) string {
	if strings.TrimSpace(module) != "" {
		return a.modulePhaseLabel(module)
	}
	switch strings.TrimSpace(phase) {
	case "", "-":
		return a.catalog.T("scan_phase_general")
	case "Attack surface and repository exposure mapping", "Saldırı yüzeyi ve depo maruziyeti haritası":
		return a.catalog.T("scan_phase_attack_surface")
	case "Secret exposure and credential leakage", "Gizli bilgi ve kimlik bilgisi sızıntısı":
		return a.catalog.T("scan_phase_secrets")
	case "Malware and suspicious payload inspection", "Zararlı yazılım ve şüpheli yük incelemesi":
		return a.catalog.T("scan_phase_malware")
	case "Code security and semantic analysis", "Kod güvenliği ve semantik analiz", "Code analysis":
		return a.catalog.T("scan_phase_code")
	case "Dependency, SBOM, and supply-chain review", "Bağımlılık, SBOM ve tedarik zinciri incelemesi":
		return a.catalog.T("scan_phase_supply_chain")
	case "Dynamic probing and web attack simulation", "Dinamik yoklama ve web saldırı simülasyonu":
		return a.catalog.T("scan_phase_dynamic")
	case "General repository analysis", "Genel depo analizi":
		return a.catalog.T("scan_phase_general")
	default:
		return strings.TrimSpace(phase)
	}
}

func (a *App) operatorText(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ""
	}
	switch trimmed {
	case "Mission completed. Evidence cards and handoff are ready.", "Görev tamamlandı. Kanıt kartları ve operatör devri hazır.":
		if a.lang == i18n.TR {
			return "Görev tamamlandı. Kanıt kartları ve operatör devri hazır."
		}
		return "Mission completed. Evidence cards and handoff are ready."
	case "Queued semantic analysis lane.", "Semantik analiz hattı kuyruğa alındı.":
		if a.lang == i18n.TR {
			return "Semantik analiz hattı kuyruğa alındı."
		}
		return "Queued semantic analysis lane."
	case "Correlated the source graph and dependency edges.", "Kaynak grafı ve bağımlılık kenarları ilişkilendirildi.":
		if a.lang == i18n.TR {
			return "Kaynak grafı ve bağımlılık kenarları ilişkilendirildi."
		}
		return "Correlated the source graph and dependency edges."
	case "Closed the mission with exportable evidence.", "Görev dışa aktarılabilir kanıtla kapatıldı.":
		if a.lang == i18n.TR {
			return "Görev dışa aktarılabilir kanıtla kapatıldı."
		}
		return "Closed the mission with exportable evidence."
	case "Enumerated the repository attack surface.", "Depo saldırı yüzeyi envanteri çıkarıldı.":
		if a.lang == i18n.TR {
			return "Depo saldırı yüzeyi envanteri çıkarıldı."
		}
		return "Enumerated the repository attack surface."
	case "Mapped repository exposure.", "Depo maruziyeti haritalandı.":
		if a.lang == i18n.TR {
			return "Depo maruziyeti haritalandı."
		}
		return "Mapped repository exposure."
	case "Correlated semantic rules across the source graph.", "Semantik kurallar kaynak grafı boyunca ilişkilendirildi.":
		if a.lang == i18n.TR {
			return "Semantik kurallar kaynak grafı boyunca ilişkilendirildi."
		}
		return "Correlated semantic rules across the source graph."
	case "Correlating semantic rules.", "Semantik kurallar ilişkilendiriliyor.":
		if a.lang == i18n.TR {
			return "Semantik kurallar ilişkilendiriliyor."
		}
		return "Correlating semantic rules."
	case "Queued for secret validation.", "Gizli doğrulaması için kuyruğa alındı.":
		if a.lang == i18n.TR {
			return "Gizli doğrulaması için kuyruğa alındı."
		}
		return "Queued for secret validation."
	case "Secret validation surfaced a blocking credential exposure.", "Gizli doğrulaması engelleyici bir kimlik bilgisi sızıntısı buldu.":
		if a.lang == i18n.TR {
			return "Gizli doğrulaması engelleyici bir kimlik bilgisi sızıntısı buldu."
		}
		return "Secret validation surfaced a blocking credential exposure."
	case "Execution failed.", "Yürütme başarısız oldu.":
		if a.lang == i18n.TR {
			return "Yürütme başarısız oldu."
		}
		return "Execution failed."
	case "Done", "Tamamlandı":
		if a.lang == i18n.TR {
			return "Tamamlandı"
		}
		return "Done"
	case "Running", "Çalışıyor":
		if a.lang == i18n.TR {
			return "Çalışıyor"
		}
		return "Running"
	case "Surface mapped.", "Yüzey haritalandı.":
		if a.lang == i18n.TR {
			return "Yüzey haritalandı."
		}
		return "Surface mapped."
	case "Auditing scripts.", "Betikler denetleniyor.":
		if a.lang == i18n.TR {
			return "Betikler denetleniyor."
		}
		return "Auditing scripts."
	case "Queued.", "Kuyrukta.":
		if a.lang == i18n.TR {
			return "Kuyrukta."
		}
		return "Queued."
	default:
		return trimmed
	}
}

func (a *App) moduleSummaryText(module domain.ModuleResult) string {
	return a.operatorText(coalesceString(module.Summary, a.moduleNarrative(module.Name)))
}

func (a *App) moduleToolLabel(module string) string {
	switch strings.TrimSpace(module) {
	case "", "-":
		return "-"
	case "stack-detector", "surface-inventory", "script-audit", "dependency-confusion", "runtime-config-audit", "binary-entropy", "secret-heuristics", "malware-signature":
		if a.lang == i18n.TR {
			return "yerleşik analiz"
		}
		return "built-in analyzer"
	case "trivy-image":
		return "trivy"
	case "yara-x":
		return "yara"
	default:
		return module
	}
}

func (a *App) executionToolLabel(trace *domain.ModuleExecutionTrace, attempt *domain.ModuleAttemptTrace) string {
	if attempt != nil {
		if len(attempt.Args) > 0 && strings.TrimSpace(attempt.Args[0]) != "" {
			return filepath.Base(strings.TrimSpace(attempt.Args[0]))
		}
		if command := strings.TrimSpace(attempt.Command); command != "" {
			return filepath.Base(strings.Fields(command)[0])
		}
	}
	if trace != nil {
		return a.moduleToolLabel(trace.Module)
	}
	return "-"
}

func (a *App) modulePhaseLabel(module string) string {
	switch strings.TrimSpace(module) {
	case "stack-detector", "surface-inventory", "script-audit", "runtime-config-audit":
		return a.catalog.T("scan_phase_attack_surface")
	case "secret-heuristics", "gitleaks":
		return a.catalog.T("scan_phase_secrets")
	case "malware-signature", "clamscan", "yara-x", "binary-entropy":
		return a.catalog.T("scan_phase_malware")
	case "semgrep", "codeql", "govulncheck", "staticcheck":
		return a.catalog.T("scan_phase_code")
	case "trivy", "trivy-image", "syft", "grype", "osv-scanner", "checkov", "tfsec", "kics", "knip", "vulture", "dependency-confusion", "licensee", "scancode":
		return a.catalog.T("scan_phase_supply_chain")
	case "nuclei", "zaproxy":
		return a.catalog.T("scan_phase_dynamic")
	default:
		return a.catalog.T("scan_phase_general")
	}
}

func (a *App) scanPhaseLines(modules []string) []string {
	seen := map[string]struct{}{}
	lines := make([]string, 0, len(modules))
	for _, module := range modules {
		phase := a.modulePhaseLabel(module)
		if _, ok := seen[phase]; ok {
			continue
		}
		seen[phase] = struct{}{}
		lines = append(lines, phase)
	}
	if len(lines) == 0 {
		lines = append(lines, a.catalog.T("scan_phase_general"))
	}
	return lines
}

type scanLaneDescriptor struct {
	Key     string
	Title   string
	Kind    string
	ETA     string
	Modules []string
}

func (a *App) scanLaneDescriptors(modules []string) []scanLaneDescriptor {
	plans := domain.LanePlans(modules)
	lanes := make([]scanLaneDescriptor, 0, len(plans))
	for _, plan := range plans {
		lanes = append(lanes, a.scanLaneDescriptorFromPlan(plan))
	}
	return lanes
}

func (a *App) scanLaneDescriptorsForProject(project domain.Project, modules []string, runs []domain.ScanRun) []scanLaneDescriptor {
	plans := domain.ProjectLanePlans(project, modules, runs)
	lanes := make([]scanLaneDescriptor, 0, len(plans))
	for _, plan := range plans {
		lanes = append(lanes, a.scanLaneDescriptorFromPlan(plan))
	}
	return lanes
}

func (a *App) moduleLaneKey(module string) string {
	return domain.ModulePlanSpecFor(strings.TrimSpace(module), "").Lane
}

func (a *App) scanLaneDescriptor(key string) scanLaneDescriptor {
	switch strings.TrimSpace(key) {
	case "surface":
		return scanLaneDescriptor{
			Key:   "surface",
			Title: a.catalog.T("app_lane_surface"),
			Kind:  a.catalog.T("app_lane_kind_fast"),
			ETA:   a.catalog.T("app_lane_eta_fast"),
		}
	case "code":
		return scanLaneDescriptor{
			Key:   "code",
			Title: a.catalog.T("app_lane_code"),
			Kind:  a.catalog.T("app_lane_kind_fast"),
			ETA:   a.catalog.T("app_lane_eta_fast"),
		}
	case "supply":
		return scanLaneDescriptor{
			Key:   "supply",
			Title: a.catalog.T("app_lane_supply"),
			Kind:  a.catalog.T("app_lane_kind_heavy"),
			ETA:   a.catalog.T("app_lane_eta_heavy"),
		}
	case "infra":
		return scanLaneDescriptor{
			Key:   "infra",
			Title: a.catalog.T("app_lane_infra"),
			Kind:  a.catalog.T("app_lane_kind_heavy"),
			ETA:   a.catalog.T("app_lane_eta_heavy"),
		}
	case "malware":
		return scanLaneDescriptor{
			Key:   "malware",
			Title: a.catalog.T("app_lane_malware"),
			Kind:  a.catalog.T("app_lane_kind_heavy"),
			ETA:   a.catalog.T("app_lane_eta_heavy"),
		}
	case "active":
		return scanLaneDescriptor{
			Key:   "active",
			Title: a.catalog.T("app_lane_active"),
			Kind:  a.catalog.T("app_lane_kind_active"),
			ETA:   a.catalog.T("app_lane_eta_target"),
		}
	default:
		return scanLaneDescriptor{
			Key:   "general",
			Title: a.catalog.T("scan_phase_general"),
			Kind:  a.catalog.T("app_lane_kind_heavy"),
			ETA:   a.catalog.T("app_lane_eta_heavy"),
		}
	}
}

func (a *App) formatLaneETA(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	duration := time.Duration(ms) * time.Millisecond
	if duration >= time.Second {
		duration = duration.Round(time.Second)
	} else if duration >= 100*time.Millisecond {
		duration = duration.Round(100 * time.Millisecond)
	}
	return "~" + duration.String()
}

func (a *App) scanLaneDescriptorFromPlan(plan domain.ScanLanePlan) scanLaneDescriptor {
	descriptor := a.scanLaneDescriptor(plan.Key)
	descriptor.Kind = a.scanLaneKindLabel(plan.Kind)
	descriptor.Modules = make([]string, 0, len(plan.Modules))
	for _, module := range plan.Modules {
		descriptor.Modules = append(descriptor.Modules, module.Name)
	}
	if plan.EstimatedMs > 0 {
		descriptor.ETA = a.formatLaneETA(plan.EstimatedMs)
	}
	return descriptor
}

func (a *App) scanLaneKindLabel(kind domain.ScanLaneKind) string {
	switch kind {
	case domain.ScanLaneKindFast:
		return a.catalog.T("app_lane_kind_fast")
	case domain.ScanLaneKindActive:
		return a.catalog.T("app_lane_kind_active")
	default:
		return a.catalog.T("app_lane_kind_heavy")
	}
}

func (a *App) formatLaneDescriptor(descriptor scanLaneDescriptor, width int) string {
	parts := []string{descriptor.Title}
	if strings.TrimSpace(descriptor.Kind) != "" {
		parts = append(parts, descriptor.Kind)
	}
	if strings.TrimSpace(descriptor.ETA) != "" {
		parts = append(parts, descriptor.ETA)
	}
	return trimForSelect(strings.Join(parts, " • "), max(18, width))
}

func (a *App) scanProgressBar(done, total int) string {
	total = max(1, total)
	done = min(done, total)
	width := 18
	filled := int(float64(done) / float64(total) * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("=", filled) + strings.Repeat(".", width-filled) + "]"
}

func (a *App) scanProgressRail(done, total, width int) string {
	total = max(1, total)
	done = min(done, total)
	if done < 0 {
		done = 0
	}
	if width < 10 {
		width = 10
	}
	filled := int(float64(done) / float64(total) * float64(width))
	if done > 0 && filled == 0 {
		filled = 1
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", max(0, width-filled))
}

func (a *App) missionProgressPercent(done, total int) int {
	total = max(1, total)
	done = min(done, total)
	if done < 0 {
		done = 0
	}
	return int(float64(done) / float64(total) * 100)
}

func (a *App) missionProgressSummary(done, total int) string {
	total = max(1, total)
	confidence := a.catalog.T("scan_progress_estimated")
	if done >= total {
		confidence = a.catalog.T("scan_progress_exact")
	}
	return fmt.Sprintf("%d%% %s • %d/%d", a.missionProgressPercent(done, total), confidence, done, total)
}

func (a *App) liveRiskLabel(critical, high, medium, low int) string {
	switch {
	case critical > 0:
		return a.catalog.T("scan_risk_critical")
	case high > 0:
		return a.catalog.T("scan_risk_high")
	case medium > 0:
		return a.catalog.T("scan_risk_medium")
	case low > 0:
		return a.catalog.T("scan_risk_low")
	default:
		return a.catalog.T("scan_risk_clear")
	}
}

func (a *App) scanPostureBadge(run domain.ScanRun) string {
	normalized := strings.ToLower(a.scanPostureLabel(run))
	return a.statusBadge(normalized)
}

func (a *App) scanPostureLabel(run domain.ScanRun) string {
	failed, _, _ := a.moduleExecutionCounts(run.ModuleResults)
	switch {
	case failed > 0 || run.Status == domain.ScanFailed:
		return a.catalog.T("scan_posture_degraded")
	case run.Summary.CountsBySeverity[domain.SeverityCritical] > 0:
		return a.catalog.T("scan_posture_breach")
	case run.Summary.CountsBySeverity[domain.SeverityHigh] > 0 || run.Summary.CountsBySeverity[domain.SeverityMedium] > 0:
		return a.catalog.T("scan_posture_warning")
	default:
		return a.catalog.T("scan_posture_clean")
	}
}

func (a *App) scanPostureSummary(run domain.ScanRun) string {
	failed, _, _ := a.moduleExecutionCounts(run.ModuleResults)
	switch {
	case failed > 0 || run.Status == domain.ScanFailed:
		return a.catalog.T("scan_posture_degraded_summary", failed)
	case run.Summary.CountsBySeverity[domain.SeverityCritical] > 0:
		return a.catalog.T("scan_posture_breach_summary", run.Summary.CountsBySeverity[domain.SeverityCritical])
	case run.Summary.CountsBySeverity[domain.SeverityHigh] > 0 || run.Summary.CountsBySeverity[domain.SeverityMedium] > 0:
		return a.catalog.T("scan_posture_warning_summary", run.Summary.CountsBySeverity[domain.SeverityHigh], run.Summary.CountsBySeverity[domain.SeverityMedium])
	default:
		return a.catalog.T("scan_posture_clean_summary")
	}
}

func (a *App) isolationContract(profile domain.ScanProfile) domain.IsolationContract {
	return a.service.ResolveIsolationContract(profile)
}

func (a *App) isolationNetworkLabel(policy domain.IsolationNetworkPolicy) string {
	switch policy {
	case domain.IsolationNetworkNone:
		return a.catalog.T("runtime_network_none")
	default:
		return a.catalog.T("runtime_network_default")
	}
}

func (a *App) isolationMountLabel(mode domain.IsolationMode, readOnly bool, writable bool) string {
	if mode != domain.IsolationContainer {
		return "-"
	}
	if readOnly {
		return a.catalog.T("runtime_mount_read_only")
	}
	if writable {
		return a.catalog.T("runtime_mount_read_write")
	}
	return "-"
}

func (a *App) isolationBoolLabel(value bool) string {
	if value {
		return a.catalog.T("runtime_enabled")
	}
	return a.catalog.T("runtime_disabled")
}

func (a *App) isolationTmpfsLabel(paths []string) string {
	if len(paths) == 0 {
		return "-"
	}
	return strings.Join(paths, ", ")
}

func (a *App) isolationCPULabel(contract domain.IsolationContract) string {
	if contract.CPUMilli <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f", float64(contract.CPUMilli)/1000)
}

func (a *App) isolationContractRows(contract domain.IsolationContract) [][]string {
	return [][]string{
		{a.catalog.T("runtime_effective_mode"), strings.ToUpper(string(contract.Mode))},
		{a.catalog.T("runtime_network_policy"), a.isolationNetworkLabel(contract.NetworkPolicy)},
		{a.catalog.T("runtime_env_allowlist"), a.isolationBoolLabel(contract.EnvAllowlist)},
		{a.catalog.T("runtime_rootfs_policy"), a.isolationMountLabel(contract.Mode, contract.RootfsReadOnly, false)},
		{a.catalog.T("runtime_workspace_policy"), a.isolationMountLabel(contract.Mode, contract.WorkspaceReadOnly, false)},
		{a.catalog.T("runtime_artifact_policy"), a.isolationMountLabel(contract.Mode, false, contract.ArtifactWritable)},
		{a.catalog.T("runtime_mirror_policy"), a.isolationMountLabel(contract.Mode, contract.MirrorReadOnly, false)},
		{a.catalog.T("runtime_tmpfs_policy"), a.isolationTmpfsLabel(contract.TmpfsPaths)},
		{a.catalog.T("runtime_pids_limit"), coalesceString(fmtInt(contract.PidsLimit), "-")},
		{a.catalog.T("runtime_memory_limit"), coalesceString(fmtMiB(contract.MemoryMiB), "-")},
		{a.catalog.T("runtime_cpu_limit"), a.isolationCPULabel(contract)},
		{a.catalog.T("runtime_no_new_privileges"), a.isolationBoolLabel(contract.NoNewPrivileges)},
		{a.catalog.T("runtime_cap_drop_all"), a.isolationBoolLabel(contract.DropAllCapabilities)},
	}
}

func (a *App) artifactProtectionRows(settings domain.RuntimeArtifactProtection) [][]string {
	protectedKinds := "-"
	if len(settings.ProtectedKinds) > 0 {
		protectedKinds = strings.Join(settings.ProtectedKinds, ", ")
	}
	return [][]string{
		{a.catalog.T("artifact_retention_days"), coalesceString(fmtInt(settings.RetentionDays), "-")},
		{a.catalog.T("artifact_redaction"), a.isolationBoolLabel(settings.RedactionEnabled)},
		{a.catalog.T("artifact_encryption"), a.isolationBoolLabel(settings.EncryptionEnabled)},
		{a.catalog.T("artifact_protected_kinds"), protectedKinds},
	}
}

func (a *App) supplyChainRows(settings domain.RuntimeSupplyChain) [][]string {
	return [][]string{
		{a.catalog.T("runtime_supply_chain_signer"), coalesceString(settings.Signer, "-")},
		{a.catalog.T("runtime_supply_chain_type"), coalesceString(settings.SignatureType, "-")},
		{a.catalog.T("runtime_supply_chain_fingerprint"), coalesceString(settings.PublicKeyFingerprint, "-")},
		{a.catalog.T("runtime_verified_tools"), coalesceString(fmtInt(settings.VerifiedTools), "0")},
		{a.catalog.T("runtime_failed_tools"), coalesceString(fmtInt(settings.FailedTools), "0")},
		{a.catalog.T("runtime_unverified_tools"), coalesceString(fmtInt(settings.UnverifiedTools), "0")},
		{a.catalog.T("runtime_checksum_covered_tools"), coalesceString(fmtInt(settings.ChecksumCoveredTools), "0")},
		{a.catalog.T("runtime_signature_covered_tools"), coalesceString(fmtInt(settings.SignatureCoveredTools), "0")},
		{a.catalog.T("runtime_source_integrity_tools"), coalesceString(fmtInt(settings.SourceIntegrityTools), "0")},
		{a.catalog.T("runtime_integrity_gap_tools"), coalesceString(fmtInt(settings.IntegrityGapTools), "0")},
		{a.catalog.T("runtime_verified_assets"), coalesceString(fmtInt(settings.VerifiedAssets), "0")},
		{a.catalog.T("runtime_failed_assets"), coalesceString(fmtInt(settings.FailedAssets), "0")},
		{a.catalog.T("runtime_unverified_assets"), coalesceString(fmtInt(settings.UnverifiedAssets), "0")},
	}
}

func (a *App) releaseBundleStatusLabel(bundle domain.RuntimeReleaseBundle) string {
	switch {
	case bundle.Signed && bundle.Verification.Status() == "verified":
		return a.statusBadge("verified")
	case bundle.Signed && bundle.Verification.Status() == "failed":
		return a.statusBadge("failed")
	case bundle.Signed:
		return a.statusBadge(bundle.Verification.Status())
	default:
		return a.statusBadge("unverified")
	}
}

func (a *App) supportRows(matrix domain.RuntimeSupportMatrix) [][]string {
	rows := [][]string{
		{a.catalog.T("runtime_support_platform"), matrix.Platform},
		{a.catalog.T("runtime_support_recommended"), a.coverageLabel(matrix.Recommended)},
	}
	for _, tier := range matrix.Tiers {
		rows = append(rows, []string{
			a.coverageLabel(tier.Coverage),
			fmt.Sprintf("%s | %s", a.runtimeSupportLevelLabel(tier.Level), coalesceString(tier.Notes, "-")),
		})
	}
	return rows
}

func (a *App) artifactProtectionLabel(artifact domain.ArtifactRef) string {
	flags := make([]string, 0, 3)
	if artifact.Redacted {
		flags = append(flags, a.catalog.T("artifact_flag_redacted"))
	}
	if artifact.Encrypted {
		flags = append(flags, a.catalog.T("artifact_flag_encrypted"))
	}
	if artifact.ExpiresAt != nil {
		flags = append(flags, a.catalog.T("artifact_flag_retained"))
	}
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ", ")
}

func (a *App) artifactExpiryLabel(artifact domain.ArtifactRef) string {
	if artifact.ExpiresAt == nil {
		return "-"
	}
	return artifact.ExpiresAt.Local().Format(time.RFC822)
}

func (a *App) verificationBadge(verification domain.RuntimeVerification) string {
	return a.statusBadge(verification.Status())
}

func (a *App) verificationDetailLabel(verification domain.RuntimeVerification) string {
	parts := make([]string, 0, 2)
	if verification.ChecksumConfigured {
		parts = append(parts, a.catalog.T("runtime_checksum_label"))
	}
	if verification.SignatureConfigured {
		parts = append(parts, a.catalog.T("runtime_signature_label"))
	}
	if len(parts) == 0 {
		return a.catalog.T("runtime_verification_unconfigured")
	}
	return strings.Join(parts, " + ")
}

func (a *App) trustedAssetVerificationLabel(asset domain.RuntimeTrustedAsset) string {
	return a.verificationBadge(asset.Verification)
}

func fmtInt(value int) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", value)
}

func fmtMiB(value int) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d MiB", value)
}

func (a *App) yesText() string {
	if a.lang == i18n.TR {
		return "Evet"
	}
	return "Yes"
}

func (a *App) noText() string {
	if a.lang == i18n.TR {
		return "Hayır"
	}
	return "No"
}

func (a *App) displayUpper(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ""
	}
	if a.lang != i18n.TR {
		return strings.ToUpper(trimmed)
	}
	replacer := strings.NewReplacer("i", "İ", "ı", "I")
	return strings.ToUpper(replacer.Replace(trimmed))
}

func (a *App) technicalUpper(text string) string {
	return strings.ToUpper(strings.TrimSpace(text))
}

func (a *App) toolDisplayUpper(text string) string {
	trimmed := strings.TrimSpace(text)
	switch trimmed {
	case "", "-":
		return "-"
	case "built-in analyzer", "yerleşik analiz":
		return a.displayUpper(trimmed)
	default:
		return a.technicalUpper(trimmed)
	}
}

func (a *App) statusText(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "queued":
		return a.catalog.T("status_queued")
	case "running":
		return a.catalog.T("status_running")
	case "completed":
		return a.catalog.T("status_completed")
	case "failed":
		return a.catalog.T("status_failed")
	case "canceled":
		return a.catalog.T("status_canceled")
	case "skipped":
		return a.catalog.T("status_skipped")
	case "available", "ready":
		return a.catalog.T("status_ready")
	case "warning", "warn":
		return a.catalog.T("status_warning")
	case "missing":
		return a.catalog.T("status_missing")
	case "verified":
		return a.catalog.T("status_verified")
	case "unverified":
		return a.catalog.T("status_unverified")
	case "supported":
		return a.catalog.T("status_supported")
	case "unsupported":
		return a.catalog.T("status_unsupported")
	case "partial":
		return a.catalog.T("status_partial")
	case "clean":
		return a.catalog.T("status_clean")
	case "breach":
		return a.catalog.T("status_breach")
	case "degraded":
		return a.catalog.T("status_degraded")
	case "drift":
		return a.catalog.T("status_drift")
	default:
		return strings.TrimSpace(status)
	}
}

func (a *App) scanStatusLabel(status domain.ScanStatus) string {
	return a.statusText(string(status))
}

func (a *App) moduleStatusLabel(status domain.ModuleStatus) string {
	return a.statusText(string(status))
}

func (a *App) runtimeCheckStatusText(status domain.RuntimeCheckStatus) string {
	switch status {
	case domain.RuntimeCheckPass:
		return a.catalog.T("status_ready")
	case domain.RuntimeCheckWarn:
		return a.catalog.T("status_warning")
	case domain.RuntimeCheckFail:
		return a.catalog.T("status_failed")
	default:
		return a.catalog.T("status_skipped")
	}
}

func (a *App) isolationModeLabel(mode domain.IsolationMode) string {
	switch mode {
	case domain.IsolationLocal:
		return a.catalog.T("scan_isolation_local_short")
	case domain.IsolationContainer:
		return a.catalog.T("scan_isolation_container_short")
	default:
		return a.catalog.T("scan_isolation_auto_short")
	}
}

func (a *App) plainBooleanLabel(value bool) string {
	if value {
		return a.yesText()
	}
	return a.noText()
}

func (a *App) plainSurfaceLabel(kind string) string {
	switch strings.TrimSpace(strings.ToLower(kind)) {
	case "overview":
		if a.lang == i18n.TR {
			return a.displayUpper(a.catalog.T("overview_tab"))
		}
		return "overview"
	case "runtime":
		if a.lang == i18n.TR {
			return a.displayUpper(a.catalog.T("runtime_command_title"))
		}
		return "runtime"
	default:
		return kind
	}
}

func (a *App) runtimeToolStateLabel(tool domain.RuntimeTool) string {
	switch {
	case !tool.Available:
		return a.displayUpper(a.statusText("missing"))
	case tool.Verification.Status() == "failed":
		return a.displayUpper(a.statusText("failed"))
	case tool.Healthy:
		return a.displayUpper(a.statusText("available"))
	default:
		return a.displayUpper(a.statusText("drift"))
	}
}

func (a *App) runtimeHealthSummary(runtime domain.RuntimeStatus) string {
	available, drift, missing, failed := runtimeToolHealthCounts(runtime)
	return fmt.Sprintf(
		"%s %d • %s %d • %s %d • %s %d",
		a.displayUpper(a.statusText("available")),
		available,
		a.displayUpper(a.statusText("drift")),
		drift,
		a.displayUpper(a.statusText("missing")),
		missing,
		a.displayUpper(a.statusText("failed")),
		failed,
	)
}

func (a *App) debriefSeverityBreakdown(run domain.ScanRun) string {
	parts := make([]string, 0, 4)
	for _, item := range []struct {
		severity domain.Severity
		count    int
	}{
		{domain.SeverityCritical, run.Summary.CountsBySeverity[domain.SeverityCritical]},
		{domain.SeverityHigh, run.Summary.CountsBySeverity[domain.SeverityHigh]},
		{domain.SeverityMedium, run.Summary.CountsBySeverity[domain.SeverityMedium]},
		{domain.SeverityLow, run.Summary.CountsBySeverity[domain.SeverityLow]},
	} {
		if item.count <= 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %d", a.displayUpper(a.severityLabel(item.severity)), item.count))
	}
	if len(parts) == 0 {
		return a.catalog.T("scan_debrief_no_findings")
	}
	return strings.Join(parts, " • ")
}

func (a *App) failedOrSkippedModuleSummary(modules []domain.ModuleResult) string {
	items := make([]string, 0, len(modules))
	for _, module := range modules {
		switch module.Status {
		case domain.ModuleFailed, domain.ModuleSkipped:
			items = append(items, fmt.Sprintf("%s %s", module.Name, strings.ToLower(a.moduleStatusLabel(module.Status))))
		}
	}
	if len(items) == 0 {
		return a.catalog.T("status_clean")
	}
	return strings.Join(items, " • ")
}

func (a *App) severityBadge(severity domain.Severity) string {
	label := a.displayUpper(a.severityLabel(severity))
	if a.colorDisabled() {
		return a.plainBadge(label)
	}
	style := pterm.NewStyle(pterm.FgWhite, pterm.BgBlue)
	switch severity {
	case domain.SeverityCritical:
		style = pterm.NewStyle(pterm.FgWhite, pterm.BgRed)
	case domain.SeverityHigh:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgYellow)
	case domain.SeverityMedium:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightMagenta)
	case domain.SeverityLow:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightGreen)
	case domain.SeverityInfo:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightBlue)
	}
	return style.Sprint(" " + label + " ")
}

func (a *App) severityBadgeCount(severity domain.Severity, count int) string {
	return fmt.Sprintf("%s %d", a.severityBadge(severity), count)
}

func (a *App) findingStatusBadge(status domain.FindingStatus) string {
	if status == "" {
		status = domain.FindingOpen
	}
	label := a.displayUpper(a.findingStatusLabel(status))
	if a.colorDisabled() {
		return a.plainBadge(label)
	}
	style := pterm.NewStyle(pterm.FgBlack, pterm.BgLightBlue)
	switch status {
	case domain.FindingInvestigating:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgYellow)
	case domain.FindingAcceptedRisk:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightMagenta)
	case domain.FindingFalsePositive:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightGreen)
	case domain.FindingFixed:
		style = pterm.NewStyle(pterm.FgWhite, pterm.BgGreen)
	}
	return style.Sprint(" " + label + " ")
}

func (a *App) modeBadge(mode domain.ScanMode) string {
	label := a.displayUpper(a.modeLabel(mode))
	if a.colorDisabled() {
		return a.plainBadge(label)
	}
	style := pterm.NewStyle(pterm.FgBlack, pterm.BgLightBlue)
	switch mode {
	case domain.ModeDeep:
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightMagenta)
	case domain.ModeActive:
		style = pterm.NewStyle(pterm.FgWhite, pterm.BgRed)
	}
	return style.Sprint(" " + label + " ")
}

func (a *App) statusBadge(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	label := a.displayUpper(a.statusText(normalized))
	if a.colorDisabled() {
		return a.plainBadge(label)
	}
	style := pterm.NewStyle(pterm.FgBlack, pterm.BgLightBlue)
	switch normalized {
	case "completed":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightGreen)
	case "drift":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightMagenta)
	case "verified":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightGreen)
	case "failed":
		style = pterm.NewStyle(pterm.FgWhite, pterm.BgRed)
	case "canceled":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightMagenta)
	case "running":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgYellow)
	case "queued":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightBlue)
	case "unverified":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgYellow)
	case "skipped", "missing":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgGray)
	case "available":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightGreen)
	case "supported":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightGreen)
	case "partial":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgYellow)
	case "breach":
		style = pterm.NewStyle(pterm.FgWhite, pterm.BgRed)
	case "warning":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgYellow)
	case "clean":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgLightGreen)
	case "degraded":
		style = pterm.NewStyle(pterm.FgWhite, pterm.BgMagenta)
	case "unsupported":
		style = pterm.NewStyle(pterm.FgBlack, pterm.BgGray)
	}
	return style.Sprint(" " + label + " ")
}

func (a *App) runtimeDoctorCheckStatusBadge(status domain.RuntimeCheckStatus) string {
	switch status {
	case domain.RuntimeCheckPass:
		return a.statusBadge("available")
	case domain.RuntimeCheckWarn:
		return a.statusBadge("warning")
	case domain.RuntimeCheckFail:
		return a.statusBadge("failed")
	default:
		return a.statusBadge("skipped")
	}
}

func (a *App) runtimeDoctorCheckLabel(name string) string {
	switch strings.TrimSpace(name) {
	case "sqlite_integrity":
		return a.catalog.T("runtime_doctor_check_sqlite")
	case "permissions_data_dir":
		return a.catalog.T("runtime_doctor_check_data_dir")
	case "permissions_output_dir":
		return a.catalog.T("runtime_doctor_check_output_dir")
	case "permissions_tools_dir":
		return a.catalog.T("runtime_doctor_check_tools_dir")
	case "disk_space":
		return a.catalog.T("runtime_doctor_check_disk")
	case "network_probe":
		return a.catalog.T("runtime_doctor_check_network")
	default:
		return name
	}
}

func (a *App) moduleStatusBadge(status domain.ModuleStatus) string {
	return a.statusBadge(string(status))
}

func (a *App) renderModuleExecutionEvent(trace domain.ModuleExecutionTrace, attempt *domain.ModuleAttemptTrace) {
	if attempt == nil {
		return
	}

	failureLabel := a.moduleFailureLabel(attempt.FailureKind)
	switch {
	case trace.Status == domain.ModuleRunning && attempt.FailureKind != domain.ModuleFailureNone && trace.AttemptsUsed < trace.MaxAttempts:
		pterm.Warning.Printf("%s\n", a.catalog.T("module_attempt_retrying", trace.Module, failureLabel, attempt.Attempt, trace.MaxAttempts))
	case trace.Status == domain.ModuleCompleted:
		pterm.Success.Printf("%s\n", a.catalog.T("module_attempt_succeeded", trace.Module, attempt.Attempt, maxInt(trace.MaxAttempts, trace.AttemptsUsed)))
	case trace.Status == domain.ModuleFailed || trace.Status == domain.ModuleSkipped:
		pterm.Error.Printf("%s\n", a.catalog.T("module_attempt_failed", trace.Module, failureLabel, attempt.Attempt, maxInt(trace.MaxAttempts, trace.AttemptsUsed)))
	}
}

func (a *App) moduleEventLabel(module domain.ModuleResult) string {
	parts := make([]string, 0, 3)
	if module.FailureKind != "" {
		parts = append(parts, a.moduleFailureLabel(module.FailureKind))
	}
	if attempts := a.maxModuleAttempts(module); attempts > 1 {
		parts = append(parts, fmt.Sprintf("%s=%d", strings.ToLower(a.catalog.T("module_attempts")), attempts))
	}
	if module.DurationMs > 0 && module.Status == domain.ModuleCompleted {
		parts = append(parts, fmt.Sprintf("%s=%s", strings.ToLower(a.catalog.T("module_duration")), a.formatModuleDuration(module.DurationMs)))
	}
	if module.TimedOut && module.FailureKind != domain.ModuleFailureTimeout {
		parts = append(parts, strings.ToLower(a.catalog.T("module_timed_out")))
	}
	if len(parts) == 0 {
		return module.Name
	}
	return fmt.Sprintf("%s (%s)", module.Name, strings.Join(parts, ", "))
}

func (a *App) daemonStateLabel(daemon domain.RuntimeDaemon) string {
	switch {
	case daemon.Active:
		return a.catalog.T("daemon_state_running")
	case daemon.Stale:
		return a.catalog.T("daemon_state_stale")
	default:
		return a.catalog.T("daemon_state_idle")
	}
}

func (a *App) formatModuleDuration(ms int64) string {
	if ms <= 0 {
		return "0ms"
	}
	return (time.Duration(ms) * time.Millisecond).String()
}

func (a *App) maxModuleAttempts(module domain.ModuleResult) int {
	if module.Attempts > 0 {
		return module.Attempts
	}
	if module.Status == domain.ModuleSkipped {
		return 0
	}
	return 1
}

func (a *App) moduleFailureLabel(kind domain.ModuleFailureKind) string {
	switch kind {
	case domain.ModuleFailureSkipped:
		if a.lang == i18n.TR {
			return "atlandı"
		}
		return "skipped"
	case domain.ModuleFailureToolMiss:
		if a.lang == i18n.TR {
			return "araç eksik"
		}
		return "tool missing"
	case domain.ModuleFailureTimeout:
		if a.lang == i18n.TR {
			return "zaman aşımı"
		}
		return "timeout"
	case domain.ModuleFailureCommand:
		if a.lang == i18n.TR {
			return "komut başarısız"
		}
		return "command failed"
	case domain.ModuleFailureParse:
		if a.lang == i18n.TR {
			return "ayrıştırma hatası"
		}
		return "parse error"
	case domain.ModuleFailureInfra:
		if a.lang == i18n.TR {
			return "altyapı hatası"
		}
		return "infra error"
	case domain.ModuleFailureArtifactIO:
		if a.lang == i18n.TR {
			return "artifact io"
		}
		return "artifact io"
	default:
		return "-"
	}
}

func (a *App) traceLastAttemptLabel(trace domain.ModuleExecutionTrace) string {
	if len(trace.AttemptJournal) == 0 {
		return "-"
	}
	last := trace.AttemptJournal[len(trace.AttemptJournal)-1]
	parts := []string{fmt.Sprintf("#%d", last.Attempt)}
	if last.FailureKind != domain.ModuleFailureNone && last.FailureKind != "" {
		parts = append(parts, a.moduleFailureLabel(last.FailureKind))
	}
	if last.TimedOut {
		parts = append(parts, strings.ToLower(a.catalog.T("module_timed_out")))
	}
	if last.ExitCode != nil {
		parts = append(parts, fmt.Sprintf("exit=%d", *last.ExitCode))
	}
	return strings.Join(parts, ", ")
}
