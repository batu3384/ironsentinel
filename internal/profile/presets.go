package profile

import "github.com/batu3384/ironsentinel/internal/domain"

type Definition struct {
	ID           domain.CompliancePreset
	Title        string
	Description  string
	Coverage     domain.CoverageProfile
	Mode         domain.ScanMode
	SeverityGate domain.Severity
	PolicyID     string
	AllowBuild   bool
	AllowNetwork bool
	Modules      []string
}

var definitions = []Definition{
	{
		ID:           domain.CompliancePresetPCIDSS,
		Title:        "PCI-DSS",
		Description:  "Payment-card oriented profile with code, dependency, IaC, license and artifact controls.",
		Coverage:     domain.CoverageFull,
		Mode:         domain.ModeDeep,
		SeverityGate: domain.SeverityHigh,
		PolicyID:     "pci-dss",
		AllowBuild:   false,
		AllowNetwork: false,
		Modules: []string{
			"stack-detector", "surface-inventory", "script-audit", "dependency-confusion", "runtime-config-audit", "binary-entropy",
			"secret-heuristics", "malware-signature", "semgrep", "gitleaks", "trivy", "syft", "grype", "osv-scanner",
			"checkov", "tfsec", "kics", "licensee", "scancode", "yara-x", "trivy-image", "codeql",
		},
	},
	{
		ID:           domain.CompliancePresetSOC2,
		Title:        "SOC 2",
		Description:  "Operational security profile with secrets, supply-chain and configuration focus.",
		Coverage:     domain.CoverageFull,
		Mode:         domain.ModeDeep,
		SeverityGate: domain.SeverityHigh,
		PolicyID:     "soc2",
		AllowBuild:   false,
		AllowNetwork: false,
		Modules: []string{
			"stack-detector", "surface-inventory", "script-audit", "dependency-confusion", "runtime-config-audit", "binary-entropy",
			"secret-heuristics", "malware-signature", "semgrep", "gitleaks", "trivy", "syft", "grype", "osv-scanner",
			"checkov", "licensee", "scancode", "yara-x", "codeql",
		},
	},
	{
		ID:           domain.CompliancePresetOWASPTop10,
		Title:        "OWASP Top 10",
		Description:  "Application attack-surface preset with SAST, dependency and dynamic checks.",
		Coverage:     domain.CoverageFull,
		Mode:         domain.ModeActive,
		SeverityGate: domain.SeverityHigh,
		PolicyID:     "owasp-top10",
		AllowBuild:   false,
		AllowNetwork: true,
		Modules: []string{
			"stack-detector", "surface-inventory", "script-audit", "dependency-confusion", "secret-heuristics",
			"semgrep", "codeql", "gitleaks", "trivy", "grype", "osv-scanner", "checkov", "nuclei", "zaproxy",
		},
	},
	{
		ID:           domain.CompliancePresetSANSTop25,
		Title:        "SANS Top 25",
		Description:  "Secure coding preset optimized for weakness classes and exploitability.",
		Coverage:     domain.CoverageFull,
		Mode:         domain.ModeDeep,
		SeverityGate: domain.SeverityMedium,
		PolicyID:     "sans-top25",
		AllowBuild:   false,
		AllowNetwork: false,
		Modules: []string{
			"stack-detector", "surface-inventory", "script-audit", "dependency-confusion", "secret-heuristics",
			"semgrep", "codeql", "gitleaks", "trivy", "syft", "grype", "osv-scanner", "checkov",
		},
	},
}

func All() []Definition {
	out := make([]Definition, len(definitions))
	copy(out, definitions)
	return out
}

func Get(id domain.CompliancePreset) (Definition, bool) {
	for _, def := range definitions {
		if def.ID == id {
			return def, true
		}
	}
	return Definition{}, false
}
