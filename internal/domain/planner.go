package domain

import (
	"sort"
	"strings"
)

type ScanLaneKind string

const (
	ScanLaneKindFast   ScanLaneKind = "fast"
	ScanLaneKindHeavy  ScanLaneKind = "heavy"
	ScanLaneKindActive ScanLaneKind = "active"
)

type ModuleTimeoutClass string

const (
	ModuleTimeoutShort    ModuleTimeoutClass = "short"
	ModuleTimeoutStandard ModuleTimeoutClass = "standard"
	ModuleTimeoutLong     ModuleTimeoutClass = "long"
	ModuleTimeoutTarget   ModuleTimeoutClass = "target"
)

type ModuleRetryClass string

const (
	ModuleRetryNone    ModuleRetryClass = "none"
	ModuleRetryBounded ModuleRetryClass = "bounded"
	ModuleRetryTarget  ModuleRetryClass = "target"
)

type ModulePlanSpec struct {
	Name                string             `json:"name"`
	Lane                string             `json:"lane"`
	Priority            int                `json:"priority"`
	Kind                ScanLaneKind       `json:"kind"`
	Prerequisites       []string           `json:"prerequisites,omitempty"`
	RuntimeRequirements []string           `json:"runtimeRequirements,omitempty"`
	ExpectedArtifacts   []string           `json:"expectedArtifacts,omitempty"`
	TimeoutClass        ModuleTimeoutClass `json:"timeoutClass,omitempty"`
	RetryClass          ModuleRetryClass   `json:"retryClass,omitempty"`
}

type ScanLanePlan struct {
	Key         string           `json:"key"`
	Priority    int              `json:"priority"`
	Kind        ScanLaneKind     `json:"kind"`
	Modules     []ModulePlanSpec `json:"modules,omitempty"`
	EstimatedMs int64            `json:"estimatedMs,omitempty"`
}

var modulePlanRegistry = map[string]ModulePlanSpec{
	"stack-detector":       newModulePlanSpec("stack-detector", "surface", 0, ModuleTimeoutShort, ModuleRetryNone, []string{"workspace"}, nil, []string{"inventory"}),
	"surface-inventory":    newModulePlanSpec("surface-inventory", "surface", 1, ModuleTimeoutShort, ModuleRetryBounded, []string{"workspace"}, nil, []string{"inventory"}),
	"script-audit":         newModulePlanSpec("script-audit", "surface", 2, ModuleTimeoutShort, ModuleRetryBounded, []string{"workspace"}, nil, []string{"report"}),
	"dependency-confusion": newModulePlanSpec("dependency-confusion", "supply", 1, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace", "network"}, []string{"stack-detector"}, []string{"report"}),
	"runtime-config-audit": newModulePlanSpec("runtime-config-audit", "surface", 3, ModuleTimeoutShort, ModuleRetryBounded, []string{"workspace"}, nil, []string{"report"}),
	"binary-entropy":       newModulePlanSpec("binary-entropy", "malware", 2, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace"}, nil, []string{"report"}),
	"secret-heuristics":    newModulePlanSpec("secret-heuristics", "code", 1, ModuleTimeoutShort, ModuleRetryBounded, []string{"workspace"}, nil, []string{"findings"}),
	"malware-signature":    newModulePlanSpec("malware-signature", "malware", 1, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace"}, nil, []string{"findings"}),
	"semgrep":              newModulePlanSpec("semgrep", "code", 2, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace"}, nil, []string{"sarif"}),
	"gitleaks":             newModulePlanSpec("gitleaks", "code", 2, ModuleTimeoutShort, ModuleRetryBounded, []string{"workspace"}, nil, []string{"json-report"}),
	"trivy":                newModulePlanSpec("trivy", "supply", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, nil, []string{"json-report"}),
	"trivy-image":          newModulePlanSpec("trivy-image", "infra", 4, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace", "container-runtime"}, nil, []string{"json-report"}),
	"syft":                 newModulePlanSpec("syft", "supply", 2, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace"}, nil, []string{"sbom"}),
	"grype":                newModulePlanSpec("grype", "supply", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, []string{"syft"}, []string{"json-report"}),
	"osv-scanner":          newModulePlanSpec("osv-scanner", "supply", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace", "network"}, nil, []string{"json-report"}),
	"checkov":              newModulePlanSpec("checkov", "infra", 2, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, nil, []string{"json-report"}),
	"tfsec":                newModulePlanSpec("tfsec", "infra", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, nil, []string{"sarif"}),
	"kics":                 newModulePlanSpec("kics", "infra", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, nil, []string{"sarif"}),
	"licensee":             newModulePlanSpec("licensee", "supply", 3, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace"}, nil, []string{"license-report"}),
	"scancode":             newModulePlanSpec("scancode", "supply", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, nil, []string{"license-report"}),
	"govulncheck":          newModulePlanSpec("govulncheck", "supply", 4, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace", "go-toolchain"}, nil, []string{"json-report"}),
	"staticcheck":          newModulePlanSpec("staticcheck", "supply", 4, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace", "go-toolchain"}, nil, []string{"json-report"}),
	"knip":                 newModulePlanSpec("knip", "supply", 4, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace", "node-runtime"}, nil, []string{"json-report"}),
	"vulture":              newModulePlanSpec("vulture", "supply", 4, ModuleTimeoutStandard, ModuleRetryBounded, []string{"workspace", "python-runtime"}, nil, []string{"json-report"}),
	"clamscan":             newModulePlanSpec("clamscan", "malware", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, nil, []string{"text-report"}),
	"yara-x":               newModulePlanSpec("yara-x", "malware", 3, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace"}, nil, []string{"json-report"}),
	"codeql":               newModulePlanSpec("codeql", "code", 5, ModuleTimeoutLong, ModuleRetryBounded, []string{"workspace", "codeql-runtime"}, nil, []string{"sarif"}),
	"nuclei":               newModulePlanSpec("nuclei", "active", 6, ModuleTimeoutTarget, ModuleRetryTarget, []string{"workspace", "network"}, []string{"target"}, []string{"json-report"}),
	"zaproxy":              newModulePlanSpec("zaproxy", "active", 7, ModuleTimeoutTarget, ModuleRetryTarget, []string{"workspace", "network", "browser-runtime"}, []string{"target"}, []string{"sarif"}),
}

func newModulePlanSpec(name, lane string, priority int, timeout ModuleTimeoutClass, retry ModuleRetryClass, requirements, prerequisites, artifacts []string) ModulePlanSpec {
	return ModulePlanSpec{
		Name:                name,
		Lane:                lane,
		Priority:            priority,
		Kind:                ScanLaneKindForKey(lane),
		Prerequisites:       append([]string(nil), prerequisites...),
		RuntimeRequirements: append([]string(nil), requirements...),
		ExpectedArtifacts:   append([]string(nil), artifacts...),
		TimeoutClass:        timeout,
		RetryClass:          retry,
	}
}

func ScanLaneKindForKey(key string) ScanLaneKind {
	switch strings.TrimSpace(key) {
	case "surface", "code":
		return ScanLaneKindFast
	case "active":
		return ScanLaneKindActive
	default:
		return ScanLaneKindHeavy
	}
}

func ScanLaneRank(key string) int {
	switch strings.TrimSpace(key) {
	case "surface":
		return 0
	case "code":
		return 1
	case "supply":
		return 2
	case "infra":
		return 3
	case "malware":
		return 4
	case "active":
		return 5
	default:
		return 6
	}
}

func ModulePlanSpecFor(name string, category FindingCategory) ModulePlanSpec {
	name = strings.TrimSpace(name)
	if spec, ok := modulePlanRegistry[name]; ok {
		return spec
	}
	lane := fallbackModuleLane(category)
	return ModulePlanSpec{
		Name:         name,
		Lane:         lane,
		Priority:     4,
		Kind:         ScanLaneKindForKey(lane),
		TimeoutClass: fallbackTimeoutClass(lane),
		RetryClass:   ModuleRetryBounded,
	}
}

func OrderedModuleNames(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := ModulePlanSpecFor(out[i], "")
		right := ModulePlanSpecFor(out[j], "")
		if ScanLaneRank(left.Lane) != ScanLaneRank(right.Lane) {
			return ScanLaneRank(left.Lane) < ScanLaneRank(right.Lane)
		}
		if left.Priority != right.Priority {
			return left.Priority < right.Priority
		}
		return out[i] < out[j]
	})
	return out
}

func LanePlans(modules []string) []ScanLanePlan {
	ordered := OrderedModuleNames(modules)
	if len(ordered) == 0 {
		return []ScanLanePlan{{
			Key:      "general",
			Priority: ScanLaneRank("general"),
			Kind:     ScanLaneKindForKey("general"),
		}}
	}
	indexByLane := make(map[string]int, len(ordered))
	plans := make([]ScanLanePlan, 0, len(ordered))
	for _, module := range ordered {
		spec := ModulePlanSpecFor(module, "")
		index, ok := indexByLane[spec.Lane]
		if !ok {
			index = len(plans)
			indexByLane[spec.Lane] = index
			plans = append(plans, ScanLanePlan{
				Key:      spec.Lane,
				Priority: ScanLaneRank(spec.Lane),
				Kind:     spec.Kind,
			})
		}
		plans[index].Modules = append(plans[index].Modules, spec)
	}
	return plans
}

func ProjectLanePlans(project Project, modules []string, runs []ScanRun) []ScanLanePlan {
	plans := LanePlans(modules)
	ordered := OrderedModuleNames(modules)
	for index := range plans {
		plans[index].EstimatedMs = EstimateLaneDurationMs(project, ordered, runs, plans[index])
	}
	return plans
}

func EstimateLaneDurationMs(project Project, orderedModules []string, runs []ScanRun, plan ScanLanePlan) int64 {
	if plan.Key == "active" || len(plan.Modules) == 0 {
		return 0
	}
	moduleSet := make(map[string]struct{}, len(plan.Modules))
	for _, module := range plan.Modules {
		moduleSet[module.Name] = struct{}{}
	}
	targetModules := len(plan.Modules)
	if targetModules == 0 {
		return 0
	}

	var (
		sampleRuns    int
		totalDuration int64
		totalModCount int
	)
	for index := len(runs) - 1; index >= 0; index-- {
		run := runs[index]
		if strings.TrimSpace(project.ID) != "" && run.ProjectID != project.ID {
			continue
		}
		laneDuration := int64(0)
		laneModules := 0
		for _, module := range run.ModuleResults {
			if _, ok := moduleSet[module.Name]; !ok || module.DurationMs <= 0 {
				continue
			}
			laneDuration += module.DurationMs
			laneModules++
		}
		if laneModules == 0 || laneDuration <= 0 {
			continue
		}
		totalDuration += laneDuration
		totalModCount += laneModules
		sampleRuns++
		if sampleRuns >= 6 {
			break
		}
	}

	historicalMs := int64(0)
	if sampleRuns > 0 && totalModCount > 0 {
		historicalMs = int64(float64(totalDuration) / float64(totalModCount) * float64(targetModules))
	}
	heuristicMs := heuristicLaneDurationMs(project, orderedModules, plan)

	switch {
	case historicalMs > 0 && heuristicMs > 0:
		historicalWeight := 0.65
		if sampleRuns <= 1 {
			historicalWeight = 0.55
		} else if sampleRuns >= 4 {
			historicalWeight = 0.75
		}
		return int64(float64(historicalMs)*historicalWeight + float64(heuristicMs)*(1-historicalWeight))
	case historicalMs > 0:
		return historicalMs
	default:
		return heuristicMs
	}
}

func heuristicLaneDurationMs(project Project, orderedModules []string, plan ScanLanePlan) int64 {
	if plan.Key == "active" {
		return 0
	}
	targetModules := len(plan.Modules)
	if targetModules == 0 {
		return 0
	}
	var basePerModule int64
	switch plan.Key {
	case "surface":
		basePerModule = 2500
	case "code":
		basePerModule = 7000
	case "supply":
		basePerModule = 60000
	case "infra":
		basePerModule = 45000
	case "malware":
		basePerModule = 35000
	default:
		basePerModule = 30000
	}
	stackFactor := 1.0
	if count := len(project.DetectedStacks); count > 1 {
		stackFactor += minFloat64(0.8, float64(count-1)*0.18)
	}
	breadthFactor := 1.0
	if moduleCount := len(orderedModules); moduleCount > 6 {
		breadthFactor += minFloat64(0.45, float64(moduleCount-6)*0.04)
	}
	return int64(float64(basePerModule*int64(targetModules)) * stackFactor * breadthFactor)
}

func fallbackModuleLane(category FindingCategory) string {
	switch category {
	case CategoryPlatform:
		return "surface"
	case CategorySAST, CategorySecret:
		return "code"
	case CategorySCA, CategoryCompliance, CategoryMaintainability:
		return "supply"
	case CategoryIaC, CategoryContainer:
		return "infra"
	case CategoryMalware:
		return "malware"
	case CategoryDAST:
		return "active"
	default:
		return "general"
	}
}

func fallbackTimeoutClass(lane string) ModuleTimeoutClass {
	switch lane {
	case "surface", "code":
		return ModuleTimeoutShort
	case "active":
		return ModuleTimeoutTarget
	default:
		return ModuleTimeoutLong
	}
}

func minFloat64(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}
