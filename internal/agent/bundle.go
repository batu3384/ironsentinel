package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

type bundleLock struct {
	Version       int                     `json:"version"`
	GeneratedAt   string                  `json:"generatedAt,omitempty"`
	Signing       bundleTrustAnchor       `json:"signing,omitempty"`
	TrustedAssets []bundleTrustedAsset    `json:"trustedAssets,omitempty"`
	Channels      map[string][]bundleSpec `json:"channels"`
}

type bundleSpec struct {
	Name             string                `json:"name"`
	Version          string                `json:"version"`
	PlatformVersions map[string]string     `json:"platformVersions,omitempty"`
	Source           string                `json:"source,omitempty"`
	Checksums        map[string]string     `json:"checksums,omitempty"`
	Signature        bundleSignature       `json:"signature,omitempty"`
	SourceIntegrity  bundleSourceIntegrity `json:"sourceIntegrity,omitempty"`
}

type bundleTrustAnchor struct {
	Type      string `json:"type,omitempty"`
	Signer    string `json:"signer,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

type bundleSignature struct {
	Value  string `json:"value,omitempty"`
	Signer string `json:"signer,omitempty"`
}

type bundleSourceIntegrity struct {
	Kind      string `json:"kind,omitempty"`
	URL       string `json:"url,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type bundleTrustedAsset struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind,omitempty"`
	Path      string          `json:"path"`
	SHA256    string          `json:"sha256,omitempty"`
	Signature bundleSignature `json:"signature,omitempty"`
}

type bundleToolMeta struct {
	Binary         string
	InstallCommand string
	VersionArgs    []string
}

var bundleToolCatalog = map[string]bundleToolMeta{
	"semgrep":     {Binary: "semgrep", InstallCommand: `python3 -m pip install "semgrep==1.119.0"`, VersionArgs: []string{"--version"}},
	"gitleaks":    {Binary: "gitleaks", InstallCommand: `brew install gitleaks`, VersionArgs: []string{"version"}},
	"trivy":       {Binary: "trivy", InstallCommand: `brew install trivy`, VersionArgs: []string{"--version"}},
	"syft":        {Binary: "syft", InstallCommand: `brew install syft`, VersionArgs: []string{"version"}},
	"osv-scanner": {Binary: "osv-scanner", InstallCommand: `brew install osv-scanner`, VersionArgs: []string{"--version"}},
	"checkov":     {Binary: "checkov", InstallCommand: `pipx install "checkov==3.2.489"`, VersionArgs: []string{"--version"}},
	"clamav":      {Binary: "clamscan", InstallCommand: `brew install clamav`, VersionArgs: []string{"--version"}},
	"staticcheck": {Binary: "staticcheck", InstallCommand: `go install honnef.co/go/tools/cmd/staticcheck@2025.1.1`, VersionArgs: []string{"-version"}},
	"govulncheck": {Binary: "govulncheck", InstallCommand: `go install golang.org/x/vuln/cmd/govulncheck@v1.1.4`, VersionArgs: []string{"-version"}},
	"codeql":      {Binary: "codeql", InstallCommand: `brew install codeql`, VersionArgs: []string{"version"}},
	"knip":        {Binary: "knip", InstallCommand: `npm install -g knip@5.70.1`, VersionArgs: []string{"--version"}},
	"vulture":     {Binary: "vulture", InstallCommand: `pipx install "vulture==2.14"`, VersionArgs: []string{"--version"}},
	"zap":         {Binary: "zaproxy", InstallCommand: `brew install --cask owasp-zap`, VersionArgs: []string{"-version"}},
	"nuclei":      {Binary: "nuclei", InstallCommand: `brew install nuclei`, VersionArgs: []string{"-version"}},
	"grype":       {Binary: "grype", InstallCommand: `brew install grype`, VersionArgs: []string{"version"}},
	"licensee":    {Binary: "licensee", InstallCommand: `gem install licensee`, VersionArgs: []string{"version"}},
	"scancode":    {Binary: "scancode", InstallCommand: `pipx install "scancode-toolkit==32.3.1"`, VersionArgs: []string{"--version"}},
	"tfsec":       {Binary: "tfsec", InstallCommand: `brew install tfsec`, VersionArgs: []string{"--version"}},
	"kics":        {Binary: "kics", InstallCommand: `brew install kics`, VersionArgs: []string{"version"}},
	"yara-x":      {Binary: "yara-x", InstallCommand: `brew install yara-x`, VersionArgs: []string{"--version"}},
}

var versionPattern = regexp.MustCompile(`\d+(?:\.\d+)+`)

func DiscoverRuntime(cfg config.Config) domain.RuntimeStatus {
	lock := loadBundleLock(cfg.BundleLockPath)
	tools := discoverBundleTools(cfg, lock)
	supplyChain := discoverSupplyChain(cfg, lock, tools)
	healthy := 0
	for index := range tools {
		if tools[index].Healthy {
			healthy++
		}
	}

	return domain.RuntimeStatus{
		AgentReachable:    true,
		BundleVersion:     lock.Version,
		BundleLockPath:    cfg.BundleLockPath,
		InstallScript:     cfg.InstallScript,
		ImageBuildScript:  cfg.ImageBuildScript,
		ContainerfilePath: cfg.ContainerfilePath,
		ScannerBundle:     tools,
		HealthyToolCount:  healthy,
		Isolation:         discoverIsolation(cfg),
		Mirrors:           discoverMirrors(cfg),
		Daemon:            discoverDaemon(cfg),
		Artifacts:         discoverArtifactProtection(cfg),
		SupplyChain:       supplyChain,
		Support:           discoverSupportMatrix(),
	}
}

func EvaluateBundleHealth(cfg config.Config, profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
	lock := loadBundleLock(cfg.BundleLockPath)
	tools := discoverBundleTools(cfg, lock)
	supplyChain := discoverSupplyChain(cfg, lock, tools)
	requiredNames := requiredBundleNames(lock, profile)
	requiredSet := make(map[string]struct{}, len(requiredNames))
	for _, name := range requiredNames {
		requiredSet[name] = struct{}{}
	}

	doctor := domain.RuntimeDoctor{
		Mode:             profile.Mode,
		StrictVersions:   strictVersions,
		RequireIntegrity: requireIntegrity,
		Ready:            true,
		Required:         make([]domain.RuntimeTool, 0, len(requiredNames)),
	}

	for index := range tools {
		tool := tools[index]
		if _, ok := requiredSet[tool.BundleName]; !ok {
			continue
		}
		tool.Required = true
		doctor.Required = append(doctor.Required, tool)
		if !tool.Available {
			doctor.Missing = append(doctor.Missing, tool)
			doctor.Ready = false
			continue
		}
		if strictVersions && tool.ExpectedVersion != "" && !tool.Healthy {
			doctor.Outdated = append(doctor.Outdated, tool)
			doctor.Ready = false
		}
		if tool.Verification.Status() == "failed" {
			doctor.FailedVerification = append(doctor.FailedVerification, tool)
			doctor.Ready = false
			continue
		}
		if requireIntegrity && !toolIntegrityCovered(tool) {
			doctor.Unverified = append(doctor.Unverified, tool)
			doctor.Ready = false
		}
	}
	for name := range requiredSet {
		found := false
		for _, tool := range doctor.Required {
			if tool.BundleName == name {
				found = true
				break
			}
		}
		if found {
			continue
		}
		meta := bundleMetadata(name)
		path, err := findBinary(cfg, meta.Binary)
		tool := domain.RuntimeTool{
			Name:           meta.Binary,
			BundleName:     name,
			Channel:        "extended",
			Source:         "catalog",
			Available:      err == nil,
			Path:           path,
			InstallCommand: meta.InstallCommand,
			Verification:   domain.RuntimeVerification{Notes: "tool is not pinned in the signed bundle lock"},
		}
		if tool.Available {
			tool.ActualVersion = detectVersion(path, meta.VersionArgs)
			tool.Healthy = strings.TrimSpace(tool.ActualVersion) != ""
		}
		doctor.Required = append(doctor.Required, tool)
		if !tool.Available {
			doctor.Missing = append(doctor.Missing, tool)
			doctor.Ready = false
			continue
		}
		if requireIntegrity {
			doctor.Unverified = append(doctor.Unverified, tool)
			doctor.Ready = false
		}
	}
	for _, asset := range supplyChain.TrustedAssets {
		if asset.Verification.Status() == "failed" {
			doctor.FailedAssets = append(doctor.FailedAssets, asset)
			doctor.Ready = false
		}
	}

	sort.Slice(doctor.Required, func(i, j int) bool { return doctor.Required[i].Name < doctor.Required[j].Name })
	sort.Slice(doctor.Missing, func(i, j int) bool { return doctor.Missing[i].Name < doctor.Missing[j].Name })
	sort.Slice(doctor.Outdated, func(i, j int) bool { return doctor.Outdated[i].Name < doctor.Outdated[j].Name })
	sort.Slice(doctor.FailedVerification, func(i, j int) bool { return doctor.FailedVerification[i].Name < doctor.FailedVerification[j].Name })
	sort.Slice(doctor.Unverified, func(i, j int) bool { return doctor.Unverified[i].Name < doctor.Unverified[j].Name })
	sort.Slice(doctor.FailedAssets, func(i, j int) bool { return doctor.FailedAssets[i].Name < doctor.FailedAssets[j].Name })
	return doctor
}

func toolIntegrityCovered(tool domain.RuntimeTool) bool {
	return tool.ChecksumCovered || tool.SignatureCovered || tool.SourceIntegrityCovered
}

func loadBundleLock(path string) bundleLock {
	payload := bundleLock{Channels: make(map[string][]bundleSpec)}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return payload
	}
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return payload
	}
	if payload.Channels == nil {
		payload.Channels = make(map[string][]bundleSpec)
	}
	return payload
}

func discoverBundleTools(cfg config.Config, lock bundleLock) []domain.RuntimeTool {
	type bundleTask struct {
		channel string
		spec    bundleSpec
	}
	tasks := make([]bundleTask, 0, 16)
	for channel, specs := range lock.Channels {
		for _, spec := range specs {
			tasks = append(tasks, bundleTask{channel: channel, spec: spec})
		}
	}
	tools := make([]domain.RuntimeTool, len(tasks))
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for index, entry := range tasks {
		go func(index int, entry bundleTask) {
			defer wg.Done()
			meta := bundleMetadata(entry.spec.Name)
			path, err := findBinary(cfg, meta.Binary)
			tool := domain.RuntimeTool{
				Name:                   meta.Binary,
				BundleName:             entry.spec.Name,
				Channel:                entry.channel,
				Source:                 entry.spec.Source,
				Available:              err == nil,
				Path:                   path,
				ExpectedVersion:        effectiveSpecVersion(entry.spec),
				InstallCommand:         meta.InstallCommand,
				ChecksumCovered:        len(entry.spec.Checksums) > 0,
				SignatureCovered:       strings.TrimSpace(entry.spec.Signature.Value) != "",
				SourceIntegrityCovered: strings.TrimSpace(entry.spec.SourceIntegrity.Digest) != "" && strings.TrimSpace(entry.spec.SourceIntegrity.Algorithm) != "",
			}
			if tool.Available {
				tool.ActualVersion = detectVersion(path, meta.VersionArgs)
				if strings.TrimSpace(tool.ExpectedVersion) == "" {
					tool.Healthy = strings.TrimSpace(tool.ActualVersion) != ""
				} else {
					tool.Healthy = matchesExpectedVersion(tool.ExpectedVersion, tool.ActualVersion)
				}
				tool.Verification = verifyToolIntegrity(path, entry.spec, lock.Signing)
			} else {
				tool.Verification = domain.RuntimeVerification{Notes: "binary unavailable"}
			}
			tools[index] = tool
		}(index, entry)
	}
	wg.Wait()

	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Channel == tools[j].Channel {
			return tools[i].Name < tools[j].Name
		}
		return tools[i].Channel < tools[j].Channel
	})
	return tools
}

func requiredBundleNames(lock bundleLock, profile domain.ScanProfile) []string {
	required := make(map[string]struct{})
	addChannel := func(name string) {
		for _, spec := range lock.Channels[name] {
			required[spec.Name] = struct{}{}
		}
	}

	if len(profile.Modules) == 0 {
		addChannel("safe")
		switch profile.Mode {
		case domain.ModeDeep:
			addChannel("deep")
		case domain.ModeActive:
			addChannel("active")
		}
	}

	for _, module := range profile.Modules {
		if bundleName := bundleNameForBinary(module); bundleName != "" {
			required[bundleName] = struct{}{}
		}
	}

	items := make([]string, 0, len(required))
	for name := range required {
		items = append(items, name)
	}
	sort.Strings(items)
	return items
}

func bundleMetadata(name string) bundleToolMeta {
	meta, ok := bundleToolCatalog[name]
	if ok {
		return meta
	}
	return bundleToolMeta{Binary: name, VersionArgs: []string{"--version"}}
}

func bundleNameForBinary(binary string) string {
	switch strings.TrimSpace(binary) {
	case "clamscan":
		return "clamav"
	case "zaproxy":
		return "zap"
	case "stack-detector", "secret-heuristics", "malware-signature":
		return ""
	default:
		for name, meta := range bundleToolCatalog {
			if meta.Binary == binary || name == binary {
				return name
			}
		}
		return ""
	}
}

func detectVersion(binary string, args []string) string {
	toolName := versionProbeToolName(binary)
	if strings.Contains(toolName, "knip") {
		if version := detectKnipVersion(binary); version != "" {
			return version
		}
	}
	if strings.Contains(toolName, "zaproxy") || strings.Contains(toolName, "zap") {
		return detectZAPVersion(binary)
	}
	output, err := runVersionProbeCommand(binary, args...)
	if err != nil && len(output) == 0 {
		return ""
	}
	return parseVersionOutput(toolName, string(output))
}

func versionProbeToolName(binary string) string {
	return strings.ToLower(filepath.Base(binary))
}

func parseVersionOutput(toolName, text string) string {
	switch {
	case strings.Contains(toolName, "govulncheck"):
		if match := regexp.MustCompile(`(?m)Scanner:\s+govulncheck@v?(\d+(?:\.\d+)+)`).FindStringSubmatch(text); len(match) == 2 {
			return match[1]
		}
	case strings.Contains(toolName, "syft"), strings.Contains(toolName, "grype"), strings.Contains(toolName, "trivy"):
		if match := regexp.MustCompile(`(?m)^Version:\s+(\d+(?:\.\d+)+)\s*$`).FindStringSubmatch(text); len(match) == 2 {
			return match[1]
		}
	case strings.Contains(toolName, "osv-scanner"):
		if match := regexp.MustCompile(`(?m)^osv-scanner version:\s+(\d+(?:\.\d+)+)\s*$`).FindStringSubmatch(text); len(match) == 2 {
			return match[1]
		}
	case strings.Contains(toolName, "zaproxy"), strings.Contains(toolName, "zap"):
		matches := regexp.MustCompile(`(?m)^\s*(\d+(?:\.\d+)+)\s*$`).FindAllStringSubmatch(text, -1)
		if len(matches) > 0 {
			return matches[len(matches)-1][1]
		}
	}

	lines := strings.Split(text, "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		match := versionPattern.FindString(strings.TrimSpace(lines[index]))
		if match != "" {
			return match
		}
	}
	return ""
}

func detectKnipVersion(binary string) string {
	candidates := []string{
		filepath.Join(filepath.Dir(binary), "..", "npm", "node_modules", "knip", "package.json"),
		filepath.Join(filepath.Dir(binary), "..", "node_modules", "knip", "package.json"),
	}
	for _, candidate := range candidates {
		bytes, err := os.ReadFile(filepath.Clean(candidate))
		if err != nil {
			continue
		}
		var payload struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(bytes, &payload) == nil && strings.TrimSpace(payload.Version) != "" {
			return strings.TrimSpace(payload.Version)
		}
	}
	return ""
}

func detectZAPVersion(binary string) string {
	candidates := zapVersionSearchDirs(binary)
	targets := zapWrapperTargets(binary)
	for _, target := range targets {
		candidates = append(candidates, zapVersionSearchDirs(target)...)
	}
	for _, candidate := range uniqueStrings(candidates) {
		if version := detectZAPVersionFromJavaDir(candidate); version != "" {
			return version
		}
	}
	output, err := runVersionProbeCommand(binary, "-version")
	if err != nil && len(output) == 0 {
		return ""
	}
	matches := regexp.MustCompile(`(?m)^\s*(\d+(?:\.\d+)+)\s*$`).FindAllStringSubmatch(string(output), -1)
	if len(matches) > 0 {
		return matches[len(matches)-1][1]
	}
	return ""
}

func zapVersionSearchDirs(binary string) []string {
	return []string{
		filepath.Join(filepath.Dir(binary), "..", "Java"),
		filepath.Join(filepath.Dir(binary), "..", "..", "Java"),
		filepath.Join(filepath.Dir(binary), "..", "Resources", "Java"),
	}
}

func detectZAPVersionFromJavaDir(candidate string) string {
	pattern := regexp.MustCompile(`^zap-(\d+(?:\.\d+)+)\.jar$`)
	entries, err := os.ReadDir(filepath.Clean(candidate))
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := pattern.FindStringSubmatch(entry.Name())
		if len(match) == 2 {
			return match[1]
		}
	}
	return ""
}

func zapWrapperTargets(binary string) []string {
	content, err := os.ReadFile(binary)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	targets := make([]string, 0, 2)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\bexec\s+([^\s"]+)`),
		regexp.MustCompile(`\bexec\s+"([^"]+)"`),
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, pattern := range patterns {
			match := pattern.FindStringSubmatch(line)
			if len(match) != 2 {
				continue
			}
			target := strings.TrimSpace(match[1])
			if target == "" || strings.HasPrefix(target, "$") {
				continue
			}
			targets = append(targets, target)
		}
	}
	return uniqueStrings(targets)
}

func matchesExpectedVersion(expected, actual string) bool {
	if expected == "" || actual == "" {
		return false
	}
	return normalizeVersion(expected) == normalizeVersion(actual)
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "v"), "V"))
	match := versionPattern.FindString(value)
	if match != "" {
		return match
	}
	return value
}

func effectiveSpecVersion(spec bundleSpec) string {
	platform := currentPlatformKey()
	if version := strings.TrimSpace(spec.PlatformVersions[platform]); version != "" {
		return version
	}
	return strings.TrimSpace(spec.Version)
}

func currentPlatformKey() string {
	return goruntime.GOOS + "/" + goruntime.GOARCH
}

func uniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	filtered := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		filtered = append(filtered, item)
	}
	return filtered
}
