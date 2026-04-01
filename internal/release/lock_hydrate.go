package release

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type LockHydrateOptions struct {
	Tools []string
	Fetch func(string) ([]byte, error)
}

type LockHydrateReport struct {
	Name        string
	Version     string
	Channel     string
	ChecksumURL string
	Status      string
	Updated     int
	Note        string
}

type checksumHydrator struct {
	name    string
	hydrate func(string, func(string) ([]byte, error)) (map[string]string, error)
}

var checksumHydrators = map[string]checksumHydrator{
	"codeql": {
		name: "codeql",
		hydrate: hydrateGitHubReleaseAssetDigests(
			"github/codeql-action",
			func(version string) string {
				return "codeql-bundle-v" + strings.TrimPrefix(strings.TrimSpace(version), "v")
			},
			func(name string) bool {
				lower := strings.ToLower(strings.TrimSpace(name))
				return strings.HasPrefix(lower, "codeql-bundle-") && strings.HasSuffix(lower, ".tar.gz") && !strings.Contains(lower, "checksum") && lower != "codeql-bundle.tar.gz"
			},
			inferCodeQLPlatform,
		),
	},
	"osv-scanner": {
		name: "osv-scanner",
		hydrate: hydrateGitHubReleaseAssetDigests(
			"google/osv-scanner",
			func(version string) string { return "v" + strings.TrimPrefix(strings.TrimSpace(version), "v") },
			func(name string) bool {
				lower := strings.ToLower(strings.TrimSpace(name))
				return strings.HasPrefix(lower, "osv-scanner_") && !strings.HasSuffix(lower, "sha256sums") && !strings.HasSuffix(lower, ".jsonl")
			},
			inferReleasePlatform,
		),
	},
	"trivy": {
		name: "trivy",
		hydrate: hydrateChecksumManifest(
			func(version string) string {
				return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_checksums.txt", version, version)
			},
			[]string{".tar.gz", ".zip"},
			inferReleasePlatform,
		),
	},
}

type sourceHydrator struct {
	name    string
	hydrate func(version string, fetch func(string) ([]byte, error)) (SourceIntegrity, error)
}

var sourceHydrators = map[string]sourceHydrator{
	"checkov": {name: "checkov", hydrate: hydratePyPISdist("checkov")},
	"clamav": {name: "clamav", hydrate: hydrateSourceDigestURL("http-tarball", func(version string) string {
		return fmt.Sprintf("https://www.clamav.net/downloads/production/clamav-%s.tar.gz", strings.TrimPrefix(strings.TrimSpace(version), "v"))
	})},
	"gitleaks": {name: "gitleaks", hydrate: hydrateSourceDigestURL("github-source-archive", func(version string) string {
		return fmt.Sprintf("https://github.com/gitleaks/gitleaks/archive/refs/tags/v%s.tar.gz", strings.TrimPrefix(strings.TrimSpace(version), "v"))
	})},
	"grype": {name: "grype", hydrate: hydrateSourceDigestURL("github-source-archive", func(version string) string {
		return fmt.Sprintf("https://github.com/anchore/grype/archive/refs/tags/v%s.tar.gz", strings.TrimPrefix(strings.TrimSpace(version), "v"))
	})},
	"govulncheck": {name: "govulncheck", hydrate: hydrateGoModule("https://proxy.golang.org/golang.org/x/vuln/@v/%s.zip")},
	"knip":        {name: "knip", hydrate: hydrateNpmTarball("knip")},
	"nuclei": {name: "nuclei", hydrate: hydrateSourceDigestURL("github-source-archive", func(version string) string {
		return fmt.Sprintf("https://github.com/projectdiscovery/nuclei/archive/refs/tags/v%s.tar.gz", strings.TrimPrefix(strings.TrimSpace(version), "v"))
	})},
	"semgrep": {name: "semgrep", hydrate: hydratePyPISdistOrFirstWheel("semgrep")},
	"syft": {name: "syft", hydrate: hydrateSourceDigestURL("github-source-archive", func(version string) string {
		return fmt.Sprintf("https://github.com/anchore/syft/archive/refs/tags/v%s.tar.gz", strings.TrimPrefix(strings.TrimSpace(version), "v"))
	})},
	"staticcheck": {name: "staticcheck", hydrate: hydrateSourceDigestURL("github-source-archive", func(version string) string {
		return fmt.Sprintf("https://github.com/dominikh/go-tools/archive/refs/tags/%s.tar.gz", strings.TrimSpace(version))
	})},
	"trivy": {name: "trivy", hydrate: hydrateSourceDigestURL("github-source-archive", func(version string) string {
		return fmt.Sprintf("https://github.com/aquasecurity/trivy/archive/refs/tags/v%s.tar.gz", strings.TrimPrefix(strings.TrimSpace(version), "v"))
	})},
	"vulture": {name: "vulture", hydrate: hydratePyPISdist("vulture")},
	"zap": {name: "zap", hydrate: hydrateSourceDigestURL("github-source-archive", func(version string) string {
		return fmt.Sprintf("https://github.com/zaproxy/zaproxy/archive/refs/tags/v%s.tar.gz", strings.TrimPrefix(strings.TrimSpace(version), "v"))
	})},
}

func SupportedChecksumTools() []string {
	tools := make([]string, 0, len(checksumHydrators)+len(sourceHydrators))
	for name := range checksumHydrators {
		tools = append(tools, name)
	}
	for name := range sourceHydrators {
		if _, ok := checksumHydrators[name]; ok {
			continue
		}
		tools = append(tools, name)
	}
	sort.Strings(tools)
	return tools
}

func HydrateLockChecksums(lock BundleLock, options LockHydrateOptions) (BundleLock, []LockHydrateReport, error) {
	if lock.Channels == nil {
		lock.Channels = make(map[string][]LockSpec)
	}
	fetch := options.Fetch
	if fetch == nil {
		client := &http.Client{Timeout: 30 * time.Second}
		fetch = func(url string) ([]byte, error) {
			res, err := client.Get(url)
			if err != nil {
				return nil, err
			}
			defer func() {
				_ = res.Body.Close()
			}()
			if res.StatusCode < 200 || res.StatusCode >= 300 {
				body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
				return nil, fmt.Errorf("unexpected HTTP %d from %s: %s", res.StatusCode, url, strings.TrimSpace(string(body)))
			}
			return io.ReadAll(res.Body)
		}
	}

	requested := make(map[string]struct{})
	for _, tool := range options.Tools {
		tool = strings.TrimSpace(strings.ToLower(tool))
		if tool == "" {
			continue
		}
		requested[tool] = struct{}{}
	}

	if len(requested) == 0 {
		for _, tool := range SupportedChecksumTools() {
			requested[tool] = struct{}{}
		}
	}

	reports := make([]LockHydrateReport, 0)
	seen := make(map[string]struct{})
	for channel, specs := range lock.Channels {
		for index := range specs {
			spec := &specs[index]
			name := strings.ToLower(strings.TrimSpace(spec.Name))
			if _, ok := requested[name]; !ok {
				continue
			}
			seen[name] = struct{}{}

			sourceUpdated := 0
			sourceCovered := strings.TrimSpace(spec.SourceIntegrity.Digest) != "" && strings.TrimSpace(spec.SourceIntegrity.Algorithm) != ""
			if hydrator, ok := sourceHydrators[name]; ok {
				source, err := hydrator.hydrate(strings.TrimSpace(spec.Version), fetch)
				if err == nil && strings.TrimSpace(source.Digest) != "" {
					if spec.SourceIntegrity != source {
						spec.SourceIntegrity = source
						sourceUpdated = 1
					}
					sourceCovered = true
				}
			}

			hydrator, ok := checksumHydrators[name]
			if !ok {
				checksumCleared := 0
				if len(spec.Checksums) > 0 {
					spec.Checksums = nil
					checksumCleared = 1
				}
				reports = append(reports, LockHydrateReport{
					Name:    spec.Name,
					Version: spec.Version,
					Channel: channel,
					Status:  sourceOnlyStatus(sourceUpdated, checksumCleared, sourceCovered),
					Updated: sourceUpdated + checksumCleared,
					Note:    sourceOnlyNote(sourceUpdated, checksumCleared, sourceCovered),
				})
				continue
			}

			updates, err := hydrator.hydrate(strings.TrimSpace(spec.Version), fetch)
			if err != nil {
				reports = append(reports, LockHydrateReport{
					Name:    spec.Name,
					Version: spec.Version,
					Channel: channel,
					Status:  "failed",
					Updated: sourceUpdated,
					Note:    appendHydrationNote(err.Error(), sourceUpdated),
				})
				continue
			}
			if len(updates) == 0 {
				reports = append(reports, LockHydrateReport{
					Name:    spec.Name,
					Version: spec.Version,
					Channel: channel,
					Status:  "failed",
					Updated: sourceUpdated,
					Note:    appendHydrationNote("no platform checksums found in upstream manifest", sourceUpdated),
				})
				continue
			}

			if spec.Checksums == nil {
				spec.Checksums = make(map[string]string)
			}
			updated := 0
			for platform, sum := range updates {
				if strings.TrimSpace(sum) == "" {
					continue
				}
				if spec.Checksums[platform] != sum {
					spec.Checksums[platform] = sum
					updated++
				}
			}

			status := "updated"
			if updated+sourceUpdated == 0 {
				status = "unchanged"
			}
			reports = append(reports, LockHydrateReport{
				Name:    spec.Name,
				Version: spec.Version,
				Channel: channel,
				Status:  status,
				Updated: updated + sourceUpdated,
				Note:    appendHydrationCounts(len(updates), sourceUpdated),
			})
		}
		lock.Channels[channel] = specs
	}

	for tool := range requested {
		if _, ok := seen[tool]; ok {
			continue
		}
		status := "unsupported"
		note := "tool not found in lock"
		if _, ok := checksumHydrators[tool]; ok {
			status = "skipped"
		}
		reports = append(reports, LockHydrateReport{
			Name:   tool,
			Status: status,
			Note:   note,
		})
	}

	sort.Slice(reports, func(i, j int) bool {
		if reports[i].Channel == reports[j].Channel {
			return reports[i].Name < reports[j].Name
		}
		return reports[i].Channel < reports[j].Channel
	})
	return lock, reports, nil
}

func parseChecksumManifest(body []byte, allowedExts []string, platformMapper func(string) (string, bool)) map[string]string {
	results := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sum := strings.TrimSpace(fields[0])
		name := strings.TrimSpace(fields[len(fields)-1])
		if !hasAllowedSuffix(name, allowedExts) {
			continue
		}
		platform, ok := platformMapper(name)
		if !ok || platform == "" {
			continue
		}
		results[platform] = sum
	}
	return results
}

func hydrateChecksumManifest(urlBuilder func(string) string, allowedExts []string, platformMapper func(string) (string, bool)) func(string, func(string) ([]byte, error)) (map[string]string, error) {
	return func(version string, fetch func(string) ([]byte, error)) (map[string]string, error) {
		url := urlBuilder(strings.TrimSpace(version))
		body, err := fetch(url)
		if err != nil {
			return nil, err
		}
		results := parseChecksumManifest(body, allowedExts, platformMapper)
		if len(results) == 0 {
			return nil, fmt.Errorf("no platform checksums found in upstream manifest")
		}
		return results, nil
	}
}

func hydrateGitHubReleaseAssetDigests(repo string, tagBuilder func(string) string, assetFilter func(string) bool, platformMapper func(string) (string, bool)) func(string, func(string) ([]byte, error)) (map[string]string, error) {
	return func(version string, fetch func(string) ([]byte, error)) (map[string]string, error) {
		tag := tagBuilder(strings.TrimSpace(version))
		url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, tag)
		body, err := fetch(url)
		if err != nil {
			return nil, err
		}
		var payload struct {
			Assets []struct {
				Name   string `json:"name"`
				Digest string `json:"digest"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		results := make(map[string]string)
		for _, asset := range payload.Assets {
			name := strings.TrimSpace(asset.Name)
			if assetFilter != nil && !assetFilter(name) {
				continue
			}
			platform, ok := platformMapper(name)
			if !ok || platform == "" {
				continue
			}
			algorithm, digest := splitColonDigest(asset.Digest)
			if algorithm != "sha256" || digest == "" {
				continue
			}
			results[platform] = digest
		}
		if len(results) == 0 {
			return nil, fmt.Errorf("no platform checksums found in GitHub release assets")
		}
		return results, nil
	}
}

func hasAllowedSuffix(name string, allowed []string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, suffix := range allowed {
		if strings.HasSuffix(lower, strings.ToLower(strings.TrimSpace(suffix))) {
			return true
		}
	}
	return false
}

func inferReleasePlatform(name string) (string, bool) {
	lower := strings.ToLower(name)

	var osName string
	switch {
	case strings.Contains(lower, "darwin"), strings.Contains(lower, "macos"):
		osName = "darwin"
	case strings.Contains(lower, "linux"):
		osName = "linux"
	case strings.Contains(lower, "windows"):
		osName = "windows"
	default:
		return "", false
	}

	var arch string
	switch {
	case strings.Contains(lower, "arm64"), strings.Contains(lower, "aarch64"):
		arch = "arm64"
	case strings.Contains(lower, "amd64"), strings.Contains(lower, "x64"), strings.Contains(lower, "x86_64"), strings.Contains(lower, "64bit"):
		arch = "amd64"
	case strings.Contains(lower, "armv6"), strings.Contains(lower, "armv7"), strings.Contains(lower, "_arm."), strings.Contains(lower, "_arm_"), strings.Contains(lower, "-arm."):
		arch = "arm"
	case strings.Contains(lower, "386"), strings.Contains(lower, "x32"), strings.Contains(lower, "32bit"):
		arch = "386"
	default:
		return "", false
	}

	return osName + "/" + arch, true
}

func inferCodeQLPlatform(name string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(lower, "linux64"):
		return "linux/amd64", true
	case strings.Contains(lower, "osx64"):
		return "darwin/amd64", true
	case strings.Contains(lower, "win64"):
		return "windows/amd64", true
	default:
		return "", false
	}
}

func hydratePyPISdist(pkg string) func(string, func(string) ([]byte, error)) (SourceIntegrity, error) {
	return func(version string, fetch func(string) ([]byte, error)) (SourceIntegrity, error) {
		url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", pkg, version)
		body, err := fetch(url)
		if err != nil {
			return SourceIntegrity{}, err
		}
		var payload struct {
			URLs []struct {
				Filename    string `json:"filename"`
				PackageType string `json:"packagetype"`
				URL         string `json:"url"`
				Digests     struct {
					SHA256 string `json:"sha256"`
				} `json:"digests"`
			} `json:"urls"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return SourceIntegrity{}, err
		}
		for _, item := range payload.URLs {
			if item.PackageType != "sdist" {
				continue
			}
			return SourceIntegrity{
				Kind:      "pypi-sdist",
				URL:       strings.TrimSpace(item.URL),
				Algorithm: "sha256",
				Digest:    strings.TrimSpace(item.Digests.SHA256),
			}, nil
		}
		return SourceIntegrity{}, fmt.Errorf("no sdist artifact found for %s %s", pkg, version)
	}
}

func hydratePyPISdistOrFirstWheel(pkg string) func(string, func(string) ([]byte, error)) (SourceIntegrity, error) {
	return func(version string, fetch func(string) ([]byte, error)) (SourceIntegrity, error) {
		url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", pkg, version)
		body, err := fetch(url)
		if err != nil {
			return SourceIntegrity{}, err
		}
		var payload struct {
			URLs []struct {
				Filename    string `json:"filename"`
				PackageType string `json:"packagetype"`
				URL         string `json:"url"`
				Digests     struct {
					SHA256 string `json:"sha256"`
				} `json:"digests"`
			} `json:"urls"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return SourceIntegrity{}, err
		}

		wheels := make([]struct {
			filename string
			url      string
			digest   string
		}, 0)
		for _, item := range payload.URLs {
			switch item.PackageType {
			case "sdist":
				return SourceIntegrity{
					Kind:      "pypi-sdist",
					URL:       strings.TrimSpace(item.URL),
					Algorithm: "sha256",
					Digest:    strings.TrimSpace(item.Digests.SHA256),
				}, nil
			case "bdist_wheel":
				wheels = append(wheels, struct {
					filename string
					url      string
					digest   string
				}{
					filename: strings.TrimSpace(item.Filename),
					url:      strings.TrimSpace(item.URL),
					digest:   strings.TrimSpace(item.Digests.SHA256),
				})
			}
		}
		if len(wheels) == 0 {
			return SourceIntegrity{}, fmt.Errorf("no sdist or wheel artifact found for %s %s", pkg, version)
		}
		sort.Slice(wheels, func(i, j int) bool { return wheels[i].filename < wheels[j].filename })
		return SourceIntegrity{
			Kind:      "pypi-wheel",
			URL:       wheels[0].url,
			Algorithm: "sha256",
			Digest:    wheels[0].digest,
		}, nil
	}
}

func hydrateNpmTarball(pkg string) func(string, func(string) ([]byte, error)) (SourceIntegrity, error) {
	return func(version string, fetch func(string) ([]byte, error)) (SourceIntegrity, error) {
		url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg, version)
		body, err := fetch(url)
		if err != nil {
			return SourceIntegrity{}, err
		}
		var payload struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Shasum    string `json:"shasum"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return SourceIntegrity{}, err
		}
		algorithm := ""
		digest := ""
		if strings.TrimSpace(payload.Dist.Integrity) != "" {
			algorithm, digest = splitNpmIntegrity(payload.Dist.Integrity)
		}
		if algorithm == "" && strings.TrimSpace(payload.Dist.Shasum) != "" {
			algorithm = "sha1"
			digest = strings.TrimSpace(payload.Dist.Shasum)
		}
		if algorithm == "" || digest == "" {
			return SourceIntegrity{}, fmt.Errorf("npm dist integrity metadata missing for %s %s", pkg, version)
		}
		return SourceIntegrity{
			Kind:      "npm-tarball",
			URL:       strings.TrimSpace(payload.Dist.Tarball),
			Algorithm: algorithm,
			Digest:    digest,
		}, nil
	}
}

func hydrateGoModule(urlPattern string) func(string, func(string) ([]byte, error)) (SourceIntegrity, error) {
	return func(version string, fetch func(string) ([]byte, error)) (SourceIntegrity, error) {
		trimmed := strings.TrimSpace(version)
		if !strings.HasPrefix(trimmed, "v") {
			trimmed = "v" + trimmed
		}
		url := fmt.Sprintf(urlPattern, trimmed)
		body, err := fetch(url)
		if err != nil {
			return SourceIntegrity{}, err
		}
		sum := sha256.Sum256(body)
		return SourceIntegrity{
			Kind:      "go-module-zip",
			URL:       url,
			Algorithm: "sha256",
			Digest:    hex.EncodeToString(sum[:]),
		}, nil
	}
}

func hydrateSourceDigestURL(kind string, urlBuilder func(string) string) func(string, func(string) ([]byte, error)) (SourceIntegrity, error) {
	return func(version string, fetch func(string) ([]byte, error)) (SourceIntegrity, error) {
		url := urlBuilder(strings.TrimSpace(version))
		body, err := fetch(url)
		if err != nil {
			return SourceIntegrity{}, err
		}
		sum := sha256.Sum256(body)
		return SourceIntegrity{
			Kind:      kind,
			URL:       url,
			Algorithm: "sha256",
			Digest:    hex.EncodeToString(sum[:]),
		}, nil
	}
}

func splitNpmIntegrity(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		return "", ""
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return parts[0], parts[1]
	}
	return parts[0], hex.EncodeToString(decoded)
}

func splitColonDigest(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func sourceOnlyStatus(sourceUpdated, checksumCleared int, sourceCovered bool) string {
	if sourceUpdated > 0 || checksumCleared > 0 {
		return "updated"
	}
	if sourceCovered {
		return "unchanged"
	}
	return "unsupported"
}

func sourceOnlyNote(sourceUpdated, checksumCleared int, sourceCovered bool) string {
	if sourceUpdated > 0 {
		if checksumCleared > 0 {
			return "source digest updated; release checksums cleared"
		}
		return "source digest updated"
	}
	if checksumCleared > 0 {
		return "release checksums cleared"
	}
	if sourceCovered {
		return "source digest already present"
	}
	return "no upstream checksum hydrator registered"
}

func appendHydrationNote(base string, sourceUpdated int) string {
	if sourceUpdated == 0 {
		return base
	}
	return fmt.Sprintf("%s; source digest updated", base)
}

func appendHydrationCounts(platformCount, sourceUpdated int) string {
	parts := make([]string, 0, 2)
	if platformCount > 0 {
		parts = append(parts, fmt.Sprintf("%d platform checksum(s)", platformCount))
	}
	if sourceUpdated > 0 {
		parts = append(parts, "source digest updated")
	}
	return strings.Join(parts, "; ")
}
