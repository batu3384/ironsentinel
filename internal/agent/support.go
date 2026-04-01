package agent

import (
	"fmt"
	"runtime"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func discoverSupportMatrix() domain.RuntimeSupportMatrix {
	return discoverSupportMatrixFor(runtime.GOOS, runtime.GOARCH)
}

func discoverSupportMatrixFor(goos, goarch string) domain.RuntimeSupportMatrix {
	matrix := domain.RuntimeSupportMatrix{
		OS:          goos,
		Arch:        goarch,
		Platform:    fmt.Sprintf("%s/%s", goos, goarch),
		Recommended: domain.CoverageCore,
		Tiers: []domain.RuntimeCoverageSupport{
			{Coverage: domain.CoverageCore, Level: domain.RuntimeSupportUnsupported, Notes: "unsupported platform"},
			{Coverage: domain.CoveragePremium, Level: domain.RuntimeSupportUnsupported, Notes: "unsupported platform"},
			{Coverage: domain.CoverageFull, Level: domain.RuntimeSupportUnsupported, Notes: "unsupported platform"},
		},
	}

	switch goos + "/" + goarch {
	case "darwin/arm64":
		matrix.Recommended = domain.CoveragePremium
		matrix.Tiers = []domain.RuntimeCoverageSupport{
			{Coverage: domain.CoverageCore, Level: domain.RuntimeSupportSupported, Notes: "portable built-in coverage"},
			{Coverage: domain.CoveragePremium, Level: domain.RuntimeSupportSupported, Notes: "best local operator experience"},
			{Coverage: domain.CoverageFull, Level: domain.RuntimeSupportSupported, Notes: "full scanner depth supported"},
		}
	case "darwin/amd64":
		matrix.Recommended = domain.CoveragePremium
		matrix.Tiers = []domain.RuntimeCoverageSupport{
			{Coverage: domain.CoverageCore, Level: domain.RuntimeSupportSupported, Notes: "portable built-in coverage"},
			{Coverage: domain.CoveragePremium, Level: domain.RuntimeSupportSupported, Notes: "supported with local or container runtime"},
			{Coverage: domain.CoverageFull, Level: domain.RuntimeSupportSupported, Notes: "full scanner depth supported"},
		}
	case "linux/amd64":
		matrix.Recommended = domain.CoverageFull
		matrix.Tiers = []domain.RuntimeCoverageSupport{
			{Coverage: domain.CoverageCore, Level: domain.RuntimeSupportSupported, Notes: "portable built-in coverage"},
			{Coverage: domain.CoveragePremium, Level: domain.RuntimeSupportSupported, Notes: "best fit for desktop and CI"},
			{Coverage: domain.CoverageFull, Level: domain.RuntimeSupportSupported, Notes: "preferred target for hardened container isolation"},
		}
	case "linux/arm64":
		matrix.Recommended = domain.CoveragePremium
		matrix.Tiers = []domain.RuntimeCoverageSupport{
			{Coverage: domain.CoverageCore, Level: domain.RuntimeSupportSupported, Notes: "portable built-in coverage"},
			{Coverage: domain.CoveragePremium, Level: domain.RuntimeSupportSupported, Notes: "supported and container-first for deeper scanners"},
			{Coverage: domain.CoverageFull, Level: domain.RuntimeSupportSupported, Notes: "full scanner depth supported"},
		}
	case "windows/amd64":
		matrix.Recommended = domain.CoveragePremium
		matrix.Tiers = []domain.RuntimeCoverageSupport{
			{Coverage: domain.CoverageCore, Level: domain.RuntimeSupportSupported, Notes: "portable built-in coverage"},
			{Coverage: domain.CoveragePremium, Level: domain.RuntimeSupportSupported, Notes: "supported local-first tier"},
			{Coverage: domain.CoverageFull, Level: domain.RuntimeSupportPartial, Notes: "active DAST and some deep scanners remain container-first"},
		}
	case "windows/arm64":
		matrix.Recommended = domain.CoverageCore
		matrix.Tiers = []domain.RuntimeCoverageSupport{
			{Coverage: domain.CoverageCore, Level: domain.RuntimeSupportSupported, Notes: "portable built-in coverage"},
			{Coverage: domain.CoveragePremium, Level: domain.RuntimeSupportPartial, Notes: "prefer container bundle when available"},
			{Coverage: domain.CoverageFull, Level: domain.RuntimeSupportPartial, Notes: "use container-first execution"},
		}
	}

	return matrix
}
