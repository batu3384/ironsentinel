package agent

import (
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestDiscoverSupportMatrixForKnownPlatforms(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		goarch       string
		recommended  domain.CoverageProfile
		fullExpected domain.RuntimeSupportLevel
	}{
		{
			name:         "linux amd64 full supported",
			goos:         "linux",
			goarch:       "amd64",
			recommended:  domain.CoverageFull,
			fullExpected: domain.RuntimeSupportSupported,
		},
		{
			name:         "windows amd64 full partial",
			goos:         "windows",
			goarch:       "amd64",
			recommended:  domain.CoveragePremium,
			fullExpected: domain.RuntimeSupportPartial,
		},
		{
			name:         "unsupported platform defaults",
			goos:         "freebsd",
			goarch:       "amd64",
			recommended:  domain.CoverageCore,
			fullExpected: domain.RuntimeSupportUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matrix := discoverSupportMatrixFor(tt.goos, tt.goarch)
			if matrix.Platform != tt.goos+"/"+tt.goarch {
				t.Fatalf("expected platform %s/%s, got %s", tt.goos, tt.goarch, matrix.Platform)
			}
			if matrix.Recommended != tt.recommended {
				t.Fatalf("expected recommended %s, got %s", tt.recommended, matrix.Recommended)
			}
			full, ok := matrix.Coverage(domain.CoverageFull)
			if !ok {
				t.Fatalf("expected full coverage entry")
			}
			if full.Level != tt.fullExpected {
				t.Fatalf("expected full level %s, got %s", tt.fullExpected, full.Level)
			}
		})
	}
}
