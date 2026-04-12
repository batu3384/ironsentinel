package agent

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestBuildSandboxEnvStripsSecrets(t *testing.T) {
	t.Setenv("PATH", os.Getenv("PATH"))
	t.Setenv("HOME", "/tmp/home")
	t.Setenv("GITHUB_TOKEN", "secret-value")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-value")

	env := buildSandboxEnv(domain.ScanProfile{
		Mode:         domain.ModeSafe,
		AllowBuild:   false,
		AllowNetwork: false,
	})
	keys := envKeys(env)

	if slices.Contains(keys, "GITHUB_TOKEN") {
		t.Fatalf("sandbox env should strip GITHUB_TOKEN")
	}
	if slices.Contains(keys, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("sandbox env should strip AWS_SECRET_ACCESS_KEY")
	}
	if !slices.Contains(keys, "IRONSENTINEL_SCAN_MODE") {
		t.Fatalf("sandbox env should include IRONSENTINEL_SCAN_MODE")
	}

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "IRONSENTINEL_ALLOW_BUILD=false") {
		t.Fatalf("sandbox env should record allow-build flag")
	}
	if !strings.Contains(joined, "IRONSENTINEL_ALLOW_NETWORK=false") {
		t.Fatalf("sandbox env should record allow-network flag")
	}
}
