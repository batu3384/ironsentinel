package agent

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestParseIsolationModeDefaultsToAuto(t *testing.T) {
	if got := parseIsolationMode(""); got != domain.IsolationAuto {
		t.Fatalf("expected auto, got %s", got)
	}
	if got := parseIsolationMode("container"); got != domain.IsolationContainer {
		t.Fatalf("expected container, got %s", got)
	}
	if got := parseIsolationMode("local"); got != domain.IsolationLocal {
		t.Fatalf("expected local, got %s", got)
	}
}

func TestValidateIsolationRequestFailsWhenContainerUnavailable(t *testing.T) {
	cfg := config.Config{
		MirrorDir:       filepath.Join(t.TempDir(), "mirrors"),
		SandboxMode:     string(domain.IsolationContainer),
		ContainerEngine: "missing-engine",
		ContainerImage:  "example.invalid/ironsentinel:latest",
	}
	err := validateIsolationRequest(cfg, domain.ScanProfile{Isolation: domain.IsolationContainer})
	if err == nil {
		t.Fatalf("expected isolation validation to fail")
	}
}

func TestTranslateArtifactPathForContainer(t *testing.T) {
	got := translateArtifactPath("/artifacts/gitleaks.json", "/tmp/output/run-1")
	want := "/tmp/output/run-1/gitleaks.json"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestResolveIsolationContractForContainerDefaults(t *testing.T) {
	cfg := config.Config{
		SandboxMode: string(domain.IsolationContainer),
		OfflineMode: true,
	}

	contract := resolveIsolationContract(cfg, domain.ScanProfile{
		Mode:       domain.ModeSafe,
		Isolation:  domain.IsolationContainer,
		AllowBuild: false,
	})

	if contract.Mode != domain.IsolationLocal {
		t.Fatalf("expected missing container runtime to fall back to local execution, got %s", contract.Mode)
	}

	containerContract := domain.ResolveIsolationContract(domain.ScanProfile{
		Mode:       domain.ModeDeep,
		Isolation:  domain.IsolationContainer,
		AllowBuild: true,
	}, domain.IsolationContainer, true)
	if containerContract.NetworkPolicy != domain.IsolationNetworkNone {
		t.Fatalf("expected offline mode to disable network, got %s", containerContract.NetworkPolicy)
	}
	if !containerContract.RootfsReadOnly || !containerContract.WorkspaceReadOnly || !containerContract.ArtifactWritable {
		t.Fatalf("expected container contract to harden rootfs/workspace/artifacts: %+v", containerContract)
	}
	if containerContract.MemoryMiB < 3072 {
		t.Fatalf("expected deep build contract to increase memory, got %d", containerContract.MemoryMiB)
	}
}

func TestModuleExecutionBuildAppliesHardeningFlags(t *testing.T) {
	command := exec.Command("semgrep", "--json")
	execution := moduleExecution{
		mode:       domain.IsolationContainer,
		contract:   domain.ResolveIsolationContract(domain.ScanProfile{Mode: domain.ModeSafe}, domain.IsolationContainer, false),
		engine:     "docker",
		enginePath: "docker",
		image:      "example.invalid/ironsentinel:latest",
		mirrorDir:  "/tmp/mirror",
	}

	wrapped := execution.build(command, "/tmp/workspace", "/tmp/output")
	args := strings.Join(wrapped.Args, " ")

	for _, fragment := range []string{
		"--read-only",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--network none",
		"--tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m",
		"--tmpfs /run:rw,noexec,nosuid,nodev,size=32m",
		"--tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=128m",
		"-v /tmp/workspace:/workspace:ro",
		"-v /tmp/output:/artifacts:rw",
		"-v /tmp/mirror:/mirror:ro",
		"-e PATH=/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"--entrypoint /bin/bash",
		"export HOME=/artifacts/.runtime/home",
		"export XDG_CACHE_HOME=/artifacts/.runtime/cache",
	} {
		if !strings.Contains(args, fragment) {
			t.Fatalf("expected wrapped args to contain %q, got %s", fragment, args)
		}
	}

	containerCommand := exec.Command("zaproxy", "-cmd")
	networked := execution
	networked.contract = domain.ResolveIsolationContract(domain.ScanProfile{Mode: domain.ModeActive, AllowNetwork: true}, domain.IsolationContainer, false)
	wrappedNetworked := networked.build(containerCommand, "/tmp/workspace", "/tmp/output")
	if !strings.Contains(strings.Join(wrappedNetworked.Args, " "), "--add-host host.docker.internal:host-gateway") {
		t.Fatalf("expected networked container args to include host-gateway mapping, got %s", strings.Join(wrappedNetworked.Args, " "))
	}
}

func TestStartDaemonHeartbeatPersistsStatus(t *testing.T) {
	cfg := config.Config{
		DataDir: filepath.Join(t.TempDir(), "data"),
	}

	stop, err := startDaemonHeartbeatWithMeta(cfg, "once", domain.RuntimeDaemon{})
	if err != nil {
		t.Fatalf("start daemon heartbeat: %v", err)
	}

	running := discoverDaemon(cfg)
	if !running.Active {
		t.Fatalf("expected daemon to be active")
	}
	if running.PID == 0 {
		t.Fatalf("expected daemon pid to be recorded")
	}
	if running.Mode != "once" {
		t.Fatalf("expected daemon mode once, got %s", running.Mode)
	}

	stop("stopped for test")

	stopped := discoverDaemon(cfg)
	if stopped.Active {
		t.Fatalf("expected daemon to be inactive after stop")
	}
	if stopped.Notes != "stopped for test" {
		t.Fatalf("expected daemon note to be persisted, got %q", stopped.Notes)
	}
}

func TestDiscoverDaemonMarksStaleHeartbeat(t *testing.T) {
	cfg := config.Config{
		DataDir: filepath.Join(t.TempDir(), "data"),
	}
	started := time.Now().UTC().Add(-2 * time.Minute)
	heartbeat := time.Now().UTC().Add(-2 * daemonHeartbeatTTL)
	if err := saveDaemonStatus(cfg, domain.RuntimeDaemon{
		PID:           42,
		Mode:          "continuous",
		Active:        true,
		StartedAt:     &started,
		LastHeartbeat: &heartbeat,
	}); err != nil {
		t.Fatalf("save daemon status: %v", err)
	}

	status := discoverDaemon(cfg)
	if !status.Stale {
		t.Fatalf("expected daemon status to be stale")
	}
	if status.Active {
		t.Fatalf("expected stale daemon to be treated as inactive")
	}
}

func TestDaemonMetadataUpdatesPersistAcrossHeartbeat(t *testing.T) {
	cfg := config.Config{
		DataDir: filepath.Join(t.TempDir(), "data"),
	}
	stop, err := startDaemonHeartbeatWithMeta(cfg, "continuous", domain.RuntimeDaemon{
		ScheduleInterval: "1h",
		DriftDetection:   true,
	})
	if err != nil {
		t.Fatalf("start daemon heartbeat with meta: %v", err)
	}
	defer stop("done")

	scheduledAt := time.Now().UTC()
	if err := UpdateDaemonSchedule(cfg, scheduledAt, "scheduled 2 scan(s)"); err != nil {
		t.Fatalf("update daemon schedule: %v", err)
	}
	notifiedAt := time.Now().UTC()
	if err := UpdateDaemonNotification(cfg, notifiedAt, "notified"); err != nil {
		t.Fatalf("update daemon notification: %v", err)
	}

	time.Sleep(1200 * time.Millisecond)

	status := discoverDaemon(cfg)
	if status.ScheduleInterval != "1h" {
		t.Fatalf("expected schedule interval to survive heartbeat, got %q", status.ScheduleInterval)
	}
	if !status.DriftDetection {
		t.Fatalf("expected drift detection metadata to persist")
	}
	if status.LastScheduledAt == nil || status.LastNotificationAt == nil {
		t.Fatalf("expected schedule and notification timestamps to persist: %+v", status)
	}
}

func TestContainerHostSupportsIsolationAllowsDockerDesktopHosts(t *testing.T) {
	if !containerHostSupportsIsolation("docker", true) {
		t.Fatalf("expected rootless docker to be supported")
	}
	if !containerHostSupportsIsolation("docker", false) && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Fatalf("expected docker desktop host to be supported on %s", runtime.GOOS)
	}
	if containerHostSupportsIsolation("podman", false) {
		t.Fatalf("expected non-rootless podman host to be unsupported")
	}
}
