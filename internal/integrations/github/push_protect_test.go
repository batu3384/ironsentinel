package github

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallPrePushHookWritesManagedScript(t *testing.T) {
	repo := initGitTestRepo(t)

	hookPath, err := InstallPrePushHook(repo, "/usr/local/bin/ironsentinel", false)
	if err != nil {
		t.Fatalf("install pre-push hook: %v", err)
	}

	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}

	text := string(body)
	for _, want := range []string{
		"Managed by IronSentinel",
		"github push-protect",
		"/usr/local/bin/ironsentinel",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected hook to contain %q, got %q", want, text)
		}
	}
}

func TestCollectOutgoingCommitBlobsIncludesSecretsFromUnpushedHistory(t *testing.T) {
	repo := initGitTestRepo(t)
	writeFile(t, filepath.Join(repo, "README.md"), []byte("base\n"))
	gitRun(t, repo, "add", "README.md")
	gitRun(t, repo, "commit", "-m", "base")

	writeFile(t, filepath.Join(repo, "secret.txt"), []byte(fakeGitHubPAT()+"\n"))
	gitRun(t, repo, "add", "secret.txt")
	gitRun(t, repo, "commit", "-m", "add secret")
	secretCommit := strings.TrimSpace(gitOutput(t, repo, "rev-parse", "HEAD"))

	if err := os.Remove(filepath.Join(repo, "secret.txt")); err != nil {
		t.Fatalf("remove secret file: %v", err)
	}
	gitRun(t, repo, "add", "-u")
	gitRun(t, repo, "commit", "-m", "remove secret")
	head := strings.TrimSpace(gitOutput(t, repo, "rev-parse", "HEAD"))

	blobs, err := CollectOutgoingCommitBlobs(repo, []PushRefUpdate{{
		LocalRef:  "refs/heads/main",
		LocalSHA:  head,
		RemoteRef: "refs/heads/main",
		RemoteSHA: strings.Repeat("0", 40),
	}}, nil)
	if err != nil {
		t.Fatalf("collect outgoing commit blobs: %v", err)
	}

	found := false
	for _, blob := range blobs {
		if blob.CommitSHA == secretCommit && blob.Path == "secret.txt" && strings.Contains(string(blob.Content), "ghp_") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected outgoing blob collection to include secret.txt from the unpushed secret commit")
	}
}

func fakeGitHubPAT() string {
	return strings.Join([]string{"gh", "p_", strings.Repeat("a", 32)}, "")
}

func initGitTestRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitRun(t, repo, "init", "-b", "main")
	gitRun(t, repo, "config", "user.name", "IronSentinel Tests")
	gitRun(t, repo, "config", "user.email", "tests@ironsentinel.local")
	return repo
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, string(out))
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}
