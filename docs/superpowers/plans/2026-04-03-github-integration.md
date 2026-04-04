# GitHub Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a first-class `ironsentinel github` command family that uploads SARIF to GitHub code scanning and submits dependency snapshots to the GitHub dependency graph without changing existing `scan`, `runs`, `export`, or TUI behavior.

**Architecture:** Keep all GitHub API logic in a new `internal/integrations/github` package. CLI code in `internal/cli` should only resolve run/project references, build canonical payloads from existing services, and call the integration client. SARIF must reuse `BuildRunReport` + `reports.Export`, while dependency submission must reuse project/run metadata and planner-derived stack/module context.

**Tech Stack:** Go, Cobra, existing `internal/core` service layer, canonical `RunReport`, planner registry, `httptest`, GitHub REST API.

---

### Task 1: Build the GitHub integration boundary

**Files:**
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/client.go`
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/auth.go`
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/repository.go`
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/client_test.go`

- [ ] **Step 1: Write the failing tests for auth, repo, ref, and sha resolution**

```go
package github

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTokenPrefersGitHubToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghs-primary")
	t.Setenv("GH_TOKEN", "ghs-secondary")

	token, source, err := ResolveToken(context.Background(), execTokenProvider(func(context.Context) (string, error) {
		return "ghs-cli", nil
	}))
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "ghs-primary" || source != "env:GITHUB_TOKEN" {
		t.Fatalf("unexpected token resolution: token=%q source=%q", token, source)
	}
}

func TestResolveRepositoryUsesOverrideBeforeGitOrigin(t *testing.T) {
	repo, err := ResolveRepository("/tmp/worktree", "batu3384/ironsentinel", execGitProvider(func(dir string, args ...string) (string, error) {
		t.Fatalf("git should not be called when override is present")
		return "", nil
	}))
	if err != nil {
		t.Fatalf("resolve repository: %v", err)
	}
	if repo.Owner != "batu3384" || repo.Name != "ironsentinel" {
		t.Fatalf("unexpected repo: %+v", repo)
	}
}

func TestResolveGitMetadataFallsBackToHead(t *testing.T) {
	dir := t.TempDir()
	sha, ref, err := ResolveGitMetadata(dir, "", "", execGitProvider(func(_ string, args ...string) (string, error) {
		switch {
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "HEAD":
			return "abc123def456", nil
		case len(args) >= 3 && args[0] == "symbolic-ref" && args[1] == "--quiet" && args[2] == "--short":
			return "main", nil
		default:
			return "", os.ErrNotExist
		}
	}))
	if err != nil {
		t.Fatalf("resolve git metadata: %v", err)
	}
	if sha != "abc123def456" || ref != "refs/heads/main" {
		t.Fatalf("unexpected git metadata: sha=%q ref=%q", sha, ref)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/integrations/github -run 'TestResolve(TokenPrefersGitHubToken|RepositoryUsesOverrideBeforeGitOrigin|GitMetadataFallsBackToHead)' -count=1
```

Expected: FAIL with undefined symbols such as `ResolveToken`, `ResolveRepository`, and `ResolveGitMetadata`.

- [ ] **Step 3: Implement the minimal GitHub client boundary**

```go
// /Users/batuhanyuksel/Documents/security/internal/integrations/github/client.go
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

func NewClient(token string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("missing GitHub token")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		baseURL:    "https://api.github.com",
		httpClient: httpClient,
		token:      token,
	}, nil
}

func (c *Client) postJSON(ctx context.Context, path string, body any) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}

func readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(data))
}
```

```go
// /Users/batuhanyuksel/Documents/security/internal/integrations/github/auth.go
package github

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type tokenProvider interface {
	Token(context.Context) (string, error)
}

type execTokenProvider func(context.Context) (string, error)

func (p execTokenProvider) Token(ctx context.Context) (string, error) { return p(ctx) }

func ResolveToken(ctx context.Context, provider tokenProvider) (string, string, error) {
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		return token, "env:GITHUB_TOKEN", nil
	}
	if token := strings.TrimSpace(os.Getenv("GH_TOKEN")); token != "" {
		return token, "env:GH_TOKEN", nil
	}
	if provider == nil {
		provider = execTokenProvider(func(ctx context.Context) (string, error) {
			out, err := exec.CommandContext(ctx, "gh", "auth", "token").CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("gh auth token: %w", err)
			}
			return strings.TrimSpace(string(out)), nil
		})
	}
	token, err := provider.Token(ctx)
	if err != nil || strings.TrimSpace(token) == "" {
		return "", "", fmt.Errorf("github auth token not found; set GITHUB_TOKEN or login with gh auth login")
	}
	return strings.TrimSpace(token), "gh auth token", nil
}
```

```go
// /Users/batuhanyuksel/Documents/security/internal/integrations/github/repository.go
package github

import (
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
)

type Repository struct {
	Owner string
	Name  string
}

type gitProvider interface {
	Run(dir string, args ...string) (string, error)
}

type execGitProvider func(dir string, args ...string) (string, error)

func (p execGitProvider) Run(dir string, args ...string) (string, error) { return p(dir, args...) }

func ResolveRepository(workdir, override string, git gitProvider) (Repository, error) {
	if strings.TrimSpace(override) != "" {
		return parseRepositoryOverride(override)
	}
	if git == nil {
		git = execGitProvider(func(dir string, args ...string) (string, error) {
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
			}
			return strings.TrimSpace(string(out)), nil
		})
	}
	remote, err := git.Run(filepath.Clean(workdir), "remote", "get-url", "origin")
	if err != nil {
		return Repository{}, fmt.Errorf("could not resolve GitHub repository from origin remote; use --repo owner/name")
	}
	return parseRepositoryRemote(remote)
}

func ResolveGitMetadata(workdir, shaOverride, refOverride string, git gitProvider) (sha string, ref string, err error) {
	if git == nil {
		git = execGitProvider(func(dir string, args ...string) (string, error) {
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(out)), nil
		})
	}
	if strings.TrimSpace(shaOverride) != "" {
		sha = strings.TrimSpace(shaOverride)
	} else if sha, err = git.Run(filepath.Clean(workdir), "rev-parse", "HEAD"); err != nil || sha == "" {
		return "", "", fmt.Errorf("could not resolve git sha; use --sha")
	}
	if strings.TrimSpace(refOverride) != "" {
		return sha, strings.TrimSpace(refOverride), nil
	}
	branch, err := git.Run(filepath.Clean(workdir), "symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil && strings.TrimSpace(branch) != "" {
		return sha, "refs/heads/" + strings.TrimSpace(branch), nil
	}
	return sha, "HEAD", nil
}

func parseRepositoryOverride(value string) (Repository, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Repository{}, fmt.Errorf("invalid repo %q; expected owner/name", value)
	}
	return Repository{Owner: parts[0], Name: parts[1]}, nil
}

func parseRepositoryRemote(remote string) (Repository, error) {
	remote = strings.TrimSpace(remote)
	if strings.HasPrefix(remote, "git@github.com:") {
		return parseRepositoryOverride(strings.TrimSuffix(strings.TrimPrefix(remote, "git@github.com:"), ".git"))
	}
	if strings.HasPrefix(remote, "https://") || strings.HasPrefix(remote, "http://") {
		u, err := url.Parse(remote)
		if err != nil {
			return Repository{}, err
		}
		return parseRepositoryOverride(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"))
	}
	return Repository{}, fmt.Errorf("unsupported origin remote %q; use --repo", remote)
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/integrations/github -run 'TestResolve(TokenPrefersGitHubToken|RepositoryUsesOverrideBeforeGitOrigin|GitMetadataFallsBackToHead)' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/batuhanyuksel/Documents/security/internal/integrations/github/client.go \
        /Users/batuhanyuksel/Documents/security/internal/integrations/github/auth.go \
        /Users/batuhanyuksel/Documents/security/internal/integrations/github/repository.go \
        /Users/batuhanyuksel/Documents/security/internal/integrations/github/client_test.go
git commit -m "feat: add GitHub integration client boundary"
```

### Task 2: Add SARIF upload support and CLI command wiring

**Files:**
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/sarif.go`
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/sarif_test.go`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/app.go`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/root_command.go`
- Test: `/Users/batuhanyuksel/Documents/security/internal/cli/app_test.go`

- [ ] **Step 1: Write the failing SARIF client and CLI tests**

```go
func TestUploadSARIFPostsCanonicalPayload(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"upload-1"}`))
	}))
	defer server.Close()

	client, err := NewClient("ghs-test", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.baseURL = server.URL

	repo := Repository{Owner: "batu3384", Name: "ironsentinel"}
	err = client.UploadSARIF(context.Background(), repo, SARIFUploadRequest{
		CommitSHA: "abc123",
		Ref:       "refs/heads/main",
		SARIF:     `{"version":"2.1.0"}`,
	})
	if err != nil {
		t.Fatalf("upload sarif: %v", err)
	}
	if !strings.Contains(body, "\"commit_sha\":\"abc123\"") {
		t.Fatalf("expected commit sha in request body: %s", body)
	}
	if !strings.Contains(body, "\"sarif\":\"eyJ2ZXJzaW9uIjoiMi4xLjAifQ==\"") {
		t.Fatalf("expected base64 sarif payload in request body: %s", body)
	}
}

func TestGitHubUploadSARIFCommandRequiresToken(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	cmd := app.githubCommand()
	cmd.SetArgs([]string{"upload-sarif", run.ID, "--repo", "batu3384/ironsentinel"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "github auth token not found") {
		t.Fatalf("expected auth error, got %v", err)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/integrations/github ./internal/cli -run 'Test(UploadSARIFPostsCanonicalPayload|GitHubUploadSARIFCommandRequiresToken)' -count=1
```

Expected: FAIL with undefined `UploadSARIF`, `SARIFUploadRequest`, or missing `githubCommand`.

- [ ] **Step 3: Implement SARIF upload and the `github upload-sarif` command**

```go
// /Users/batuhanyuksel/Documents/security/internal/integrations/github/sarif.go
package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
)

type SARIFUploadRequest struct {
	CommitSHA string
	Ref       string
	SARIF     string
	Category  string
}

func (c *Client) UploadSARIF(ctx context.Context, repo Repository, req SARIFUploadRequest) error {
	payload := map[string]any{
		"commit_sha": req.CommitSHA,
		"ref":        req.Ref,
		"sarif":      base64.StdEncoding.EncodeToString([]byte(req.SARIF)),
	}
	if req.Category != "" {
		payload["category"] = req.Category
	}
	resp, err := c.postJSON(ctx, fmt.Sprintf("/repos/%s/%s/code-scanning/sarifs", repo.Owner, repo.Name), payload)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusAccepted {
		return mapHTTPError("sarif upload", repo, resp)
	}
	_ = readBody(resp)
	return nil
}
```

```go
// excerpt for /Users/batuhanyuksel/Documents/security/internal/cli/app.go
func (a *App) githubCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "github",
		Short: "GitHub publishing",
	}
	cmd.AddCommand(a.githubUploadSARIFCommand())
	cmd.AddCommand(a.githubSubmitDepsCommand())
	return cmd
}

func (a *App) githubUploadSARIFCommand() *cobra.Command {
	var repoFlag, refFlag, shaFlag, baselineFlag string
	command := &cobra.Command{
		Use:   "upload-sarif [run-id]",
		Short: "Upload SARIF to GitHub code scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := strings.TrimSpace(args[0])
			report, err := a.service.BuildRunReport(runID, baselineFlag)
			if err != nil {
				return err
			}
			sarif, err := reports.Export("sarif", report)
			if err != nil {
				return err
			}
			token, _, err := ghint.ResolveToken(cmd.Context(), nil)
			if err != nil {
				return err
			}
			repo, err := ghint.ResolveRepository(a.cwd, repoFlag, nil)
			if err != nil {
				return err
			}
			sha, ref, err := ghint.ResolveGitMetadata(a.cwd, shaFlag, refFlag, nil)
			if err != nil {
				return err
			}
			client, err := ghint.NewClient(token, nil)
			if err != nil {
				return err
			}
			if err := client.UploadSARIF(cmd.Context(), repo, ghint.SARIFUploadRequest{
				CommitSHA: sha,
				Ref:       ref,
				SARIF:     sarif,
				Category:  "ironsentinel/" + runID,
			}); err != nil {
				return err
			}
			pterm.Success.Printf("Uploaded SARIF for %s to %s/%s\n", runID, repo.Owner, repo.Name)
			return nil
		},
	}
	command.Flags().StringVar(&repoFlag, "repo", "", "GitHub repository in owner/name form")
	command.Flags().StringVar(&refFlag, "ref", "", "Git ref override")
	command.Flags().StringVar(&shaFlag, "sha", "", "Commit SHA override")
	command.Flags().StringVar(&baselineFlag, "baseline", "", "Explicit baseline run ID")
	return command
}
```

```go
// excerpt for /Users/batuhanyuksel/Documents/security/internal/cli/root_command.go
root.AddCommand(a.githubCommand())
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/integrations/github ./internal/cli -run 'Test(UploadSARIFPostsCanonicalPayload|GitHubUploadSARIFCommandRequiresToken)' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/batuhanyuksel/Documents/security/internal/integrations/github/sarif.go \
        /Users/batuhanyuksel/Documents/security/internal/integrations/github/sarif_test.go \
        /Users/batuhanyuksel/Documents/security/internal/cli/app.go \
        /Users/batuhanyuksel/Documents/security/internal/cli/root_command.go \
        /Users/batuhanyuksel/Documents/security/internal/cli/app_test.go
git commit -m "feat: add GitHub SARIF upload command"
```

### Task 3: Add dependency submission support

**Files:**
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/deps.go`
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/deps_test.go`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/app.go`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/app_test.go`

- [ ] **Step 1: Write the failing dependency submission tests**

```go
func TestBuildDependencySnapshotIncludesDetectorAndManifest(t *testing.T) {
	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "ironsentinel",
		Path:           "/workspace/ironsentinel",
		DetectedStacks: []string{"go", "terraform"},
	}
	run := domain.ScanRun{ID: "run-1", ProjectID: "prj-1"}
	manifest, err := BuildDependencySnapshot(project, &run, []string{"go", "terraform"}, []DependencyPackage{
		{Name: "github.com/spf13/cobra", Version: "1.9.1", Ecosystem: "go"},
	})
	if err != nil {
		t.Fatalf("build dependency snapshot: %v", err)
	}
	if manifest.Detector.Name != "ironsentinel" {
		t.Fatalf("expected ironsentinel detector, got %+v", manifest.Detector)
	}
	if len(manifest.Manifests) != 1 {
		t.Fatalf("expected one manifest, got %d", len(manifest.Manifests))
	}
}

func TestGitHubSubmitDepsCommandFailsWithoutDependencyInventory(t *testing.T) {
	app, _, _, project := newFocusedRunFilterFixture(t)
	cmd := app.githubCommand()
	cmd.SetArgs([]string{"submit-deps", project.ID, "--repo", "batu3384/ironsentinel"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no dependency inventory available") {
		t.Fatalf("expected dependency inventory error, got %v", err)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/integrations/github ./internal/cli -run 'Test(BuildDependencySnapshotIncludesDetectorAndManifest|GitHubSubmitDepsCommandFailsWithoutDependencyInventory)' -count=1
```

Expected: FAIL with undefined `BuildDependencySnapshot`, `DependencyPackage`, or `github submit-deps` behavior.

- [ ] **Step 3: Implement dependency snapshot generation and CLI submission**

```go
// /Users/batuhanyuksel/Documents/security/internal/integrations/github/deps.go
package github

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type DependencyPackage struct {
	Name      string
	Version   string
	Ecosystem string
}

type DependencySnapshot struct {
	Version   int                    `json:"version"`
	Sha       string                 `json:"sha"`
	Ref       string                 `json:"ref"`
	Detector  map[string]string      `json:"detector"`
	Job       map[string]string      `json:"job"`
	Scanned   string                 `json:"scanned"`
	Manifests map[string]any         `json:"manifests"`
	Metadata  map[string]any         `json:"metadata,omitempty"`
}

func BuildDependencySnapshot(project domain.Project, run *domain.ScanRun, stacks []string, packages []DependencyPackage) (DependencySnapshot, error) {
	if len(packages) == 0 {
		return DependencySnapshot{}, fmt.Errorf("no dependency inventory available")
	}
	resolved := make(map[string]any, len(packages))
	for _, pkg := range packages {
		resolved[pkg.Name] = map[string]any{
			"package_url": fmt.Sprintf("pkg:%s/%s@%s", pkg.Ecosystem, pkg.Name, pkg.Version),
			"relationship": "direct",
		}
	}
	manifestKey := filepath.Base(project.Path)
	if manifestKey == "" {
		manifestKey = project.ID
	}
	return DependencySnapshot{
		Version: 0,
		Detector: map[string]string{
			"name":    "ironsentinel",
			"url":     "https://github.com/batu3384/ironsentinel",
			"version": "dev",
		},
		Job: map[string]string{
			"id": "ironsentinel-dependency-submission",
		},
		Scanned: time.Now().UTC().Format(time.RFC3339),
		Manifests: map[string]any{
			manifestKey: map[string]any{
				"name":     project.DisplayName,
				"file":     manifestKey,
				"resolved": resolved,
			},
		},
		Metadata: map[string]any{
			"projectId": project.ID,
			"runId":     func() string { if run == nil { return "" }; return run.ID }(),
			"stacks":    stacks,
		},
	}, nil
}

func (c *Client) SubmitDependencies(ctx context.Context, repo Repository, snapshot DependencySnapshot) error {
	resp, err := c.postJSON(ctx, fmt.Sprintf("/repos/%s/%s/dependency-graph/snapshots", repo.Owner, repo.Name), snapshot)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		return mapHTTPError("dependency submission", repo, resp)
	}
	_ = readBody(resp)
	return nil
}
```

```go
// excerpt for /Users/batuhanyuksel/Documents/security/internal/cli/app.go
func (a *App) githubSubmitDepsCommand() *cobra.Command {
	var repoFlag, refFlag, shaFlag, runIDFlag string
	command := &cobra.Command{
		Use:   "submit-deps [project-id]",
		Short: "Submit dependencies to the GitHub dependency graph",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := ""
			if len(args) > 0 {
				projectID = strings.TrimSpace(args[0])
			}
			project, run, packages, err := a.githubDependencyInventory(projectID, runIDFlag)
			if err != nil {
				return err
			}
			token, _, err := ghint.ResolveToken(cmd.Context(), nil)
			if err != nil {
				return err
			}
			repo, err := ghint.ResolveRepository(a.cwd, repoFlag, nil)
			if err != nil {
				return err
			}
			sha, ref, err := ghint.ResolveGitMetadata(a.cwd, shaFlag, refFlag, nil)
			if err != nil {
				return err
			}
			snapshot, err := ghint.BuildDependencySnapshot(project, run, project.DetectedStacks, packages)
			if err != nil {
				return err
			}
			snapshot.Sha = sha
			snapshot.Ref = ref
			client, err := ghint.NewClient(token, nil)
			if err != nil {
				return err
			}
			if err := client.SubmitDependencies(cmd.Context(), repo, snapshot); err != nil {
				return err
			}
			pterm.Success.Printf("Submitted dependency snapshot for %s to %s/%s\n", project.DisplayName, repo.Owner, repo.Name)
			return nil
		},
	}
	command.Flags().StringVar(&repoFlag, "repo", "", "GitHub repository in owner/name form")
	command.Flags().StringVar(&refFlag, "ref", "", "Git ref override")
	command.Flags().StringVar(&shaFlag, "sha", "", "Commit SHA override")
	command.Flags().StringVar(&runIDFlag, "run", "", "Run ID to source dependency inventory from")
	return command
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/integrations/github ./internal/cli -run 'Test(BuildDependencySnapshotIncludesDetectorAndManifest|GitHubSubmitDepsCommandFailsWithoutDependencyInventory)' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/batuhanyuksel/Documents/security/internal/integrations/github/deps.go \
        /Users/batuhanyuksel/Documents/security/internal/integrations/github/deps_test.go \
        /Users/batuhanyuksel/Documents/security/internal/cli/app.go \
        /Users/batuhanyuksel/Documents/security/internal/cli/app_test.go
git commit -m "feat: add GitHub dependency submission command"
```

### Task 4: Finalize help, docs, and end-to-end verification

**Files:**
- Modify: `/Users/batuhanyuksel/Documents/security/README.md`
- Modify: `/Users/batuhanyuksel/Documents/security/docs/architecture.md`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/app_test.go`

- [ ] **Step 1: Write the failing help and docs tests**

```go
func TestGitHubCommandAppearsInRootHelp(t *testing.T) {
	app := newTestApp(t)
	root := app.RootCommand()
	buffer := new(bytes.Buffer)
	root.SetOut(buffer)
	root.SetErr(buffer)
	root.SetArgs([]string{"--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root help: %v", err)
	}
	output := buffer.String()
	if !strings.Contains(output, "github") {
		t.Fatalf("expected github command in root help, got:\n%s", output)
	}
	if !strings.Contains(output, "upload-sarif") {
		t.Fatalf("expected github subcommand docs in help output")
	}
}
```

- [ ] **Step 2: Run the help/documentation test and verify it fails**

Run:

```bash
go test ./internal/cli -run TestGitHubCommandAppearsInRootHelp -count=1
```

Expected: FAIL until `github` command is wired and documented.

- [ ] **Step 3: Update docs and help text**

```md
<!-- /Users/batuhanyuksel/Documents/security/README.md -->
## GitHub Publishing

IronSentinel can publish findings and dependency inventory directly to GitHub:

```bash
ironsentinel github upload-sarif <run-id> --repo batu3384/ironsentinel
ironsentinel github submit-deps <project-id> --repo batu3384/ironsentinel
```
```

```md
<!-- /Users/batuhanyuksel/Documents/security/docs/architecture.md -->
### GitHub integration

`internal/integrations/github` is the only GitHub API boundary.

Current supported operations:

- SARIF upload to code scanning
- dependency snapshot submission to the dependency graph
```

- [ ] **Step 4: Run the full verification suite**

Run:

```bash
go test ./...
go vet ./...
bash scripts/quality_local.sh
go run ./cmd/ironsentinel github --help
go run ./cmd/ironsentinel github upload-sarif --help
go run ./cmd/ironsentinel github submit-deps --help
```

Expected:

- all tests PASS
- `go vet` exits 0
- quality gate exits 0
- help commands show the new GitHub command family

- [ ] **Step 5: Commit**

```bash
git add /Users/batuhanyuksel/Documents/security/README.md \
        /Users/batuhanyuksel/Documents/security/docs/architecture.md \
        /Users/batuhanyuksel/Documents/security/internal/cli/app_test.go
git commit -m "docs: document GitHub publishing workflow"
```
