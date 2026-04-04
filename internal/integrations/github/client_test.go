package github

import (
	"context"
	"errors"
	"os"
	"strings"
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

func TestResolveTokenFallsBackToGHToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "ghs-secondary")

	token, source, err := ResolveToken(context.Background(), execTokenProvider(func(context.Context) (string, error) {
		t.Fatalf("provider should not be called when GH_TOKEN is set")
		return "", nil
	}))
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "ghs-secondary" || source != "env:GH_TOKEN" {
		t.Fatalf("unexpected token resolution: token=%q source=%q", token, source)
	}
}

func TestResolveTokenUsesGhAuthTokenProvider(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	token, source, err := ResolveToken(context.Background(), execTokenProvider(func(context.Context) (string, error) {
		return "ghs-cli", nil
	}))
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "ghs-cli" || source != "gh auth token" {
		t.Fatalf("unexpected token resolution: token=%q source=%q", token, source)
	}
}

func TestResolveTokenReturnsErrorForGhAuthTokenFailure(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	_, _, err := ResolveToken(context.Background(), execTokenProvider(func(context.Context) (string, error) {
		return "", errors.New("gh login expired")
	}))
	if err == nil || !strings.Contains(err.Error(), "gh login expired") {
		t.Fatalf("expected provider error to be returned, got %v", err)
	}
}

func TestResolveTokenReturnsErrorForEmptyGhAuthToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	_, _, err := ResolveToken(context.Background(), execTokenProvider(func(context.Context) (string, error) {
		return "   ", nil
	}))
	if err == nil || !strings.Contains(err.Error(), "github auth token not found") {
		t.Fatalf("expected empty token error, got %v", err)
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

func TestResolveRepositoryRejectsNonGitHubRemote(t *testing.T) {
	_, err := ResolveRepository("/tmp/worktree", "", execGitProvider(func(dir string, args ...string) (string, error) {
		return "https://gitlab.com/batu3384/ironsentinel.git", nil
	}))
	if err == nil || !strings.Contains(err.Error(), "use --repo") {
		t.Fatalf("expected non-GitHub remote to be rejected, got %v", err)
	}
}

func TestResolveGitMetadataResolvesBranchRef(t *testing.T) {
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

func TestResolveGitMetadataRejectsDetachedHead(t *testing.T) {
	dir := t.TempDir()
	_, _, err := ResolveGitMetadata(dir, "", "", execGitProvider(func(_ string, args ...string) (string, error) {
		switch {
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "HEAD":
			return "abc123def456", nil
		case len(args) >= 4 && args[0] == "symbolic-ref" && args[1] == "--quiet" && args[2] == "--short" && args[3] == "HEAD":
			return "", os.ErrNotExist
		default:
			return "", os.ErrNotExist
		}
	}))
	if err == nil || !strings.Contains(err.Error(), "use --ref") {
		t.Fatalf("expected detached HEAD to require --ref, got %v", err)
	}
}
