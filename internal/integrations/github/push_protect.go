package github

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

const managedPrePushHookMarker = "Managed by IronSentinel"

type PushRefUpdate struct {
	LocalRef  string
	LocalSHA  string
	RemoteRef string
	RemoteSHA string
}

type CommitBlob struct {
	CommitSHA string
	Path      string
	Content   []byte
}

type gitBlobProvider interface {
	RunText(dir string, args ...string) (string, error)
	RunBytes(dir string, args ...string) ([]byte, error)
}

type execGitBlobProvider struct{}

func (execGitBlobProvider) RunText(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = filepath.Clean(dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (execGitBlobProvider) RunBytes(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = filepath.Clean(dir)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

func ResolveGitRepoRoot(workdir string) (string, error) {
	root, err := execGitBlobProvider{}.RunText(workdir, "rev-parse", "--show-toplevel")
	if err != nil || strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("could not resolve git repository root from %q", workdir)
	}
	return filepath.Clean(root), nil
}

func InstallPrePushHook(repoRoot, binary string, force bool) (string, error) {
	repoRoot = filepath.Clean(repoRoot)
	if strings.TrimSpace(binary) == "" {
		binary = "ironsentinel"
	}
	hookPath := filepath.Join(repoRoot, ".git", "hooks", "pre-push")
	if existing, err := os.ReadFile(hookPath); err == nil {
		if !force && !bytes.Contains(existing, []byte(managedPrePushHookMarker)) {
			return "", fmt.Errorf("pre-push hook already exists at %s; re-run with --force to replace it", hookPath)
		}
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		return "", err
	}
	body := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
# %s. Re-run "ironsentinel setup install-pre-push --force" to update.
exec %q github push-protect "$@"
`, managedPrePushHookMarker, binary)
	if err := os.WriteFile(hookPath, []byte(body), 0o755); err != nil {
		return "", err
	}
	return hookPath, nil
}

func ParsePrePushUpdates(r io.Reader) ([]PushRefUpdate, error) {
	if r == nil {
		return nil, nil
	}
	scanner := bufio.NewScanner(r)
	updates := make([]PushRefUpdate, 0, 4)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("invalid pre-push update line %q", line)
		}
		updates = append(updates, PushRefUpdate{
			LocalRef:  fields[0],
			LocalSHA:  fields[1],
			RemoteRef: fields[2],
			RemoteSHA: fields[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return updates, nil
}

func DefaultPushRefUpdates(repoRoot string) ([]PushRefUpdate, error) {
	git := execGitBlobProvider{}
	sha, err := git.RunText(repoRoot, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	ref, err := git.RunText(repoRoot, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || strings.TrimSpace(ref) == "" {
		ref = "HEAD"
	}
	return []PushRefUpdate{{
		LocalRef:  ref,
		LocalSHA:  sha,
		RemoteRef: "",
		RemoteSHA: strings.Repeat("0", 40),
	}}, nil
}

func CollectOutgoingCommitBlobs(repoRoot string, updates []PushRefUpdate, git gitBlobProvider) ([]CommitBlob, error) {
	if git == nil {
		git = execGitBlobProvider{}
	}
	commits := make([]string, 0, 8)
	seenCommits := make(map[string]struct{}, 8)

	for _, update := range updates {
		localSHA := strings.TrimSpace(update.LocalSHA)
		if localSHA == "" || isZeroSHA(localSHA) {
			continue
		}

		var commitLines string
		var err error
		if remoteSHA := strings.TrimSpace(update.RemoteSHA); remoteSHA == "" || isZeroSHA(remoteSHA) {
			commitLines, err = git.RunText(repoRoot, "rev-list", "--reverse", localSHA, "--not", "--remotes")
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(commitLines) == "" {
				commitLines = localSHA
			}
		} else {
			commitLines, err = git.RunText(repoRoot, "rev-list", "--reverse", remoteSHA+".."+localSHA)
			if err != nil {
				return nil, err
			}
		}

		for _, commit := range strings.Split(commitLines, "\n") {
			commit = strings.TrimSpace(commit)
			if commit == "" {
				continue
			}
			if _, ok := seenCommits[commit]; ok {
				continue
			}
			seenCommits[commit] = struct{}{}
			commits = append(commits, commit)
		}
	}

	blobs := make([]CommitBlob, 0, len(commits))
	for _, commit := range commits {
		pathsText, err := git.RunText(repoRoot, "diff-tree", "--root", "--no-commit-id", "--name-only", "--diff-filter=ACMRT", "-r", commit)
		if err != nil {
			return nil, err
		}
		paths := strings.Fields(pathsText)
		slices.Sort(paths)
		paths = slices.Compact(paths)
		for _, path := range paths {
			content, err := git.RunBytes(repoRoot, "show", commit+":"+path)
			if err != nil {
				return nil, err
			}
			blobs = append(blobs, CommitBlob{
				CommitSHA: commit,
				Path:      filepath.ToSlash(path),
				Content:   content,
			})
		}
	}

	return blobs, nil
}

func isZeroSHA(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	for _, ch := range value {
		if ch != '0' {
			return false
		}
	}
	return true
}
