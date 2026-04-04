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
	} else if sha, err = git.Run(filepath.Clean(workdir), "rev-parse", "HEAD"); err != nil || strings.TrimSpace(sha) == "" {
		return "", "", fmt.Errorf("could not resolve git sha; use --sha")
	}

	if strings.TrimSpace(refOverride) != "" {
		return sha, strings.TrimSpace(refOverride), nil
	}

	branch, err := git.Run(filepath.Clean(workdir), "symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil && strings.TrimSpace(branch) != "" {
		return sha, "refs/heads/" + strings.TrimSpace(branch), nil
	}
	return "", "", fmt.Errorf("could not resolve git ref from detached HEAD; use --ref")
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
		if !strings.EqualFold(u.Hostname(), "github.com") {
			return Repository{}, fmt.Errorf("unsupported origin remote %q; use --repo owner/name", remote)
		}
		return parseRepositoryOverride(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"))
	}
	return Repository{}, fmt.Errorf("unsupported origin remote %q; use --repo", remote)
}
