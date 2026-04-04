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
	if err != nil {
		return "", "", fmt.Errorf("github auth token not found; set GITHUB_TOKEN or login with gh auth login: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", fmt.Errorf("github auth token not found; set GITHUB_TOKEN or login with gh auth login")
	}
	return token, "gh auth token", nil
}
