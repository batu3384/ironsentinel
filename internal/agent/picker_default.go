//go:build !darwin

package agent

import (
	"context"
	"fmt"
)

func pickDirectory(ctx context.Context, _ string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("native folder picker is not available on this platform; pass a project path explicitly")
}
