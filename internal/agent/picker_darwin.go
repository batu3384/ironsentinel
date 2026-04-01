//go:build darwin

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func pickDirectory(ctx context.Context, prompt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	script := fmt.Sprintf(`POSIX path of (choose folder with prompt "%s")`, escapeAppleScript(prompt))
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("native folder picker failed: %s", message)
	}

	return strings.TrimSpace(stdout.String()), nil
}

func escapeAppleScript(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return replacer.Replace(value)
}
