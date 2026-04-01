//go:build windows

package agent

import "os/exec"

func setProbeSysProcAttr(cmd *exec.Cmd) {
	_ = cmd
}

func killProbeProcessTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
