package agent

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

const (
	runtimeVersionProbeTimeout = 2500 * time.Millisecond
	runtimeHostProbeTimeout    = 2500 * time.Millisecond
)

func runVersionProbeCommand(binary string, args ...string) ([]byte, error) {
	return runProbeCommandWithTimeout(runtimeVersionProbeTimeout, binary, args...)
}

func runHostProbeCommand(binary string, args ...string) ([]byte, error) {
	return runProbeCommandWithTimeout(runtimeHostProbeTimeout, binary, args...)
}

func runProbeCommandWithTimeout(timeout time.Duration, binary string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := exec.Command(binary, args...)
	setProbeSysProcAttr(command)

	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		return nil, err
	}

	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
	}()

	select {
	case err := <-done:
		return output.Bytes(), err
	case <-ctx.Done():
		killProbeProcessTree(command)
		<-done
		return output.Bytes(), ctx.Err()
	}
}
