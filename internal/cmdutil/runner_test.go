package cmdutil

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

type fakeCommand struct {
	ctx context.Context
	err error
}

type runnerTestContextKey struct{}

func (f *fakeCommand) ExecuteContext(ctx context.Context) error {
	f.ctx = ctx
	return f.err
}

func TestRunReturnsBuilderError(t *testing.T) {
	var stderr bytes.Buffer
	called := false

	exitCode := Run(&stderr, func() (ExecuteContexter, error) {
		return nil, errors.New("boom")
	}, func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
		called = true
		return parent, func() {}
	})

	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if called {
		t.Fatalf("expected notify function not to be called when build fails")
	}
	if got := stderr.String(); got != "boom\n" {
		t.Fatalf("stderr = %q, want boom", got)
	}
}

func TestRunExecutesCommandWithSignalContext(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &fakeCommand{}
	stopCalled := false
	var receivedSignals []os.Signal
	ctxKey := runnerTestContextKey{}
	wantCtx := context.WithValue(context.Background(), ctxKey, "value")

	exitCode := Run(&stderr, func() (ExecuteContexter, error) {
		return cmd, nil
	}, func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
		receivedSignals = append(receivedSignals, signals...)
		return wantCtx, func() { stopCalled = true }
	})

	if exitCode != 0 {
		t.Fatalf("Run() exit code = %d, want 0", exitCode)
	}
	if cmd.ctx != wantCtx {
		t.Fatalf("expected command to receive notify context")
	}
	if !stopCalled {
		t.Fatalf("expected cancel func to be called")
	}
	if len(receivedSignals) != 1 || receivedSignals[0] != os.Interrupt {
		t.Fatalf("signals = %#v, want [os.Interrupt]", receivedSignals)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunReturnsCommandError(t *testing.T) {
	var stderr bytes.Buffer
	cmd := &fakeCommand{err: errors.New("execute failed")}

	exitCode := Run(&stderr, func() (ExecuteContexter, error) {
		return cmd, nil
	}, func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
		return parent, func() {}
	})

	if exitCode != 1 {
		t.Fatalf("Run() exit code = %d, want 1", exitCode)
	}
	if got := stderr.String(); got != "execute failed\n" {
		t.Fatalf("stderr = %q, want execute failed", got)
	}
}
