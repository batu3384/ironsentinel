package cmdutil

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
)

type ExecuteContexter interface {
	ExecuteContext(ctx context.Context) error
}

type NotifyContextFunc func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc)

func Run(stderr io.Writer, build func() (ExecuteContexter, error), notify NotifyContextFunc) int {
	if stderr == nil {
		stderr = io.Discard
	}
	if build == nil {
		_, _ = fmt.Fprintln(stderr, "command builder is nil")
		return 1
	}

	cmd, err := build()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if cmd == nil {
		_, _ = fmt.Fprintln(stderr, "command builder returned nil command")
		return 1
	}

	notifyContext := notify
	if notifyContext == nil {
		notifyContext = signal.NotifyContext
	}
	ctx, stop := notifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := cmd.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
