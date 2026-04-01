package main

import (
	"os"

	"github.com/batu3384/ironsentinel/internal/cli"
	"github.com/batu3384/ironsentinel/internal/cmdutil"
	"github.com/batu3384/ironsentinel/internal/config"
)

func run() int {
	return cmdutil.Run(os.Stderr, func() (cmdutil.ExecuteContexter, error) {
		app, err := cli.New(config.Load())
		if err != nil {
			return nil, err
		}
		return app.RootCommand(), nil
	}, nil)
}

func main() {
	os.Exit(run())
}
