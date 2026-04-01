package cli

import "github.com/spf13/cobra"

func (a *App) tuiCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "tui",
		Aliases: []string{"ui"},
		Short:   a.catalog.T("tui_title"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireInteractiveSurface(); err != nil {
				return err
			}
			return a.launchTUI(cmd.Context())
		},
	}
}
