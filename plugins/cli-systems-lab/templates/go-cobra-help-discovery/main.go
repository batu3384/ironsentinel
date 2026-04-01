package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "__APP_SLUG__",
		Short: "__APP_TITLE__ command surface",
		Long:  "__APP_TITLE__ keeps the top operator tasks visible and plain-output safe.",
		Example: "__APP_SLUG__ doctor\n" +
			"__APP_SLUG__ init --project demo\n" +
			"__APP_SLUG__ scan --target ./repo",
	}

	root.SetHelpTemplate(`{{with .Long}}{{.}}

{{end}}Top tasks:
  {{.CommandPath}} doctor        Validate local prerequisites
  {{.CommandPath}} init          Create the first project profile
  {{.CommandPath}} scan          Start the main workflow

Examples:
{{.Example}}

Available commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}{{rpad .Name .NamePadding }} {{.Short}}
{{end}}{{end}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`)

	root.AddCommand(
		&cobra.Command{
			Use:   "doctor",
			Short: "Validate local prerequisites",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Fprintln(cmd.OutOrStdout(), "__APP_TITLE__ doctor")
				fmt.Fprintln(cmd.OutOrStdout(), "- Go version")
				fmt.Fprintln(cmd.OutOrStdout(), "- Config path")
				fmt.Fprintln(cmd.OutOrStdout(), "- Workspace status")
			},
		},
		&cobra.Command{
			Use:   "init",
			Short: "Create the first project profile",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Fprintln(cmd.OutOrStdout(), "Created the initial profile.")
			},
		},
		&cobra.Command{
			Use:   "scan",
			Short: "Start the main workflow",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Fprintln(cmd.OutOrStdout(), "Scan placeholder")
			},
		},
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
