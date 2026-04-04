package cli

import (
	"strings"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	ghint "github.com/batu3384/ironsentinel/internal/integrations/github"
)

func (a *App) setupInstallPrePushCommand() *cobra.Command {
	var (
		repoRootFlag string
		binaryFlag   string
		force        bool
	)

	command := &cobra.Command{
		Use:   "install-pre-push",
		Short: "Install the IronSentinel pre-push guard into the current repository",
		RunE: func(_ *cobra.Command, _ []string) error {
			repoRoot := strings.TrimSpace(repoRootFlag)
			if repoRoot == "" {
				repoRoot = a.cwd
			}
			root, err := ghint.ResolveGitRepoRoot(repoRoot)
			if err != nil {
				return err
			}
			hookPath, err := ghint.InstallPrePushHook(root, binaryFlag, force)
			if err != nil {
				return err
			}
			pterm.Success.Printf("Installed IronSentinel pre-push hook at %s\n", hookPath)
			pterm.Info.Println("The hook will run `ironsentinel github push-protect` before each push.")
			return nil
		},
	}

	command.Flags().StringVar(&repoRootFlag, "repo-root", "", "Git repository root override")
	command.Flags().StringVar(&binaryFlag, "binary", "ironsentinel", "Binary or absolute executable path to invoke from the hook")
	command.Flags().BoolVar(&force, "force", false, "Replace an existing pre-push hook")
	return command
}
