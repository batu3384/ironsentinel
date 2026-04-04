package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/batu3384/ironsentinel/internal/agent"
	ghint "github.com/batu3384/ironsentinel/internal/integrations/github"
)

func (a *App) githubPushProtectCommand() *cobra.Command {
	var repoRootFlag string

	command := &cobra.Command{
		Use:   "push-protect [remote-name] [remote-url]",
		Short: "Block pushes that contain high-confidence secrets",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, _ []string) error {
			repoRoot := strings.TrimSpace(repoRootFlag)
			if repoRoot == "" {
				repoRoot = a.cwd
			}
			root, err := ghint.ResolveGitRepoRoot(repoRoot)
			if err != nil {
				return err
			}

			updates, err := ghint.ParsePrePushUpdates(cmd.InOrStdin())
			if err != nil {
				return err
			}
			if len(updates) == 0 {
				updates, err = ghint.DefaultPushRefUpdates(root)
				if err != nil {
					return err
				}
			}

			blobs, err := ghint.CollectOutgoingCommitBlobs(root, updates, nil)
			if err != nil {
				return err
			}
			findings := agent.DetectPushProtectedSecrets("push-protect", "", toPushProtectionBlobs(blobs))
			if len(findings) == 0 {
				_, _ = fmt.Fprintln(os.Stdout, "IronSentinel push protection passed. No high-confidence secrets were found in outgoing commits.")
				return nil
			}

			_, _ = fmt.Fprintf(os.Stderr, "IronSentinel blocked this push. %d high-confidence secret finding(s) were detected in outgoing commits.\n", len(findings))
			for _, finding := range findings {
				_, _ = fmt.Fprintf(os.Stderr, "- [%s] %s | %s\n", strings.ToUpper(string(finding.Severity)), finding.Location, finding.Title)
			}
			_, _ = fmt.Fprintln(os.Stderr, "Rotate the secret, rewrite the affected commit history if needed, and rerun the push.")
			return fmt.Errorf("push protection failed")
		},
	}

	command.Flags().StringVar(&repoRootFlag, "repo-root", "", "Git repository root override")
	return command
}

func toPushProtectionBlobs(blobs []ghint.CommitBlob) []agent.PushProtectionBlob {
	items := make([]agent.PushProtectionBlob, 0, len(blobs))
	for _, blob := range blobs {
		items = append(items, agent.PushProtectionBlob{
			CommitSHA: blob.CommitSHA,
			Path:      blob.Path,
			Content:   blob.Content,
		})
	}
	return items
}
