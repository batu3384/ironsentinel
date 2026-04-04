package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (a *App) RootCommand() *cobra.Command {
	var langFlag string
	var uiModeFlag string
	if previewLang, previewMode := previewPersistentFlagValues(os.Args[1:]); previewLang != "" || previewMode != "" {
		if previewLang != "" {
			_ = a.SetLanguage(previewLang)
		}
		if previewMode != "" {
			_ = a.SetUIMode(previewMode)
		}
	}

	root := &cobra.Command{
		Use:           brandPrimaryBinary,
		Short:         a.catalog.T("app_subtitle"),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runPrimarySurface(cmd.Context())
		},
	}
	root.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		if langFlag != "" {
			if err := a.SetLanguage(langFlag); err != nil {
				return err
			}
		}
		if uiModeFlag != "" {
			if err := a.SetUIMode(uiModeFlag); err != nil {
				return err
			}
		}
		if err := a.ensureInitialLanguageSelection(root, langFlag); err != nil {
			return err
		}
		return nil
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetUsageTemplate(a.localizedUsageTemplate())
	root.SetHelpCommand(a.newHelpCommand(root))

	root.PersistentFlags().StringVar(&langFlag, "lang", "", a.catalog.T("lang_flag"))
	root.PersistentFlags().StringVar(&uiModeFlag, "ui-mode", "", a.catalog.T("ui_mode_flag"))

	root.AddCommand(a.overviewCommand())
	root.AddCommand(a.tuiCommand())
	root.AddCommand(a.consoleCommand())
	root.AddCommand(a.setupCommand())
	root.AddCommand(a.daemonCommand())
	root.AddCommand(a.initCommand())
	root.AddCommand(a.openCommand())
	root.AddCommand(a.pickCommand())
	root.AddCommand(a.scanCommand())
	root.AddCommand(a.findingsCommand())
	root.AddCommand(a.reviewCommand())
	root.AddCommand(a.triageCommand())
	root.AddCommand(a.runtimeCommand())
	root.AddCommand(a.projectsCommand())
	root.AddCommand(a.runsCommand())
	root.AddCommand(a.exportCommand())
	root.AddCommand(a.suppressCommand())
	root.AddCommand(a.dastCommand())
	root.AddCommand(a.configCommand())
	root.AddCommand(a.campaignsCommand())
	root.AddCommand(a.githubCommand())
	a.localizeHelpFlags(root)

	return root
}

func (a *App) ensureInitialLanguageSelection(root *cobra.Command, langFlag string) error {
	if !a.shouldPromptForInitialLanguage(root, langFlag) {
		return nil
	}

	a.renderInitialLanguageOnboarding()

	selection, err := a.promptInitialLanguageSelection()
	if err != nil {
		return err
	}
	if err := a.SaveLanguage(selection); err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("language_saved", strings.ToUpper(string(a.lang))))
	return nil
}

func (a *App) shouldPromptForInitialLanguage(root *cobra.Command, langFlag string) bool {
	interactive := a.isInteractiveTerminal()
	args := os.Args[1:]
	if root == nil {
		return a.shouldPromptForInitialLanguageForCommand("", langFlag, interactive, args)
	}
	command, _, err := root.Find(args)
	if err != nil || command == nil {
		return a.shouldPromptForInitialLanguageForCommand("", langFlag, interactive, args)
	}
	return a.shouldPromptForInitialLanguageForCommand(command.CommandPath(), langFlag, interactive, args)
}

func (a *App) shouldPromptForInitialLanguageForCommand(commandPath, langFlag string, interactive bool, args []string) bool {
	if a.languageConfigured {
		return false
	}
	if strings.TrimSpace(langFlag) != "" {
		return false
	}
	if !interactive {
		return false
	}
	if hasHelpIntent(args) {
		return false
	}
	path := strings.TrimSpace(commandPath)
	if path == "" {
		return true
	}
	return !isConfigLanguageCommandPath(path)
}

func hasHelpIntent(args []string) bool {
	for _, arg := range args {
		switch strings.TrimSpace(arg) {
		case "-h", "--help", "help":
			return true
		}
	}
	return false
}

func (a *App) consoleCommand() *cobra.Command {
	return &cobra.Command{
		Use:        "console",
		Aliases:    []string{"menu"},
		Short:      a.catalog.T("console_title"),
		Hidden:     true,
		Deprecated: a.catalog.T("console_deprecated"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.requireInteractiveSurface(); err != nil {
				return err
			}
			return a.launchTUI(cmd.Context())
		},
	}
}

func (a *App) overviewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "overview",
		Short: a.catalog.T("overview_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderHome()
		},
	}
}

func (a *App) setupCommand() *cobra.Command {
	var (
		target     string
		coverage   string
		withMirror bool
	)

	command := &cobra.Command{
		Use:   "setup",
		Short: a.catalog.T("setup_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := a.runSetup(target, domain.CoverageProfile(coverage), withMirror); err != nil {
				return fmt.Errorf("%s", a.catalog.T("setup_failed", err.Error()))
			}
			pterm.Success.Println(a.catalog.T("setup_completed"))
			return a.renderRuntimeDetails()
		},
	}
	command.Flags().StringVar(&target, "target", "auto", a.catalog.T("setup_target_flag"))
	command.Flags().StringVar(&coverage, "coverage", string(domain.CoveragePremium), a.catalog.T("setup_coverage_flag"))
	command.Flags().BoolVar(&withMirror, "mirror", true, a.catalog.T("setup_mirror_flag"))
	command.AddCommand(a.setupInstallPrePushCommand())
	return command
}

func (a *App) initCommand() *cobra.Command {
	var (
		displayName string
		picker      bool
	)

	command := &cobra.Command{
		Use:   "init [path]",
		Short: a.catalog.T("init_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			if picker {
				path = ""
			}

			project, _, err := a.ensureProject(cmd.Context(), path, displayName, picker)
			if err != nil {
				return err
			}
			return a.renderProjects([]domain.Project{project})
		},
	}

	command.Flags().StringVar(&displayName, "name", "", a.catalog.T("display_name_flag"))
	command.Flags().BoolVar(&picker, "picker", false, a.catalog.T("prompt_use_picker"))
	return command
}

func (a *App) openCommand() *cobra.Command {
	command := &cobra.Command{
		Use:        "open [project-id]",
		Short:      a.catalog.T("open_title"),
		Hidden:     true,
		Deprecated: a.catalog.T("open_deprecated"),
		Args:       cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := ""
			if len(args) > 0 {
				projectID = strings.TrimSpace(args[0])
			}

			project, err := a.resolveProjectReference(projectID)
			if err != nil {
				return err
			}
			return a.runQuickScan(cmd.Context(), project)
		},
	}

	return command
}

func (a *App) pickCommand() *cobra.Command {
	var displayName string

	command := &cobra.Command{
		Use:        "pick",
		Short:      a.catalog.T("pick_title"),
		Hidden:     true,
		Deprecated: a.catalog.T("pick_deprecated"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			project, _, err := a.ensureProject(cmd.Context(), "", displayName, true)
			if err != nil {
				return err
			}
			return a.runQuickScan(cmd.Context(), project)
		},
	}

	command.Flags().StringVar(&displayName, "name", "", a.catalog.T("display_name_flag"))
	return command
}

func (a *App) daemonCommand() *cobra.Command {
	var (
		once             bool
		interval         string
		projectIDs       []string
		presetID         string
		mode             string
		coverage         string
		driftDetect      bool
		autoUpdateBundle bool
		slackWebhook     string
		webhookURL       string
	)

	command := &cobra.Command{
		Use:   "daemon",
		Short: a.catalog.T("daemon_title"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			duration, err := time.ParseDuration(strings.TrimSpace(interval))
			if err != nil && strings.TrimSpace(interval) != "" {
				return fmt.Errorf("%s", a.catalog.T("daemon_schedule_interval_invalid", interval))
			}
			return a.runDaemon(cmd.Context(), once, daemonOptions{
				Interval:         duration,
				ProjectIDs:       projectIDs,
				PresetID:         domain.CompliancePreset(presetID),
				Mode:             domain.ScanMode(mode),
				Coverage:         domain.CoverageProfile(coverage),
				AutoUpdateBundle: autoUpdateBundle,
				DriftDetection:   driftDetect,
				SlackWebhook:     coalesceString(slackWebhook, os.Getenv("SLACK_WEBHOOK_URL")),
				WebhookURL:       coalesceString(webhookURL, os.Getenv("APPSEC_WEBHOOK_URL")),
			})
		},
	}
	command.Flags().BoolVar(&once, "once", false, a.catalog.T("daemon_once_flag"))
	command.Flags().StringVar(&interval, "interval", "", a.catalog.T("daemon_schedule_interval_flag"))
	command.Flags().StringArrayVar(&projectIDs, "project", nil, a.catalog.T("daemon_schedule_project_flag"))
	command.Flags().StringVar(&presetID, "preset", "", a.catalog.T("daemon_schedule_preset_flag"))
	command.Flags().StringVar(&mode, "mode", "", a.catalog.T("daemon_schedule_mode_flag"))
	command.Flags().StringVar(&coverage, "coverage", "", a.catalog.T("daemon_schedule_coverage_flag"))
	command.Flags().BoolVar(&autoUpdateBundle, "auto-update-bundle", false, a.catalog.T("daemon_schedule_auto_update_flag"))
	command.Flags().BoolVar(&driftDetect, "drift-detection", true, a.catalog.T("daemon_schedule_drift_flag"))
	command.Flags().StringVar(&slackWebhook, "slack-webhook-url", "", a.catalog.T("daemon_schedule_slack_flag"))
	command.Flags().StringVar(&webhookURL, "webhook-url", "", a.catalog.T("daemon_schedule_webhook_flag"))
	return command
}
