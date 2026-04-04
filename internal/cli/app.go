package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/batu3384/ironsentinel/internal/agent"
	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/core"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/evidence"
	"github.com/batu3384/ironsentinel/internal/i18n"
	ghint "github.com/batu3384/ironsentinel/internal/integrations/github"
	"github.com/batu3384/ironsentinel/internal/preferences"
	scanprofile "github.com/batu3384/ironsentinel/internal/profile"
	"github.com/batu3384/ironsentinel/internal/reports"
	"github.com/batu3384/ironsentinel/internal/sbom"
	"github.com/batu3384/ironsentinel/internal/store"
)

var selectableModules = []string{
	"stack-detector",
	"surface-inventory",
	"script-audit",
	"dependency-confusion",
	"runtime-config-audit",
	"binary-entropy",
	"secret-heuristics",
	"malware-signature",
	"semgrep",
	"gitleaks",
	"trivy",
	"trivy-image",
	"syft",
	"grype",
	"osv-scanner",
	"checkov",
	"tfsec",
	"kics",
	"licensee",
	"scancode",
	"govulncheck",
	"staticcheck",
	"knip",
	"vulture",
	"clamscan",
	"yara-x",
	"codeql",
	"nuclei",
	"zaproxy",
}

var selectableFindingStatuses = []domain.FindingStatus{
	domain.FindingOpen,
	domain.FindingInvestigating,
	domain.FindingAcceptedRisk,
	domain.FindingFalsePositive,
	domain.FindingFixed,
}

type App struct {
	cfg                   config.Config
	service               *core.Service
	cwd                   string
	lang                  i18n.Language
	uiMode                uiMode
	catalog               i18n.Catalog
	preferences           preferences.Preferences
	languageConfigured    bool
	streamVerbose         bool
	streamMissionControl  bool
	runtimeCacheMu        sync.Mutex
	runtimeCache          domain.RuntimeStatus
	runtimeCacheAt        time.Time
	runtimeDoctorFn       func(domain.ScanProfile, bool, bool) domain.RuntimeDoctor
	runtimeDoctorCache    domain.RuntimeDoctor
	runtimeDoctorCacheKey string
	runtimeDoctorCacheAt  time.Time
}

type labeledValue struct {
	Label string
	Value string
}

type projectChoice struct {
	Label       string
	ProjectID   string
	Path        string
	DisplayName string
	Picker      bool
	Existing    bool
}

type scanWizardDefaults struct {
	DisplayName    string
	Mode           string
	Isolation      string
	Coverage       string
	PresetID       string
	Gate           string
	FailOnNew      string
	BaselineRun    string
	PolicyID       string
	RequireBundle  bool
	StrictVersions bool
	AllowBuild     bool
	AllowNetwork   bool
	DASTTargets    []string
	DASTTargetAuth []string
	DASTAuthFile   string
	Modules        []string
}

func New(cfg config.Config) (*App, error) {
	service, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	prefs, err := preferences.Load(cfg)
	if err != nil {
		return nil, err
	}

	initialLanguage := strings.TrimSpace(prefs.Language)
	if initialLanguage == "" {
		initialLanguage = cfg.DefaultLanguage
	}
	lang := i18n.Parse(initialLanguage)
	mode, err := parseUIMode(prefs.UIMode)
	if err != nil {
		mode = uiModeStandard
	}
	app := &App{
		cfg:                cfg,
		service:            service,
		cwd:                cwd,
		lang:               lang,
		uiMode:             mode,
		catalog:            i18n.New(lang),
		preferences:        prefs,
		languageConfigured: prefs.LanguageConfigured,
	}
	return app.withOutputCapabilities(), nil
}

func (a *App) withOutputCapabilities() *App {
	if a == nil {
		return a
	}
	if a.colorDisabled() {
		pterm.DisableColor()
		pterm.DisableStyling()
		return a
	}
	pterm.EnableColor()
	pterm.EnableStyling()
	return a
}

func commandContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (a *App) SetLanguage(language string) error {
	if language == "" {
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(language)) {
	case "en":
		a.lang = i18n.EN
	case "tr":
		a.lang = i18n.TR
	default:
		return fmt.Errorf("%s", a.catalog.T("language_invalid", language))
	}

	a.catalog = i18n.New(a.lang)
	return nil
}

func (a *App) SaveLanguage(language string) error {
	if err := a.SetLanguage(language); err != nil {
		return err
	}
	a.preferences.Language = string(a.lang)
	a.languageConfigured = true
	return preferences.Save(a.cfg, a.preferences)
}

func previewPersistentFlagValues(args []string) (lang, mode string) {
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case strings.HasPrefix(arg, "--lang="):
			lang = strings.TrimSpace(strings.TrimPrefix(arg, "--lang="))
		case arg == "--lang" && i+1 < len(args):
			i++
			lang = strings.TrimSpace(args[i])
		case strings.HasPrefix(arg, "--ui-mode="):
			mode = strings.TrimSpace(strings.TrimPrefix(arg, "--ui-mode="))
		case arg == "--ui-mode" && i+1 < len(args):
			i++
			mode = strings.TrimSpace(args[i])
		}
	}
	return lang, mode
}

func (a *App) localizedUsageTemplate() string {
	return fmt.Sprintf(`%s:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

%s:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

%s:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

%s:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

%s:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

%s:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

%s:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

%s:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

%s{{end}}
`,
		a.catalog.T("help_usage"),
		a.catalog.T("help_aliases"),
		a.catalog.T("help_examples"),
		a.catalog.T("help_available_commands"),
		a.catalog.T("help_additional_commands"),
		a.catalog.T("help_flags"),
		a.catalog.T("help_global_flags"),
		a.catalog.T("help_topics"),
		a.catalog.T("help_more_info", "{{.CommandPath}}"),
	)
}

func (a *App) newHelpCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: a.catalog.T("help_command_short"),
		Long:  a.catalog.T("help_command_short"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _, err := root.Find(args)
			if err != nil {
				return err
			}
			return target.Help()
		},
	}
}

func (a *App) localizeHelpFlags(command *cobra.Command) {
	if command == nil {
		return
	}
	command.InitDefaultHelpFlag()
	if flag := command.Flags().Lookup("help"); flag != nil {
		name := strings.TrimSpace(command.DisplayName())
		if name == "" {
			name = a.catalog.T("help_flag_this_command")
		}
		flag.Usage = a.catalog.T("help_flag_usage", name)
	}
	for _, child := range command.Commands() {
		a.localizeHelpFlags(child)
	}
}

func (a *App) runtimeCommand() *cobra.Command {
	var (
		mode                       string
		strictVersions             bool
		requireIntegrity           bool
		supportCoverage            string
		releaseVersion             string
		requireSignature           bool
		requireAttestation         bool
		requireExternalAttestation bool
		requireCleanSource         bool
		mirrorTool                 string
		imageEngine                string
		imageTag                   string
		imagePlatform              string
		pushImage                  bool
		bundleMode                 string
		rollbackSnapshotID         string
	)

	command := &cobra.Command{
		Use:   "runtime",
		Short: a.catalog.T("runtime_command_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeDetails()
		},
	}

	doctor := &cobra.Command{
		Use:   "doctor",
		Short: a.catalog.T("runtime_doctor_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			profile := domain.ScanProfile{Mode: domain.ScanMode(mode)}
			return a.enforceRuntimeDoctor(profile, strictVersions, requireIntegrity, true)
		},
	}
	doctor.Flags().StringVar(&mode, "mode", string(domain.ModeSafe), a.catalog.T("runtime_mode_flag"))
	doctor.Flags().BoolVar(&strictVersions, "strict-versions", false, a.catalog.T("runtime_strict_versions_flag"))
	doctor.Flags().BoolVar(&requireIntegrity, "require-integrity", false, a.catalog.T("runtime_require_integrity_flag"))

	support := &cobra.Command{
		Use:   "support",
		Short: a.catalog.T("runtime_support_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeSupportView(domain.CoverageProfile(supportCoverage))
		},
	}
	support.Flags().StringVar(&supportCoverage, "coverage", "", a.catalog.T("runtime_support_coverage_flag"))

	releaseCmd := &cobra.Command{
		Use:   "release",
		Short: a.catalog.T("runtime_release_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeReleasesView(releaseVersion)
		},
	}
	releaseCmd.Flags().StringVar(&releaseVersion, "version", "", a.catalog.T("runtime_release_version_flag"))
	verifyRelease := &cobra.Command{
		Use:   "verify",
		Short: a.catalog.T("runtime_release_verify_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.verifyRuntimeReleases(releaseVersion, requireSignature, requireAttestation, requireExternalAttestation, requireCleanSource)
		},
	}
	verifyRelease.Flags().StringVar(&releaseVersion, "version", "", a.catalog.T("runtime_release_version_flag"))
	verifyRelease.Flags().BoolVar(&requireSignature, "require-signature", true, a.catalog.T("runtime_require_signature_flag"))
	verifyRelease.Flags().BoolVar(&requireAttestation, "require-attestation", true, a.catalog.T("runtime_require_attestation_flag"))
	verifyRelease.Flags().BoolVar(&requireExternalAttestation, "require-external-attestation", false, a.catalog.T("runtime_require_external_attestation_flag"))
	verifyRelease.Flags().BoolVar(&requireCleanSource, "require-clean-source", false, a.catalog.T("runtime_require_clean_source_flag"))
	releaseCmd.AddCommand(verifyRelease)

	lockCmd := &cobra.Command{
		Use:   "lock",
		Short: a.catalog.T("runtime_lock_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeLockCoverage(false)
		},
	}
	lockCoverage := &cobra.Command{
		Use:   "coverage",
		Short: a.catalog.T("runtime_lock_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeLockCoverage(false)
		},
	}
	var missingOnly bool
	lockCoverage.Flags().BoolVar(&missingOnly, "missing-only", false, a.catalog.T("runtime_lock_missing_only_flag"))
	lockCoverage.RunE = func(_ *cobra.Command, _ []string) error {
		return a.renderRuntimeLockCoverage(missingOnly)
	}
	lockCmd.AddCommand(lockCoverage)

	mirror := &cobra.Command{
		Use:   "mirror",
		Short: a.catalog.T("runtime_mirrors_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeDetails()
		},
	}
	refresh := &cobra.Command{
		Use:   "refresh",
		Short: a.catalog.T("mirror_refresh_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			mirror, err := a.service.RefreshMirror(mirrorTool)
			if err != nil {
				return fmt.Errorf("%s", a.catalog.T("mirror_refresh_failed", err.Error()))
			}
			pterm.Success.Printf("%s\n", a.catalog.T("mirror_refreshed", mirror.Tool))
			return a.renderRuntimeDetails()
		},
	}
	refresh.Flags().StringVar(&mirrorTool, "tool", "trivy", a.catalog.T("runtime_mirror_tool_flag"))
	mirror.AddCommand(refresh)

	image := &cobra.Command{
		Use:   "image",
		Short: a.catalog.T("runtime_image_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeDetails()
		},
	}
	build := &cobra.Command{
		Use:   "build",
		Short: a.catalog.T("runtime_image_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.runImageBuild(imageEngine, imageTag, imagePlatform, pushImage)
		},
	}
	build.Flags().StringVar(&imageEngine, "engine", a.cfg.ContainerEngine, a.catalog.T("runtime_image_engine_flag"))
	build.Flags().StringVar(&imageTag, "image", a.cfg.ContainerImage, a.catalog.T("runtime_image_tag_flag"))
	build.Flags().StringVar(&imagePlatform, "platform", a.cfg.ContainerPlatform, a.catalog.T("runtime_image_platform_flag"))
	build.Flags().BoolVar(&pushImage, "push", false, a.catalog.T("runtime_image_push_flag"))
	image.AddCommand(build)

	bundle := &cobra.Command{
		Use:   "bundle",
		Short: a.catalog.T("runtime_bundle_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeBundleHistory()
		},
	}
	updateBundle := &cobra.Command{
		Use:   "update",
		Short: a.catalog.T("runtime_bundle_update_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.runBundleUpdate(bundleMode)
		},
	}
	updateBundle.Flags().StringVar(&bundleMode, "mode", "safe", a.catalog.T("runtime_bundle_mode_flag"))
	rollbackBundle := &cobra.Command{
		Use:   "rollback",
		Short: a.catalog.T("runtime_bundle_rollback_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.runBundleRollback(rollbackSnapshotID)
		},
	}
	rollbackBundle.Flags().StringVar(&rollbackSnapshotID, "snapshot", "", a.catalog.T("runtime_bundle_snapshot_flag"))
	historyBundle := &cobra.Command{
		Use:   "history",
		Short: a.catalog.T("runtime_bundle_history_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuntimeBundleHistory()
		},
	}
	bundle.AddCommand(updateBundle, rollbackBundle, historyBundle)

	command.AddCommand(doctor, support, releaseCmd, lockCmd, mirror, image, bundle)
	return command
}

func (a *App) renderRuntimeDetails() error {
	if a.shellSafeSurfaceOutput() {
		return a.renderRuntimeDetailsPlain()
	}
	return a.renderRuntimeDetailsModern()
}

func (a *App) enforceRuntimeDoctor(profile domain.ScanProfile, strictVersions, requireIntegrity, render bool) error {
	doctor := a.runtimeDoctor(profile, strictVersions, requireIntegrity)
	if render {
		a.renderRuntimeDoctor(doctor)
	}
	if doctor.Ready {
		return nil
	}
	failedChecks := 0
	for _, check := range doctor.Checks {
		if check.Status == domain.RuntimeCheckFail {
			failedChecks++
		}
	}
	return fmt.Errorf("%s", a.catalog.T(
		"runtime_doctor_failed",
		len(doctor.Missing),
		len(doctor.Outdated),
		len(doctor.Unverified),
		len(doctor.FailedVerification),
		len(doctor.FailedAssets),
		failedChecks,
		strings.ToUpper(string(profile.Mode)),
	))
}

func (a *App) runImageBuild(engine, image, platform string, push bool) error {
	pterm.Info.Printf("%s\n", a.catalog.T("runtime_image_build_started", image))
	command, err := agent.CommandForScript(a.cfg.ImageBuildScript, exec.LookPath, "--engine", engine, "--image", image)
	if err != nil {
		return fmt.Errorf("%s", a.catalog.T("runtime_image_build_failed", err.Error()))
	}
	if strings.TrimSpace(platform) != "" {
		command.Args = append(command.Args, "--platform", platform)
	}
	if push {
		command.Args = append(command.Args, "--push")
	}
	command.Dir = filepath.Dir(a.cfg.ImageBuildScript)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = append(os.Environ(),
		"AEGIS_CONTAINER_ENGINE="+engine,
		"AEGIS_CONTAINER_IMAGE="+image,
		"AEGIS_CONTAINER_PLATFORM="+platform,
		"APPSEC_CONTAINERFILE_PATH="+a.cfg.ContainerfilePath,
		"AEGIS_TOOLS_DIR="+a.cfg.ToolsDir,
	)
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s", a.catalog.T("runtime_image_build_failed", err.Error()))
	}
	pterm.Success.Printf("%s\n", a.catalog.T("runtime_image_build_completed", image))
	return a.renderRuntimeDetails()
}

func (a *App) runInstallBundle(mode string) error {
	command, err := agent.CommandForScript(a.cfg.InstallScript, exec.LookPath, "--mode", mode, "--apply")
	if err != nil {
		return err
	}
	command.Dir = filepath.Dir(a.cfg.InstallScript)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = append(os.Environ(), "AEGIS_TOOLS_DIR="+a.cfg.ToolsDir)
	return command.Run()
}

func (a *App) runBundleUpdate(mode string) error {
	pterm.Info.Printf("%s\n", a.catalog.T("runtime_bundle_update_started", strings.ToLower(strings.TrimSpace(mode))))
	snapshot, err := agent.UpdateManagedBundle(a.cfg, mode, a.runInstallBundle)
	if err != nil {
		return fmt.Errorf("%s", a.catalog.T("runtime_bundle_update_failed", err.Error()))
	}
	pterm.Success.Printf("%s\n", a.catalog.T("runtime_bundle_update_completed", snapshot.ID))
	return a.renderRuntimeBundleHistory()
}

func (a *App) runBundleRollback(snapshotID string) error {
	snapshot, err := agent.RollbackManagedBundle(a.cfg, snapshotID)
	if err != nil {
		return fmt.Errorf("%s", a.catalog.T("runtime_bundle_rollback_failed", err.Error()))
	}
	pterm.Success.Printf("%s\n", a.catalog.T("runtime_bundle_rollback_completed", snapshot.ID))
	return a.renderRuntimeBundleHistory()
}

func (a *App) renderRuntimeBundleHistory() error {
	snapshots, err := agent.ListBundleSnapshots(a.cfg)
	if err != nil {
		return err
	}
	pterm.DefaultHeader.Println(a.catalog.T("runtime_bundle_history_title"))
	if len(snapshots) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("runtime_bundle_history_empty"))
		return nil
	}
	data := pterm.TableData{{a.catalog.T("title"), a.catalog.T("scan_mode"), a.catalog.T("created_at"), a.catalog.T("binary_path")}}
	for _, snapshot := range snapshots {
		data = append(data, []string{
			snapshot.ID,
			strings.ToUpper(coalesceString(snapshot.Mode, "-")),
			snapshot.CreatedAt.Local().Format(time.RFC822),
			snapshot.Path,
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) runSetup(target string, coverage domain.CoverageProfile, withMirror bool) error {
	runtime := a.service.Runtime()
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		target = "auto"
	}
	if coverage == "" {
		coverage = domain.CoveragePremium
	}
	if tier, ok := runtime.Support.Coverage(coverage); ok {
		switch tier.Level {
		case domain.RuntimeSupportUnsupported:
			return fmt.Errorf("%s", a.catalog.T("runtime_support_unsupported_setup", a.coverageLabel(coverage), runtime.Support.Platform))
		case domain.RuntimeSupportPartial:
			pterm.Warning.Printf("%s\n", a.catalog.T("runtime_support_partial_setup", a.coverageLabel(coverage), runtime.Support.Platform, tier.Notes))
		}
	}

	installMode := "safe"
	switch coverage {
	case domain.CoverageFull:
		installMode = "full"
	case domain.CoveragePremium:
		installMode = "safe"
	case domain.CoverageCore:
		installMode = "safe"
	}

	switch target {
	case "container":
		if runtime.Isolation.Engine == "" {
			return fmt.Errorf("no supported container engine found")
		}
		if err := a.runImageBuild(runtime.Isolation.Engine, a.cfg.ContainerImage, a.cfg.ContainerPlatform, false); err != nil {
			return err
		}
	case "local":
		if coverage != domain.CoverageCore {
			if err := a.runInstallBundle(installMode); err != nil {
				return err
			}
		}
	default:
		if runtime.Isolation.Engine != "" {
			if coverage != domain.CoverageCore {
				if err := a.runImageBuild(runtime.Isolation.Engine, a.cfg.ContainerImage, a.cfg.ContainerPlatform, false); err != nil {
					return err
				}
			}
		} else if coverage != domain.CoverageCore {
			if err := a.runInstallBundle(installMode); err != nil {
				return err
			}
		}
	}

	if withMirror && coverage != domain.CoverageCore {
		for _, tool := range []string{"trivy", "osv-scanner"} {
			if _, err := a.service.RefreshMirror(tool); err != nil {
				pterm.Warning.Printf("%s\n", a.catalog.T("mirror_refresh_failed", err.Error()))
			}
		}
	}

	project := domain.Project{DetectedStacks: []string{"javascript", "typescript", "python", "go", "terraform", "iac", "docker", "container"}}
	profile := domain.ScanProfile{
		Mode:       domain.ModeSafe,
		Isolation:  domain.IsolationMode(target),
		Coverage:   coverage,
		Modules:    nil,
		AllowBuild: false,
	}
	profile.Modules = a.resolveModulesForProject(project, profile)
	if coverage == domain.CoverageFull {
		profile.Modules = uniqueStrings(append(profile.Modules, "nuclei", "zaproxy"))
	}
	if err := a.enforceRequiredRuntime(project, profile, true, false); err != nil {
		return err
	}
	if coverage != domain.CoverageCore {
		return a.enforceRuntimeDoctor(profile, true, true, false)
	}
	return nil
}

func (a *App) runDaemon(ctx context.Context, once bool, opts daemonOptions) error {
	ctx, stop := signal.NotifyContext(commandContext(ctx), os.Interrupt)
	defer stop()

	mode := "continuous"
	if once {
		mode = "once"
	}
	meta := domain.RuntimeDaemon{
		ScheduleInterval:  strings.TrimSpace(opts.Interval.String()),
		ScheduledProjects: append([]string(nil), opts.ProjectIDs...),
		DriftDetection:    opts.DriftDetection,
		SlackEnabled:      strings.TrimSpace(opts.SlackWebhook) != "",
		WebhookEnabled:    strings.TrimSpace(opts.WebhookURL) != "",
	}
	if opts.Interval <= 0 {
		meta.ScheduleInterval = ""
	}
	stopHeartbeat, err := agentStartDaemonHeartbeatWithMeta(a.cfg, mode, meta)
	if err != nil {
		return err
	}
	finalDaemonNote := a.catalog.T("daemon_stopped")
	defer func() {
		stopHeartbeat(finalDaemonNote)
	}()

	pterm.DefaultHeader.Println(a.catalog.T("daemon_title"))
	pterm.Info.Println(a.catalog.T("daemon_started"))
	notifier := newDaemonNotifier(a, opts)
	if opts.Interval > 0 {
		if once {
			if count, scheduleErr := a.enqueueScheduledScans(opts, notifier); scheduleErr != nil {
				return scheduleErr
			} else if count > 0 {
				pterm.Info.Printf("%s\n", a.catalog.T("daemon_schedule_enqueued", count))
			}
		} else {
			a.startDaemonScheduler(ctx, opts, notifier)
		}
	}
	err = a.service.RunQueueWorker(ctx, once, func(event domain.StreamEvent) {
		a.renderStreamEvent(event)
		notifier.Handle(event)
	})
	if err != nil {
		finalDaemonNote = err.Error()
		return err
	}
	pterm.Success.Println(a.catalog.T("daemon_stopped"))
	return nil
}

var agentStartDaemonHeartbeatWithMeta = agent.StartDaemonHeartbeatWithMeta

func (a *App) projectsCommand() *cobra.Command {
	projects := &cobra.Command{
		Use:   "projects",
		Short: a.catalog.T("projects_title"),
	}

	var displayName string
	var picker bool
	add := &cobra.Command{
		Use:   "add [path]",
		Short: a.catalog.T("project_registered"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			if picker {
				path = ""
			}

			if displayName == "" && a.isInteractiveTerminal() {
				defaultName := ""
				if path != "" {
					defaultName = filepath.Base(path)
				}
				name, err := a.promptText(a.catalog.T("project_name_prompt"), defaultName)
				if err != nil {
					return err
				}
				displayName = strings.TrimSpace(name)
			}

			project, _, err := a.ensureProject(cmd.Context(), path, displayName, picker)
			if err != nil {
				return err
			}
			return a.renderProjects([]domain.Project{project})
		},
	}
	add.Flags().StringVar(&displayName, "name", "", a.catalog.T("display_name_flag"))
	add.Flags().BoolVar(&picker, "picker", false, a.catalog.T("prompt_use_picker"))

	list := &cobra.Command{
		Use:   "list",
		Short: a.catalog.T("projects_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderProjects(a.service.ListProjects())
		},
	}

	projects.AddCommand(add, list)
	return projects
}

func (a *App) runsCommand() *cobra.Command {
	runs := &cobra.Command{
		Use:   "runs",
		Short: a.catalog.T("runs_title"),
	}

	list := &cobra.Command{
		Use:   "list",
		Short: a.catalog.T("runs_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderRuns(a.service.ListRuns())
		},
	}

	show := &cobra.Command{
		Use:   "show [run-id]",
		Short: a.catalog.T("show_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			return a.renderRunDetails(runID)
		},
	}

	var watchInterval time.Duration
	watch := &cobra.Command{
		Use:   "watch [run-id]",
		Short: a.catalog.T("watch_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			return a.watchRuns(cmd.Context(), runID, watchInterval)
		},
	}
	watch.Flags().DurationVar(&watchInterval, "interval", 2*time.Second, a.catalog.T("watch_interval_flag"))

	artifacts := &cobra.Command{
		Use:   "artifacts [run-id]",
		Short: a.catalog.T("artifacts_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			run, ok := a.service.GetRun(runID)
			if !ok {
				return fmt.Errorf("%s", a.catalog.T("run_not_found", runID))
			}
			return a.renderArtifacts(run.ArtifactRefs)
		},
	}

	var baselineRunID string
	diff := &cobra.Command{
		Use:   "diff [run-id]",
		Short: a.catalog.T("diff_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			return a.renderRunDeltaView(runID, baselineRunID)
		},
	}
	diff.Flags().StringVar(&baselineRunID, "baseline", "", a.catalog.T("baseline_run_flag"))

	var gateBaselineRunID string
	var gateSeverity string
	var gateVEXFile string
	gate := &cobra.Command{
		Use:   "gate [run-id]",
		Short: a.catalog.T("gate_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			return a.runRegressionGateWithVEX(runID, gateBaselineRunID, domain.Severity(gateSeverity), gateVEXFile)
		},
	}
	gate.Flags().StringVar(&gateBaselineRunID, "baseline", "", a.catalog.T("baseline_run_flag"))
	gate.Flags().StringVar(&gateSeverity, "severity", string(domain.SeverityHigh), "critical|high|medium|low|info")
	gate.Flags().StringVar(&gateVEXFile, "vex-file", "", a.catalog.T("vex_file_flag"))

	var policyBaselineRunID string
	var policyID string
	var policyVEXFile string
	policyCommand := &cobra.Command{
		Use:   "policy [run-id]",
		Short: a.catalog.T("policy_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			return a.runPolicyEvaluationWithVEX(runID, policyBaselineRunID, policyID, policyVEXFile)
		},
	}
	policyCommand.Flags().StringVar(&policyBaselineRunID, "baseline", "", a.catalog.T("baseline_run_flag"))
	policyCommand.Flags().StringVar(&policyID, "policy", "premium-default", a.catalog.T("policy_pack_flag"))
	policyCommand.Flags().StringVar(&policyVEXFile, "vex-file", "", a.catalog.T("vex_file_flag"))

	var attestationFile string
	verifySBOMAttestation := &cobra.Command{
		Use:   "verify-sbom-attestation [run-id]",
		Short: a.catalog.T("run_verify_sbom_attestation_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			return a.verifySBOMAttestation(runID, attestationFile)
		},
	}
	verifySBOMAttestation.Flags().StringVar(&attestationFile, "file", "", a.catalog.T("run_verify_sbom_attestation_file_flag"))
	_ = verifySBOMAttestation.MarkFlagRequired("file")

	cancel := &cobra.Command{
		Use:   "cancel [run-id]",
		Short: a.catalog.T("run_cancel_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			run, err := a.service.CancelRun(runID)
			if err != nil {
				return err
			}
			if run.Status == domain.ScanCanceled {
				pterm.Success.Printf("%s\n", a.catalog.T("run_canceled", run.ID))
			} else {
				pterm.Success.Printf("%s\n", a.catalog.T("run_cancel_requested", run.ID))
			}
			return a.renderRunDetails(run.ID)
		},
	}

	retryFailed := &cobra.Command{
		Use:   "retry-failed [run-id]",
		Short: a.catalog.T("run_retry_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}
			if run, ok := a.service.GetRun(runID); ok && run.Status != domain.ScanFailed && run.Status != domain.ScanCanceled {
				return fmt.Errorf("%s", a.catalog.T("run_not_retryable", string(run.Status)))
			}
			retryRun, err := a.service.RetryFailedRun(runID)
			if err != nil {
				return err
			}
			pterm.Success.Printf("%s\n", a.catalog.T("run_retry_enqueued", runID, retryRun.ID))
			return a.renderRuns([]domain.ScanRun{retryRun})
		},
	}

	runs.AddCommand(list, show, watch, artifacts, diff, gate, policyCommand, verifySBOMAttestation, cancel, retryFailed)
	return runs
}

func (a *App) scanCommand() *cobra.Command {
	var (
		displayName    string
		mode           string
		isolation      string
		coverage       string
		presetID       string
		gate           string
		failOnNew      string
		baselineRun    string
		policyID       string
		requireBundle  bool
		strictVersions bool
		allowBuild     bool
		allowNetwork   bool
		picker         bool
		wizard         bool
		enqueue        bool
		dastTargets    []string
		dastTargetAuth []string
		dastAuthFile   string
		modules        []string
	)

	command := &cobra.Command{
		Use:   "scan [path]",
		Short: a.catalog.T("scan_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			if picker {
				path = ""
			}

			if wizard {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("interactive_required"))
				}
				return a.guidedScan(cmd.Context(), scanWizardDefaults{
					DisplayName:    displayName,
					Mode:           mode,
					Isolation:      isolation,
					Coverage:       coverage,
					PresetID:       presetID,
					Gate:           gate,
					FailOnNew:      failOnNew,
					BaselineRun:    baselineRun,
					PolicyID:       policyID,
					RequireBundle:  requireBundle,
					StrictVersions: strictVersions,
					AllowBuild:     allowBuild,
					AllowNetwork:   allowNetwork,
					DASTTargets:    dastTargets,
					DASTTargetAuth: dastTargetAuth,
					DASTAuthFile:   dastAuthFile,
					Modules:        modules,
				})
			}

			if a.isInteractiveTerminal() && !enqueue {
				review := defaultScanReviewState(a.cfg.SandboxMode)
				review.Isolation = domain.IsolationMode(isolation)
				review.StrictVersions = strictVersions || requireBundle
				review.RequireIntegrity = strictVersions || requireBundle
				if presetID != "" {
					review.Preset = reviewPresetCompliance
					review.CompliancePreset = domain.CompliancePreset(presetID)
				} else if domain.ScanMode(mode) == domain.ModeSafe || domain.CoverageProfile(coverage) == domain.CoverageCore || domain.CoverageProfile(coverage) == domain.CoveragePremium {
					review.Preset = reviewPresetQuickSafe
				}
				targets, authProfiles, err := prepareDASTConfiguration(dastTargets, dastTargetAuth, dastAuthFile)
				if err != nil {
					return err
				}
				if domain.ScanMode(mode) == domain.ModeActive || len(targets) > 0 {
					review.ActiveValidation = true
					if len(targets) > 0 {
						review.DASTTarget = targets[0].URL
					}
				}

				state := appShellLaunchState{
					Route:              appRouteScanReview,
					Review:             review,
					ReviewDASTTargets:  append([]domain.DastTarget(nil), targets...),
					ReviewAuthProfiles: append([]domain.DastAuthProfile(nil), authProfiles...),
				}
				if picker {
					state.Route = appRouteProjects
					state.Notice = a.catalog.T("app_projects_pick_hint")
					return a.launchTUIWithState(cmd.Context(), state)
				}

				project, _, err := a.ensureProjectWithNotice(cmd.Context(), path, displayName, false, false)
				if err != nil {
					return err
				}
				state.SelectedProjectID = project.ID
				return a.launchTUIWithState(cmd.Context(), state)
			}

			project, _, err := a.ensureProjectWithNotice(cmd.Context(), path, displayName, picker, !a.isInteractiveTerminal())
			if err != nil {
				return err
			}

			targets, authProfiles, err := prepareDASTConfiguration(dastTargets, dastTargetAuth, dastAuthFile)
			if err != nil {
				return err
			}

			profile := domain.ScanProfile{
				Mode:             domain.ScanMode(mode),
				Isolation:        domain.IsolationMode(isolation),
				Coverage:         domain.CoverageProfile(coverage),
				PresetID:         domain.CompliancePreset(presetID),
				Modules:          modules,
				SeverityGate:     domain.Severity(gate),
				PolicyID:         policyID,
				AllowBuild:       allowBuild,
				AllowNetwork:     allowNetwork,
				DASTTargets:      targets,
				DASTAuthProfiles: authProfiles,
			}

			profile = a.applyCompliancePreset(project, profile,
				cmd.Flags().Changed("mode"),
				cmd.Flags().Changed("coverage"),
				cmd.Flags().Changed("gate"),
				cmd.Flags().Changed("policy"),
				cmd.Flags().Changed("allow-build"),
				cmd.Flags().Changed("allow-network"),
				cmd.Flags().Changed("module"),
			)

			profile.Modules = a.resolveModulesForProject(project, profile)
			if err := a.enforceRequiredRuntime(project, profile, strictVersions || requireBundle, !a.isInteractiveTerminal()); err != nil {
				return err
			}

			if enqueue {
				return a.enqueueScan(project, profile)
			}
			return a.executeScan(cmd.Context(), project, profile, domain.Severity(failOnNew), baselineRun)
		},
	}

	command.Flags().StringVar(&displayName, "name", "", a.catalog.T("display_name_flag"))
	command.Flags().StringVar(&mode, "mode", string(domain.ModeSafe), a.catalog.T("scan_mode_flag"))
	command.Flags().StringVar(&isolation, "isolation", a.cfg.SandboxMode, a.catalog.T("scan_isolation_flag"))
	command.Flags().StringVar(&coverage, "coverage", string(domain.CoveragePremium), a.catalog.T("scan_coverage_flag"))
	command.Flags().StringVar(&presetID, "preset", "", a.catalog.T("scan_preset_flag"))
	command.Flags().StringVar(&gate, "gate", string(domain.SeverityHigh), a.catalog.T("scan_gate_flag"))
	command.Flags().StringVar(&failOnNew, "fail-on-new", "", a.catalog.T("scan_fail_on_new_flag"))
	command.Flags().StringVar(&baselineRun, "baseline", "", a.catalog.T("scan_baseline_flag"))
	command.Flags().StringVar(&policyID, "policy", "", a.catalog.T("scan_policy_flag"))
	command.Flags().BoolVar(&requireBundle, "require-bundle", false, a.catalog.T("scan_require_bundle_flag"))
	command.Flags().BoolVar(&strictVersions, "strict-versions", false, a.catalog.T("scan_strict_versions_flag"))
	command.Flags().BoolVar(&allowBuild, "allow-build", false, a.catalog.T("scan_allow_build_flag"))
	command.Flags().BoolVar(&allowNetwork, "allow-network", false, a.catalog.T("scan_allow_network_flag"))
	command.Flags().BoolVar(&picker, "picker", false, a.catalog.T("prompt_use_picker"))
	command.Flags().BoolVar(&wizard, "wizard", false, a.catalog.T("scan_wizard_flag"))
	command.Flags().BoolVar(&enqueue, "enqueue", false, a.catalog.T("scan_enqueue_flag"))
	command.Flags().StringArrayVar(&dastTargets, "dast-target", nil, a.catalog.T("scan_dast_target_flag"))
	command.Flags().StringArrayVar(&dastTargetAuth, "dast-target-auth", nil, a.catalog.T("scan_dast_target_auth_flag"))
	command.Flags().StringVar(&dastAuthFile, "dast-auth-file", "", a.catalog.T("scan_dast_auth_file_flag"))
	command.Flags().StringArrayVar(&modules, "module", nil, a.catalog.T("scan_module_flag"))

	return command
}

func (a *App) findingsCommand() *cobra.Command {
	var (
		runID    string
		severity string
		category string
		status   string
		change   string
		limit    int
	)

	command := &cobra.Command{
		Use:   "findings",
		Short: a.catalog.T("findings_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderFindingsView(runID, severity, category, status, change, limit)
		},
	}

	command.Flags().StringVar(&runID, "run", "", a.catalog.T("findings_run_flag"))
	command.Flags().StringVar(&severity, "severity", "", a.catalog.T("findings_severity_flag"))
	command.Flags().StringVar(&category, "category", "", a.catalog.T("findings_category_flag"))
	command.Flags().StringVar(&status, "status", "", a.catalog.T("findings_status_flag"))
	command.Flags().StringVar(&change, "change", "", a.catalog.T("findings_change_flag"))
	command.Flags().IntVar(&limit, "limit", 25, a.catalog.T("findings_limit_flag"))

	show := &cobra.Command{
		Use:   "show [fingerprint]",
		Short: a.catalog.T("finding_details_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fingerprint := ""
			if len(args) > 0 {
				fingerprint = args[0]
			}
			return a.showFinding(runID, fingerprint)
		},
	}
	show.Flags().StringVar(&runID, "run", "", a.catalog.T("triage_run_flag"))

	command.AddCommand(show)
	return command
}

func (a *App) reviewCommand() *cobra.Command {
	var runID string

	command := &cobra.Command{
		Use:   "review [fingerprint]",
		Short: a.catalog.T("review_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fingerprint := ""
			if len(args) > 0 {
				fingerprint = args[0]
			}
			return a.reviewFinding(runID, fingerprint)
		},
	}
	command.Flags().StringVar(&runID, "run", "", a.catalog.T("review_run_flag"))
	return command
}

func (a *App) triageCommand() *cobra.Command {
	var (
		runID  string
		status string
		tags   []string
		note   string
		owner  string
	)

	command := &cobra.Command{
		Use:   "triage",
		Short: a.catalog.T("triage_title"),
	}

	set := &cobra.Command{
		Use:   "set [fingerprint]",
		Short: a.catalog.T("triage_set_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fingerprint := ""
			if len(args) > 0 {
				fingerprint = args[0]
			}
			return a.guidedTriage(runID, fingerprint, status, tags, note, owner)
		},
	}
	set.Flags().StringVar(&runID, "run", "", a.catalog.T("triage_run_flag"))
	set.Flags().StringVar(&status, "status", "", a.catalog.T("triage_status_flag"))
	set.Flags().StringArrayVar(&tags, "tag", nil, a.catalog.T("triage_tag_flag"))
	set.Flags().StringVar(&note, "note", "", a.catalog.T("triage_note_flag"))
	set.Flags().StringVar(&owner, "owner", "", a.catalog.T("triage_owner_flag"))

	var listStatus string
	list := &cobra.Command{
		Use:   "list",
		Short: a.catalog.T("triage_list_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderTriage(listStatus)
		},
	}
	list.Flags().StringVar(&listStatus, "status", "", a.catalog.T("triage_list_status_flag"))

	clear := &cobra.Command{
		Use:   "clear [fingerprint]",
		Short: a.catalog.T("triage_clear_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fingerprint := ""
			if len(args) > 0 {
				fingerprint = args[0]
			}
			return a.clearTriage(fingerprint)
		},
	}

	command.AddCommand(set, list, clear)
	return command
}

func (a *App) exportCommand() *cobra.Command {
	var format string
	var output string
	var baselineRunID string
	var vexFile string

	command := &cobra.Command{
		Use:   "export [run-id]",
		Short: a.catalog.T("export_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			runID := ""
			if len(args) > 0 {
				runID = args[0]
			}
			if runID == "" {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("run_not_found", ""))
				}
				selected, err := a.selectRun("")
				if err != nil {
					return err
				}
				runID = selected
			}

			return a.exportRunWithVEX(runID, format, output, baselineRunID, vexFile)
		},
	}

	command.Flags().StringVar(&format, "format", a.catalog.T("export_default_format"), a.catalog.T("export_format_flag"))
	command.Flags().StringVar(&output, "output", "", a.catalog.T("export_output_flag"))
	command.Flags().StringVar(&baselineRunID, "baseline", "", a.catalog.T("baseline_run_flag"))
	command.Flags().StringVar(&vexFile, "vex-file", "", a.catalog.T("vex_file_flag"))
	return command
}

func (a *App) suppressCommand() *cobra.Command {
	var (
		runID  string
		reason string
		owner  string
		days   int
		ticket string
	)

	command := &cobra.Command{
		Use:   "suppress [fingerprint]",
		Short: a.catalog.T("suppress_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fingerprint := ""
			if len(args) > 0 {
				fingerprint = args[0]
			}
			return a.guidedSuppression(runID, fingerprint, reason, days, ticket, owner)
		},
	}

	command.PersistentFlags().StringVar(&runID, "run", "", a.catalog.T("suppress_run_flag"))
	command.PersistentFlags().StringVar(&reason, "reason", "", a.catalog.T("suppress_reason_flag"))
	command.PersistentFlags().StringVar(&owner, "owner", "", a.catalog.T("suppress_owner_flag"))
	command.PersistentFlags().IntVar(&days, "days", 30, a.catalog.T("suppress_days_flag"))
	command.PersistentFlags().StringVar(&ticket, "ticket", "", a.catalog.T("suppress_ticket_flag"))

	list := &cobra.Command{
		Use:   "list",
		Short: a.catalog.T("suppress_list_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.renderSuppressions()
		},
	}

	remove := &cobra.Command{
		Use:   "remove [fingerprint]",
		Short: a.catalog.T("suppress_remove_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fingerprint := ""
			if len(args) > 0 {
				fingerprint = args[0]
			}
			return a.guidedUnsuppression(fingerprint)
		},
	}

	renew := &cobra.Command{
		Use:   "renew [fingerprint]",
		Short: a.catalog.T("suppress_renew_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			fingerprint := ""
			if len(args) > 0 {
				fingerprint = args[0]
			}
			return a.guidedRenewSuppression(fingerprint, days, ticket, owner, reason)
		},
	}

	command.AddCommand(list, remove, renew)
	return command
}

func (a *App) dastCommand() *cobra.Command {
	dast := &cobra.Command{
		Use:   "dast",
		Short: a.catalog.T("dast_title"),
	}

	var (
		active       bool
		targets      []string
		targetAuth   []string
		dastAuthFile string
	)
	plan := &cobra.Command{
		Use:   "plan [project-id]",
		Short: a.catalog.T("dast_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			projectID := ""
			if len(args) > 0 {
				projectID = args[0]
			}
			resolvedTargets, authProfiles, err := prepareDASTConfiguration(targets, targetAuth, dastAuthFile)
			if err != nil {
				return err
			}
			return a.guidedDASTPlan(projectID, resolvedTargets, authProfiles, active)
		},
	}
	plan.Flags().BoolVar(&active, "active", false, a.catalog.T("dast_active_flag"))
	plan.Flags().StringArrayVar(&targets, "target", nil, a.catalog.T("dast_target_flag"))
	plan.Flags().StringArrayVar(&targetAuth, "target-auth", nil, a.catalog.T("dast_target_auth_flag"))
	plan.Flags().StringVar(&dastAuthFile, "dast-auth-file", "", a.catalog.T("dast_auth_file_flag"))

	dast.AddCommand(plan, a.dastAuthTemplateCommand())
	return dast
}

func (a *App) configCommand() *cobra.Command {
	configCommand := &cobra.Command{
		Use:   "config",
		Short: a.catalog.T("config_command_title"),
	}

	language := &cobra.Command{
		Use:   "language [en|tr]",
		Short: a.catalog.T("lang_option"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			selection := ""
			if len(args) > 0 {
				selection = args[0]
			} else {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("interactive_required"))
				}
				selected, err := a.promptLanguageSelection()
				if err != nil {
					return err
				}
				selection = selected
			}

			if err := a.SaveLanguage(selection); err != nil {
				return err
			}
			pterm.Success.Printf("%s\n", a.catalog.T("language_saved", strings.ToUpper(string(a.lang))))
			return nil
		},
	}

	uiModeCommand := &cobra.Command{
		Use:   "ui-mode [standard|plain|compact]",
		Short: a.catalog.T("ui_mode_title"),
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			selection := ""
			if len(args) > 0 {
				selection = args[0]
			} else {
				if !a.isInteractiveTerminal() {
					return fmt.Errorf("%s", a.catalog.T("interactive_required"))
				}
				selected, err := a.promptUIModeSelection()
				if err != nil {
					return err
				}
				selection = selected
			}

			if err := a.SaveUIMode(selection); err != nil {
				return err
			}
			pterm.Success.Printf("%s\n", a.catalog.T("ui_mode_saved", a.uiModeLabel(a.currentUIMode())))
			return nil
		},
	}

	show := &cobra.Command{
		Use:   "show",
		Short: a.catalog.T("config_title"),
		RunE: func(_ *cobra.Command, _ []string) error {
			pterm.DefaultHeader.Println(a.catalog.T("config_command_title"))
			return pterm.DefaultTable.WithHasHeader().WithData(pterm.TableData{
				{a.catalog.T("lang_option"), a.catalog.T("ui_mode_title"), a.catalog.T("runtime_output_dir"), a.catalog.T("data_dir"), a.catalog.T("app_root"), a.catalog.T("runtime_tools_dir"), a.catalog.T("runtime_bundle_path")},
				{strings.ToUpper(string(a.lang)), a.uiModeLabel(a.currentUIMode()), a.cfg.OutputDir, a.cfg.DataDir, a.cfg.AppRoot, a.cfg.ToolsDir, a.cfg.BundleLockPath},
			}).Render()
		},
	}

	configCommand.AddCommand(language, uiModeCommand, show)
	return configCommand
}

func (a *App) exportRun(runID, format, output, baselineRunID string) error {
	return a.exportRunWithVEX(runID, format, output, baselineRunID, "")
}

func (a *App) exportRunWithVEX(runID, format, output, baselineRunID, vexPath string) error {
	if output == "" {
		content, err := a.service.ExportWithVEX(runID, format, baselineRunID, vexPath)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprint(os.Stdout, content)
		return nil
	}

	output, err := a.writeRunExportWithVEX(runID, format, output, baselineRunID, vexPath)
	if err != nil {
		return err
	}
	if a.shellSafeSurfaceOutput() {
		fmt.Println(a.catalog.T("report_saved", output))
		return nil
	}
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("export_title")))
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("run_id"), runID)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("export_format_label"), strings.ToUpper(format))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("artifact_uri"), output)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				a.catalog.T("export_focus_saved"),
				a.catalog.T("overview_next_steps"),
				a.commandHint("runs", "show", runID),
			)},
		},
	}).Render()
	pterm.Success.Printf("%s\n", a.catalog.T("report_saved", output))
	return nil
}

func (a *App) campaignsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "campaigns",
		Short: a.catalog.T("campaigns_title"),
	}
	command.AddCommand(a.campaignsListCommand())
	command.AddCommand(a.campaignsShowCommand())
	command.AddCommand(a.campaignsCreateCommand())
	command.AddCommand(a.campaignsAddFindingsCommand())
	command.AddCommand(a.campaignsPublishGitHubCommand())
	return command
}

func (a *App) campaignsListCommand() *cobra.Command {
	var projectID string

	command := &cobra.Command{
		Use:   "list",
		Short: a.catalog.T("campaigns_list_title"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			items, err := a.loadCampaigns(projectID)
			if err != nil {
				return err
			}
			if len(items) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), a.catalog.T("campaigns_empty"))
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n", a.catalog.T("campaigns_list_heading")); err != nil {
				return err
			}
			for _, campaign := range items {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "- %s | %s | %s | %d %s\n",
					campaign.ID,
					campaign.Title,
					a.campaignProjectLabel(campaign.ProjectID),
					len(campaign.FindingFingerprints),
					a.catalog.T("campaigns_list_findings_suffix"),
				); err != nil {
					return err
				}
			}
			return nil
		},
	}
	command.Flags().StringVar(&projectID, "project", "", a.catalog.T("campaigns_project_flag"))
	return command
}

func (a *App) campaignsShowCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "show [campaign-id]",
		Short: a.catalog.T("campaigns_show_title"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			campaign, err := a.loadCampaign(strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			return a.renderCampaign(cmd.OutOrStdout(), campaign)
		},
	}
	return command
}

func (a *App) campaignsCreateCommand() *cobra.Command {
	var (
		projectID     string
		runID         string
		campaignID    string
		title         string
		summary       string
		baselineRunID string
		findings      []string
	)

	command := &cobra.Command{
		Use:   "create",
		Short: a.catalog.T("campaigns_create_title"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := strings.TrimSpace(projectID)
			runID := strings.TrimSpace(runID)

			project, ok := a.service.GetProject(projectID)
			if !ok {
				return fmt.Errorf("%s", a.catalog.T("project_not_found", projectID))
			}
			run, ok := a.service.GetRun(runID)
			if !ok {
				return fmt.Errorf("%s", a.catalog.T("run_not_found", runID))
			}
			if run.ProjectID != project.ID {
				return fmt.Errorf("campaign source run %s does not belong to project %s", runID, projectID)
			}

			resolvedFindings := append([]string(nil), findings...)
			if len(resolvedFindings) == 0 {
				return fmt.Errorf("campaign requires at least one valid finding fingerprint")
			}

			resolvedID := strings.TrimSpace(campaignID)
			if resolvedID == "" {
				resolvedID = a.generateCampaignID(project.ID, run.ID)
			}
			created, err := a.service.CreateCampaign(domain.Campaign{
				ID:                  resolvedID,
				ProjectID:           project.ID,
				Title:               strings.TrimSpace(title),
				Summary:             strings.TrimSpace(summary),
				SourceRunID:         run.ID,
				BaselineRunID:       strings.TrimSpace(baselineRunID),
				FindingFingerprints: resolvedFindings,
			})
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", a.catalog.T("campaigns_created", created.ID, created.Title))
			return err
		},
	}

	command.Flags().StringVar(&projectID, "project", "", a.catalog.T("campaign_create_project_flag"))
	command.Flags().StringVar(&runID, "run", "", a.catalog.T("campaign_create_run_flag"))
	command.Flags().StringVar(&campaignID, "id", "", a.catalog.T("campaign_id_flag"))
	command.Flags().StringVar(&title, "title", "", a.catalog.T("campaign_title_flag"))
	command.Flags().StringVar(&summary, "summary", "", a.catalog.T("campaign_summary_flag"))
	command.Flags().StringVar(&baselineRunID, "baseline", "", a.catalog.T("campaign_baseline_flag"))
	command.Flags().StringSliceVar(&findings, "finding", nil, a.catalog.T("campaign_findings_flag"))
	_ = command.MarkFlagRequired("project")
	_ = command.MarkFlagRequired("run")
	_ = command.MarkFlagRequired("title")
	_ = command.MarkFlagRequired("finding")
	return command
}

func (a *App) campaignsAddFindingsCommand() *cobra.Command {
	var (
		runID    string
		findings []string
	)

	command := &cobra.Command{
		Use:   "add-findings [campaign-id]",
		Short: a.catalog.T("campaigns_add_findings_title"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			campaignID := strings.TrimSpace(args[0])
			campaign, err := a.loadCampaign(campaignID)
			if err != nil {
				return err
			}
			if strings.TrimSpace(runID) != campaign.SourceRunID {
				return fmt.Errorf("campaign source run %s does not match %s", campaign.SourceRunID, strings.TrimSpace(runID))
			}
			updated, err := a.service.AddFindingsToCampaign(campaignID, findings)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", a.catalog.T("campaigns_added_findings", updated.ID, len(updated.FindingFingerprints)))
			return err
		},
	}
	command.Flags().StringVar(&runID, "run", "", a.catalog.T("campaign_create_run_flag"))
	command.Flags().StringSliceVar(&findings, "finding", nil, a.catalog.T("campaign_findings_flag"))
	_ = command.MarkFlagRequired("run")
	_ = command.MarkFlagRequired("finding")
	return command
}

func (a *App) campaignsPublishGitHubCommand() *cobra.Command {
	var repoFlag string

	command := &cobra.Command{
		Use:   "publish-github [campaign-id]",
		Short: a.catalog.T("campaigns_publish_github_title"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.publishCampaignToGitHub(cmd.Context(), strings.TrimSpace(args[0]), repoFlag)
		},
	}
	command.Flags().StringVar(&repoFlag, "repo", "", a.catalog.T("campaign_repo_flag"))
	_ = command.MarkFlagRequired("repo")
	return command
}

func (a *App) loadCampaigns(projectID string) ([]domain.Campaign, error) {
	st, err := a.campaignStore()
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()
	return st.ListCampaigns(strings.TrimSpace(projectID)), nil
}

func (a *App) loadCampaign(campaignID string) (domain.Campaign, error) {
	st, err := a.campaignStore()
	if err != nil {
		return domain.Campaign{}, err
	}
	defer func() { _ = st.Close() }()
	campaign, ok := st.GetCampaign(strings.TrimSpace(campaignID))
	if !ok {
		return domain.Campaign{}, fmt.Errorf("%s", a.catalog.T("campaign_not_found", campaignID))
	}
	return campaign, nil
}

func (a *App) campaignStore() (*store.StateStore, error) {
	return store.NewStateStore(filepath.Join(a.cfg.DataDir, "state.db"))
}

func (a *App) renderCampaign(out io.Writer, campaign domain.Campaign) error {
	projectLabel := a.campaignProjectLabel(campaign.ProjectID)
	if _, err := fmt.Fprintf(out, "%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %d\n%s: %d\n",
		a.catalog.T("campaign_id_label"), campaign.ID,
		a.catalog.T("campaign_title_label"), campaign.Title,
		a.catalog.T("campaign_project_label"), projectLabel,
		a.catalog.T("campaign_status_label"), campaign.Status,
		a.catalog.T("campaign_source_run_label"), campaign.SourceRunID,
		a.catalog.T("campaign_baseline_label"), campaignValueOrDash(strings.TrimSpace(campaign.BaselineRunID)),
		a.catalog.T("campaign_findings_label"), len(campaign.FindingFingerprints),
		a.catalog.T("campaign_published_issues_label"), len(campaign.PublishedIssues),
	); err != nil {
		return err
	}
	if summary := strings.TrimSpace(campaign.Summary); summary != "" {
		_, err := fmt.Fprintf(out, "%s: %s\n", a.catalog.T("campaign_summary_label"), summary)
		return err
	}
	return nil
}

func (a *App) publishCampaignToGitHub(ctx context.Context, campaignID, repoFlag string) error {
	repoFlag = strings.TrimSpace(repoFlag)
	if repoFlag == "" {
		return fmt.Errorf("%s", a.catalog.T("campaign_repo_required"))
	}
	campaign, err := a.loadCampaign(campaignID)
	if err != nil {
		return err
	}
	project, ok := a.service.GetProject(campaign.ProjectID)
	if !ok {
		return fmt.Errorf("%s", a.catalog.T("project_not_found", campaign.ProjectID))
	}
	if _, ok := a.service.GetRun(campaign.SourceRunID); !ok {
		return fmt.Errorf("%s", a.catalog.T("run_not_found", campaign.SourceRunID))
	}
	findings := campaignScopedFindings(a.service.ListFindings(campaign.SourceRunID), campaign.FindingFingerprints)
	if len(findings) == 0 {
		return fmt.Errorf("campaign %s has no live findings to publish", campaign.ID)
	}
	token, _, err := ghint.ResolveToken(ctx, nil)
	if err != nil {
		return err
	}
	repo, err := ghint.ResolveRepository(a.githubCampaignMetadataRoot(project), repoFlag, nil)
	if err != nil {
		return err
	}
	repoName := repo.Owner + "/" + repo.Name
	for _, published := range campaign.PublishedIssues {
		if published.Provider == "github" && published.Repo == repoName {
			pterm.Info.Printf("%s\n", a.catalog.T("campaigns_already_published", campaign.ID, repoName, published.Number))
			return nil
		}
	}
	client, err := ghint.NewClient(token, nil)
	if err != nil {
		return err
	}
	issue, err := client.CreateIssue(ctx, repo, ghint.BuildCampaignIssuePayload(campaign, findings))
	if err != nil {
		return err
	}
	st, err := a.campaignStore()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	updated, err := st.UpdateCampaign(campaign.ID, func(current domain.Campaign) (domain.Campaign, error) {
		now := time.Now().UTC()
		current.UpdatedAt = now
		current.PublishedIssues = append(current.PublishedIssues, domain.CampaignIssueRef{
			Provider: "github",
			Repo:     repoName,
			Number:   issue.Number,
			URL:      issue.URL,
			State:    issue.State,
		})
		return current, nil
	})
	if err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("campaigns_published", updated.ID, repo.Owner, repo.Name, issue.Number))
	return nil
}

func campaignScopedFindings(findings []domain.Finding, fingerprints []string) []domain.Finding {
	if len(findings) == 0 || len(fingerprints) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fingerprint = strings.TrimSpace(fingerprint)
		if fingerprint == "" {
			continue
		}
		allowed[fingerprint] = struct{}{}
	}
	scoped := make([]domain.Finding, 0, len(allowed))
	for _, finding := range findings {
		if _, ok := allowed[finding.Fingerprint]; !ok {
			continue
		}
		scoped = append(scoped, finding)
	}
	return scoped
}

func (a *App) generateCampaignID(projectID, runID string) string {
	return fmt.Sprintf("cmp-%s-%s-%d", sanitizeIDComponent(projectID), sanitizeIDComponent(runID), time.Now().UTC().UnixNano())
}

func (a *App) campaignProjectLabel(projectID string) string {
	if project, ok := a.service.GetProject(projectID); ok {
		if label := strings.TrimSpace(project.DisplayName); label != "" {
			return label
		}
		if label := strings.TrimSpace(project.LocationHint); label != "" {
			return label
		}
	}
	return projectID
}

func (a *App) githubCampaignMetadataRoot(project domain.Project) string {
	if root := strings.TrimSpace(project.LocationHint); root != "" {
		return root
	}
	if root := strings.TrimSpace(a.cwd); root != "" {
		return root
	}
	return "."
}

func sanitizeIDComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "campaign"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func campaignValueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "n/a"
	}
	return value
}

func (a *App) githubCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "github",
		Short: "GitHub publishing",
	}
	command.AddCommand(a.githubExportCustomPatternsCommand())
	command.AddCommand(a.githubUploadSARIFCommand())
	command.AddCommand(a.githubSubmitDepsCommand())
	command.AddCommand(a.githubPushProtectCommand())
	command.AddCommand(a.githubCreateIssuesFromCampaignCommand())
	return command
}

func (a *App) githubCreateIssuesFromCampaignCommand() *cobra.Command {
	var repoFlag string

	command := &cobra.Command{
		Use:   "create-issues-from-campaign [campaign-id]",
		Short: a.catalog.T("campaigns_publish_github_title"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.publishCampaignToGitHub(cmd.Context(), strings.TrimSpace(args[0]), repoFlag)
		},
	}
	command.Flags().StringVar(&repoFlag, "repo", "", a.catalog.T("campaign_repo_flag"))
	_ = command.MarkFlagRequired("repo")
	return command
}

func (a *App) githubExportCustomPatternsCommand() *cobra.Command {
	var output string

	command := &cobra.Command{
		Use:   "export-custom-patterns",
		Short: "Export IronSentinel secret patterns in GitHub custom pattern form",
		RunE: func(cmd *cobra.Command, _ []string) error {
			sources := agent.PushProtectionCustomPatterns()
			items := make([]ghint.CustomPatternSource, 0, len(sources))
			for _, source := range sources {
				items = append(items, ghint.CustomPatternSource{
					RuleID:      source.RuleID,
					Title:       source.Title,
					Description: source.Description,
					Pattern:     source.Pattern,
				})
			}
			manifest := ghint.BuildCustomPatternManifest(items)
			body, err := json.MarshalIndent(manifest, "", "  ")
			if err != nil {
				return err
			}
			body = append(body, '\n')
			if strings.TrimSpace(output) == "" {
				_, err = cmd.OutOrStdout().Write(body)
				return err
			}
			if err := os.WriteFile(output, body, 0o644); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved GitHub custom pattern manifest to %s\n", output)
			return err
		},
	}

	command.Flags().StringVar(&output, "output", "", "Write the GitHub custom pattern manifest to a file")
	return command
}

func (a *App) githubUploadSARIFCommand() *cobra.Command {
	var (
		repoFlag    string
		refFlag     string
		shaFlag     string
		baselineRun string
	)

	command := &cobra.Command{
		Use:   "upload-sarif [run-id]",
		Short: "Upload SARIF to GitHub code scanning",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := strings.TrimSpace(args[0])
			report, err := a.service.BuildRunReport(runID, baselineRun)
			if err != nil {
				return err
			}
			sarif, err := reports.Export("sarif", report)
			if err != nil {
				return err
			}
			token, _, err := ghint.ResolveToken(cmd.Context(), nil)
			if err != nil {
				return err
			}
			metadataRoot := a.githubMetadataRoot(report)
			repo, err := ghint.ResolveRepository(metadataRoot, repoFlag, nil)
			if err != nil {
				return err
			}
			sha, ref, err := ghint.ResolveGitMetadata(metadataRoot, shaFlag, refFlag, nil)
			if err != nil {
				return err
			}
			client, err := ghint.NewClient(token, nil)
			if err != nil {
				return err
			}
			if err := client.UploadSARIF(cmd.Context(), repo, ghint.SARIFUploadRequest{
				CommitSHA: sha,
				Ref:       ref,
				SARIF:     sarif,
				Category:  "ironsentinel/" + runID,
			}); err != nil {
				return err
			}
			pterm.Success.Printf("Uploaded SARIF for %s to %s/%s\n", runID, repo.Owner, repo.Name)
			return nil
		},
	}

	command.Flags().StringVar(&repoFlag, "repo", "", "GitHub repository in owner/name form")
	command.Flags().StringVar(&refFlag, "ref", "", "Git ref override")
	command.Flags().StringVar(&shaFlag, "sha", "", "Commit SHA override")
	command.Flags().StringVar(&baselineRun, "baseline", "", "Explicit baseline run ID")
	return command
}

func (a *App) githubMetadataRoot(report domain.RunReport) string {
	if project, ok := a.service.GetProject(report.Run.ProjectID); ok {
		if root := strings.TrimSpace(project.LocationHint); root != "" {
			return root
		}
	}
	if root := strings.TrimSpace(a.cwd); root != "" {
		return root
	}
	return "."
}

func (a *App) githubSubmitDepsCommand() *cobra.Command {
	var (
		repoFlag  string
		refFlag   string
		shaFlag   string
		runIDFlag string
	)
	command := &cobra.Command{
		Use:   "submit-deps [project-id]",
		Short: "Submit dependencies to the GitHub dependency graph",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectID := ""
			if len(args) > 0 {
				projectID = strings.TrimSpace(args[0])
			}
			project, run, packages, err := a.githubDependencyInventory(projectID, runIDFlag)
			if err != nil {
				return err
			}

			token, _, err := ghint.ResolveToken(cmd.Context(), nil)
			if err != nil {
				return err
			}
			metadataRoot := a.githubDependencyMetadataRoot(project)
			repo, err := ghint.ResolveRepository(metadataRoot, repoFlag, nil)
			if err != nil {
				return err
			}
			sha, ref, err := ghint.ResolveGitMetadata(metadataRoot, shaFlag, refFlag, nil)
			if err != nil {
				return err
			}

			snapshot, err := ghint.BuildDependencySnapshot(project, run, project.DetectedStacks, packages)
			if err != nil {
				return err
			}
			snapshot.Sha = sha
			snapshot.Ref = ref

			client, err := ghint.NewClient(token, nil)
			if err != nil {
				return err
			}
			if err := client.SubmitDependencies(cmd.Context(), repo, snapshot); err != nil {
				return err
			}
			pterm.Success.Printf("Submitted dependency snapshot for %s to %s/%s\n", project.DisplayName, repo.Owner, repo.Name)
			return nil
		},
	}
	command.Flags().StringVar(&repoFlag, "repo", "", "GitHub repository in owner/name form")
	command.Flags().StringVar(&refFlag, "ref", "", "Git ref override")
	command.Flags().StringVar(&shaFlag, "sha", "", "Commit SHA override")
	command.Flags().StringVar(&runIDFlag, "run", "", "Run ID to source dependency inventory from")
	return command
}

func (a *App) githubDependencyMetadataRoot(project domain.Project) string {
	if root := strings.TrimSpace(project.LocationHint); root != "" {
		return root
	}
	if root := strings.TrimSpace(a.cwd); root != "" {
		return root
	}
	return "."
}

func (a *App) githubDependencyInventory(projectID, runID string) (domain.Project, *domain.ScanRun, []ghint.DependencyPackage, error) {
	project, err := a.resolveProjectReference(projectID)
	if err != nil {
		return domain.Project{}, nil, nil, err
	}

	run, err := a.githubDependencyRun(project, runID)
	if err != nil {
		return project, nil, nil, err
	}

	packages, err := a.githubDependencyPackages(*run)
	if err != nil {
		return project, run, nil, err
	}
	if len(packages) == 0 {
		return project, run, nil, fmt.Errorf("no dependency inventory available")
	}
	return project, run, packages, nil
}

func (a *App) githubDependencyRun(project domain.Project, runID string) (*domain.ScanRun, error) {
	runID = strings.TrimSpace(runID)
	if runID != "" {
		run, ok := a.service.GetRun(runID)
		if !ok {
			return nil, fmt.Errorf("run not found: %s", runID)
		}
		if run.ProjectID != project.ID {
			return nil, fmt.Errorf("run %s belongs to a different project", runID)
		}
		return &run, nil
	}

	runs := a.service.ListRuns()
	for _, run := range runs {
		if run.ProjectID != project.ID {
			continue
		}
		if run.Status != domain.ScanCompleted {
			continue
		}
		packages, err := a.githubDependencyPackages(run)
		if err != nil {
			continue
		}
		if len(packages) == 0 {
			continue
		}
		current := run
		return &current, nil
	}
	return nil, fmt.Errorf("no dependency inventory available")
}

func (a *App) githubDependencyPackages(run domain.ScanRun) ([]ghint.DependencyPackage, error) {
	type cyclonedxComponent struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
		Type    string `json:"type"`
	}
	type cyclonedxDocument struct {
		Components []cyclonedxComponent `json:"components"`
	}

	packages := make([]ghint.DependencyPackage, 0)
	seen := make(map[string]struct{})
	for _, artifact := range run.ArtifactRefs {
		if artifact.Kind != "sbom" || strings.TrimSpace(artifact.URI) == "" || artifact.URI == "inline" {
			continue
		}
		body, err := os.ReadFile(artifact.URI)
		if err != nil {
			continue
		}
		var document cyclonedxDocument
		if err := json.Unmarshal(body, &document); err != nil {
			continue
		}
		for _, component := range document.Components {
			pkg, ok := dependencyPackageFromCycloneDX(component)
			if !ok {
				continue
			}
			key := pkg.PackageURL
			if strings.TrimSpace(key) == "" {
				key = pkg.Name + "@" + pkg.Version + "|" + pkg.Ecosystem
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			packages = append(packages, pkg)
		}
	}
	return packages, nil
}

func dependencyPackageFromCycloneDX(component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Type    string `json:"type"`
}) (ghint.DependencyPackage, bool) {
	name := strings.TrimSpace(component.Name)
	if name == "" {
		return ghint.DependencyPackage{}, false
	}

	purl := strings.TrimSpace(component.PURL)
	if purl != "" {
		return ghint.DependencyPackage{
			Name:         name,
			Version:      strings.TrimSpace(component.Version),
			Ecosystem:    dependencyPackageEcosystemFromPURL(purl),
			PackageURL:   purl,
			Relationship: "indirect",
		}, true
	}

	version := strings.TrimSpace(component.Version)
	if version == "" {
		return ghint.DependencyPackage{}, false
	}

	return ghint.DependencyPackage{
		Name:         name,
		Version:      version,
		Ecosystem:    "generic",
		PackageURL:   "",
		Relationship: "indirect",
	}, true
}

func dependencyPackageEcosystemFromPURL(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if strings.HasPrefix(trimmed, "pkg:") {
		trimmed = strings.TrimPrefix(trimmed, "pkg:")
		if slash := strings.Index(trimmed, "/"); slash > 0 {
			ecosystem := strings.ToLower(strings.TrimSpace(trimmed[:slash]))
			if ecosystem != "" {
				return ecosystem
			}
		}
	}
	return "generic"
}

func (a *App) defaultRunReportPath(runID, format string) string {
	ext := strings.ToLower(strings.TrimSpace(format))
	if ext == "" {
		ext = "html"
	}
	return filepath.Join(a.cfg.OutputDir, runID, "ironsentinel-report."+ext)
}

func (a *App) writeRunExport(runID, format, output, baselineRunID string) (string, error) {
	return a.writeRunExportWithVEX(runID, format, output, baselineRunID, "")
}

func (a *App) writeRunExportWithVEX(runID, format, output, baselineRunID, vexPath string) (string, error) {
	content, err := a.service.ExportWithVEX(runID, format, baselineRunID, vexPath)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(output) == "" {
		output = a.defaultRunReportPath(runID, format)
	}
	artifact, err := evidence.PolicyFromConfig(a.cfg).WriteFile(output, "report", "Run report export", []byte(content))
	if err != nil {
		return "", err
	}
	return artifact.URI, nil
}

func (a *App) verifySBOMAttestation(runID, attestationPath string) error {
	run, ok := a.service.GetRun(runID)
	if !ok {
		return fmt.Errorf("%s", a.catalog.T("run_not_found", runID))
	}
	attestation, err := sbom.ParseAttestationFile(attestationPath)
	if err != nil {
		return err
	}
	if err := sbom.VerifyAttestation(run, attestation); err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("run_verify_sbom_attestation_passed", run.ID))
	return nil
}

func (a *App) guidedSuppression(runID, fingerprint, reason string, days int, ticket, owner string) error {
	findings := a.service.ListFindings(runID)
	if len(findings) == 0 {
		return fmt.Errorf("%s", a.catalog.T("no_findings_to_suppress"))
	}

	var selected domain.Finding
	if strings.TrimSpace(fingerprint) != "" {
		var found bool
		for _, finding := range findings {
			if finding.Fingerprint == fingerprint {
				selected = finding
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s", a.catalog.T("finding_not_found", fingerprint))
		}
	} else {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("interactive_required"))
		}
		value, err := a.selectFinding(findings, "")
		if err != nil {
			return err
		}
		selected = value
	}

	if strings.TrimSpace(reason) == "" {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("suppression_reason_required"))
		}
		value, err := a.promptText(a.catalog.T("suppress_reason_prompt"), selected.Title)
		if err != nil {
			return err
		}
		reason = strings.TrimSpace(value)
	}
	if strings.TrimSpace(owner) == "" {
		if a.isInteractiveTerminal() {
			value, err := a.promptText(a.catalog.T("suppress_owner_prompt"), os.Getenv("USER"))
			if err != nil {
				return err
			}
			owner = strings.TrimSpace(value)
		} else {
			owner = "cli"
		}
	}
	if days <= 0 {
		if a.isInteractiveTerminal() {
			value, err := a.promptText(a.catalog.T("suppress_days_prompt"), "30")
			if err != nil {
				return err
			}
			parsedDays, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || parsedDays <= 0 {
				return fmt.Errorf("%s", a.catalog.T("suppression_days_invalid"))
			}
			days = parsedDays
		} else {
			days = 30
		}
	}
	if strings.TrimSpace(ticket) == "" && a.isInteractiveTerminal() {
		value, err := a.promptText(a.catalog.T("suppress_ticket_prompt"), "")
		if err != nil {
			return err
		}
		ticket = strings.TrimSpace(value)
	}

	suppression := domain.Suppression{
		Fingerprint: selected.Fingerprint,
		Reason:      reason,
		Owner:       owner,
		ExpiresAt:   time.Now().UTC().AddDate(0, 0, days),
		TicketRef:   ticket,
	}
	return a.saveSuppression(suppression)
}

func (a *App) guidedUnsuppression(fingerprint string) error {
	suppressions := a.service.ListSuppressions()
	if len(suppressions) == 0 {
		return fmt.Errorf("%s", a.catalog.T("no_suppressions"))
	}

	if strings.TrimSpace(fingerprint) == "" {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("interactive_required"))
		}
		selected, err := a.selectSuppression("")
		if err != nil {
			return err
		}
		fingerprint = selected
	}

	if err := a.service.DeleteSuppression(fingerprint); err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("suppress_removed", fingerprint))
	return nil
}

func (a *App) guidedRenewSuppression(fingerprint string, days int, ticket, owner, reason string) error {
	suppressions := a.service.ListSuppressions()
	if len(suppressions) == 0 {
		return fmt.Errorf("%s", a.catalog.T("no_suppressions"))
	}

	current, found := domain.Suppression{}, false
	if strings.TrimSpace(fingerprint) != "" {
		for _, suppression := range suppressions {
			if suppression.Fingerprint == fingerprint {
				current = suppression
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s", a.catalog.T("suppression_not_found", fingerprint))
		}
	} else {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("interactive_required"))
		}
		selected, err := a.selectSuppression("")
		if err != nil {
			return err
		}
		for _, suppression := range suppressions {
			if suppression.Fingerprint == selected {
				current = suppression
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s", a.catalog.T("suppression_not_found", selected))
		}
	}

	if strings.TrimSpace(reason) == "" {
		reason = current.Reason
	}
	if strings.TrimSpace(owner) == "" {
		owner = current.Owner
	}
	if strings.TrimSpace(ticket) == "" {
		ticket = current.TicketRef
	}
	if days <= 0 {
		if a.isInteractiveTerminal() {
			value, err := a.promptText(a.catalog.T("suppress_days_prompt"), "30")
			if err != nil {
				return err
			}
			parsedDays, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || parsedDays <= 0 {
				return fmt.Errorf("%s", a.catalog.T("suppression_days_invalid"))
			}
			days = parsedDays
		} else {
			days = 30
		}
	}

	current.Reason = reason
	current.Owner = owner
	current.TicketRef = ticket
	current.ExpiresAt = time.Now().UTC().AddDate(0, 0, days)
	return a.saveSuppression(current)
}

func (a *App) guidedTriage(runID, fingerprint, status string, tags []string, note, owner string) error {
	findings := a.service.ListFindings(runID)
	if len(findings) == 0 {
		return fmt.Errorf("%s", a.catalog.T("no_findings"))
	}

	var selected domain.Finding
	if strings.TrimSpace(fingerprint) != "" {
		finding, ok := a.service.GetFinding(runID, fingerprint)
		if !ok {
			return fmt.Errorf("%s", a.catalog.T("finding_not_found", fingerprint))
		}
		selected = finding
	} else {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("interactive_required"))
		}
		finding, err := a.selectFinding(findings, "")
		if err != nil {
			return err
		}
		selected = finding
	}

	if strings.TrimSpace(status) == "" {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("triage_status_required"))
		}
		selectedStatus, err := a.promptStatusSelection(selected.Status)
		if err != nil {
			return err
		}
		status = selectedStatus
	}
	if strings.TrimSpace(owner) == "" {
		if a.isInteractiveTerminal() {
			value, err := a.promptText(a.catalog.T("triage_owner_prompt"), defaultString(selected.Owner, os.Getenv("USER")))
			if err != nil {
				return err
			}
			owner = strings.TrimSpace(value)
		} else {
			owner = "cli"
		}
	}
	if len(tags) == 0 && a.isInteractiveTerminal() {
		value, err := a.promptText(a.catalog.T("triage_tags_prompt"), strings.Join(selected.Tags, ","))
		if err != nil {
			return err
		}
		tags = parseCSVTags(value)
	}
	if strings.TrimSpace(note) == "" && a.isInteractiveTerminal() {
		value, err := a.promptText(a.catalog.T("triage_note_prompt"), selected.Note)
		if err != nil {
			return err
		}
		note = strings.TrimSpace(value)
	}

	triage := domain.FindingTriage{
		Fingerprint: selected.Fingerprint,
		Status:      domain.FindingStatus(status),
		Tags:        normalizeTags(tags),
		Note:        note,
		Owner:       owner,
		UpdatedAt:   time.Now().UTC(),
	}
	if err := a.service.SaveFindingTriage(triage); err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("triage_saved", selected.Fingerprint))
	return nil
}

func (a *App) clearTriage(fingerprint string) error {
	if strings.TrimSpace(fingerprint) == "" {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("interactive_required"))
		}
		selected, err := a.selectTriage("")
		if err != nil {
			return err
		}
		fingerprint = selected
	}
	if err := a.service.DeleteFindingTriage(fingerprint); err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("triage_cleared", fingerprint))
	return nil
}

func (a *App) saveSuppression(suppression domain.Suppression) error {
	if err := a.service.SaveSuppression(suppression); err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("suppress_saved", suppression.Fingerprint))
	return nil
}

func (a *App) reviewFinding(runID, fingerprint string) error {
	findings := a.service.ListFindings(runID)
	if len(findings) == 0 {
		return fmt.Errorf("%s", a.catalog.T("no_findings"))
	}

	var selected domain.Finding
	if strings.TrimSpace(fingerprint) != "" {
		finding, ok := a.service.GetFinding(runID, fingerprint)
		if !ok {
			return fmt.Errorf("%s", a.catalog.T("finding_not_found", fingerprint))
		}
		selected = finding
	} else {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("interactive_required"))
		}
		finding, err := a.selectFinding(findings, "")
		if err != nil {
			return err
		}
		selected = finding
	}

	if err := a.renderFindingDetails(selected); err != nil {
		return err
	}
	if !a.isInteractiveTerminal() {
		return nil
	}

	action, err := a.promptSelect(
		a.catalog.T("review_prompt"),
		[]labeledValue{
			{Label: a.catalog.T("review_action_keep"), Value: "keep"},
			{Label: a.catalog.T("review_action_triage"), Value: "triage"},
			{Label: a.catalog.T("review_action_suppress"), Value: "suppress"},
			{Label: a.catalog.T("review_action_back"), Value: "back"},
		},
		"back",
	)
	if err != nil {
		return err
	}

	switch action {
	case "triage":
		return a.guidedTriage(runID, selected.Fingerprint, "", nil, "", "")
	case "suppress":
		return a.guidedSuppression(runID, selected.Fingerprint, "", 30, "", "")
	default:
		return nil
	}
}

func (a *App) guidedDASTPlan(projectID string, targets []domain.DastTarget, authProfiles []domain.DastAuthProfile, active bool) error {
	if projectID == "" {
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("project_select_required"))
		}
		selected, err := a.selectProject("")
		if err != nil {
			return err
		}
		projectID = selected
	}

	if len(targets) == 0 && a.isInteractiveTerminal() {
		addTarget, err := a.promptConfirm(a.catalog.T("dast_add_prompt"), true)
		if err != nil {
			return err
		}
		if addTarget {
			targetName, err := a.promptText(a.catalog.T("dast_name_prompt"), "staging")
			if err != nil {
				return err
			}
			targetURL, err := a.promptText(a.catalog.T("dast_url_prompt"), "https://staging.example.test")
			if err != nil {
				return err
			}
			targets = []domain.DastTarget{{
				Name:     strings.TrimSpace(targetName),
				URL:      strings.TrimSpace(targetURL),
				AuthType: domain.DastAuthNone,
			}}
		}
	}

	if a.isInteractiveTerminal() {
		selection, err := a.promptConfirm(a.catalog.T("dast_active_prompt"), active)
		if err != nil {
			return err
		}
		active = selection
	}

	plan := a.service.DASTPlan(projectID, targets, authProfiles, active)
	return a.renderDASTPlan(plan, targets)
}

func (a *App) guidedScan(ctx context.Context, defaults scanWizardDefaults) error {
	project, err := a.promptProjectChoice(ctx, defaults.DisplayName)
	if err != nil {
		return err
	}

	modeValue := defaults.Mode
	if modeValue == "" {
		modeValue = string(domain.ModeSafe)
	}
	modeSelection, err := a.promptSelect(
		a.catalog.T("mode_prompt"),
		[]labeledValue{
			{Label: a.modeLabel(domain.ModeSafe) + " | local read-only", Value: string(domain.ModeSafe)},
			{Label: a.modeLabel(domain.ModeDeep) + " | sandboxed deep analysis", Value: string(domain.ModeDeep)},
			{Label: a.modeLabel(domain.ModeActive) + " | authenticated API / DAST", Value: string(domain.ModeActive)},
		},
		modeValue,
	)
	if err != nil {
		return err
	}

	coverageValue := defaults.Coverage
	if coverageValue == "" {
		coverageValue = string(domain.CoveragePremium)
	}
	coverageSelection, err := a.promptSelect(
		a.catalog.T("coverage_prompt"),
		[]labeledValue{
			{Label: a.catalog.T("coverage_core"), Value: string(domain.CoverageCore)},
			{Label: a.catalog.T("coverage_premium"), Value: string(domain.CoveragePremium)},
			{Label: a.catalog.T("coverage_full"), Value: string(domain.CoverageFull)},
		},
		coverageValue,
	)
	if err != nil {
		return err
	}

	presetValue := defaults.PresetID
	presetSelection, err := a.promptSelect(
		a.catalog.T("preset_prompt"),
		a.compliancePresetOptions(),
		presetValue,
	)
	if err != nil {
		return err
	}

	isolationValue := defaults.Isolation
	if isolationValue == "" {
		isolationValue = a.cfg.SandboxMode
	}
	isolationSelection, err := a.promptSelect(
		a.catalog.T("runtime_preferred_mode"),
		[]labeledValue{
			{Label: a.catalog.T("scan_isolation_auto_label"), Value: string(domain.IsolationAuto)},
			{Label: a.catalog.T("scan_isolation_local_label"), Value: string(domain.IsolationLocal)},
			{Label: a.catalog.T("scan_isolation_container_label"), Value: string(domain.IsolationContainer)},
		},
		isolationValue,
	)
	if err != nil {
		return err
	}

	gateValue := defaults.Gate
	if gateValue == "" {
		gateValue = string(domain.SeverityHigh)
	}
	gateSelection, err := a.promptSelect(
		a.catalog.T("gate_prompt"),
		[]labeledValue{
			{Label: a.severityLabel(domain.SeverityCritical), Value: string(domain.SeverityCritical)},
			{Label: a.severityLabel(domain.SeverityHigh), Value: string(domain.SeverityHigh)},
			{Label: a.severityLabel(domain.SeverityMedium), Value: string(domain.SeverityMedium)},
			{Label: a.severityLabel(domain.SeverityLow), Value: string(domain.SeverityLow)},
			{Label: a.severityLabel(domain.SeverityInfo), Value: string(domain.SeverityInfo)},
		},
		gateValue,
	)
	if err != nil {
		return err
	}

	modules := defaults.Modules
	customModules, err := a.promptConfirm(a.catalog.T("modules_scope_prompt"), len(modules) > 0)
	if err != nil {
		return err
	}
	if customModules {
		selected, err := a.promptMultiSelect(a.catalog.T("modules_prompt"), selectableModules, modules)
		if err != nil {
			return err
		}
		modules = selected
	}

	allowBuild, err := a.promptConfirm(a.catalog.T("allow_build_prompt"), defaults.AllowBuild)
	if err != nil {
		return err
	}

	allowNetworkDefault := defaults.AllowNetwork || modeSelection == string(domain.ModeActive)
	allowNetwork, err := a.promptConfirm(a.catalog.T("allow_network_prompt"), allowNetworkDefault)
	if err != nil {
		return err
	}

	targets, authProfiles, err := prepareDASTConfiguration(defaults.DASTTargets, defaults.DASTTargetAuth, defaults.DASTAuthFile)
	if err != nil {
		return err
	}
	if modeSelection == string(domain.ModeActive) || len(targets) > 0 {
		addDAST := len(targets) > 0
		if !addDAST {
			addDAST, err = a.promptConfirm(a.catalog.T("dast_add_prompt"), true)
			if err != nil {
				return err
			}
		}
		if addDAST && len(targets) == 0 {
			targetName, err := a.promptText(a.catalog.T("dast_name_prompt"), "staging")
			if err != nil {
				return err
			}
			targetURL, err := a.promptText(a.catalog.T("dast_url_prompt"), "https://staging.example.test")
			if err != nil {
				return err
			}
			targets = []domain.DastTarget{{
				Name:     strings.TrimSpace(targetName),
				URL:      strings.TrimSpace(targetURL),
				AuthType: domain.DastAuthNone,
			}}
		}
	}

	profile := domain.ScanProfile{
		Mode:             domain.ScanMode(modeSelection),
		Isolation:        domain.IsolationMode(isolationSelection),
		Coverage:         domain.CoverageProfile(coverageSelection),
		PresetID:         domain.CompliancePreset(presetSelection),
		Modules:          modules,
		SeverityGate:     domain.Severity(gateSelection),
		PolicyID:         defaults.PolicyID,
		AllowBuild:       allowBuild,
		AllowNetwork:     allowNetwork,
		DASTTargets:      targets,
		DASTAuthProfiles: authProfiles,
	}
	profile = a.applyCompliancePreset(project, profile, false, false, false, false, false, false, customModules)
	profile.Modules = a.resolveModulesForProject(project, profile)
	if err := a.enforceRequiredRuntime(project, profile, defaults.StrictVersions || defaults.RequireBundle, !a.isInteractiveTerminal()); err != nil {
		return err
	}

	return a.executeScan(ctx, project, profile, domain.Severity(defaults.FailOnNew), defaults.BaselineRun)
}

func (a *App) ensureProject(ctx context.Context, path, displayName string, picker bool) (domain.Project, bool, error) {
	return a.ensureProjectWithNotice(ctx, path, displayName, picker, true)
}

func (a *App) ensureProjectWithNotice(ctx context.Context, path, displayName string, picker, announce bool) (domain.Project, bool, error) {
	if picker {
		pterm.Info.Println(a.catalog.T("picker_notice"))
	}

	project, existed, err := a.service.EnsureProject(commandContext(ctx), path, displayName, picker)
	if err != nil {
		return domain.Project{}, false, err
	}
	if announce {
		if existed {
			pterm.Warning.Printf("%s\n", a.catalog.T("project_existing", project.DisplayName))
		} else {
			pterm.Success.Printf("%s\n", a.catalog.T("project_registered", project.DisplayName))
		}
	}
	return project, existed, nil
}

func (a *App) resolveProjectReference(projectID string) (domain.Project, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID != "" {
		project, ok := a.service.GetProject(projectID)
		if !ok {
			return domain.Project{}, fmt.Errorf("%s", a.catalog.T("project_not_found", projectID))
		}
		return project, nil
	}

	projects := a.service.ListProjects()
	if len(projects) == 0 {
		return domain.Project{}, fmt.Errorf("%s", a.catalog.T("no_projects"))
	}
	if len(projects) == 1 {
		return projects[0], nil
	}
	if !a.isInteractiveTerminal() {
		return domain.Project{}, fmt.Errorf("%s", a.catalog.T("interactive_required"))
	}

	selected, err := a.selectProject(projects[0].ID)
	if err != nil {
		return domain.Project{}, err
	}
	project, ok := a.service.GetProject(selected)
	if !ok {
		return domain.Project{}, fmt.Errorf("%s", a.catalog.T("project_not_found", selected))
	}
	return project, nil
}

func (a *App) quickScanProfile(project domain.Project) domain.ScanProfile {
	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Isolation:    domain.IsolationMode(a.cfg.SandboxMode),
		Coverage:     domain.CoveragePremium,
		SeverityGate: domain.SeverityHigh,
	}
	profile.Modules = a.resolveModulesForProject(project, profile)
	return profile
}

func (a *App) compliancePresetOptions() []labeledValue {
	options := []labeledValue{{Label: a.catalog.T("preset_none"), Value: ""}}
	for _, preset := range scanprofile.All() {
		options = append(options, labeledValue{
			Label: fmt.Sprintf("%s | %s", a.compliancePresetLabel(preset.ID), a.compliancePresetNote(preset.ID)),
			Value: string(preset.ID),
		})
	}
	return options
}

func (a *App) applyCompliancePreset(project domain.Project, profile domain.ScanProfile, modeChanged, coverageChanged, gateChanged, policyChanged, allowBuildChanged, allowNetworkChanged, modulesChanged bool) domain.ScanProfile {
	if profile.PresetID == "" {
		return profile
	}
	preset, ok := scanprofile.Get(profile.PresetID)
	if !ok {
		return profile
	}
	if !modeChanged {
		profile.Mode = preset.Mode
	}
	if !coverageChanged {
		profile.Coverage = preset.Coverage
	}
	if !gateChanged {
		profile.SeverityGate = preset.SeverityGate
	}
	if !policyChanged {
		profile.PolicyID = preset.PolicyID
	}
	if !allowBuildChanged {
		profile.AllowBuild = preset.AllowBuild
	}
	if !allowNetworkChanged {
		profile.AllowNetwork = preset.AllowNetwork
	}
	if !modulesChanged {
		profile.Modules = uniqueStrings(append([]string{}, preset.Modules...))
	} else {
		profile.Modules = uniqueStrings(append(append([]string{}, preset.Modules...), profile.Modules...))
	}

	// Keep container scanners only when the project hints at image/container assets.
	if !hasAnyStack(project.DetectedStacks, "docker", "container", "kubernetes") {
		profile.Modules = slices.DeleteFunc(profile.Modules, func(module string) bool {
			return module == "trivy-image"
		})
	}
	if !hasAnyStack(project.DetectedStacks, "terraform", "iac", "helm", "kubernetes") {
		profile.Modules = slices.DeleteFunc(profile.Modules, func(module string) bool {
			return module == "tfsec" || module == "kics"
		})
	}
	return profile
}

func (a *App) runQuickScan(ctx context.Context, project domain.Project) error {
	profile := a.quickScanProfile(project)
	if err := a.enforceRequiredRuntime(project, profile, false, !a.isInteractiveTerminal()); err != nil {
		return err
	}
	return a.executeScan(ctx, project, profile, "", "")
}

func (a *App) executeScan(ctx context.Context, project domain.Project, profile domain.ScanProfile, failOnNew domain.Severity, baselineRunID string) error {
	previousVerbose := a.streamVerbose
	previousMissionControl := a.streamMissionControl
	a.streamMissionControl = a.isInteractiveTerminal()
	a.streamVerbose = !a.streamMissionControl
	defer func() {
		a.streamVerbose = previousVerbose
		a.streamMissionControl = previousMissionControl
	}()

	if a.streamMissionControl {
		outcome, err := a.runFullscreenScanMode(ctx, project, profile)
		if err != nil {
			return err
		}
		if outcome.scanErr != nil {
			if actionErr := a.handleScanMissionAction(outcome); actionErr != nil {
				return actionErr
			}
			return outcome.scanErr
		}
		if outcome.requiredErr != nil {
			if actionErr := a.handleScanMissionAction(outcome); actionErr != nil {
				return actionErr
			}
			return outcome.requiredErr
		}
		if failOnNew != "" {
			if err := a.runRegressionGate(outcome.run.ID, baselineRunID, failOnNew); err != nil {
				return err
			}
		}
		if strings.TrimSpace(profile.PolicyID) != "" {
			if err := a.runPolicyEvaluation(outcome.run.ID, baselineRunID, profile.PolicyID); err != nil {
				return err
			}
		}
		return a.handleScanMissionAction(outcome)
	}

	pterm.DefaultHeader.Println(a.catalog.T("scan_title"))
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("title"), project.DisplayName, a.catalog.T("scan_target"), project.LocationHint)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("scan_mode"), a.modeLabel(profile.Mode), a.catalog.T("scan_gate"), a.severityLabel(profile.SeverityGate), a.catalog.T("runtime_preferred_mode"), strings.ToUpper(string(profile.Isolation)))},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%s[-]", a.catalog.T("scan_modules"), a.moduleCount(profile.Modules), a.catalog.T("lang_current"), strings.ToUpper(string(a.lang)))},
		},
	}).Render()

	tracker := a.startLiveScanTracker(project, profile)
	missionControl := a.newLiveScanConsole(project, profile)
	run, findings, err := a.service.Scan(commandContext(ctx), project.ID, profile, func(event domain.StreamEvent) {
		a.updateLiveScanTracker(tracker, event)
		if missionControl != nil {
			missionControl.update(a, event)
			missionControl.render(a)
		}
		a.renderStreamEvent(event)
	})
	if err != nil {
		a.updateLiveScanTracker(tracker, domain.StreamEvent{Type: "run.failed"})
		pterm.Error.Printf("%s: %v\n", a.catalog.T("scan_failed"), err)
		return err
	}

	requiredErr := a.enforceRequiredModuleResults(run, profile.Modules)

	if a.streamMissionControl {
		a.renderMissionDebrief(project, run, findings, requiredErr)
	} else {
		a.renderRunSummary(run, &project, findings)
		a.renderModules(run.ModuleResults)
		a.renderFindings(findings)
		a.renderScanOutcome(run, findings, requiredErr)
		a.renderScanPhaseVerdicts(run)
		a.renderFindingSpotlight(findings, 3)
		a.renderAnalystHandoff(run, findings, requiredErr)
	}
	if requiredErr != nil {
		if err := a.handlePostScanFollowUp(run, findings, requiredErr); err != nil {
			return err
		}
		pterm.Error.Printf("%s: %v\n", a.catalog.T("scan_failed"), requiredErr)
		return requiredErr
	}
	if failOnNew != "" {
		pterm.Println()
		pterm.Info.Printf("%s\n", a.catalog.T("scan_gate_after_scan", strings.ToUpper(string(failOnNew))))
		if err := a.runRegressionGate(run.ID, baselineRunID, failOnNew); err != nil {
			return err
		}
	}
	if strings.TrimSpace(profile.PolicyID) != "" {
		pterm.Println()
		pterm.Info.Printf("%s\n", a.catalog.T("scan_policy_after_scan", profile.PolicyID))
		if err := a.runPolicyEvaluation(run.ID, baselineRunID, profile.PolicyID); err != nil {
			return err
		}
	}
	if err := a.handlePostScanFollowUp(run, findings, nil); err != nil {
		return err
	}
	return nil
}

func (a *App) handleScanMissionAction(outcome scanMissionOutcome) error {
	switch outcome.action {
	case scanMissionActionDoctor:
		return a.renderRuntimeDetails()
	case scanMissionActionReview:
		if finding, ok := a.nextReviewFinding(outcome.findings); ok {
			return a.reviewFinding(outcome.run.ID, finding.Fingerprint)
		}
		if outcome.run.ID != "" {
			return a.renderRunDetails(outcome.run.ID)
		}
	case scanMissionActionDetails:
		if outcome.run.ID != "" {
			return a.renderRunDetails(outcome.run.ID)
		}
	}
	return nil
}

func (a *App) enqueueScan(project domain.Project, profile domain.ScanProfile) error {
	run, err := a.service.EnqueueScan(project.ID, profile)
	if err != nil {
		return err
	}
	pterm.Success.Printf("%s\n", a.catalog.T("scan_enqueued", run.ID))
	return a.renderRuns([]domain.ScanRun{run})
}

func (a *App) handlePostScanFollowUp(run domain.ScanRun, findings []domain.Finding, requiredErr error) error {
	if !a.isInteractiveTerminal() {
		return nil
	}

	if requiredErr != nil {
		openDoctor, err := a.promptConfirm(a.catalog.T("scan_followup_doctor_prompt"), true)
		if err != nil {
			return err
		}
		if openDoctor {
			return a.renderRuntimeDetails()
		}
		return nil
	}

	if len(findings) == 0 {
		return nil
	}

	openReview, err := a.promptConfirm(a.catalog.T("scan_followup_review_prompt"), true)
	if err != nil {
		return err
	}
	if openReview {
		if finding, ok := a.nextReviewFinding(findings); ok {
			return a.reviewFinding(run.ID, finding.Fingerprint)
		}
		return a.renderRunDetails(run.ID)
	}
	return nil
}

func (a *App) nextReviewFinding(findings []domain.Finding) (domain.Finding, bool) {
	if len(findings) == 0 {
		return domain.Finding{}, false
	}
	best := findings[0]
	for _, finding := range findings[1:] {
		if domain.SeverityRank(finding.Severity) < domain.SeverityRank(best.Severity) {
			best = finding
			continue
		}
		if domain.SeverityRank(finding.Severity) == domain.SeverityRank(best.Severity) && strings.Compare(finding.Title, best.Title) < 0 {
			best = finding
		}
	}
	return best, true
}

func (a *App) watchRuns(ctx context.Context, runID string, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	ctx, stop := signal.NotifyContext(commandContext(ctx), os.Interrupt)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		a.clearTerminalView()
		pterm.DefaultHeader.Println(a.catalog.T("watch_title"))
		if runID != "" {
			pterm.Info.Println(a.catalog.T("watch_scope_run", runID))
			if err := a.renderRunWatchFrame(runID, interval); err != nil {
				return err
			}
			run, ok := a.service.GetRun(runID)
			if !ok {
				return fmt.Errorf("%s", a.catalog.T("run_not_found", runID))
			}
			if a.isTerminalRunStatus(run.Status) {
				pterm.Println()
				pterm.Success.Println(a.catalog.T("watch_terminal_state", strings.ToUpper(string(run.Status))))
				return nil
			}
		} else {
			pterm.Info.Println(a.catalog.T("watch_scope_all"))
			pterm.Info.Println(a.catalog.T("watch_interval", interval.String()))
			if err := a.renderQueueWatchFrame(); err != nil {
				return err
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func (a *App) showFinding(runID, fingerprint string) error {
	if strings.TrimSpace(fingerprint) == "" {
		findings := a.service.ListFindings(runID)
		if len(findings) == 0 {
			return fmt.Errorf("%s", a.catalog.T("no_findings"))
		}
		if !a.isInteractiveTerminal() {
			return fmt.Errorf("%s", a.catalog.T("interactive_required"))
		}
		selected, err := a.selectFinding(findings, "")
		if err != nil {
			return err
		}
		return a.renderFindingDetails(selected)
	}

	finding, ok := a.service.GetFinding(runID, fingerprint)
	if !ok {
		return fmt.Errorf("%s", a.catalog.T("finding_not_found", fingerprint))
	}
	return a.renderFindingDetails(finding)
}

func (a *App) promptProjectChoice(ctx context.Context, displayName string) (domain.Project, error) {
	choices := make([]projectChoice, 0, len(a.service.ListProjects())+3)

	cwd, _ := os.Getwd()
	choices = append(choices,
		projectChoice{Label: a.catalog.T("project_source_current"), Path: cwd, DisplayName: displayName},
		projectChoice{Label: a.catalog.T("project_source_custom"), DisplayName: displayName},
		projectChoice{Label: a.catalog.T("project_source_picker"), Picker: true, DisplayName: displayName},
	)
	for _, project := range a.service.ListProjects() {
		choices = append(choices, projectChoice{
			Label:     a.catalog.T("project_source_existing", project.DisplayName, project.LocationHint),
			ProjectID: project.ID,
			Existing:  true,
		})
	}

	options := make([]labeledValue, 0, len(choices))
	for _, choice := range choices {
		options = append(options, labeledValue{Label: choice.Label, Value: choice.Label})
	}

	selected, err := a.promptSelect(a.catalog.T("project_source_prompt"), options, choices[0].Label)
	if err != nil {
		return domain.Project{}, err
	}

	for _, choice := range choices {
		if choice.Label != selected {
			continue
		}

		if choice.Existing {
			project, ok := a.service.GetProject(choice.ProjectID)
			if !ok {
				return domain.Project{}, fmt.Errorf("%s", a.catalog.T("project_not_found", choice.ProjectID))
			}
			return project, nil
		}

		path := choice.Path
		picker := choice.Picker
		var err error
		if choice.Label == a.catalog.T("project_source_custom") {
			path, err = a.promptText(a.catalog.T("project_path_prompt"), cwd)
			if err != nil {
				return domain.Project{}, err
			}
			path = strings.TrimSpace(path)
		}

		name := choice.DisplayName
		defaultName := name
		if defaultName == "" && path != "" {
			defaultName = filepath.Base(path)
		}
		if name == "" {
			value, err := a.promptText(a.catalog.T("project_name_prompt"), defaultName)
			if err != nil {
				return domain.Project{}, err
			}
			name = strings.TrimSpace(value)
		}

		if picker {
			pterm.Info.Println(a.catalog.T("picker_notice"))
		}

		project, existed, err := a.service.EnsureProject(commandContext(ctx), path, name, picker)
		if err != nil {
			return domain.Project{}, err
		}
		if existed {
			pterm.Warning.Printf("%s\n", a.catalog.T("project_existing", project.DisplayName))
		} else {
			pterm.Success.Printf("%s\n", a.catalog.T("project_registered", project.DisplayName))
		}
		return project, nil
	}

	return domain.Project{}, fmt.Errorf("%s", a.catalog.T("project_not_found", selected))
}

func (a *App) promptLanguageSelection() (string, error) {
	return a.promptLanguageSelectionWithOptions(a.languageSelectionOptions(false), string(a.lang))
}

func (a *App) promptInitialLanguageSelection() (string, error) {
	return a.promptLanguageSelectionWithOptions(a.languageSelectionOptions(true), string(a.lang))
}

func (a *App) promptLanguageSelectionWithOptions(options []labeledValue, defaultValue string) (string, error) {
	return a.promptSelect(
		a.catalog.T("language_prompt"),
		options,
		defaultValue,
	)
}

func (a *App) languageSelectionOptions(markRecommended bool) []labeledValue {
	options := []labeledValue{
		{Label: a.languageLabel(i18n.EN), Value: "en"},
		{Label: a.languageLabel(i18n.TR), Value: "tr"},
	}
	if !markRecommended {
		return options
	}
	defaultLanguage := i18n.Parse(a.cfg.DefaultLanguage)
	for index := range options {
		if options[index].Value != string(defaultLanguage) {
			continue
		}
		options[index].Label = a.catalog.T("language_recommended_option", options[index].Label)
	}
	return options
}

func (a *App) promptUIModeSelection() (string, error) {
	options := make([]labeledValue, 0, len(selectableUIModes))
	for _, mode := range selectableUIModes {
		options = append(options, labeledValue{
			Label: a.uiModeLabel(mode),
			Value: string(mode),
		})
	}
	return a.promptSelect(a.catalog.T("ui_mode_prompt"), options, string(a.currentUIMode()))
}

func (a *App) promptStatusSelection(current domain.FindingStatus) (string, error) {
	options := make([]labeledValue, 0, len(selectableFindingStatuses))
	for _, status := range selectableFindingStatuses {
		options = append(options, labeledValue{
			Label: a.findingStatusLabel(status),
			Value: string(status),
		})
	}
	return a.promptSelect(a.catalog.T("triage_status_prompt"), options, string(current))
}

func (a *App) selectProject(defaultProjectID string) (string, error) {
	projects := a.service.ListProjects()
	if len(projects) == 0 {
		return "", fmt.Errorf("%s", a.catalog.T("no_projects"))
	}

	options := make([]labeledValue, 0, len(projects))
	for _, project := range projects {
		options = append(options, labeledValue{
			Label: fmt.Sprintf("%s | %s | %s", project.ID, project.DisplayName, project.LocationHint),
			Value: project.ID,
		})
	}
	return a.promptSelect(a.catalog.T("project_select_prompt"), options, defaultProjectID)
}

func (a *App) selectRun(defaultRunID string) (string, error) {
	runs := a.service.ListRuns()
	if len(runs) == 0 {
		return "", fmt.Errorf("%s", a.catalog.T("no_runs"))
	}

	options := make([]labeledValue, 0, len(runs))
	for _, run := range runs {
		options = append(options, labeledValue{
			Label: fmt.Sprintf("%s | %s | %s | %s | %d", run.ID, a.projectLabel(run.ProjectID), a.modeLabel(run.Profile.Mode), string(run.Status), run.Summary.TotalFindings),
			Value: run.ID,
		})
	}

	return a.promptSelect(a.catalog.T("run_select_prompt"), options, defaultRunID)
}

func (a *App) selectFinding(findings []domain.Finding, defaultFingerprint string) (domain.Finding, error) {
	options := make([]labeledValue, 0, len(findings))
	for _, finding := range findings {
		options = append(options, labeledValue{
			Label: fmt.Sprintf("%s | %s | %s | %s", finding.Fingerprint, a.severityLabel(finding.Severity), trimForSelect(finding.Title, 50), trimForSelect(finding.Location, 50)),
			Value: finding.Fingerprint,
		})
	}

	selected, err := a.promptSelect(a.catalog.T("finding_select_prompt"), options, defaultFingerprint)
	if err != nil {
		return domain.Finding{}, err
	}

	for _, finding := range findings {
		if finding.Fingerprint == selected {
			return finding, nil
		}
	}
	return domain.Finding{}, fmt.Errorf("%s", a.catalog.T("finding_not_found", selected))
}

func (a *App) selectSuppression(defaultFingerprint string) (string, error) {
	suppressions := a.service.ListSuppressions()
	options := make([]labeledValue, 0, len(suppressions))
	for _, suppression := range suppressions {
		options = append(options, labeledValue{
			Label: fmt.Sprintf("%s | %s | %s | %s", suppression.Fingerprint, trimForSelect(suppression.Reason, 36), suppression.Owner, suppression.ExpiresAt.Local().Format("2006-01-02")),
			Value: suppression.Fingerprint,
		})
	}
	return a.promptSelect(a.catalog.T("suppress_select_prompt"), options, defaultFingerprint)
}

func (a *App) selectTriage(defaultFingerprint string) (string, error) {
	items := a.service.ListTriage()
	options := make([]labeledValue, 0, len(items))
	for _, item := range items {
		options = append(options, labeledValue{
			Label: fmt.Sprintf("%s | %s | %s", item.Fingerprint, a.findingStatusLabel(item.Status), trimForSelect(strings.Join(item.Tags, ","), 30)),
			Value: item.Fingerprint,
		})
	}
	return a.promptSelect(a.catalog.T("triage_select_prompt"), options, defaultFingerprint)
}

func (a *App) resolveModulesForProject(project domain.Project, profile domain.ScanProfile) []string {
	if len(profile.Modules) > 0 {
		return orderResolvedModules(profile.Modules)
	}

	coverage := profile.Coverage
	if coverage == "" {
		coverage = domain.CoveragePremium
	}

	base := []string{"stack-detector", "surface-inventory", "script-audit", "dependency-confusion", "runtime-config-audit", "binary-entropy", "secret-heuristics", "malware-signature"}
	if coverage == domain.CoverageCore {
		return base
	}

	modules := append([]string{}, base...)
	modules = append(modules, "semgrep", "gitleaks", "trivy", "syft", "grype", "osv-scanner")

	if hasAnyStack(project.DetectedStacks, "terraform", "iac", "helm", "kubernetes", "docker", "container") {
		modules = append(modules, "checkov")
	}
	if hasAnyStack(project.DetectedStacks, "go") {
		modules = append(modules, "govulncheck", "staticcheck")
	}

	if profile.Mode == domain.ModeDeep || coverage == domain.CoverageFull {
		modules = append(modules, "codeql")
		if hasAnyStack(project.DetectedStacks, "javascript", "typescript") {
			modules = append(modules, "knip")
		}
		if hasAnyStack(project.DetectedStacks, "python") {
			modules = append(modules, "vulture")
		}
	}

	if coverage == domain.CoverageFull {
		modules = append(modules, "licensee", "scancode", "yara-x")
		if hasAnyStack(project.DetectedStacks, "terraform", "iac", "helm", "kubernetes") {
			modules = append(modules, "tfsec", "kics")
		}
		if hasAnyStack(project.DetectedStacks, "docker", "container", "kubernetes") {
			modules = append(modules, "trivy-image")
		}
	}

	if profile.Mode == domain.ModeActive {
		modules = append(modules, "nuclei", "zaproxy")
	}

	return orderResolvedModules(modules)
}

func (a *App) enforceRequiredRuntime(project domain.Project, profile domain.ScanProfile, strictVersions, render bool) error {
	runtime := a.service.Runtime()
	requested := profile.Isolation
	if requested == "" {
		requested = domain.IsolationMode(a.cfg.SandboxMode)
	}
	requiredRuntimeModules := requiredRuntimeModules(profile.Modules)

	if requested == domain.IsolationContainer || (requested == domain.IsolationAuto && runtime.Isolation.EffectiveMode == domain.IsolationContainer) {
		if runtime.Isolation.Ready {
			return nil
		}
		return fmt.Errorf("%s", a.catalog.T("required_modules_failed", len(requiredRuntimeModules)))
	}

	if err := a.enforceRuntimeDoctor(profile, strictVersions, false, render); err != nil {
		return fmt.Errorf("%s: %s", a.catalog.T("required_modules_failed", len(requiredRuntimeModules)), strings.Join(requiredRuntimeModules, ", "))
	}
	return nil
}

func (a *App) enforceRequiredModuleResults(run domain.ScanRun, requiredModules []string) error {
	if len(requiredModules) == 0 {
		return nil
	}

	index := make(map[string]domain.ModuleStatus, len(run.ModuleResults))
	for _, result := range run.ModuleResults {
		index[result.Name] = result.Status
	}

	missing := make([]string, 0)
	for _, module := range requiredModules {
		status, ok := index[module]
		if !ok || (status != domain.ModuleCompleted && status != domain.ModuleRunning) {
			missing = append(missing, module)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %s", a.catalog.T("required_modules_failed", len(missing)), strings.Join(missing, ", "))
}

func hasAnyStack(stacks []string, expected ...string) bool {
	for _, candidate := range expected {
		if slices.Contains(stacks, candidate) {
			return true
		}
	}
	return false
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func orderResolvedModules(items []string) []string {
	return domain.OrderedModuleNames(items)
}

func requiredRuntimeModules(modules []string) []string {
	filtered := make([]string, 0, len(modules))
	for _, module := range modules {
		if bundleName := moduleRuntimeName(module); bundleName != "" {
			filtered = append(filtered, module)
		}
	}
	return uniqueStrings(filtered)
}

func moduleRuntimeName(module string) string {
	switch strings.TrimSpace(module) {
	case "stack-detector", "surface-inventory", "script-audit", "dependency-confusion", "runtime-config-audit", "binary-entropy", "secret-heuristics", "malware-signature":
		return ""
	default:
		return module
	}
}

func (a *App) promptSelect(prompt string, options []labeledValue, defaultValue string) (string, error) {
	labels := make([]string, 0, len(options))
	defaultLabel := ""
	for _, option := range options {
		labels = append(labels, option.Label)
		if option.Value == defaultValue || option.Label == defaultValue {
			defaultLabel = option.Label
		}
	}

	printer := pterm.DefaultInteractiveSelect.
		WithOptions(labels).
		WithFilterInputPlaceholder(a.catalog.T("select_search_placeholder")).
		WithMaxHeight(8)
	if defaultLabel != "" {
		printer = printer.WithDefaultOption(defaultLabel)
	}

	selected, err := printer.Show(prompt)
	if err != nil {
		return "", err
	}

	for _, option := range options {
		if option.Label == selected {
			return option.Value, nil
		}
	}

	return "", fmt.Errorf("selected option not found: %s", selected)
}

func (a *App) promptMultiSelect(prompt string, options []string, defaults []string) ([]string, error) {
	defaultLabels := make([]string, 0, len(defaults))
	for _, item := range defaults {
		if slices.Contains(options, item) {
			defaultLabels = append(defaultLabels, item)
		}
	}

	printer := pterm.DefaultInteractiveMultiselect.
		WithOptions(options).
		WithDefaultOptions(defaultLabels).
		WithShowSelectedOptions(true).
		WithFilterInputPlaceholder(a.catalog.T("multiselect_search_placeholder")).
		WithMaxHeight(10)

	selected, err := printer.Show(prompt)
	if err != nil {
		return nil, err
	}
	return selected, nil
}

func (a *App) promptText(prompt, defaultValue string) (string, error) {
	if defaultValue != "" {
		return pterm.DefaultInteractiveTextInput.WithDefaultValue(defaultValue).Show(prompt)
	}
	return pterm.DefaultInteractiveTextInput.Show(prompt)
}

func (a *App) promptConfirm(prompt string, defaultValue bool) (bool, error) {
	printer := pterm.DefaultInteractiveConfirm.
		WithDefaultValue(defaultValue).
		WithConfirmText(a.yesText()).
		WithRejectText(a.noText())
	return printer.Show(prompt)
}

func (a *App) isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func (a *App) shellSafeSurfaceOutput() bool {
	return !a.isInteractiveTerminal() || a.tuiTheme().plain()
}

func (a *App) colorDisabled() bool {
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb")
}

func (a *App) reducedMotion() bool {
	for _, key := range []string{"IRONSENTINEL_REDUCED_MOTION", "AEGIS_REDUCED_MOTION"} {
		if truthyEnv(os.Getenv(key)) {
			return true
		}
	}
	if strings.TrimSpace(os.Getenv("CI")) != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb")
}

func truthyEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (a *App) moduleCount(modules []string) int {
	if len(modules) == 0 {
		return len(selectableModules)
	}
	return len(modules)
}

func (a *App) moduleExecutionCounts(modules []domain.ModuleResult) (failed, skipped, retried int) {
	for _, module := range modules {
		if module.Status == domain.ModuleFailed {
			failed++
		}
		if module.Status == domain.ModuleSkipped {
			skipped++
		}
		if module.Attempts > 1 {
			retried++
		}
	}
	return failed, skipped, retried
}

func (a *App) moduleStatusCounts(modules []domain.ModuleResult) (queued, running, completed, failed, skipped int) {
	for _, module := range modules {
		switch module.Status {
		case domain.ModuleQueued:
			queued++
		case domain.ModuleRunning:
			running++
		case domain.ModuleCompleted:
			completed++
		case domain.ModuleFailed:
			failed++
		case domain.ModuleSkipped:
			skipped++
		}
	}
	return queued, running, completed, failed, skipped
}

func (a *App) clearTerminalView() {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		_, _ = fmt.Fprint(os.Stdout, "\033[H\033[2J")
	}
}

func (a *App) isTerminalRunStatus(status domain.ScanStatus) bool {
	switch status {
	case domain.ScanCompleted, domain.ScanFailed, domain.ScanCanceled:
		return true
	default:
		return false
	}
}

type runStatusCounts struct {
	Queued    int
	Running   int
	Canceled  int
	Completed int
	Failed    int
}

func (a *App) countRunStatuses(runs []domain.ScanRun) runStatusCounts {
	counts := runStatusCounts{}
	for _, run := range runs {
		switch run.Status {
		case domain.ScanQueued:
			counts.Queued++
		case domain.ScanRunning:
			counts.Running++
		case domain.ScanCanceled:
			counts.Canceled++
		case domain.ScanCompleted:
			counts.Completed++
		case domain.ScanFailed:
			counts.Failed++
		}
	}
	return counts
}

func (a *App) activeQueueRuns(runs []domain.ScanRun, limit int) []domain.ScanRun {
	active := make([]domain.ScanRun, 0, len(runs))
	for _, run := range runs {
		if run.Status == domain.ScanQueued || run.Status == domain.ScanRunning {
			active = append(active, run)
		}
	}
	if limit > 0 && len(active) > limit {
		return active[:limit]
	}
	return active
}

func filterFindings(findings []domain.Finding, severity, category, status string, limit int) []domain.Finding {
	severity = strings.ToLower(strings.TrimSpace(severity))
	category = strings.ToLower(strings.TrimSpace(category))
	status = strings.ToLower(strings.TrimSpace(status))

	filtered := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if severity != "" && string(finding.Severity) != severity {
			continue
		}
		if category != "" && string(finding.Category) != category {
			continue
		}
		if status != "" && string(finding.Status) != status {
			continue
		}
		filtered = append(filtered, finding)
	}

	if limit > 0 && len(filtered) > limit {
		return filtered[:limit]
	}
	return filtered
}

func filterFindingsByChange(findings []domain.Finding, delta domain.RunDelta, change string) []domain.Finding {
	change = strings.ToLower(strings.TrimSpace(change))
	allowed := make(map[string]struct{}, len(findings))

	switch domain.FindingChange(change) {
	case domain.FindingExisting:
		for _, finding := range delta.ExistingFindings {
			allowed[finding.Fingerprint] = struct{}{}
		}
	case domain.FindingResolved:
		for _, finding := range delta.ResolvedFindings {
			allowed[finding.Fingerprint] = struct{}{}
		}
	default:
		for _, finding := range delta.NewFindings {
			allowed[finding.Fingerprint] = struct{}{}
		}
	}

	filtered := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if _, ok := allowed[finding.Fingerprint]; ok {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func parseTargets(items []string) []domain.DastTarget {
	targets := make([]domain.DastTarget, 0, len(items))
	for _, item := range items {
		name, url, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		targets = append(targets, domain.DastTarget{
			Name:     strings.TrimSpace(name),
			URL:      strings.TrimSpace(url),
			AuthType: domain.DastAuthNone,
		})
	}
	return targets
}

func trimForSelect(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	if max < 4 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func parseCSVTags(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return normalizeTags(strings.Split(value, ","))
}

func normalizeTags(tags []string) []string {
	set := make(map[string]struct{}, len(tags))
	items := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if _, ok := set[tag]; ok {
			continue
		}
		set[tag] = struct{}{}
		items = append(items, tag)
	}
	slices.Sort(items)
	return items
}

func countFindingStatus(findings []domain.Finding, status domain.FindingStatus) int {
	total := 0
	for _, finding := range findings {
		current := finding.Status
		if current == "" {
			current = domain.FindingOpen
		}
		if current == status {
			total++
		}
	}
	return total
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func ternary[T any](condition bool, left, right T) T {
	if condition {
		return left
	}
	return right
}
