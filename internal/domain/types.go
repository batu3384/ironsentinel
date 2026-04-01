package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}

type ScanMode string

const (
	ModeSafe   ScanMode = "safe"
	ModeDeep   ScanMode = "deep"
	ModeActive ScanMode = "active"
)

type IsolationMode string

const (
	IsolationAuto      IsolationMode = "auto"
	IsolationLocal     IsolationMode = "local"
	IsolationContainer IsolationMode = "container"
)

type IsolationNetworkPolicy string

const (
	IsolationNetworkNone    IsolationNetworkPolicy = "none"
	IsolationNetworkDefault IsolationNetworkPolicy = "container_default"
)

type IsolationContract struct {
	Mode                IsolationMode          `json:"mode"`
	NetworkPolicy       IsolationNetworkPolicy `json:"networkPolicy"`
	EnvAllowlist        bool                   `json:"envAllowlist"`
	WorkspaceReadOnly   bool                   `json:"workspaceReadOnly"`
	RootfsReadOnly      bool                   `json:"rootfsReadOnly"`
	ArtifactWritable    bool                   `json:"artifactWritable"`
	MirrorReadOnly      bool                   `json:"mirrorReadOnly"`
	NoNewPrivileges     bool                   `json:"noNewPrivileges"`
	DropAllCapabilities bool                   `json:"dropAllCapabilities"`
	TmpfsPaths          []string               `json:"tmpfsPaths,omitempty"`
	PidsLimit           int                    `json:"pidsLimit,omitempty"`
	MemoryMiB           int                    `json:"memoryMiB,omitempty"`
	CPUMilli            int                    `json:"cpuMilli,omitempty"`
}

type CoverageProfile string

const (
	CoverageCore    CoverageProfile = "core"
	CoveragePremium CoverageProfile = "premium"
	CoverageFull    CoverageProfile = "full"
)

type CompliancePreset string

const (
	CompliancePresetNone       CompliancePreset = ""
	CompliancePresetPCIDSS     CompliancePreset = "pci-dss"
	CompliancePresetSOC2       CompliancePreset = "soc2"
	CompliancePresetOWASPTop10 CompliancePreset = "owasp-top10"
	CompliancePresetSANSTop25  CompliancePreset = "sans-top25"
)

type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCanceled  ScanStatus = "canceled"
)

type ModuleStatus string

const (
	ModuleQueued    ModuleStatus = "queued"
	ModuleRunning   ModuleStatus = "running"
	ModuleCompleted ModuleStatus = "completed"
	ModuleFailed    ModuleStatus = "failed"
	ModuleSkipped   ModuleStatus = "skipped"
)

type ModuleFailureKind string

const (
	ModuleFailureNone       ModuleFailureKind = ""
	ModuleFailureSkipped    ModuleFailureKind = "skipped"
	ModuleFailureToolMiss   ModuleFailureKind = "tool_missing"
	ModuleFailureTimeout    ModuleFailureKind = "timeout"
	ModuleFailureCommand    ModuleFailureKind = "command_failed"
	ModuleFailureParse      ModuleFailureKind = "parse_error"
	ModuleFailureInfra      ModuleFailureKind = "infra_error"
	ModuleFailureArtifactIO ModuleFailureKind = "artifact_io"
)

type FindingCategory string

const (
	CategorySAST            FindingCategory = "sast"
	CategorySCA             FindingCategory = "sca"
	CategorySecret          FindingCategory = "secret"
	CategoryIaC             FindingCategory = "iac"
	CategoryContainer       FindingCategory = "container"
	CategoryMalware         FindingCategory = "malware"
	CategoryDAST            FindingCategory = "dast"
	CategoryCompliance      FindingCategory = "compliance"
	CategoryMaintainability FindingCategory = "maintainability"
	CategoryPlatform        FindingCategory = "platform"
)

type FindingStatus string

const (
	FindingOpen          FindingStatus = "open"
	FindingInvestigating FindingStatus = "investigating"
	FindingAcceptedRisk  FindingStatus = "accepted_risk"
	FindingFalsePositive FindingStatus = "false_positive"
	FindingFixed         FindingStatus = "fixed"
)

func AllFindingStatuses() []FindingStatus {
	return []FindingStatus{
		FindingOpen,
		FindingInvestigating,
		FindingAcceptedRisk,
		FindingFalsePositive,
		FindingFixed,
	}
}

type FindingChange string

const (
	FindingNew      FindingChange = "new"
	FindingExisting FindingChange = "existing"
	FindingResolved FindingChange = "resolved"
)

func AllFindingChanges() []FindingChange {
	return []FindingChange{
		FindingNew,
		FindingExisting,
		FindingResolved,
	}
}

type PolicyOutcome string

const (
	PolicyOutcomePass PolicyOutcome = "pass"
	PolicyOutcomeWarn PolicyOutcome = "warn"
	PolicyOutcomeFail PolicyOutcome = "fail"
)

type DastTarget struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	AuthType string `json:"authType,omitempty"`
}

type ScanProfile struct {
	Mode           ScanMode         `json:"mode"`
	Isolation      IsolationMode    `json:"isolation,omitempty"`
	Coverage       CoverageProfile  `json:"coverage,omitempty"`
	PresetID       CompliancePreset `json:"presetId,omitempty"`
	Modules        []string         `json:"modules"`
	SeverityGate   Severity         `json:"severityGate"`
	PolicyID       string           `json:"policyId,omitempty"`
	AllowBuild     bool             `json:"allowBuild"`
	AllowNetwork   bool             `json:"allowNetwork"`
	DASTTargets    []DastTarget     `json:"dastTargets"`
	CredentialsRef string           `json:"credentialsRef,omitempty"`
}

type Project struct {
	ID             string    `json:"id"`
	TargetHandle   string    `json:"targetHandle"`
	DisplayName    string    `json:"displayName"`
	DetectedStacks []string  `json:"detectedStacks"`
	PolicyID       string    `json:"policyId,omitempty"`
	LocationHint   string    `json:"locationHint,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

type ArtifactRef struct {
	Kind      string     `json:"kind"`
	Label     string     `json:"label"`
	URI       string     `json:"uri"`
	Redacted  bool       `json:"redacted,omitempty"`
	Encrypted bool       `json:"encrypted,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

type ModuleResult struct {
	Name         string            `json:"name"`
	Category     FindingCategory   `json:"category"`
	Status       ModuleStatus      `json:"status"`
	Summary      string            `json:"summary"`
	FindingCount int               `json:"findingCount"`
	DurationMs   int64             `json:"durationMs"`
	Attempts     int               `json:"attempts,omitempty"`
	TimedOut     bool              `json:"timedOut,omitempty"`
	FailureKind  ModuleFailureKind `json:"failureKind,omitempty"`
	ExitCode     *int              `json:"exitCode,omitempty"`
	Artifacts    []ArtifactRef     `json:"artifacts"`
}

type Finding struct {
	ID           string          `json:"id"`
	ScanID       string          `json:"scanId"`
	ProjectID    string          `json:"projectId"`
	Category     FindingCategory `json:"category"`
	RuleID       string          `json:"ruleId"`
	Title        string          `json:"title"`
	Severity     Severity        `json:"severity"`
	Confidence   float64         `json:"confidence"`
	Reachability string          `json:"reachability"`
	Fingerprint  string          `json:"fingerprint"`
	EvidenceRef  string          `json:"evidenceRef,omitempty"`
	Remediation  string          `json:"remediation"`
	Location     string          `json:"location,omitempty"`
	Module       string          `json:"module"`
	CVSS31       float64         `json:"cvss31,omitempty"`
	CVSS40       float64         `json:"cvss40,omitempty"`
	EPSSScore    float64         `json:"epssScore,omitempty"`
	EPSSPercent  float64         `json:"epssPercent,omitempty"`
	KEV          bool            `json:"kev,omitempty"`
	CWEs         []string        `json:"cwes,omitempty"`
	Compliance   []string        `json:"compliance,omitempty"`
	Priority     float64         `json:"priority,omitempty"`
	AssetValue   float64         `json:"assetValue,omitempty"`
	AttackChain  string          `json:"attackChain,omitempty"`
	Related      []string        `json:"related,omitempty"`
	Status       FindingStatus   `json:"status,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	Note         string          `json:"note,omitempty"`
	Owner        string          `json:"owner,omitempty"`
	UpdatedAt    *time.Time      `json:"updatedAt,omitempty"`
}

type RunTrendPoint struct {
	RunID          string    `json:"runId"`
	StartedAt      time.Time `json:"startedAt"`
	TotalFindings  int       `json:"totalFindings"`
	Critical       int       `json:"critical"`
	High           int       `json:"high"`
	Medium         int       `json:"medium"`
	Low            int       `json:"low"`
	ComplianceHits int       `json:"complianceHits,omitempty"`
}

type FindingTriage struct {
	Fingerprint string        `json:"fingerprint"`
	Status      FindingStatus `json:"status"`
	Tags        []string      `json:"tags,omitempty"`
	Note        string        `json:"note,omitempty"`
	Owner       string        `json:"owner,omitempty"`
	UpdatedAt   time.Time     `json:"updatedAt"`
}

type ScanSummary struct {
	TotalFindings    int                     `json:"totalFindings"`
	CountsBySeverity map[Severity]int        `json:"countsBySeverity"`
	CountsByCategory map[FindingCategory]int `json:"countsByCategory"`
	CountsByStatus   map[FindingStatus]int   `json:"countsByStatus"`
	Blocked          bool                    `json:"blocked"`
}

type ScanRun struct {
	ID               string         `json:"id"`
	ProjectID        string         `json:"projectId"`
	Status           ScanStatus     `json:"status"`
	StartedAt        time.Time      `json:"startedAt"`
	FinishedAt       *time.Time     `json:"finishedAt,omitempty"`
	Summary          ScanSummary    `json:"summary"`
	ArtifactRefs     []ArtifactRef  `json:"artifactRefs"`
	ModuleResults    []ModuleResult `json:"moduleResults"`
	Profile          ScanProfile    `json:"profile"`
	CancelRequested  bool           `json:"cancelRequested,omitempty"`
	RetriedFromRunID string         `json:"retriedFromRunId,omitempty"`
	ExecutionMode    string         `json:"executionMode,omitempty"`
}

type RunDelta struct {
	ProjectID        string                `json:"projectId"`
	RunID            string                `json:"runId"`
	BaselineRunID    string                `json:"baselineRunId,omitempty"`
	CountsByChange   map[FindingChange]int `json:"countsByChange"`
	NewFindings      []Finding             `json:"newFindings"`
	ExistingFindings []Finding             `json:"existingFindings"`
	ResolvedFindings []Finding             `json:"resolvedFindings"`
}

type Suppression struct {
	Fingerprint string    `json:"fingerprint"`
	Reason      string    `json:"reason"`
	Owner       string    `json:"owner"`
	ExpiresAt   time.Time `json:"expiresAt"`
	TicketRef   string    `json:"ticketRef,omitempty"`
}

type RuntimeTool struct {
	Name                   string              `json:"name"`
	BundleName             string              `json:"bundleName,omitempty"`
	Channel                string              `json:"channel,omitempty"`
	Source                 string              `json:"source,omitempty"`
	Available              bool                `json:"available"`
	Required               bool                `json:"required,omitempty"`
	Healthy                bool                `json:"healthy"`
	Path                   string              `json:"path,omitempty"`
	ExpectedVersion        string              `json:"expectedVersion,omitempty"`
	ActualVersion          string              `json:"actualVersion,omitempty"`
	InstallCommand         string              `json:"installCommand,omitempty"`
	ChecksumCovered        bool                `json:"checksumCovered,omitempty"`
	SignatureCovered       bool                `json:"signatureCovered,omitempty"`
	SourceIntegrityCovered bool                `json:"sourceIntegrityCovered,omitempty"`
	Verification           RuntimeVerification `json:"verification,omitempty"`
}

type RuntimeVerification struct {
	ChecksumConfigured  bool   `json:"checksumConfigured,omitempty"`
	ChecksumExpected    string `json:"checksumExpected,omitempty"`
	ChecksumActual      string `json:"checksumActual,omitempty"`
	ChecksumVerified    bool   `json:"checksumVerified,omitempty"`
	SignatureConfigured bool   `json:"signatureConfigured,omitempty"`
	SignatureType       string `json:"signatureType,omitempty"`
	SignatureSigner     string `json:"signatureSigner,omitempty"`
	SignatureVerified   bool   `json:"signatureVerified,omitempty"`
	Notes               string `json:"notes,omitempty"`
}

func (v RuntimeVerification) Status() string {
	switch {
	case (v.ChecksumConfigured && !v.ChecksumVerified) || (v.SignatureConfigured && !v.SignatureVerified):
		return "failed"
	case (v.ChecksumConfigured && v.ChecksumVerified) || (v.SignatureConfigured && v.SignatureVerified):
		return "verified"
	default:
		return "unverified"
	}
}

type RuntimeTrustedAsset struct {
	Name         string              `json:"name"`
	Kind         string              `json:"kind,omitempty"`
	Path         string              `json:"path"`
	Verification RuntimeVerification `json:"verification,omitempty"`
}

type RuntimeLockCoverage struct {
	Name                   string   `json:"name"`
	Channel                string   `json:"channel,omitempty"`
	Version                string   `json:"version,omitempty"`
	Source                 string   `json:"source,omitempty"`
	ChecksumCovered        bool     `json:"checksumCovered,omitempty"`
	SignatureCovered       bool     `json:"signatureCovered,omitempty"`
	SourceIntegrityCovered bool     `json:"sourceIntegrityCovered,omitempty"`
	Platforms              []string `json:"platforms,omitempty"`
}

type RuntimeReleaseArtifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	OS     string `json:"os,omitempty"`
	Arch   string `json:"arch,omitempty"`
	Format string `json:"format,omitempty"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

type RuntimeReleaseProvenance struct {
	Commit       string `json:"commit,omitempty"`
	Ref          string `json:"ref,omitempty"`
	Builder      string `json:"builder,omitempty"`
	GoVersion    string `json:"goVersion,omitempty"`
	HostPlatform string `json:"hostPlatform,omitempty"`
	Repository   string `json:"repository,omitempty"`
	Workflow     string `json:"workflow,omitempty"`
	RunID        string `json:"runId,omitempty"`
	RunAttempt   string `json:"runAttempt,omitempty"`
	SourceDirty  bool   `json:"sourceDirty,omitempty"`
}

type RuntimeReleaseBundle struct {
	Version                         string                   `json:"version"`
	Path                            string                   `json:"path"`
	GeneratedAt                     *time.Time               `json:"generatedAt,omitempty"`
	ArtifactCount                   int                      `json:"artifactCount"`
	Signed                          bool                     `json:"signed"`
	Verification                    RuntimeVerification      `json:"verification,omitempty"`
	TrustAnchor                     RuntimeTrustedAsset      `json:"trustAnchor,omitempty"`
	ChecksumsPath                   string                   `json:"checksumsPath,omitempty"`
	ManifestPath                    string                   `json:"manifestPath,omitempty"`
	SignaturePath                   string                   `json:"signaturePath,omitempty"`
	Attested                        bool                     `json:"attested"`
	AttestationPath                 string                   `json:"attestationPath,omitempty"`
	AttestationSignaturePath        string                   `json:"attestationSignaturePath,omitempty"`
	AttestationVerification         RuntimeVerification      `json:"attestationVerification,omitempty"`
	ExternalAttested                bool                     `json:"externalAttested"`
	ExternalAttestationPath         string                   `json:"externalAttestationPath,omitempty"`
	ExternalAttestationProvider     string                   `json:"externalAttestationProvider,omitempty"`
	ExternalAttestationSourceURI    string                   `json:"externalAttestationSourceUri,omitempty"`
	ExternalAttestationVerification RuntimeVerification      `json:"externalAttestationVerification,omitempty"`
	Artifacts                       []RuntimeReleaseArtifact `json:"artifacts,omitempty"`
	Provenance                      RuntimeReleaseProvenance `json:"provenance,omitempty"`
}

type RuntimeSupplyChain struct {
	Signer                string                 `json:"signer,omitempty"`
	SignatureType         string                 `json:"signatureType,omitempty"`
	PublicKeyFingerprint  string                 `json:"publicKeyFingerprint,omitempty"`
	TrustedAssets         []RuntimeTrustedAsset  `json:"trustedAssets,omitempty"`
	LockCoverage          []RuntimeLockCoverage  `json:"lockCoverage,omitempty"`
	ReleaseBundles        []RuntimeReleaseBundle `json:"releaseBundles,omitempty"`
	VerifiedTools         int                    `json:"verifiedTools"`
	FailedTools           int                    `json:"failedTools"`
	UnverifiedTools       int                    `json:"unverifiedTools"`
	ChecksumCoveredTools  int                    `json:"checksumCoveredTools"`
	SignatureCoveredTools int                    `json:"signatureCoveredTools"`
	SourceIntegrityTools  int                    `json:"sourceIntegrityTools"`
	IntegrityGapTools     int                    `json:"integrityGapTools"`
	VerifiedAssets        int                    `json:"verifiedAssets"`
	FailedAssets          int                    `json:"failedAssets"`
	UnverifiedAssets      int                    `json:"unverifiedAssets"`
}

type RuntimeIsolation struct {
	PreferredMode   IsolationMode     `json:"preferredMode"`
	EffectiveMode   IsolationMode     `json:"effectiveMode"`
	Engine          string            `json:"engine,omitempty"`
	EnginePath      string            `json:"enginePath,omitempty"`
	Platform        string            `json:"platform,omitempty"`
	Rootless        bool              `json:"rootless"`
	ContainerImage  string            `json:"containerImage,omitempty"`
	ImagePresent    bool              `json:"imagePresent"`
	Ready           bool              `json:"ready"`
	DefaultContract IsolationContract `json:"defaultContract,omitempty"`
}

type RuntimeMirror struct {
	Tool      string     `json:"tool"`
	Path      string     `json:"path"`
	Available bool       `json:"available"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	Notes     string     `json:"notes,omitempty"`
}

type RuntimeDaemon struct {
	PID                int        `json:"pid,omitempty"`
	Mode               string     `json:"mode,omitempty"`
	Active             bool       `json:"active"`
	Stale              bool       `json:"stale,omitempty"`
	StartedAt          *time.Time `json:"startedAt,omitempty"`
	LastHeartbeat      *time.Time `json:"lastHeartbeat,omitempty"`
	StoppedAt          *time.Time `json:"stoppedAt,omitempty"`
	ScheduleInterval   string     `json:"scheduleInterval,omitempty"`
	ScheduledProjects  []string   `json:"scheduledProjects,omitempty"`
	DriftDetection     bool       `json:"driftDetection,omitempty"`
	SlackEnabled       bool       `json:"slackEnabled,omitempty"`
	WebhookEnabled     bool       `json:"webhookEnabled,omitempty"`
	LastScheduledAt    *time.Time `json:"lastScheduledAt,omitempty"`
	LastNotificationAt *time.Time `json:"lastNotificationAt,omitempty"`
	Notes              string     `json:"notes,omitempty"`
}

type RuntimeSupportLevel string

const (
	RuntimeSupportSupported   RuntimeSupportLevel = "supported"
	RuntimeSupportPartial     RuntimeSupportLevel = "partial"
	RuntimeSupportUnsupported RuntimeSupportLevel = "unsupported"
)

type RuntimeCoverageSupport struct {
	Coverage CoverageProfile     `json:"coverage"`
	Level    RuntimeSupportLevel `json:"level"`
	Notes    string              `json:"notes,omitempty"`
}

type RuntimeSupportMatrix struct {
	OS          string                   `json:"os"`
	Arch        string                   `json:"arch"`
	Platform    string                   `json:"platform"`
	Recommended CoverageProfile          `json:"recommended"`
	Tiers       []RuntimeCoverageSupport `json:"tiers,omitempty"`
}

func (m RuntimeSupportMatrix) Coverage(coverage CoverageProfile) (RuntimeCoverageSupport, bool) {
	for _, tier := range m.Tiers {
		if tier.Coverage == coverage {
			return tier, true
		}
	}
	return RuntimeCoverageSupport{}, false
}

type RuntimeStatus struct {
	AgentReachable    bool                      `json:"agentReachable"`
	SocketPath        string                    `json:"socketPath"`
	BundleVersion     int                       `json:"bundleVersion"`
	BundleLockPath    string                    `json:"bundleLockPath,omitempty"`
	InstallScript     string                    `json:"installScript,omitempty"`
	ImageBuildScript  string                    `json:"imageBuildScript,omitempty"`
	ContainerfilePath string                    `json:"containerfilePath,omitempty"`
	ScannerBundle     []RuntimeTool             `json:"scannerBundle"`
	HealthyToolCount  int                       `json:"healthyToolCount"`
	RequiredMissing   int                       `json:"requiredMissing"`
	RequiredOutdated  int                       `json:"requiredOutdated"`
	Isolation         RuntimeIsolation          `json:"isolation"`
	Mirrors           []RuntimeMirror           `json:"mirrors,omitempty"`
	Daemon            RuntimeDaemon             `json:"daemon"`
	Artifacts         RuntimeArtifactProtection `json:"artifacts"`
	SupplyChain       RuntimeSupplyChain        `json:"supplyChain"`
	Support           RuntimeSupportMatrix      `json:"support"`
}

type RuntimeArtifactProtection struct {
	RetentionDays     int      `json:"retentionDays"`
	RedactionEnabled  bool     `json:"redactionEnabled"`
	EncryptionEnabled bool     `json:"encryptionEnabled"`
	ProtectedKinds    []string `json:"protectedKinds,omitempty"`
}

func ResolveIsolationContract(profile ScanProfile, mode IsolationMode, offline bool) IsolationContract {
	networkPolicy := IsolationNetworkDefault
	if offline || !profile.AllowNetwork {
		networkPolicy = IsolationNetworkNone
	}

	contract := IsolationContract{
		Mode:          mode,
		NetworkPolicy: networkPolicy,
		EnvAllowlist:  true,
	}
	if mode != IsolationContainer {
		return contract
	}

	contract.WorkspaceReadOnly = true
	contract.RootfsReadOnly = true
	contract.ArtifactWritable = true
	contract.MirrorReadOnly = true
	contract.NoNewPrivileges = true
	contract.DropAllCapabilities = true
	contract.TmpfsPaths = []string{"/tmp", "/run", "/var/tmp"}

	switch profile.Mode {
	case ModeDeep:
		contract.PidsLimit = 256
		contract.MemoryMiB = 2048
		contract.CPUMilli = 2000
	case ModeActive:
		contract.PidsLimit = 384
		contract.MemoryMiB = 3072
		contract.CPUMilli = 2000
	default:
		contract.PidsLimit = 128
		contract.MemoryMiB = 1024
		contract.CPUMilli = 1000
	}

	if profile.AllowBuild {
		contract.PidsLimit += 64
		contract.MemoryMiB += 1024
		contract.CPUMilli += 1000
	}

	return contract
}

type RuntimeDoctor struct {
	Mode               ScanMode              `json:"mode"`
	StrictVersions     bool                  `json:"strictVersions"`
	RequireIntegrity   bool                  `json:"requireIntegrity"`
	Ready              bool                  `json:"ready"`
	Required           []RuntimeTool         `json:"required"`
	Missing            []RuntimeTool         `json:"missing"`
	Outdated           []RuntimeTool         `json:"outdated"`
	FailedVerification []RuntimeTool         `json:"failedVerification,omitempty"`
	Unverified         []RuntimeTool         `json:"unverified,omitempty"`
	FailedAssets       []RuntimeTrustedAsset `json:"failedAssets,omitempty"`
	Checks             []RuntimeDoctorCheck  `json:"checks,omitempty"`
}

type RuntimeCheckStatus string

const (
	RuntimeCheckPass RuntimeCheckStatus = "pass"
	RuntimeCheckWarn RuntimeCheckStatus = "warn"
	RuntimeCheckFail RuntimeCheckStatus = "fail"
	RuntimeCheckSkip RuntimeCheckStatus = "skip"
)

type RuntimeDoctorCheck struct {
	Name    string             `json:"name"`
	Status  RuntimeCheckStatus `json:"status"`
	Summary string             `json:"summary,omitempty"`
	Details []string           `json:"details,omitempty"`
}

type PolicyRule struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Outcome     PolicyOutcome   `json:"outcome"`
	Threshold   int             `json:"threshold"`
	ChangeScope FindingChange   `json:"changeScope,omitempty"`
	Severity    Severity        `json:"severity,omitempty"`
	Category    FindingCategory `json:"category,omitempty"`
}

type PolicyPack struct {
	ID    string       `json:"id"`
	Title string       `json:"title"`
	Rules []PolicyRule `json:"rules"`
}

type PolicyRuleResult struct {
	Rule         PolicyRule    `json:"rule"`
	Outcome      PolicyOutcome `json:"outcome"`
	MatchedCount int           `json:"matchedCount"`
	Findings     []Finding     `json:"findings,omitempty"`
}

type PolicyEvaluation struct {
	PolicyID      string             `json:"policyId"`
	RunID         string             `json:"runId"`
	BaselineRunID string             `json:"baselineRunId,omitempty"`
	Passed        bool               `json:"passed"`
	Results       []PolicyRuleResult `json:"results"`
}

type DashboardSnapshot struct {
	Projects []Project     `json:"projects"`
	Runs     []ScanRun     `json:"runs"`
	Findings []Finding     `json:"findings"`
	Runtime  RuntimeStatus `json:"runtime"`
}

type RegisterProjectRequest struct {
	DisplayName    string `json:"displayName"`
	Path           string `json:"path,omitempty"`
	UseAgentPicker bool   `json:"useAgentPicker,omitempty"`
	PolicyID       string `json:"policyId,omitempty"`
}

type CreateScanRequest struct {
	ProjectID string      `json:"projectId"`
	Profile   ScanProfile `json:"profile"`
}

type ExportReportRequest struct {
	ScanID string `json:"scanId"`
	Format string `json:"format"`
}

type DastPlanRequest struct {
	ProjectID string       `json:"projectId"`
	Targets   []DastTarget `json:"targets"`
	Active    bool         `json:"active"`
}

type DastPlan struct {
	ProjectID string   `json:"projectId"`
	Policy    string   `json:"policy"`
	Steps     []string `json:"steps"`
}

type ModuleAttemptTrace struct {
	Attempt      int               `json:"attempt"`
	StartedAt    time.Time         `json:"startedAt"`
	FinishedAt   time.Time         `json:"finishedAt"`
	DurationMs   int64             `json:"durationMs"`
	FailureKind  ModuleFailureKind `json:"failureKind,omitempty"`
	TimedOut     bool              `json:"timedOut,omitempty"`
	ExitCode     *int              `json:"exitCode,omitempty"`
	Command      string            `json:"command,omitempty"`
	Args         []string          `json:"args,omitempty"`
	WorkingDir   string            `json:"workingDir,omitempty"`
	Environment  []string          `json:"environment,omitempty"`
	ArtifactRefs []ArtifactRef     `json:"artifactRefs,omitempty"`
}

type ModuleExecutionTrace struct {
	Module         string               `json:"module"`
	Status         ModuleStatus         `json:"status"`
	FailureKind    ModuleFailureKind    `json:"failureKind,omitempty"`
	TimeoutSec     int                  `json:"timeoutSec,omitempty"`
	MaxAttempts    int                  `json:"maxAttempts,omitempty"`
	AttemptsUsed   int                  `json:"attemptsUsed,omitempty"`
	StartedAt      time.Time            `json:"startedAt"`
	FinishedAt     time.Time            `json:"finishedAt"`
	DurationMs     int64                `json:"durationMs"`
	AttemptJournal []ModuleAttemptTrace `json:"attemptJournal,omitempty"`
}

type StreamEvent struct {
	Type      string                `json:"type"`
	Run       ScanRun               `json:"run"`
	Module    *ModuleResult         `json:"module,omitempty"`
	Finding   *Finding              `json:"finding,omitempty"`
	Attempt   *ModuleAttemptTrace   `json:"attempt,omitempty"`
	Execution *ModuleExecutionTrace `json:"execution,omitempty"`
	Message   string                `json:"message,omitempty"`
	At        time.Time             `json:"at"`
}

type ResolveTargetRequest struct {
	Path        string `json:"path,omitempty"`
	Interactive bool   `json:"interactive,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type ResolveTargetResponse struct {
	Handle         string   `json:"handle"`
	Path           string   `json:"path"`
	DisplayName    string   `json:"displayName"`
	DetectedStacks []string `json:"detectedStacks"`
}

type AgentScanRequest struct {
	ScanID       string      `json:"scanId"`
	ProjectID    string      `json:"projectId"`
	TargetHandle string      `json:"targetHandle"`
	TargetPath   string      `json:"targetPath"`
	DisplayName  string      `json:"displayName"`
	Profile      ScanProfile `json:"profile"`
}

type AgentEvent struct {
	Type           string                `json:"type"`
	Module         *ModuleResult         `json:"module,omitempty"`
	Finding        *Finding              `json:"finding,omitempty"`
	Attempt        *ModuleAttemptTrace   `json:"attempt,omitempty"`
	Execution      *ModuleExecutionTrace `json:"execution,omitempty"`
	Message        string                `json:"message,omitempty"`
	DetectedStacks []string              `json:"detectedStacks,omitempty"`
	Artifacts      []ArtifactRef         `json:"artifacts,omitempty"`
	At             time.Time             `json:"at"`
}

func NewScanSummary() ScanSummary {
	counts := make(map[Severity]int, len(AllSeverities()))
	for _, severity := range AllSeverities() {
		counts[severity] = 0
	}

	statusCounts := make(map[FindingStatus]int, len(AllFindingStatuses()))
	for _, status := range AllFindingStatuses() {
		statusCounts[status] = 0
	}

	return ScanSummary{
		CountsBySeverity: counts,
		CountsByCategory: make(map[FindingCategory]int),
		CountsByStatus:   statusCounts,
	}
}

func NewRunDelta(runID, baselineRunID, projectID string) RunDelta {
	counts := make(map[FindingChange]int, len(AllFindingChanges()))
	for _, change := range AllFindingChanges() {
		counts[change] = 0
	}

	return RunDelta{
		ProjectID:      projectID,
		RunID:          runID,
		BaselineRunID:  baselineRunID,
		CountsByChange: counts,
	}
}

func RecalculateSummary(findings []Finding, gate Severity) ScanSummary {
	summary := NewScanSummary()
	gateRank := SeverityRank(gate)

	for _, finding := range findings {
		status := finding.Status
		if status == "" {
			status = FindingOpen
		}
		summary.TotalFindings++
		summary.CountsBySeverity[finding.Severity]++
		summary.CountsByCategory[finding.Category]++
		summary.CountsByStatus[status]++
		if SeverityRank(finding.Severity) <= gateRank {
			summary.Blocked = true
		}
	}

	return summary
}

func FilterFindingsAtOrAboveSeverity(findings []Finding, threshold Severity) []Finding {
	thresholdRank := SeverityRank(threshold)
	filtered := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if SeverityRank(finding.Severity) <= thresholdRank {
			filtered = append(filtered, finding)
		}
	}
	sortFindings(filtered)
	return filtered
}

func CalculateRunDelta(current, baseline []Finding, runID, baselineRunID, projectID string) RunDelta {
	delta := NewRunDelta(runID, baselineRunID, projectID)

	currentByFingerprint := make(map[string]Finding, len(current))
	for _, finding := range current {
		currentByFingerprint[finding.Fingerprint] = finding
	}

	baselineByFingerprint := make(map[string]Finding, len(baseline))
	for _, finding := range baseline {
		baselineByFingerprint[finding.Fingerprint] = finding
	}

	for fingerprint, finding := range currentByFingerprint {
		if _, ok := baselineByFingerprint[fingerprint]; ok {
			delta.ExistingFindings = append(delta.ExistingFindings, finding)
			delta.CountsByChange[FindingExisting]++
			continue
		}
		delta.NewFindings = append(delta.NewFindings, finding)
		delta.CountsByChange[FindingNew]++
	}

	for fingerprint, finding := range baselineByFingerprint {
		if _, ok := currentByFingerprint[fingerprint]; ok {
			continue
		}
		delta.ResolvedFindings = append(delta.ResolvedFindings, finding)
		delta.CountsByChange[FindingResolved]++
	}

	sortFindings(delta.NewFindings)
	sortFindings(delta.ExistingFindings)
	sortFindings(delta.ResolvedFindings)

	return delta
}

func SeverityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

func sortFindings(items []Finding) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i]
		right := items[j]

		if rankDiff := SeverityRank(left.Severity) - SeverityRank(right.Severity); rankDiff != 0 {
			return rankDiff < 0
		}
		if left.Title != right.Title {
			return left.Title < right.Title
		}
		if left.Location != right.Location {
			return left.Location < right.Location
		}
		return left.Fingerprint < right.Fingerprint
	})
}

func NormalizeStacks(stacks []string) []string {
	set := make(map[string]struct{}, len(stacks))
	for _, stack := range stacks {
		stack = strings.TrimSpace(strings.ToLower(stack))
		if stack == "" {
			continue
		}
		set[stack] = struct{}{}
	}

	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	sort.Strings(items)
	return items
}

func MakeFingerprint(parts ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(hash[:])[:16]
}

func NewFindingID(scanID string, index int) string {
	return fmt.Sprintf("%s-f%03d", scanID, index)
}
