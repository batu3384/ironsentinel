package findingtext

import (
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func Title(catalog i18n.Catalog, finding domain.Finding) string {
	title := strings.TrimSpace(finding.Title)
	key := findingTextKey(finding, "title")
	if key == "" {
		return title
	}
	return catalog.T(key)
}

func Remediation(catalog i18n.Catalog, finding domain.Finding) string {
	remediation := strings.TrimSpace(finding.Remediation)
	key := findingTextKey(finding, "remediation")
	if key == "" {
		return remediation
	}
	return catalog.T(key)
}

func findingTextKey(finding domain.Finding, suffix string) string {
	ruleID := strings.TrimSpace(finding.RuleID)
	if ruleID == "" {
		ruleID = ruleIDFromKnownTitle(strings.TrimSpace(finding.Title))
	}
	switch ruleID {
	case "surface.sensitive_repo_file":
		return "finding_surface_sensitive_repo_file_" + suffix
	case "surface.binary_artifact":
		return "finding_surface_binary_artifact_" + suffix
	case "runtime.committed_env_file":
		return "finding_runtime_committed_env_file_" + suffix
	case "secret.aws_access_key":
		return "finding_secret_aws_access_key_" + suffix
	case "secret.generic_assignment":
		return "finding_secret_generic_assignment_" + suffix
	case "secret.github_pat":
		return "finding_secret_github_pat_" + suffix
	case "script.remote_pipe_shell":
		return "finding_script_remote_pipe_shell_" + suffix
	case "script.remote_process_substitution":
		return "finding_script_remote_process_substitution_" + suffix
	case "script.privileged_container":
		return "finding_script_privileged_container_" + suffix
	case "script.disable_tls_verify":
		return "finding_script_disable_tls_verify_" + suffix
	case "script.world_writable_permissions":
		return "finding_script_world_writable_permissions_" + suffix
	case "malware.eicar":
		return "finding_malware_eicar_" + suffix
	default:
		return ""
	}
}

func ruleIDFromKnownTitle(title string) string {
	switch title {
	case "Sensitive operational file committed to the repository":
		return "surface.sensitive_repo_file"
	case "Binary or opaque artifact committed to the repository":
		return "surface.binary_artifact"
	case "Committed environment file detected in repository":
		return "runtime.committed_env_file"
	case "Potential AWS access key detected":
		return "secret.aws_access_key"
	case "Potential hard-coded secret assignment":
		return "secret.generic_assignment"
	case "Potential GitHub personal access token":
		return "secret.github_pat"
	case "Remote script piped directly into a shell":
		return "script.remote_pipe_shell"
	case "Remote script executed through process substitution":
		return "script.remote_process_substitution"
	case "Privileged container execution detected":
		return "script.privileged_container"
	case "TLS verification disabled in fetch command":
		return "script.disable_tls_verify"
	case "World-writable permissions command detected":
		return "script.world_writable_permissions"
	case "EICAR test signature detected":
		return "malware.eicar"
	default:
		return ""
	}
}
