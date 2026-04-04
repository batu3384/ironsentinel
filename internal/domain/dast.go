package domain

import (
	"fmt"
	"strings"
)

func NormalizeDastAuthProfile(profile DastAuthProfile) DastAuthProfile {
	profile.Name = strings.TrimSpace(profile.Name)
	profile.Type = NormalizeDastAuthType(profile.Type.String())
	profile.HeaderName = strings.TrimSpace(profile.HeaderName)
	profile.SecretEnv = strings.TrimSpace(profile.SecretEnv)
	profile.UsernameEnv = strings.TrimSpace(profile.UsernameEnv)
	profile.PasswordEnv = strings.TrimSpace(profile.PasswordEnv)
	profile.LoginPageURL = strings.TrimSpace(profile.LoginPageURL)
	profile.BrowserID = strings.TrimSpace(profile.BrowserID)
	profile.LoginRequestURL = strings.TrimSpace(profile.LoginRequestURL)
	profile.LoginRequestBody = strings.TrimSpace(profile.LoginRequestBody)
	profile.SessionCheckURL = strings.TrimSpace(profile.SessionCheckURL)
	profile.SessionCheckPattern = strings.TrimSpace(profile.SessionCheckPattern)
	profile.LoggedInRegex = strings.TrimSpace(profile.LoggedInRegex)
	profile.LoggedOutRegex = strings.TrimSpace(profile.LoggedOutRegex)
	return profile
}

func NormalizeDastAuthProfiles(profiles []DastAuthProfile) []DastAuthProfile {
	normalized := make([]DastAuthProfile, 0, len(profiles))
	for _, profile := range profiles {
		normalized = append(normalized, NormalizeDastAuthProfile(profile))
	}
	return normalized
}

func ValidateDastAuthProfile(profile DastAuthProfile) error {
	profile = NormalizeDastAuthProfile(profile)
	if profile.Name == "" {
		return fmt.Errorf("dast auth profile name is required")
	}
	if profile.Type == "" {
		return fmt.Errorf("dast auth profile %q type is required", profile.Name)
	}

	switch profile.Type {
	case DastAuthNone:
		return nil
	case DastAuthBearer:
		if profile.SecretEnv == "" {
			return fmt.Errorf("dast auth profile %q bearer secretEnv is required", profile.Name)
		}
	case DastAuthHeader:
		if profile.HeaderName == "" {
			return fmt.Errorf("dast auth profile %q headerName is required for header auth", profile.Name)
		}
		if profile.SecretEnv == "" {
			return fmt.Errorf("dast auth profile %q secretEnv is required for header auth", profile.Name)
		}
	case DastAuthBasic:
		if profile.UsernameEnv == "" {
			return fmt.Errorf("dast auth profile %q usernameEnv is required for basic auth", profile.Name)
		}
		if profile.PasswordEnv == "" {
			return fmt.Errorf("dast auth profile %q passwordEnv is required for basic auth", profile.Name)
		}
	case DastAuthBrowser:
		if profile.LoginPageURL == "" {
			return fmt.Errorf("dast auth profile %q loginPageUrl is required for browser auth", profile.Name)
		}
		if profile.UsernameEnv == "" {
			return fmt.Errorf("dast auth profile %q usernameEnv is required for browser auth", profile.Name)
		}
		if profile.PasswordEnv == "" {
			return fmt.Errorf("dast auth profile %q passwordEnv is required for browser auth", profile.Name)
		}
	case DastAuthForm:
		if profile.LoginPageURL == "" {
			return fmt.Errorf("dast auth profile %q loginPageUrl is required for form auth", profile.Name)
		}
		if profile.LoginRequestURL == "" {
			return fmt.Errorf("dast auth profile %q loginRequestUrl is required for form auth", profile.Name)
		}
		if profile.LoginRequestBody == "" {
			return fmt.Errorf("dast auth profile %q loginRequestBody is required for form auth", profile.Name)
		}
		if profile.UsernameEnv == "" {
			return fmt.Errorf("dast auth profile %q usernameEnv is required for form auth", profile.Name)
		}
		if profile.PasswordEnv == "" {
			return fmt.Errorf("dast auth profile %q passwordEnv is required for form auth", profile.Name)
		}
		if profile.SessionCheckURL == "" && profile.LoggedInRegex == "" && profile.LoggedOutRegex == "" {
			return fmt.Errorf("dast auth profile %q requires sessionCheckUrl or loggedInRegex/loggedOutRegex for form auth verification", profile.Name)
		}
	default:
		return fmt.Errorf("dast auth profile %q uses unsupported auth type %q", profile.Name, profile.Type)
	}
	return nil
}

func IndexDastAuthProfiles(profiles []DastAuthProfile) (map[string]DastAuthProfile, error) {
	index := make(map[string]DastAuthProfile, len(profiles))
	for _, profile := range profiles {
		normalized := NormalizeDastAuthProfile(profile)
		if err := ValidateDastAuthProfile(normalized); err != nil {
			return nil, err
		}
		if _, exists := index[normalized.Name]; exists {
			return nil, fmt.Errorf("duplicate dast auth profile %q", normalized.Name)
		}
		index[normalized.Name] = normalized
	}
	return index, nil
}

func ResolveDastTargetAuth(target DastTarget, profiles []DastAuthProfile) (DastTarget, *DastAuthProfile, error) {
	target.Name = strings.TrimSpace(target.Name)
	target.URL = strings.TrimSpace(target.URL)
	target.AuthProfile = strings.TrimSpace(target.AuthProfile)
	target.AuthType = NormalizeDastAuthType(target.AuthType.String())

	if target.AuthProfile == "" {
		if target.AuthType == "" {
			target.AuthType = DastAuthNone
		}
		return target, nil, nil
	}

	index, err := IndexDastAuthProfiles(profiles)
	if err != nil {
		return DastTarget{}, nil, err
	}
	profile, ok := index[target.AuthProfile]
	if !ok {
		return DastTarget{}, nil, fmt.Errorf("unknown dast auth profile %q", target.AuthProfile)
	}
	if target.AuthType != "" && target.AuthType != DastAuthNone && target.AuthType != profile.Type {
		return DastTarget{}, nil, fmt.Errorf(
			"dast target %q auth type %q conflicts with profile %q type %q",
			target.Name,
			target.AuthType,
			profile.Name,
			profile.Type,
		)
	}
	target.AuthType = profile.Type
	return target, &profile, nil
}
