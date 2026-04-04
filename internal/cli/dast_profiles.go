package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func loadDASTAuthProfiles(path string) ([]domain.DastAuthProfile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Profiles []domain.DastAuthProfile `json:"profiles"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Profiles) > 0 {
		profiles := domain.NormalizeDastAuthProfiles(envelope.Profiles)
		_, err := domain.IndexDastAuthProfiles(profiles)
		return profiles, err
	}

	var profiles []domain.DastAuthProfile
	if err := json.Unmarshal(body, &profiles); err != nil {
		return nil, fmt.Errorf("parse dast auth profiles: %w", err)
	}
	profiles = domain.NormalizeDastAuthProfiles(profiles)
	_, err = domain.IndexDastAuthProfiles(profiles)
	return profiles, err
}

func bindDASTTargetAuthProfiles(targets []domain.DastTarget, mappings []string, profiles []domain.DastAuthProfile) ([]domain.DastTarget, error) {
	targets = append([]domain.DastTarget(nil), targets...)
	mappingIndex := make(map[string]string, len(mappings))
	for _, item := range mappings {
		name, profileName, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("invalid dast target auth mapping %q", item)
		}
		name = strings.TrimSpace(name)
		profileName = strings.TrimSpace(profileName)
		if name == "" || profileName == "" {
			return nil, fmt.Errorf("invalid dast target auth mapping %q", item)
		}
		mappingIndex[name] = profileName
	}

	foundTargets := make(map[string]struct{}, len(targets))
	for index, target := range targets {
		target.AuthProfile = mappingIndex[target.Name]
		resolved, _, err := domain.ResolveDastTargetAuth(target, profiles)
		if err != nil {
			return nil, err
		}
		targets[index] = resolved
		foundTargets[target.Name] = struct{}{}
	}

	for targetName := range mappingIndex {
		if _, ok := foundTargets[targetName]; !ok {
			return nil, fmt.Errorf("unknown dast target %q in auth mapping", targetName)
		}
	}
	return targets, nil
}

func prepareDASTConfiguration(targetItems, targetAuthItems []string, authFile string) ([]domain.DastTarget, []domain.DastAuthProfile, error) {
	profiles, err := loadDASTAuthProfiles(authFile)
	if err != nil {
		return nil, nil, err
	}
	targets, err := bindDASTTargetAuthProfiles(parseTargets(targetItems), targetAuthItems, profiles)
	if err != nil {
		return nil, nil, err
	}
	return targets, profiles, nil
}
