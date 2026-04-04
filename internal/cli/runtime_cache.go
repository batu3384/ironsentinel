package cli

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

const uiRuntimeCacheTTL = 5 * time.Second
const uiRuntimeDoctorCacheTTL = 5 * time.Second

func (a *App) runtimeStatus(force bool) domain.RuntimeStatus {
	if a == nil || a.service == nil {
		return domain.RuntimeStatus{}
	}

	a.runtimeCacheMu.Lock()
	if !force && !a.runtimeCacheAt.IsZero() && time.Since(a.runtimeCacheAt) < uiRuntimeCacheTTL {
		status := a.runtimeCache
		a.runtimeCacheMu.Unlock()
		return status
	}
	a.runtimeCacheMu.Unlock()

	status := a.service.Runtime()

	a.runtimeCacheMu.Lock()
	a.runtimeCache = status
	a.runtimeCacheAt = time.Now()
	a.runtimeCacheMu.Unlock()
	return status
}

func (a *App) invalidateRuntimeCache() {
	if a == nil {
		return
	}
	a.runtimeCacheMu.Lock()
	a.runtimeCache = domain.RuntimeStatus{}
	a.runtimeCacheAt = time.Time{}
	a.runtimeDoctorCache = domain.RuntimeDoctor{}
	a.runtimeDoctorCacheKey = ""
	a.runtimeDoctorCacheAt = time.Time{}
	a.runtimeCacheMu.Unlock()
}

func (a *App) runtimeDoctor(profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
	if a == nil {
		return domain.RuntimeDoctor{}
	}

	key := runtimeDoctorCacheKey(profile, strictVersions, requireIntegrity)
	a.runtimeCacheMu.Lock()
	if !a.runtimeDoctorCacheAt.IsZero() &&
		a.runtimeDoctorCacheKey == key &&
		time.Since(a.runtimeDoctorCacheAt) < uiRuntimeDoctorCacheTTL {
		doctor := a.runtimeDoctorCache
		a.runtimeCacheMu.Unlock()
		return doctor
	}
	doctorFn := a.runtimeDoctorFn
	a.runtimeCacheMu.Unlock()

	var doctor domain.RuntimeDoctor
	switch {
	case doctorFn != nil:
		doctor = doctorFn(profile, strictVersions, requireIntegrity)
	case a.service != nil:
		doctor = a.service.RuntimeDoctor(profile, strictVersions, requireIntegrity)
	default:
		return domain.RuntimeDoctor{}
	}

	a.runtimeCacheMu.Lock()
	a.runtimeDoctorCache = doctor
	a.runtimeDoctorCacheKey = key
	a.runtimeDoctorCacheAt = time.Now()
	a.runtimeCacheMu.Unlock()
	return doctor
}

func runtimeDoctorCacheKey(profile domain.ScanProfile, strictVersions, requireIntegrity bool) string {
	normalized := profile
	normalized.Modules = append([]string(nil), profile.Modules...)
	slices.Sort(normalized.Modules)

	normalized.DASTTargets = append([]domain.DastTarget(nil), profile.DASTTargets...)
	slices.SortFunc(normalized.DASTTargets, func(a, b domain.DastTarget) int {
		if a.URL != b.URL {
			if a.URL < b.URL {
				return -1
			}
			return 1
		}
		if a.Name != b.Name {
			if a.Name < b.Name {
				return -1
			}
			return 1
		}
		if a.AuthProfile != b.AuthProfile {
			if a.AuthProfile < b.AuthProfile {
				return -1
			}
			return 1
		}
		if a.AuthType != b.AuthType {
			if a.AuthType.String() < b.AuthType.String() {
				return -1
			}
			return 1
		}
		return 0
	})

	payload, err := json.Marshal(struct {
		Profile          domain.ScanProfile `json:"profile"`
		StrictVersions   bool               `json:"strictVersions"`
		RequireIntegrity bool               `json:"requireIntegrity"`
	}{
		Profile:          normalized,
		StrictVersions:   strictVersions,
		RequireIntegrity: requireIntegrity,
	})
	if err != nil {
		return ""
	}
	return string(payload)
}
