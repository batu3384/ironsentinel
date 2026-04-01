package cli

import (
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

const uiRuntimeCacheTTL = 5 * time.Second

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
	a.runtimeCacheMu.Unlock()
}
