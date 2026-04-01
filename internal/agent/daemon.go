package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

const daemonHeartbeatTTL = 5 * time.Second

func daemonStatusPath(cfg config.Config) string {
	return filepath.Join(cfg.DataDir, "daemon-status.json")
}

func discoverDaemon(cfg config.Config) domain.RuntimeDaemon {
	path := daemonStatusPath(cfg)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return domain.RuntimeDaemon{Notes: "daemon not started"}
	}

	var status domain.RuntimeDaemon
	if err := json.Unmarshal(bytes, &status); err != nil {
		return domain.RuntimeDaemon{Notes: "daemon status unreadable"}
	}

	if status.Active && status.LastHeartbeat != nil {
		status.Stale = time.Since(status.LastHeartbeat.UTC()) > daemonHeartbeatTTL
	}
	if status.Stale {
		status.Active = false
		if status.Notes == "" {
			status.Notes = "daemon heartbeat is stale"
		}
	}
	if !status.Active && status.Notes == "" {
		status.Notes = "daemon is idle"
	}
	return status
}

func saveDaemonStatus(cfg config.Config, status domain.RuntimeDaemon) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	path := daemonStatusPath(cfg)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, bytes, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func startDaemonHeartbeatWithMeta(cfg config.Config, mode string, meta domain.RuntimeDaemon) (func(string), error) {
	now := time.Now().UTC()
	status := meta
	status.PID = os.Getpid()
	status.Mode = mode
	status.Active = true
	status.Stale = false
	status.StartedAt = &now
	status.LastHeartbeat = &now
	if status.ScheduledProjects == nil {
		status.ScheduledProjects = []string{}
	}
	if err := saveDaemonStatus(cfg, status); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case tick := <-ticker.C:
				mu.Lock()
				current := discoverDaemon(cfg)
				if current.PID == status.PID && current.StartedAt != nil {
					status = current
				}
				heartbeat := tick.UTC()
				status.Active = true
				status.Stale = false
				status.LastHeartbeat = &heartbeat
				_ = saveDaemonStatus(cfg, status)
				mu.Unlock()
			}
		}
	}()

	return func(note string) {
		cancel()
		mu.Lock()
		defer mu.Unlock()
		current := discoverDaemon(cfg)
		if current.PID == status.PID && current.StartedAt != nil {
			status = current
		}
		stoppedAt := time.Now().UTC()
		status.Active = false
		status.Stale = false
		status.StoppedAt = &stoppedAt
		status.LastHeartbeat = &stoppedAt
		status.Notes = note
		_ = saveDaemonStatus(cfg, status)
	}, nil
}

func StartDaemonHeartbeatWithMeta(cfg config.Config, mode string, meta domain.RuntimeDaemon) (func(string), error) {
	return startDaemonHeartbeatWithMeta(cfg, mode, meta)
}

func updateDaemonStatus(cfg config.Config, mutate func(*domain.RuntimeDaemon)) error {
	status := discoverDaemon(cfg)
	mutate(&status)
	return saveDaemonStatus(cfg, status)
}

func UpdateDaemonSchedule(cfg config.Config, scheduledAt time.Time, note string) error {
	return updateDaemonStatus(cfg, func(status *domain.RuntimeDaemon) {
		tick := scheduledAt.UTC()
		status.LastScheduledAt = &tick
		if strings.TrimSpace(note) != "" {
			status.Notes = note
		}
	})
}

func UpdateDaemonNotification(cfg config.Config, notifiedAt time.Time, note string) error {
	return updateDaemonStatus(cfg, func(status *domain.RuntimeDaemon) {
		tick := notifiedAt.UTC()
		status.LastNotificationAt = &tick
		if strings.TrimSpace(note) != "" {
			status.Notes = note
		}
	})
}
