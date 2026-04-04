package core

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

var runtimeDoctorProbeURLs = []string{
	"https://osv.dev",
	"https://api.github.com",
}

func (s *Service) augmentRuntimeDoctor(doctor domain.RuntimeDoctor) domain.RuntimeDoctor {
	checks := []domain.RuntimeDoctorCheck{
		s.sqliteDoctorCheck(),
		s.directoryPermissionCheck("data_dir", s.config.DataDir),
		s.directoryPermissionCheck("output_dir", s.config.OutputDir),
		s.directoryPermissionCheck("tools_dir", s.config.ToolsDir),
		s.diskDoctorCheck(),
		s.networkDoctorCheck(),
	}

	for _, check := range checks {
		if check.Name == "" {
			continue
		}
		doctor.Checks = append(doctor.Checks, check)
		if check.Status == domain.RuntimeCheckFail {
			doctor.Ready = false
		}
	}
	return doctor
}

func (s *Service) sqliteDoctorCheck() domain.RuntimeDoctorCheck {
	results, err := s.store.IntegrityCheck()
	if err != nil {
		return domain.RuntimeDoctorCheck{
			Name:    "sqlite_integrity",
			Class:   domain.RuntimeCheckClassIntegrity,
			Status:  domain.RuntimeCheckFail,
			Summary: "SQLite integrity check failed.",
			Details: []string{err.Error()},
		}
	}

	issues := make([]string, 0, len(results))
	for _, item := range results {
		if !strings.EqualFold(strings.TrimSpace(item), "ok") {
			issues = append(issues, item)
		}
	}
	if len(issues) > 0 {
		return domain.RuntimeDoctorCheck{
			Name:    "sqlite_integrity",
			Class:   domain.RuntimeCheckClassIntegrity,
			Status:  domain.RuntimeCheckFail,
			Summary: "SQLite integrity issues detected.",
			Details: issues,
		}
	}
	return domain.RuntimeDoctorCheck{
		Name:    "sqlite_integrity",
		Class:   domain.RuntimeCheckClassIntegrity,
		Status:  domain.RuntimeCheckPass,
		Summary: "SQLite integrity check returned ok.",
		Details: []string{s.store.Path()},
	}
}

func (s *Service) directoryPermissionCheck(name, path string) domain.RuntimeDoctorCheck {
	if strings.TrimSpace(path) == "" {
		return domain.RuntimeDoctorCheck{
			Name:    "permissions_" + name,
			Class:   domain.RuntimeCheckClassFilesystem,
			Status:  domain.RuntimeCheckSkip,
			Summary: "No path configured.",
		}
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return domain.RuntimeDoctorCheck{
			Name:    "permissions_" + name,
			Class:   domain.RuntimeCheckClassFilesystem,
			Status:  domain.RuntimeCheckFail,
			Summary: "Directory creation failed.",
			Details: []string{path, err.Error()},
		}
	}
	probe := filepath.Join(path, ".ironsentinel-write-check")
	if err := os.WriteFile(probe, []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0o644); err != nil {
		return domain.RuntimeDoctorCheck{
			Name:    "permissions_" + name,
			Class:   domain.RuntimeCheckClassFilesystem,
			Status:  domain.RuntimeCheckFail,
			Summary: "Directory is not writable.",
			Details: []string{path, err.Error()},
		}
	}
	_ = os.Remove(probe)
	return domain.RuntimeDoctorCheck{
		Name:    "permissions_" + name,
		Class:   domain.RuntimeCheckClassFilesystem,
		Status:  domain.RuntimeCheckPass,
		Summary: "Directory write probe succeeded.",
		Details: []string{path},
	}
}

func (s *Service) diskDoctorCheck() domain.RuntimeDoctorCheck {
	free, err := availableDiskBytes(s.config.OutputDir)
	if err != nil {
		return domain.RuntimeDoctorCheck{
			Name:    "disk_space",
			Class:   domain.RuntimeCheckClassFilesystem,
			Status:  domain.RuntimeCheckSkip,
			Summary: "Disk space probe unavailable.",
			Details: []string{err.Error()},
		}
	}

	const (
		failFloor = 512 * 1024 * 1024
		warnFloor = 2 * 1024 * 1024 * 1024
	)
	status := domain.RuntimeCheckPass
	summary := fmt.Sprintf("Free disk: %.1f GiB.", float64(free)/(1024*1024*1024))
	if free < failFloor {
		status = domain.RuntimeCheckFail
		summary = fmt.Sprintf("Free disk critically low: %.1f GiB.", float64(free)/(1024*1024*1024))
	} else if free < warnFloor {
		status = domain.RuntimeCheckWarn
		summary = fmt.Sprintf("Free disk is low: %.1f GiB.", float64(free)/(1024*1024*1024))
	}
	return domain.RuntimeDoctorCheck{
		Name:    "disk_space",
		Class:   domain.RuntimeCheckClassFilesystem,
		Status:  status,
		Summary: summary,
		Details: []string{s.config.OutputDir},
	}
}

func (s *Service) networkDoctorCheck() domain.RuntimeDoctorCheck {
	if s.config.OfflineMode {
		return domain.RuntimeDoctorCheck{
			Name:    "network_probe",
			Class:   domain.RuntimeCheckClassNetwork,
			Status:  domain.RuntimeCheckSkip,
			Summary: "Offline mode is forced by configuration.",
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	failures := make([]string, 0, len(runtimeDoctorProbeURLs))
	for _, probe := range runtimeDoctorProbeURLs {
		req, err := http.NewRequest(http.MethodHead, probe, nil)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", probe, err))
			continue
		}
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return domain.RuntimeDoctorCheck{
					Name:    "network_probe",
					Class:   domain.RuntimeCheckClassNetwork,
					Status:  domain.RuntimeCheckPass,
					Summary: "Outbound connectivity looks healthy.",
					Details: []string{probe, resp.Status},
				}
			}
			failures = append(failures, fmt.Sprintf("%s: %s", probe, resp.Status))
			continue
		}
		failures = append(failures, fmt.Sprintf("%s: %v", probe, err))
	}
	return domain.RuntimeDoctorCheck{
		Name:    "network_probe",
		Class:   domain.RuntimeCheckClassNetwork,
		Status:  domain.RuntimeCheckWarn,
		Summary: "Outbound connectivity probe could not confirm online state.",
		Details: failures,
	}
}
