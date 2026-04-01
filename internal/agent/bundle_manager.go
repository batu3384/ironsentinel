package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
)

type BundleSnapshot struct {
	ID        string    `json:"id"`
	Mode      string    `json:"mode"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"createdAt"`
}

type bundleHistory struct {
	Snapshots []BundleSnapshot `json:"snapshots"`
}

func bundleHistoryPath(cfg config.Config) string {
	return filepath.Join(cfg.DataDir, "bundle-history.json")
}

func bundleBackupRoot(cfg config.Config) string {
	return filepath.Join(cfg.DataDir, "bundle-backups")
}

func managedToolsRoot(cfg config.Config) string {
	root := filepath.Dir(cfg.ToolsDir)
	if root == "." || root == "" {
		return cfg.ToolsDir
	}
	return root
}

func ListBundleSnapshots(cfg config.Config) ([]BundleSnapshot, error) {
	history, err := loadBundleHistory(cfg)
	if err != nil {
		return nil, err
	}
	sort.Slice(history.Snapshots, func(i, j int) bool {
		return history.Snapshots[i].CreatedAt.After(history.Snapshots[j].CreatedAt)
	})
	return history.Snapshots, nil
}

func UpdateManagedBundle(cfg config.Config, mode string, apply func(string) error) (BundleSnapshot, error) {
	snapshot, err := backupManagedBundle(cfg, mode)
	if err != nil {
		return BundleSnapshot{}, err
	}
	if err := apply(mode); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func RollbackManagedBundle(cfg config.Config, snapshotID string) (BundleSnapshot, error) {
	history, err := loadBundleHistory(cfg)
	if err != nil {
		return BundleSnapshot{}, err
	}
	if len(history.Snapshots) == 0 {
		return BundleSnapshot{}, fmt.Errorf("no managed bundle snapshots available")
	}

	var selected BundleSnapshot
	if snapshotID == "" {
		sort.Slice(history.Snapshots, func(i, j int) bool {
			return history.Snapshots[i].CreatedAt.After(history.Snapshots[j].CreatedAt)
		})
		selected = history.Snapshots[0]
	} else {
		for _, snapshot := range history.Snapshots {
			if snapshot.ID == snapshotID {
				selected = snapshot
				break
			}
		}
		if selected.ID == "" {
			return BundleSnapshot{}, fmt.Errorf("managed bundle snapshot not found: %s", snapshotID)
		}
	}

	root := managedToolsRoot(cfg)
	if err := os.RemoveAll(root); err != nil {
		return BundleSnapshot{}, err
	}
	if err := copyDir(selected.Path, root); err != nil {
		return BundleSnapshot{}, err
	}
	return selected, nil
}

func backupManagedBundle(cfg config.Config, mode string) (BundleSnapshot, error) {
	root := managedToolsRoot(cfg)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return BundleSnapshot{}, err
	}
	if err := os.MkdirAll(bundleBackupRoot(cfg), 0o755); err != nil {
		return BundleSnapshot{}, err
	}

	snapshot := BundleSnapshot{
		ID:        time.Now().UTC().Format("20060102T150405Z"),
		Mode:      mode,
		Path:      filepath.Join(bundleBackupRoot(cfg), time.Now().UTC().Format("20060102T150405Z")),
		CreatedAt: time.Now().UTC(),
	}
	snapshot.Path = filepath.Join(bundleBackupRoot(cfg), snapshot.ID)

	if err := copyDir(root, snapshot.Path); err != nil {
		return BundleSnapshot{}, err
	}
	history, err := loadBundleHistory(cfg)
	if err != nil {
		return BundleSnapshot{}, err
	}
	history.Snapshots = append(history.Snapshots, snapshot)
	if err := saveBundleHistory(cfg, history); err != nil {
		return BundleSnapshot{}, err
	}
	return snapshot, nil
}

func loadBundleHistory(cfg config.Config) (bundleHistory, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return bundleHistory{}, err
	}
	path := bundleHistoryPath(cfg)
	bytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return bundleHistory{}, nil
		}
		return bundleHistory{}, err
	}
	var history bundleHistory
	if err := json.Unmarshal(bytes, &history); err != nil {
		return bundleHistory{}, err
	}
	return history, nil
}

func saveBundleHistory(cfg config.Config, history bundleHistory) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	path := bundleHistoryPath(cfg)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dst, 0o755)
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(src, entry.Name())
		destPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDir(sourcePath, destPath); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(sourcePath, destPath); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	bytes, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, bytes, info.Mode())
}
