package preferences

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/batu3384/ironsentinel/internal/config"
)

type Preferences struct {
	Language           string `json:"language"`
	UIMode             string `json:"ui_mode"`
	LanguageConfigured bool   `json:"-"`
}

func Load(cfg config.Config) (Preferences, error) {
	path := filepath.Join(cfg.DataDir, "preferences.json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Preferences{
				UIMode: "standard",
			}, nil
		}
		return Preferences{}, err
	}

	var preferences Preferences
	if err := json.Unmarshal(bytes, &preferences); err != nil {
		return Preferences{}, err
	}
	if preferences.Language != "" {
		preferences.LanguageConfigured = true
	}
	if preferences.UIMode == "" {
		preferences.UIMode = "standard"
	}
	return preferences, nil
}

func Save(cfg config.Config, preferences Preferences) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(preferences, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(cfg.DataDir, "preferences.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, bytes, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
