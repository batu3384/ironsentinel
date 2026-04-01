package preferences

import (
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
)

func TestLoadWithoutPreferencesLeavesLanguageUnconfigured(t *testing.T) {
	cfg := config.Config{
		DataDir:         t.TempDir(),
		DefaultLanguage: "tr",
	}

	prefs, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if prefs.Language != "" {
		t.Fatalf("Load() language = %q, want empty for first-run prompt", prefs.Language)
	}
	if prefs.LanguageConfigured {
		t.Fatalf("Load() LanguageConfigured = true, want false when no file exists")
	}
	if prefs.UIMode != "standard" {
		t.Fatalf("Load() ui mode = %q, want standard", prefs.UIMode)
	}
}

func TestSaveAndReloadMarksLanguageConfigured(t *testing.T) {
	cfg := config.Config{
		DataDir:         t.TempDir(),
		DefaultLanguage: "en",
	}

	if err := Save(cfg, Preferences{Language: "tr", UIMode: "compact"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	prefs, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if prefs.Language != "tr" {
		t.Fatalf("Load() language = %q, want tr", prefs.Language)
	}
	if !prefs.LanguageConfigured {
		t.Fatalf("Load() LanguageConfigured = false, want true after save")
	}
	if prefs.UIMode != "compact" {
		t.Fatalf("Load() ui mode = %q, want compact", prefs.UIMode)
	}
}
