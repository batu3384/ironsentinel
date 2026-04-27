package i18n

import (
	"strings"
	"testing"
)

func TestCatalogParityAcrossLanguages(t *testing.T) {
	en := messages[EN]
	tr := messages[TR]

	for key, value := range en {
		translated, ok := tr[key]
		if !ok {
			t.Fatalf("missing Turkish translation for key %q", key)
		}
		if countFormatVerbs(value) != countFormatVerbs(translated) {
			t.Fatalf("format verb mismatch for key %q: en=%d tr=%d", key, countFormatVerbs(value), countFormatVerbs(translated))
		}
	}

	for key := range tr {
		if _, ok := en[key]; !ok {
			t.Fatalf("missing English translation for key %q", key)
		}
	}
}

func TestTurkishCatalogTrustConsoleCriticalCopy(t *testing.T) {
	tr := messages[TR]
	cases := map[string]string{
		"console_stage_mission":          "Görev",
		"scan_mc_progress":               "Görev ilerlemesi",
		"module_timed_out":               "Zaman aşımı",
		"runtime_daemon_title":           "Daemon sağlığı",
		"empty_state":                    "Gösterilecek öğe yok.",
		"picker_notice":                  "Yerel klasör seçici açılıyor...",
		"finding_reachability_reachable": "erişilebilir",
		"finding_signal_reachable_path":  "erişilebilir yol",
		"attempt_details_title":          "Deneme detayları",
		"artifact_filter_label":          "Artefakt filtresi",
		"range_label":                    "Gösterilen",
		"ticket":                         "Bilet",
	}
	for key, expected := range cases {
		if tr[key] != expected {
			t.Fatalf("unexpected Turkish copy for %s: got %q want %q", key, tr[key], expected)
		}
	}
}

func TestTurkishCatalogRejectsCriticalASCIITurkish(t *testing.T) {
	tr := messages[TR]
	keys := []string{
		"run_focus_actions",
		"tui_queue_action_drain",
		"tui_finding_action_suppress",
		"runtime_daemon_title",
		"picker_notice",
	}
	forbidden := []string{" odakli", " acar", " degistir", " siddet", " bolunmus", " gorunum", " doner", " kosu", " kuyruga", " bastirma", " sagligi", " klasor", " secici", " aciliyor"}
	for _, key := range keys {
		value := tr[key]
		for _, token := range forbidden {
			if strings.Contains(value, token) {
				t.Fatalf("Turkish copy for %s contains ASCII-only token %q in %q", key, token, value)
			}
		}
	}
}

func countFormatVerbs(value string) int {
	count := 0
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if index+1 < len(value) && value[index+1] == '%' {
			index++
			continue
		}
		count++
	}
	return count
}
