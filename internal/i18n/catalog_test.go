package i18n

import "testing"

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
