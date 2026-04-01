package cli

import "testing"

func TestPtermSprintfStripsMarkupWhenNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	app := &App{}
	rendered := app.ptermSprintf("%s [cyan]%d[-]", "ready", 3)

	if rendered != "ready 3" {
		t.Fatalf("expected plain text without markup, got %q", rendered)
	}
}
