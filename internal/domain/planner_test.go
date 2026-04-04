package domain

import "testing"

func TestProjectLanePlansUseCanonicalOrderingAndMetadata(t *testing.T) {
	project := Project{ID: "prj-1", DetectedStacks: []string{"go", "terraform"}}
	plans := ProjectLanePlans(project, []string{"trivy", "stack-detector", "semgrep", "tfsec"}, nil)
	if len(plans) != 4 {
		t.Fatalf("expected 4 lane plans, got %d", len(plans))
	}
	if plans[0].Key != "surface" || plans[1].Key != "code" || plans[2].Key != "supply" || plans[3].Key != "infra" {
		t.Fatalf("unexpected lane order: %+v", plans)
	}
	if plans[1].Kind != ScanLaneKindFast {
		t.Fatalf("expected code lane to be fast, got %s", plans[1].Kind)
	}
	if len(plans[3].Modules) != 1 || plans[3].Modules[0].Name != "tfsec" {
		t.Fatalf("expected infra lane to include tfsec, got %+v", plans[3].Modules)
	}
	if plans[3].Modules[0].TimeoutClass != ModuleTimeoutLong {
		t.Fatalf("expected tfsec timeout class to be long, got %s", plans[3].Modules[0].TimeoutClass)
	}
}

func TestProjectLanePlansBlendHistoricalAndHeuristicDuration(t *testing.T) {
	project := Project{ID: "prj-1", DetectedStacks: []string{"go"}}
	runs := []ScanRun{
		{
			ID:        "run-1",
			ProjectID: "prj-1",
			ModuleResults: []ModuleResult{
				{Name: "stack-detector", DurationMs: 1000},
				{Name: "surface-inventory", DurationMs: 3000},
				{Name: "trivy", DurationMs: 90000},
				{Name: "syft", DurationMs: 30000},
			},
		},
		{
			ID:        "run-2",
			ProjectID: "prj-1",
			ModuleResults: []ModuleResult{
				{Name: "stack-detector", DurationMs: 2000},
				{Name: "surface-inventory", DurationMs: 2000},
				{Name: "trivy", DurationMs: 60000},
				{Name: "syft", DurationMs: 60000},
			},
		},
	}
	plans := ProjectLanePlans(project, []string{"stack-detector", "surface-inventory", "trivy", "syft"}, runs)
	if got := plans[0].EstimatedMs; got != 4350 {
		t.Fatalf("expected blended surface ETA 4350ms, got %d", got)
	}
	if got := plans[1].EstimatedMs; got != 120000 {
		t.Fatalf("expected blended supply ETA 120000ms, got %d", got)
	}
}
