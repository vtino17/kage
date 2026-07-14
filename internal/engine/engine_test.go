package engine

import (
	"testing"

	"github.com/vtino17/kage/internal/model"
	"github.com/vtino17/kage/internal/scanner"
)

func TestEngineEmptyFindings(t *testing.T) {
	e := NewEngine()
	results := e.Process([]scanner.Result{})
	if len(results) != 0 {
		t.Errorf("expected 0 findings, got %d", len(results))
	}
}

func TestEngineDeduplicate(t *testing.T) {
	e := NewEngine()
	results := []scanner.Result{
		{
			ScannerName: "test",
			Findings: []model.Finding{
				{Scanner: "test", FilePath: "a.go", Title: "rule1"},
				{Scanner: "test", FilePath: "a.go", Title: "rule1"},
				{Scanner: "test", FilePath: "b.go", Title: "rule2"},
			},
		},
	}

	findings := e.Process(results)
	if len(findings) != 2 {
		t.Errorf("expected 2 unique findings, got %d", len(findings))
	}
}

func TestEngineSeveritySort(t *testing.T) {
	e := NewEngine()
	results := []scanner.Result{
		{
			ScannerName: "test",
			Findings: []model.Finding{
				{Title: "low", Severity: model.SeverityLow},
				{Title: "critical", Severity: model.SeverityCritical},
				{Title: "high", Severity: model.SeverityHigh},
			},
		},
	}

	findings := e.Process(results)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("first finding should be critical, got %v", findings[0].Severity)
	}
	if findings[1].Severity != model.SeverityHigh {
		t.Errorf("second finding should be high, got %v", findings[1].Severity)
	}
	if findings[2].Severity != model.SeverityLow {
		t.Errorf("third finding should be low, got %v", findings[2].Severity)
	}
}

func TestEngineSeverityCount(t *testing.T) {
	e := NewEngine()
	findings := []model.Finding{
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityHigh},
		{Severity: model.SeverityCritical},
	}

	counts := e.SeverityCount(findings)
	if counts[model.SeverityCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", counts[model.SeverityCritical])
	}
	if counts[model.SeverityHigh] != 1 {
		t.Errorf("expected 1 high, got %d", counts[model.SeverityHigh])
	}
}

func TestEngineCategorize(t *testing.T) {
	e := NewEngine()
	findings := []model.Finding{
		{Title: "a", Category: "sast"},
		{Title: "b", Category: "secret"},
		{Title: "c", Category: "sast"},
	}

	cats := e.Categorize(findings)
	if len(cats["sast"]) != 2 {
		t.Errorf("expected 2 sast, got %d", len(cats["sast"]))
	}
	if len(cats["secret"]) != 1 {
		t.Errorf("expected 1 secret, got %d", len(cats["secret"]))
	}
}
