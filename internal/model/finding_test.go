package model

import (
	"testing"
	"time"
)

func TestFindingDedupKey(t *testing.T) {
	f := Finding{
		Scanner:  "semgrep",
		FilePath: "src/main.go",
		Title:    "test-rule",
	}
	key := f.DedupKey()
	expected := "semgrep:src/main.go:test-rule"
	if key != expected {
		t.Errorf("expected %q, got %q", expected, key)
	}
}

func TestFindingDedupKeyConsistency(t *testing.T) {
	f1 := Finding{
		Scanner:   "gitleaks",
		FilePath:  "config.env",
		Title:     "hardcoded-password",
		CreatedAt: time.Now(),
	}
	f2 := Finding{
		Scanner:   "gitleaks",
		FilePath:  "config.env",
		Title:     "hardcoded-password",
		CreatedAt: time.Now().Add(1 * time.Hour),
	}
	if f1.DedupKey() != f2.DedupKey() {
		t.Error("dedup key should not depend on timestamp")
	}
}

func TestScanResultAddFinding(t *testing.T) {
	target := ScanTarget{Type: "directory", Path: "/test"}
	result := NewScanResult(target)

	f := Finding{
		Scanner:  "test",
		Title:    "test-finding",
		Severity: SeverityHigh,
	}
	result.AddFinding(f)

	if result.Summary.Total != 1 {
		t.Errorf("expected 1 finding, got %d", result.Summary.Total)
	}
}

func TestScanResultFinalize(t *testing.T) {
	target := ScanTarget{Type: "directory", Path: "/test"}
	result := NewScanResult(target)

	result.AddFinding(Finding{Severity: SeverityCritical})
	result.AddFinding(Finding{Severity: SeverityHigh})
	result.AddFinding(Finding{Severity: SeverityCritical})

	result.Finalize()

	if result.Summary.Total != 3 {
		t.Errorf("expected 3 findings, got %d", result.Summary.Total)
	}
	if result.Summary.BySeverity[SeverityCritical] != 2 {
		t.Errorf("expected 2 critical, got %d", result.Summary.BySeverity[SeverityCritical])
	}
	if result.Status != ScanStatusCompleted {
		t.Errorf("expected completed status, got %v", result.Status)
	}
}
