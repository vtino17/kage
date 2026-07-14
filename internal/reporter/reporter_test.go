package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/vtino17/kage/internal/model"
)

func TestFormatTerminal(t *testing.T) {
	now := time.Now()
	result := &model.ScanResult{
		ID:        "test-1",
		Status:    model.ScanStatusCompleted,
		Target:    model.ScanTarget{Type: "directory", Path: "/test", Files: 10, Lines: 100},
		CreatedAt: now,
		Duration:  now.Sub(now.Add(-2 * time.Second)),
		Summary:   model.ScanSummary{Total: 1, BySeverity: map[model.SeverityLevel]int{"high": 1}},
		Findings: []model.Finding{
			{
				Title:    "test-rule",
				Severity: model.SeverityHigh,
				FilePath: "main.go",
				LineStart: 10,
				Message:  "test message",
				Category: "sast",
			},
		},
	}

	output, err := Format(result, "terminal")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if !strings.Contains(output, "KAGE") {
		t.Error("output should contain 'KAGE'")
	}
	if !strings.Contains(output, "test-rule") {
		t.Error("output should contain finding title")
	}
	if !strings.Contains(output, "HIGH") {
		t.Error("output should contain severity")
	}
}

func TestFormatJSON(t *testing.T) {
	result := &model.ScanResult{
		ID:     "test-1",
		Status: model.ScanStatusCompleted,
		Target: model.ScanTarget{Type: "directory", Path: "/test"},
		Summary: model.ScanSummary{Total: 1, BySeverity: map[model.SeverityLevel]int{"critical": 1}},
		Findings: []model.Finding{
			{Title: "CVE-2024-XXX", Severity: model.SeverityCritical},
		},
	}

	output, err := Format(result, "json")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if !strings.Contains(output, "CVE-2024-XXX") {
		t.Error("JSON output should contain finding title")
	}
}

func TestFormatSARIF(t *testing.T) {
	result := &model.ScanResult{
		ID:     "test-1",
		Version: "0.1.0",
		Status: model.ScanStatusCompleted,
		Target: model.ScanTarget{Type: "directory", Path: "/test"},
		Summary: model.ScanSummary{Total: 2, BySeverity: map[model.SeverityLevel]int{"critical": 1, "high": 1}},
		Findings: []model.Finding{
			{Title: "CVE-2024-XXX", Severity: model.SeverityCritical, FilePath: "main.go", LineStart: 10, LineEnd: 15, Message: "critical vuln"},
			{Title: "SECRET-001", Severity: model.SeverityHigh, FilePath: "config.env", LineStart: 5, Message: "hardcoded key"},
		},
	}

	output, err := Format(result, "sarif")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if !strings.Contains(output, "$schema") {
		t.Error("SARIF output should contain schema reference")
	}
	if !strings.Contains(output, "CVE-2024-XXX") {
		t.Error("SARIF output should contain first finding")
	}
	if !strings.Contains(output, "SECRET-001") {
		t.Error("SARIF output should contain second finding")
	}
}

func TestFormatEmptyFindings(t *testing.T) {
	result := &model.ScanResult{
		ID:      "test-empty",
		Status:  model.ScanStatusCompleted,
		Target:  model.ScanTarget{Type: "directory", Path: "/clean"},
		Summary: model.ScanSummary{Total: 0, BySeverity: make(map[model.SeverityLevel]int)},
	}

	output, err := Format(result, "terminal")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if !strings.Contains(output, "0") && !strings.Contains(output, "no") {
		t.Logf("output for empty findings: %s", output)
	}
}
