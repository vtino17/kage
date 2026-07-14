package reporter

import (
	"strings"
	"testing"

	"github.com/vtino17/kage/internal/model"
)

func TestFormatHTML(t *testing.T) {
	result := &model.ScanResult{
		ID:      "test-html",
		Version: "0.1.0",
		Status:  model.ScanStatusCompleted,
		Target:  model.ScanTarget{Type: "directory", Path: "/test"},
		Summary: model.ScanSummary{Total: 1, BySeverity: map[model.SeverityLevel]int{"critical": 1}},
		Findings: []model.Finding{
			{
				Title:    "CVE-2024-TEST",
				Severity: model.SeverityCritical,
				FilePath: "main.go",
				LineStart: 10,
				Category: "sast",
				Message:  "critical vulnerability found",
			},
		},
	}

	output, err := formatHTML(result)
	if err != nil {
		t.Fatalf("formatHTML() error: %v", err)
	}

	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("output should be HTML")
	}
	if !strings.Contains(output, "CVE-2024-TEST") {
		t.Error("output should contain finding title")
	}
	if !strings.Contains(output, "severity-critical") {
		t.Error("output should have severity class")
	}
}

func TestFormatHTMLEmpty(t *testing.T) {
	result := &model.ScanResult{
		Version: "0.1.0",
		Status:  model.ScanStatusCompleted,
		Target:  model.ScanTarget{Type: "directory", Path: "/clean"},
		Summary: model.ScanSummary{Total: 0, BySeverity: make(map[model.SeverityLevel]int)},
	}

	output, err := formatHTML(result)
	if err != nil {
		t.Fatalf("formatHTML() error: %v", err)
	}

	if !strings.Contains(output, "KAGE") {
		t.Error("output should contain KAGE")
	}
}
