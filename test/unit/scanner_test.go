package unit

import (
	"testing"

	"github.com/vtino17/kage/internal/model"
)

func TestSeverityLevelValues(t *testing.T) {
	tests := []struct {
		level    model.SeverityLevel
		expected string
	}{
		{model.SeverityCritical, "critical"},
		{model.SeverityHigh, "high"},
		{model.SeverityMedium, "medium"},
		{model.SeverityLow, "low"},
		{model.SeverityInfo, "info"},
	}

	for _, tt := range tests {
		if string(tt.level) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, string(tt.level))
		}
	}
}

func TestScanResultInit(t *testing.T) {
	target := model.ScanTarget{
		Type: "directory",
		Path: "/test/path",
	}
	result := model.NewScanResult(target)

	if result.Status != model.ScanStatusRunning {
		t.Errorf("expected running status, got %v", result.Status)
	}
	if result.Target.Path != "/test/path" {
		t.Errorf("expected /test/path, got %s", result.Target.Path)
	}
	if result.Findings == nil {
		t.Error("Findings should not be nil")
	}
}
