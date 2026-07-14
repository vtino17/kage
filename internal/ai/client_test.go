package ai

import (
	"testing"

	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/model"
)

func TestNewClient(t *testing.T) {
	cfg := config.DefaultConfig()
	client := NewClient(cfg)
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
}

func TestAnalyzeNoProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AI.Provider = ""

	client := NewClient(cfg)
	findings := []model.Finding{
		{Title: "test", Severity: model.SeverityHigh, FilePath: "main.go"},
	}

	result, err := client.Analyze(findings)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result))
	}
}

func TestTruncate(t *testing.T) {
	short := "short text"
	if truncate(short, 100) != short {
		t.Error("short text should not be truncated")
	}

	long := "a" + "bcdefghijklmnopqrstuvwxyz1234567890"
	result := truncate(long, 10)
	if len(result) > 13 {
		t.Errorf("truncated string too long: %d", len(result))
	}
	if result[len(result)-3:] != "..." {
		t.Error("truncated string should end with '...'")
	}
}

func TestAnalyzeWithOllamaEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AI.Provider = config.AIProviderOllama
	cfg.AI.Endpoint = "http://127.0.0.1:1"
	cfg.AI.Model = "test-model"

	client := NewClient(cfg)
	findings := []model.Finding{
		{Title: "CVE-2024-TEST", Severity: model.SeverityCritical},
	}

	result, err := client.Analyze(findings)
	if err != nil {
		t.Fatalf("Analyze() should not error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result))
	}
}
