package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vtino17/kage/internal/config"
)

func TestRegistryRegister(t *testing.T) {
	r := NewRegistry()
	if len(r.Names()) != 0 {
		t.Error("expected empty registry")
	}

	cfg := config.DefaultConfig()
	cfg.Scanner.Semgrep.Enabled = true
	cfg.Scanner.Gitleaks.Enabled = true
	cfg.Scanner.Trivy.Enabled = true

	r.Register(NewSemgrepScanner(cfg))
	r.Register(NewGitleaksScanner(cfg))
	r.Register(NewTrivyScanner(cfg))

	names := r.Names()
	if len(names) != 3 {
		t.Errorf("expected 3 scanners, got %d", len(names))
	}
}

func TestRegistryRunAllNoTarget(t *testing.T) {
	r := NewRegistry()
	cfg := config.DefaultConfig()
	cfg.Scanner.Semgrep.Enabled = true

	r.Register(NewSemgrepScanner(cfg))

	tmpDir := t.TempDir()
	results, errors := r.RunAll(tmpDir)

	if len(errors) > 0 {
		t.Logf("scanner errors (expected without binary): %v", errors)
	}
	_ = results
}

func TestSemgrepScannerName(t *testing.T) {
	cfg := config.DefaultConfig()
	s := NewSemgrepScanner(cfg)
	if s.Name() != "semgrep" {
		t.Errorf("expected 'semgrep', got '%s'", s.Name())
	}
}

func TestGitleaksScannerName(t *testing.T) {
	cfg := config.DefaultConfig()
	s := NewGitleaksScanner(cfg)
	if s.Name() != "gitleaks" {
		t.Errorf("expected 'gitleaks', got '%s'", s.Name())
	}
}

func TestTrivyScannerName(t *testing.T) {
	cfg := config.DefaultConfig()
	s := NewTrivyScanner(cfg)
	if s.Name() != "trivy" {
		t.Errorf("expected 'trivy', got '%s'", s.Name())
	}
}

func TestDisabledScanner(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Scanner.Semgrep.Enabled = false
	cfg.Scanner.Gitleaks.Enabled = false
	cfg.Scanner.Trivy.Enabled = false

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644)

	sem := NewSemgrepScanner(cfg)
	result, err := sem.Scan(dir)
	if err != nil {
		t.Fatalf("disabled scanner should not error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Error("disabled scanner should return empty findings")
	}

	gl := NewGitleaksScanner(cfg)
	result, err = gl.Scan(dir)
	if err != nil {
		t.Fatalf("disabled scanner should not error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Error("disabled scanner should return empty findings")
	}

	tv := NewTrivyScanner(cfg)
	result, err = tv.Scan(dir)
	if err != nil {
		t.Fatalf("disabled scanner should not error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Error("disabled scanner should return empty findings")
	}
}

func TestMapSemgrepSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ERROR", "critical"},
		{"WARNING", "high"},
		{"INFO", "medium"},
		{"", "medium"},
	}

	for _, tt := range tests {
		result := mapSemgrepSeverity(tt.input)
		if string(result) != tt.expected {
			t.Errorf("mapSemgrepSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMapTrivySeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"UNKNOWN", "info"},
	}

	for _, tt := range tests {
		result := mapTrivySeverity(tt.input)
		if string(result) != tt.expected {
			t.Errorf("mapTrivySeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSemgrepParseOutput(t *testing.T) {
	cfg := config.DefaultConfig()
	s := NewSemgrepScanner(cfg)

	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, "test.js"), []byte("var x = 1;"), 0644)

	result, err := s.Scan(tmpDir)
	if err != nil {
		t.Logf("semgrep not installed, skipping: %v", err)
		return
	}

	for _, f := range result.Findings {
		if f.Scanner != "semgrep" {
			t.Errorf("expected scanner 'semgrep', got '%s'", f.Scanner)
		}
		if f.Category != "sast" {
			t.Errorf("expected category 'sast', got '%s'", f.Category)
		}
	}
}

func TestRegistryNamesUnique(t *testing.T) {
	r := NewRegistry()
	cfg := config.DefaultConfig()

	r.Register(NewSemgrepScanner(cfg))
	r.Register(NewGitleaksScanner(cfg))
	r.Register(NewTrivyScanner(cfg))

	names := r.Names()
	seen := make(map[string]bool)
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate scanner name: %s", n)
		}
		seen[n] = true
	}
}
