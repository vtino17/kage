package fixer

import (
	"testing"

	"github.com/vtino17/kage/internal/ai"
	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/model"
)

func TestNewFixer(t *testing.T) {
	cfg := config.DefaultConfig()
	aiClient := ai.NewClient(cfg)
	f := NewFixer(cfg, aiClient)
	if f == nil {
		t.Fatal("NewFixer() returned nil")
	}
}

func TestGenerateFixesEmpty(t *testing.T) {
	cfg := config.DefaultConfig()
	aiClient := ai.NewClient(cfg)
	f := NewFixer(cfg, aiClient)

	proposal, err := f.GenerateFixes([]model.Finding{})
	if err != nil {
		t.Fatalf("GenerateFixes() error: %v", err)
	}
	if proposal == nil {
		t.Fatal("GenerateFixes() returned nil")
	}
	if len(proposal.Patches) != 0 {
		t.Errorf("expected 0 patches, got %d", len(proposal.Patches))
	}
}

func TestGenerateFixesWithFix(t *testing.T) {
	cfg := config.DefaultConfig()
	aiClient := ai.NewClient(cfg)
	f := NewFixer(cfg, aiClient)

	findings := []model.Finding{
		{
			ID:           "test-1",
			Title:        "test-rule",
			FilePath:     "main.go",
			CodeSnippet:  "old code",
			Fix:          "new code",
			Severity:     model.SeverityHigh,
		},
	}

	proposal, err := f.GenerateFixes(findings)
	if err != nil {
		t.Fatalf("GenerateFixes() error: %v", err)
	}

	if len(proposal.Patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(proposal.Patches))
	}

	if proposal.Patches[0].FilePath != "main.go" {
		t.Errorf("expected 'main.go', got '%s'", proposal.Patches[0].FilePath)
	}
}

func TestParseRepo(t *testing.T) {
	tests := []struct {
		url         string
		wantOwner   string
		wantRepo    string
	}{
		{"github.com/vtino17/kage", "vtino17", "kage"},
		{"https://github.com/vtino17/kage.git", "vtino17", "kage"},
		{"github.com/owner/repo.git", "owner", "repo"},
		{"invalid", "", ""},
	}

	for _, tt := range tests {
		owner, repo := parseRepo(tt.url)
		if owner != tt.wantOwner || repo != tt.wantRepo {
			t.Errorf("parseRepo(%q) = (%q, %q), want (%q, %q)", tt.url, owner, repo, tt.wantOwner, tt.wantRepo)
		}
	}
}

func TestTruncateLine(t *testing.T) {
	short := "short"
	if truncateLine(short) != short {
		t.Errorf("short line should not be truncated: %s", truncateLine(short))
	}

	long := ""
	for i := 0; i < 100; i++ {
		long += "x"
	}
	result := truncateLine(long)
	if len(result) > 80 {
		t.Errorf("truncated line too long: %d", len(result))
	}
}

func TestRandSuffix(t *testing.T) {
	s1 := randSuffix(8)
	s2 := randSuffix(8)

	if len(s1) != 8 {
		t.Errorf("expected length 8, got %d", len(s1))
	}
	if s1 == s2 {
		t.Log("random suffix collision (extremely unlikely)")
	}
}
