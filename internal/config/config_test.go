package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
	if !cfg.Scanner.Semgrep.Enabled {
		t.Error("semgrep should be enabled by default")
	}
	if !cfg.Scanner.Gitleaks.Enabled {
		t.Error("gitleaks should be enabled by default")
	}
	if !cfg.Scanner.Trivy.Enabled {
		t.Error("trivy should be enabled by default")
	}
	if cfg.AI.Provider != AIProviderGemini {
		t.Errorf("expected default AI provider gemini, got %s", cfg.AI.Provider)
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldUserProfile := os.Getenv("USERPROFILE")
	os.Setenv("HOME", tmpDir)
	os.Setenv("USERPROFILE", tmpDir)
	defer os.Setenv("HOME", oldHome)
	defer os.Setenv("USERPROFILE", oldUserProfile)

	cfg := DefaultConfig()
	cfg.AI.Provider = AIProviderOpenAI
	cfg.AI.Model = "gpt-4o"

	if err := Save(cfg); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	configPath := filepath.Join(tmpDir, ".kage", "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("config file was not created")
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if loaded.AI.Provider != AIProviderOpenAI {
		t.Errorf("expected openai, got %s", loaded.AI.Provider)
	}
	if loaded.AI.Model != "gpt-4o" {
		t.Errorf("expected gpt-4o, got %s", loaded.AI.Model)
	}
}

func TestConfigPath(t *testing.T) {
	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath() failed: %v", err)
	}
	if path == "" {
		t.Fatal("ConfigPath() returned empty string")
	}
}

func TestScannersDir(t *testing.T) {
	dir, err := ScannersDir()
	if err != nil {
		t.Fatalf("ScannersDir() failed: %v", err)
	}
	if dir == "" {
		t.Fatal("ScannersDir() returned empty string")
	}
}
