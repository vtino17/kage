package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNoIgnoreFile(t *testing.T) {
	ign, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load() without file should not error: %v", err)
	}
	if ign == nil {
		t.Fatal("Load() returned nil")
	}
}

func TestIgnorePatterns(t *testing.T) {
	tmpDir := t.TempDir()
	content := []byte("node_modules\n*.log\n.DS_Store\n")
	if err := os.WriteFile(filepath.Join(tmpDir, ".kageignore"), content, 0644); err != nil {
		t.Fatal(err)
	}

	ign, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	tests := []struct {
		path     string
		ignored  bool
	}{
		{"node_modules/package/index.js", true},
		{"src/app.log", true},
		{".DS_Store", true},
		{"src/main.go", false},
		{"README.md", false},
	}

	for _, tt := range tests {
		result := ign.IsIgnored(tt.path)
		if result != tt.ignored {
			t.Errorf("IsIgnored(%q) = %v, want %v", tt.path, result, tt.ignored)
		}
	}
}

func TestFilter(t *testing.T) {
	ign := &Ignorer{patterns: []string{"node_modules", ".git", "vendor"}}
	paths := []string{
		"src/main.go",
		"node_modules/pkg/index.js",
		"src/utils.go",
		".git/config",
		"vendor/pkg/main.go",
	}

	filtered := ign.Filter(paths)
	if len(filtered) != 2 {
		t.Errorf("expected 2, got %d: %v", len(filtered), filtered)
	}
}

func TestCommentsAndEmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	content := []byte("# comment\n\n# another\n*.tmp\n")
	if err := os.WriteFile(filepath.Join(tmpDir, ".kageignore"), content, 0644); err != nil {
		t.Fatal(err)
	}

	ign, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if ign.IsIgnored("file.tmp") != true {
		t.Error("*.tmp should be ignored")
	}
}
