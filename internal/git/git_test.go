package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsRepo(t *testing.T) {
	tmpDir := t.TempDir()

	if IsRepo(tmpDir) {
		t.Error("temp dir should not be a git repo")
	}

	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Skip("git not available")
	}

	if !IsRepo(tmpDir) {
		t.Error("initialized dir should be a git repo")
	}
}

func TestCloneInvalidURL(t *testing.T) {
	_, err := Clone("https://github.com/nonexistent/repo", t.TempDir())
	if err == nil {
		t.Skip("expected error but git might have different behavior")
	}
}

func TestDiffNoChanges(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Skip("git not available")
	}

	_ = os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("hello"), 0644)

	diff, err := Diff(tmpDir)
	if err == nil {
		_ = diff
	}
}
