package git

import (
	"fmt"
	"os/exec"
	"strings"
)

type RepoInfo struct {
	Owner  string
	Repo   string
	Branch string
	Commit string
}

func Clone(url string, dest string) (*RepoInfo, error) {
	cmd := exec.Command("git", "clone", "--depth=1", url, dest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git clone failed: %s: %w", string(output), err)
	}

	info := &RepoInfo{}

	parts := strings.Split(strings.TrimPrefix(url, "https://"), "/")
	if len(parts) >= 2 {
		info.Owner = parts[len(parts)-2]
		info.Repo = strings.TrimSuffix(parts[len(parts)-1], ".git")
	}

	branchCmd := exec.Command("git", "-C", dest, "rev-parse", "--abbrev-ref", "HEAD")
	branchOut, _ := branchCmd.Output()
	info.Branch = strings.TrimSpace(string(branchOut))

	commitCmd := exec.Command("git", "-C", dest, "rev-parse", "--short", "HEAD")
	commitOut, _ := commitCmd.Output()
	info.Commit = strings.TrimSpace(string(commitOut))

	return info, nil
}

func Diff(repoPath string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "diff", "--no-color")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git diff failed: %w", err)
	}
	return string(output), nil
}

func IsRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}
