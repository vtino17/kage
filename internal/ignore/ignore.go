package ignore

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Ignorer struct {
	patterns []string
}

func Load(path string) (*Ignorer, error) {
	ignoreFile := filepath.Join(path, ".kageignore")
	f, err := os.Open(ignoreFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &Ignorer{}, nil
		}
		return nil, fmt.Errorf("failed to read .kageignore: %w", err)
	}
	defer f.Close()

	ign := &Ignorer{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ign.patterns = append(ign.patterns, line)
	}

	return ign, scanner.Err()
}

func (ig *Ignorer) IsIgnored(path string) bool {
	for _, pattern := range ig.patterns {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
		matched, err = filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func (ig *Ignorer) Filter(paths []string) []string {
	if len(ig.patterns) == 0 {
		return paths
	}
	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		if !ig.IsIgnored(p) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
