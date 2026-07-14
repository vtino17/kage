package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/model"
)

type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	Message     string `json:"Message"`
	Fingerprint string `json:"Fingerprint"`
}

type GitleaksScanner struct {
	cfg *config.Config
}

func NewGitleaksScanner(cfg *config.Config) *GitleaksScanner {
	return &GitleaksScanner{cfg: cfg}
}

func (s *GitleaksScanner) Name() string {
	return "gitleaks"
}

func (s *GitleaksScanner) Scan(targetPath string) (*Result, error) {
	if !s.cfg.Scanner.Gitleaks.Enabled {
		return &Result{ScannerName: s.Name(), Findings: nil}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gitleaks", "detect",
		"--source", targetPath,
		"--no-git",
		"--report-format", "json",
		"--report-path", "-",
		"--verbose=false",
	)

	output, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// gitleaks exits 1 when finds -- that is expected
		} else {
			return nil, fmt.Errorf("gitleaks execution failed: %w", err)
		}
	}

	var findings []model.Finding
	if len(output) > 0 {
		var rawFindings []gitleaksFinding
		if err := json.Unmarshal(output, &rawFindings); err != nil {
			return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
		}

		for _, f := range rawFindings {
			finding := model.Finding{
				Scanner:   s.Name(),
				Title:     f.RuleID,
				FilePath:  f.File,
				LineStart: f.StartLine,
				LineEnd:   f.EndLine,
				Severity:  model.SeverityHigh,
				Category:  "secret",
				Message:   f.Message,
				CreatedAt: time.Now(),
			}
			finding.Hash = finding.DedupKey()
			findings = append(findings, finding)
		}
	}

	return &Result{ScannerName: s.Name(), Findings: findings}, nil
}
