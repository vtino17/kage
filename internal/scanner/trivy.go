package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/model"
)

type trivyResult struct {
	Results []struct {
		Target         string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string  `json:"VulnerabilityID"`
			PkgName         string  `json:"PkgName"`
			Severity        string  `json:"Severity"`
			Title           string  `json:"Title"`
			Description     string  `json:"Description"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion    string  `json:"FixedVersion"`
			CVSS            map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type TrivyScanner struct {
	cfg *config.Config
}

func NewTrivyScanner(cfg *config.Config) *TrivyScanner {
	return &TrivyScanner{cfg: cfg}
}

func (s *TrivyScanner) Name() string {
	return "trivy"
}

func (s *TrivyScanner) Scan(targetPath string) (*Result, error) {
	if !s.cfg.Scanner.Trivy.Enabled {
		return &Result{ScannerName: s.Name(), Findings: nil}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	args := []string{
		"fs",
		"--format", "json",
		"--quiet",
		"--severity", s.cfg.Scanner.Trivy.Severity,
		targetPath,
	}

	cmd := exec.CommandContext(ctx, "trivy", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if len(exitErr.Stderr) > 0 {
				return nil, fmt.Errorf("trivy stderr: %s", string(exitErr.Stderr))
			}
		}
		return nil, fmt.Errorf("trivy execution failed: %w", err)
	}

	var parsed trivyResult
	if len(output) > 0 {
		if err := json.Unmarshal(output, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse trivy output: %w", err)
		}
	}

	findings := make([]model.Finding, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		for _, v := range r.Vulnerabilities {
			cvss := 0.0
			for _, scores := range v.CVSS {
				if scores.V3Score > 0 {
					cvss = scores.V3Score
					break
				}
			}

			finding := model.Finding{
				Scanner:    s.Name(),
				Title:      v.VulnerabilityID,
				Description: v.Title,
				Severity:   mapTrivySeverity(v.Severity),
				CVE:        v.VulnerabilityID,
				CVSS:       cvss,
				FilePath:   r.Target,
				Category:   "dependency",
				Message:    fmt.Sprintf("%s in %s (installed: %s, fixed: %s)", v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.FixedVersion),
				CreatedAt:  time.Now(),
			}
			finding.Hash = finding.DedupKey()
			findings = append(findings, finding)
		}
	}

	return &Result{ScannerName: s.Name(), Findings: findings}, nil
}

func mapTrivySeverity(s string) model.SeverityLevel {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}
