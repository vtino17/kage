package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/model"
)

type semgrepFinding struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
	} `json:"end"`
	Extra struct {
		Severity   string            `json:"severity"`
		Message    string            `json:"message"`
		Metadata   map[string]string `json:"metadata"`
		Lines      string            `json:"lines"`
	} `json:"extra"`
}

type semgrepResults struct {
	Results []semgrepFinding `json:"results"`
}

type SemgrepScanner struct {
	cfg *config.Config
}

func NewSemgrepScanner(cfg *config.Config) *SemgrepScanner {
	return &SemgrepScanner{cfg: cfg}
}

func (s *SemgrepScanner) Name() string {
	return "semgrep"
}

func (s *SemgrepScanner) Scan(targetPath string) (*Result, error) {
	if !s.cfg.Scanner.Semgrep.Enabled {
		return &Result{ScannerName: s.Name(), Findings: nil}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "semgrep",
		"--config", s.cfg.Scanner.Semgrep.Ruleset,
		"--json",
		"--quiet",
		targetPath,
	)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if len(exitErr.Stderr) > 0 {
				log.Warn().Str("scanner", "semgrep").Str("stderr", string(exitErr.Stderr)).Msg("scanner stderr")
			}
		}
	}

	var parsed semgrepResults
	if len(output) > 0 {
		if err := json.Unmarshal(output, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
		}
	}

	findings := make([]model.Finding, 0, len(parsed.Results))
	for _, f := range parsed.Results {
		cve := ""
		if f.Extra.Metadata != nil {
			cve = f.Extra.Metadata["cve"]
		}

		finding := model.Finding{
			Scanner:     s.Name(),
			Title:       f.CheckID,
			Description: f.Extra.Message,
			Severity:    mapSemgrepSeverity(f.Extra.Severity),
			CVE:         cve,
			FilePath:    f.Path,
			LineStart:   f.Start.Line,
			LineEnd:     f.End.Line,
			CodeSnippet: f.Extra.Lines,
			Category:    "sast",
			Message:     f.Extra.Message,
			CreatedAt:   time.Now(),
		}
		finding.Hash = finding.DedupKey()
		findings = append(findings, finding)
	}

	return &Result{ScannerName: s.Name(), Findings: findings}, nil
}

func mapSemgrepSeverity(s string) model.SeverityLevel {
	switch s {
	case "ERROR":
		return model.SeverityCritical
	case "WARNING":
		return model.SeverityHigh
	default:
		return model.SeverityMedium
	}
}
