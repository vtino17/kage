package reporter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vtino17/kage/internal/engine"
	"github.com/vtino17/kage/internal/model"
)

func Format(result *model.ScanResult, format string) (string, error) {
	switch format {
	case "json":
		return formatJSON(result)
	case "sarif":
		return formatSARIF(result)
	case "html":
		return formatHTML(result)
	case "terminal":
		return formatTerminal(result)
	default:
		return formatTerminal(result)
	}
}

func formatTerminal(result *model.ScanResult) (string, error) {
	var b strings.Builder

	eng := engine.NewEngine()

	b.WriteString("KAGE - AI Security Co-Pilot")
	b.WriteString("\n")
	b.WriteString(strings.Repeat("=", 50))
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("Target:  %s\n", result.Target.Path))
	b.WriteString(fmt.Sprintf("Type:    %s\n", result.Target.Type))
	if result.Target.Branch != "" {
		b.WriteString(fmt.Sprintf("Branch:  %s\n", result.Target.Branch))
	}

	b.WriteString(fmt.Sprintf("\nFindings: %d\n\n", result.Summary.Total))

	categories := eng.Categorize(result.Findings)
	for _, cat := range []string{"sast", "secret", "dependency", "other"} {
		findings, ok := categories[cat]
		if !ok || len(findings) == 0 {
			continue
		}

		b.WriteString(fmt.Sprintf("[%s]\n", strings.ToUpper(cat)))
		b.WriteString(strings.Repeat("-", 50))
		b.WriteString("\n")

		for _, f := range findings {
			sevLabel := strings.ToUpper(string(f.Severity))
			b.WriteString(fmt.Sprintf("  %s %s\n", sevLabel, f.Title))
			if f.CVE != "" {
				b.WriteString(fmt.Sprintf("    CVE:    %s (CVSS: %.1f)\n", f.CVE, f.CVSS))
			}
			if f.FilePath != "" {
				b.WriteString(fmt.Sprintf("    File:   %s:%d\n", f.FilePath, f.LineStart))
			}
			b.WriteString(fmt.Sprintf("    Detail: %s\n", f.Message))
			if f.AIExplanation != "" {
				b.WriteString(fmt.Sprintf("    AI:     %s\n", f.AIExplanation))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString(strings.Repeat("=", 50))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Total: %d finding(s) | Duration: %v\n", result.Summary.Total, result.Duration))

	if len(result.Errors) > 0 {
		b.WriteString(fmt.Sprintf("\nErrors (%d):\n", len(result.Errors)))
		for _, e := range result.Errors {
			b.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	return b.String(), nil
}

func formatJSON(result *model.ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(data), nil
}

func formatSARIF(result *model.ScanResult) (string, error) {
	type sarifTool struct {
		Driver struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"driver"`
	}

	type sarifResult struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
		Message   struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
					EndLine   int `json:"endLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}

	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}

	type sarifLog struct {
		Schema  string    `json:"$schema"`
		Version string    `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	run := sarifRun{
		Tool: sarifTool{
			Driver: struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}{
				Name:    "KAGE",
				Version: result.Version,
			},
		},
		Results: make([]sarifResult, 0, len(result.Findings)),
	}

	for _, f := range result.Findings {
		sLevel := "warning"
		switch f.Severity {
		case model.SeverityCritical:
			sLevel = "error"
		case model.SeverityHigh:
			sLevel = "error"
		case model.SeverityMedium:
			sLevel = "warning"
		default:
			sLevel = "note"
		}

		sr := sarifResult{
			RuleID: f.Title,
			Level:  sLevel,
		}
		sr.Message.Text = f.Message
		sr.Locations = []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
					EndLine   int `json:"endLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		}{
			{
				PhysicalLocation: struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
						EndLine   int `json:"endLine"`
					} `json:"region"`
				}{
					ArtifactLocation: struct {
						URI string `json:"uri"`
					}{
						URI: f.FilePath,
					},
					Region: struct {
						StartLine int `json:"startLine"`
						EndLine   int `json:"endLine"`
					}{
						StartLine: f.LineStart,
						EndLine:   f.LineEnd,
					},
				},
			},
		}

		run.Results = append(run.Results, sr)
	}

	log := sarifLog{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-v2.1.0-cos01-schema.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	return string(data), nil
}

var _ = time.Now
