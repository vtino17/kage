package engine

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/vtino17/kage/internal/model"
	"github.com/vtino17/kage/internal/scanner"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Process(results []scanner.Result) []model.Finding {
	allFindings := make([]model.Finding, 0)
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	deduped := e.deduplicate(allFindings)

	scored := e.score(deduped)

	e.sort(scored)

	return scored
}

func (e *Engine) deduplicate(findings []model.Finding) []model.Finding {
	seen := make(map[string]bool)
	result := make([]model.Finding, 0, len(findings))

	for _, f := range findings {
		key := f.DedupKey()
		if f.Hash != "" {
			key = f.Hash
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		h := sha256.Sum256([]byte(key))
		f.Hash = fmt.Sprintf("%x", h[:8])

		result = append(result, f)
	}

	return result
}

func (e *Engine) score(findings []model.Finding) []model.Finding {
	for i, f := range findings {
		if f.CVSS > 0 {
			switch {
			case f.CVSS >= 9.0:
				findings[i].Severity = model.SeverityCritical
			case f.CVSS >= 7.0:
				findings[i].Severity = model.SeverityHigh
			case f.CVSS >= 4.0:
				findings[i].Severity = model.SeverityMedium
			default:
				findings[i].Severity = model.SeverityLow
			}
		}
	}
	return findings
}

func (e *Engine) sort(findings []model.Finding) {
	order := map[model.SeverityLevel]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}

	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if order[findings[i].Severity] > order[findings[j].Severity] {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}

func (e *Engine) Categorize(findings []model.Finding) map[string][]model.Finding {
	categories := make(map[string][]model.Finding)
	for _, f := range findings {
		cat := f.Category
		if cat == "" {
			cat = "other"
		}
		categories[cat] = append(categories[cat], f)
	}
	return categories
}

func (e *Engine) SeverityCount(findings []model.Finding) map[model.SeverityLevel]int {
	counts := make(map[model.SeverityLevel]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func (e *Engine) SeverityColor(s model.SeverityLevel) string {
	switch s {
	case model.SeverityCritical:
		return "\033[31m" // red
	case model.SeverityHigh:
		return "\033[33m" // yellow
	case model.SeverityMedium:
		return "\033[35m" // magenta
	case model.SeverityLow:
		return "\033[36m" // cyan
	default:
		return "\033[32m" // green
	}
}

func (e *Engine) ResetColor() string {
	return "\033[0m"
}

func severityLabel(s model.SeverityLevel) string {
	return strings.ToUpper(string(s))
}
