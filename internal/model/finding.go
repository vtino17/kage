package model

import "time"

type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityInfo     SeverityLevel = "info"
)

type Finding struct {
	ID          string            `json:"id"`
	Scanner     string            `json:"scanner"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    SeverityLevel     `json:"severity"`
	CVE         string            `json:"cve,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	FilePath    string            `json:"file_path"`
	LineStart   int               `json:"line_start"`
	LineEnd     int               `json:"line_end,omitempty"`
	CodeSnippet string            `json:"code_snippet,omitempty"`
	Category    string            `json:"category"`
	Message     string            `json:"message"`
	Fix         string            `json:"fix,omitempty"`
	AIExplanation string          `json:"ai_explanation,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Hash        string            `json:"hash"`
}

func (f *Finding) DedupKey() string {
	return f.Scanner + ":" + f.FilePath + ":" + f.Title
}
