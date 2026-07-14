package model

import "time"

type ScanStatus string

const (
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

type ScanTarget struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	Branch   string `json:"branch,omitempty"`
	Commit   string `json:"commit,omitempty"`
	Files    int    `json:"files"`
	Lines    int    `json:"lines"`
}

type ScanSummary struct {
	Total     int            `json:"total"`
	BySeverity map[SeverityLevel]int `json:"by_severity"`
}

type ScanResult struct {
	ID          string            `json:"id"`
	Status      ScanStatus        `json:"status"`
	Version     string            `json:"version"`
	Target      ScanTarget        `json:"target"`
	Findings    []Finding         `json:"findings"`
	Summary     ScanSummary       `json:"summary"`
	Duration    time.Duration     `json:"duration_ms"`
	Scanners    []string          `json:"scanners"`
	Errors      []string          `json:"errors,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

func NewScanResult(target ScanTarget) *ScanResult {
	return &ScanResult{
		Status:    ScanStatusRunning,
		Target:    target,
		Findings:  make([]Finding, 0),
		Summary:   ScanSummary{BySeverity: make(map[SeverityLevel]int)},
		Scanners:  make([]string, 0),
		Errors:    make([]string, 0),
		CreatedAt: time.Now(),
	}
}

func (r *ScanResult) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
	r.Summary.Total++
	r.Summary.BySeverity[f.Severity]++
}

func (r *ScanResult) Finalize() {
	r.Status = ScanStatusCompleted
	r.Summary.BySeverity = make(map[SeverityLevel]int)
	for _, f := range r.Findings {
		r.Summary.BySeverity[f.Severity]++
	}
	r.Summary.Total = len(r.Findings)
}
