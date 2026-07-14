package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/model"
)

type Client struct {
	cfg        *config.Config
	httpClient *http.Client
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

type analyzeRequest struct {
	Findings []findingInput `json:"findings"`
	Mode     string         `json:"mode"`
}

type findingInput struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	FilePath    string `json:"file_path"`
	LineStart   int    `json:"line_start"`
	CodeSnippet string `json:"code_snippet"`
	Category    string `json:"category"`
	Message     string `json:"message"`
}

type analyzeResponse struct {
	Analysis []findingOutput `json:"analysis"`
}

type findingOutput struct {
	FindingID          string `json:"finding_id"`
	RiskExplanation    string `json:"risk_explanation"`
	SeverityAdjustment string `json:"severity_adjustment"`
	SuggestedFix       string `json:"suggested_fix"`
}

func (c *Client) Analyze(findings []model.Finding) ([]model.Finding, error) {
	if c.cfg.AI.Provider == "" || c.cfg.AI.Provider == "ollama" {
		if c.cfg.AI.Provider == "" {
			log.Info().Msg("AI provider not configured, skipping AI analysis")
			return findings, nil
		}
	}

	inputs := make([]findingInput, 0, len(findings))
	for _, f := range findings {
		inputs = append(inputs, findingInput{
			Title:       f.Title,
			Description: f.Description,
			Severity:    string(f.Severity),
			FilePath:    f.FilePath,
			LineStart:   f.LineStart,
			CodeSnippet: truncate(f.CodeSnippet, 500),
			Category:    f.Category,
			Message:     f.Message,
		})
	}

	req := analyzeRequest{
		Findings: inputs,
		Mode:     "analyze",
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AI request: %w", err)
	}

	endpoint := c.cfg.AI.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	httpReq, err := http.NewRequest("POST", endpoint+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create AI request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if c.cfg.AI.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.AI.APIKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		log.Warn().Err(err).Msg("AI engine unreachable, skipping AI analysis")
		return findings, nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read AI response: %w", err)
	}

	var parsed analyzeResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		log.Warn().Err(err).Msg("failed to parse AI response, using raw findings")
		return findings, nil
	}

	enriched := make([]model.Finding, len(findings))
	for i, f := range findings {
		enriched[i] = f
		for _, a := range parsed.Analysis {
			if a.FindingID == fmt.Sprintf("%d", i) {
				enriched[i].AIExplanation = a.RiskExplanation
				if a.SuggestedFix != "" {
					enriched[i].Fix = a.SuggestedFix
				}
				break
			}
		}
	}

	return enriched, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
