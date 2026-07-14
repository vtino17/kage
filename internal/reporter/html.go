package reporter

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/vtino17/kage/internal/engine"
	"github.com/vtino17/kage/internal/model"
)

func formatHTML(result *model.ScanResult) (string, error) {
	eng := engine.NewEngine()

	var b strings.Builder

	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"UTF-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	b.WriteString(fmt.Sprintf("<title>KAGE Scan Report - %s</title>\n", html.EscapeString(result.Target.Path)))
	b.WriteString("<style>\n")
	b.WriteString("body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;background:#0d1117;color:#c9d1d9;line-height:1.6}\n")
	b.WriteString("h1{color:#ff6b6b;border-bottom:2px solid #30363d;padding-bottom:12px}\n")
	b.WriteString("h2{color:#ffa07a;margin-top:32px}\n")
	b.WriteString(".summary{display:flex;gap:16px;margin:20px 0}\n")
	b.WriteString(".stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;flex:1;text-align:center}\n")
	b.WriteString(".stat-value{font-size:28px;font-weight:bold}\n")
	b.WriteString(".stat-label{font-size:12px;color:#8b949e;text-transform:uppercase}\n")
	b.WriteString(".finding{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}\n")
	b.WriteString(".finding-header{display:flex;justify-content:space-between;align-items:center}\n")
	b.WriteString(".severity{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;text-transform:uppercase}\n")
	b.WriteString(".severity-critical{background:#ff6b6b;color:#fff}\n")
	b.WriteString(".severity-high{background:#ffa07a;color:#000}\n")
	b.WriteString(".severity-medium{background:#ffd700;color:#000}\n")
	b.WriteString(".severity-low{background:#7ee787;color:#000}\n")
	b.WriteString(".severity-info{background:#8b949e;color:#fff}\n")
	b.WriteString(".meta{color:#8b949e;font-size:13px;margin-top:8px}\n")
	b.WriteString(".code{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:12px;overflow-x:auto;font-family:'SF Mono','Fira Code',monospace;font-size:13px;margin-top:8px;white-space:pre}\n")
	b.WriteString(".ai-box{background:#1c2333;border-left:3px solid #58a6ff;padding:12px;margin-top:8px;border-radius:4px;font-size:14px}\n")
	b.WriteString("footer{text-align:center;margin-top:40px;padding:20px;color:#8b949e;font-size:13px;border-top:1px solid #30363d}\n")
	b.WriteString("a{color:#58a6ff}\n")
	b.WriteString("</style>\n</head>\n<body>\n")

	b.WriteString(fmt.Sprintf("<h1>KAGE Security Scan Report</h1>\n"))
	b.WriteString(fmt.Sprintf("<p>Target: <strong>%s</strong> | Type: %s", html.EscapeString(result.Target.Path), result.Target.Type))
	if result.Target.Branch != "" {
		b.WriteString(fmt.Sprintf(" | Branch: %s", html.EscapeString(result.Target.Branch)))
	}
	b.WriteString(fmt.Sprintf(" | Duration: %v</p>\n", result.Duration))

	b.WriteString("<div class=\"summary\">\n")
	counts := eng.SeverityCount(result.Findings)
	order := []model.SeverityLevel{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	labels := map[model.SeverityLevel]string{
		model.SeverityCritical: "Critical",
		model.SeverityHigh:     "High",
		model.SeverityMedium:   "Medium",
		model.SeverityLow:      "Low",
		model.SeverityInfo:     "Info",
	}
	for _, sev := range order {
		count := counts[sev]
		label := labels[sev]
		b.WriteString(fmt.Sprintf("<div class=\"stat\"><div class=\"stat-value %s\">%d</div><div class=\"stat-label\">%s</div></div>\n", cssClassForSeverity(sev), count, label))
	}
	b.WriteString("</div>\n")

	categories := eng.Categorize(result.Findings)
	catOrder := []string{"sast", "secret", "dependency"}
	catLabels := map[string]string{
		"sast":       "Static Analysis (SAST)",
		"secret":     "Secrets",
		"dependency": "Dependencies",
	}

	for _, cat := range catOrder {
		findings, ok := categories[cat]
		if !ok || len(findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("<h2>%s (%d)</h2>\n", catLabels[cat], len(findings)))

		for _, f := range findings {
			b.WriteString(fmt.Sprintf("<div class=\"finding\">\n"))
			b.WriteString(fmt.Sprintf("<div class=\"finding-header\">\n"))
			b.WriteString(fmt.Sprintf("<strong>%s</strong>\n", html.EscapeString(f.Title)))
			b.WriteString(fmt.Sprintf("<span class=\"severity severity-%s\">%s</span>\n", cssClassForSeverity(f.Severity), strings.ToUpper(string(f.Severity))))
			b.WriteString("</div>\n")

			if f.CVE != "" {
				b.WriteString(fmt.Sprintf("<div class=\"meta\">CVE: %s | CVSS: %.1f</div>\n", f.CVE, f.CVSS))
			}
			if f.FilePath != "" {
				b.WriteString(fmt.Sprintf("<div class=\"meta\">File: %s:%d</div>\n", html.EscapeString(f.FilePath), f.LineStart))
			}
			b.WriteString(fmt.Sprintf("<div class=\"meta\">%s</div>\n", html.EscapeString(f.Message)))

			if f.CodeSnippet != "" {
				b.WriteString(fmt.Sprintf("<div class=\"code\">%s</div>\n", html.EscapeString(f.CodeSnippet)))
			}

			if f.AIExplanation != "" {
				b.WriteString(fmt.Sprintf("<div class=\"ai-box\"><strong>AI Analysis:</strong> %s</div>\n", html.EscapeString(f.AIExplanation)))
			}

			b.WriteString("</div>\n")
		}
	}

	b.WriteString(footerHTML(result))
	b.WriteString("</body>\n</html>\n")

	return b.String(), nil
}

func cssClassForSeverity(s model.SeverityLevel) string {
	switch s {
	case model.SeverityCritical:
		return "severity-critical"
	case model.SeverityHigh:
		return "severity-high"
	case model.SeverityMedium:
		return "severity-medium"
	case model.SeverityLow:
		return "severity-low"
	default:
		return "severity-info"
	}
}

func footerHTML(result *model.ScanResult) string {
	f := fmt.Sprintf("<footer>Generated by KAGE v%s | %s | %d finding(s)</footer>",
		result.Version,
		time.Now().Format("2006-01-02 15:04:05"),
		result.Summary.Total)
	return f
}
