# Hacker News Launch Post

Title: KAGE - Open-source AI security copilot that scans and fixes your code

Body:

KAGE is an open-source CLI tool that combines multiple security scanners
(Semgrep, Gitleaks, Trivy) with optional AI analysis to find, explain,
and fix vulnerabilities in your codebase.

One command to scan, one flag to fix:

  kage scan ./my-project
  kage scan github.com/owner/repo --fix

Why I built this:
- Snyk, Checkmarx, Wiz exist but cost thousands per seat
- Existing open-source tools are fragmented (one for SAST, one for secrets, etc.)
- Most scanners alert but don't help you fix the problem

KAGE:
- Integrates 3 scanners in one CLI
- AI explains each finding in plain language (optional, supports Ollama for local/offline)
- Auto-generates patches and opens PRs
- Outputs SARIF for GitHub Advanced Security integration
- Runs fully offline without AI

Stack: Go (CLI + core engine), Python (AI engine), TypeScript-ready (dashboard in v0.2)

GitHub: https://github.com/vtino17/kage

Install:
  curl -sfL https://raw.githubusercontent.com/vtino17/kage/main/scripts/install.sh | sh

Happy to answer questions and hear feedback. The project is early-stage
and I am looking for contributors.
