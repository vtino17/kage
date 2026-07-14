Title: I built an open-source AI security copilot that scans and fixes vulnerabilities

I got tired of juggling between Semgrep, Gitleaks, Trivy, and other
security tools. So I built KAGE - a single CLI that combines them all.

Features:
- Multi-scanner engine (SAST + secrets + dependencies) in one binary
- Optional AI analysis (OpenAI, Anthropic, Gemini, or local Ollama)
- Auto-generates fixes and creates GitHub PRs
- SARIF output for CI pipelines
- Local-first: runs fully offline without AI

Built with Go and Python. Looking for early adopters and contributors.

https://github.com/vtino17/kage
