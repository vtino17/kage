# KAGE - AI-Powered Security Scanner and Fixer

KAGE is an open-source CLI tool that scans your codebase for security vulnerabilities, explains risks in plain language, and can automatically generate fixes.

## Features

- **Multi-scanner engine**: Integrates Semgrep (SAST), Gitleaks (secrets), and Trivy (dependencies) in a single CLI
- **AI-powered analysis**: Explains each finding in plain language with risk context (optional)
- **Auto-fix generation**: Creates patches for common vulnerabilities (optional)
- **GitHub PR integration**: Opens pull requests with fixes directly from the CLI
- **CI/CD ready**: SARIF output format, exit code integration
- **Local-first**: Works fully offline without AI or API keys

## Installation

### Quick install (Linux/macOS)

```bash
curl -sfL https://raw.githubusercontent.com/vtino17/kage/main/scripts/install.sh | sh
```

### From source

```bash
go install github.com/vtino17/kage/cmd/kage@latest
```

### Docker

```bash
docker run ghcr.io/vtino17/kage scan ./project
```

## Quick Start

```bash
# Initialize configuration and scanner dependencies
kage init

# Scan a local directory
kage scan ./my-project

# Scan a GitHub repository
kage scan github.com/owner/repo

# Scan with AI-powered analysis
kage scan . --ai

# Scan and auto-create a fix PR
kage scan github.com/owner/repo --fix

# CI mode with SARIF output
kage scan . --ci --format sarif
```

## Commands

| Command   | Description                                      |
|-----------|--------------------------------------------------|
| `init`    | Initialize configuration and scanner dependencies |
| `scan`    | Scan a codebase for vulnerabilities              |
| `version` | Print version information                        |

## AI Configuration

KAGE supports multiple AI providers for enhanced analysis. Configure in `~/.kage/config.json`:

| Provider   | API Key Env Var    | Default Model      |
|------------|-------------------|--------------------|
| OpenAI     | OPENAI_API_KEY    | gpt-4o             |
| Anthropic  | ANTHROPIC_API_KEY | claude-sonnet-4    |
| Google Gemini | GEMINI_API_KEY | gemini-2.0-flash   |
| Ollama     | (local, no key)   | llama3.2           |

## Configuration

Configuration is stored at `~/.kage/config.json`. Run `kage init` to create it.

```json
{
  "version": 1,
  "scanner": {
    "semgrep": { "enabled": true, "ruleset": "p/default" },
    "gitleaks": { "enabled": true },
    "trivy": { "enabled": true, "severity": "CRITICAL,HIGH" }
  },
  "ai": {
    "provider": "gemini",
    "model": "gemini-2.0-flash",
    "api_key": "",
    "endpoint": ""
  }
}
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run KAGE security scan
  uses: vtino17/kage-action@v1
  with:
    args: scan . --ci --format sarif
```

### GitLab CI

```yaml
kage-scan:
  image: ghcr.io/vtino17/kage:latest
  script:
    - kage scan . --ci --format sarif
```

## Output Formats

- **terminal** (default): Human-readable color output
- **json**: Machine-readable JSON
- **sarif**: SARIF 2.1.0 (GitHub Advanced Security compatible)

## Architecture

```
CLI (Go) -> Scanner Hub (Semgrep, Gitleaks, Trivy) -> Engine (dedup, score)
  -> AI Engine (Python, optional) -> Reporter (terminal/json/sarif)
  -> Fixer (patch, GitHub PR, optional)
```

## Development

```bash
git clone https://github.com/vtino17/kage.git
cd kage
go test ./... -race -count=1
go build -o kage ./cmd/kage
```

## Requirements

- Go 1.25+ (to build from source)
- Semgrep, Gitleaks, Trivy (for full scanning; run `kage init`)

## License

Apache 2.0
