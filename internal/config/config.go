package config

type ScannerConfig struct {
	Semgrep  SemgrepConfig  `json:"semgrep" mapstructure:"semgrep"`
	Gitleaks GitleaksConfig `json:"gitleaks" mapstructure:"gitleaks"`
	Trivy    TrivyConfig    `json:"trivy" mapstructure:"trivy"`
}

type SemgrepConfig struct {
	Enabled bool   `json:"enabled" mapstructure:"enabled"`
	Ruleset string `json:"ruleset" mapstructure:"ruleset"`
}

type GitleaksConfig struct {
	Enabled bool `json:"enabled" mapstructure:"enabled"`
}

type TrivyConfig struct {
	Enabled  bool   `json:"enabled" mapstructure:"enabled"`
	Severity string `json:"severity" mapstructure:"severity"`
}

type AIProvider string

const (
	AIProviderOpenAI    AIProvider = "openai"
	AIProviderAnthropic AIProvider = "anthropic"
	AIProviderGemini    AIProvider = "gemini"
	AIProviderOllama    AIProvider = "ollama"
)

type AIConfig struct {
	Provider AIProvider `json:"provider" mapstructure:"provider"`
	Model    string     `json:"model" mapstructure:"model"`
	APIKey   string     `json:"api_key" mapstructure:"api_key"`
	Endpoint string     `json:"endpoint" mapstructure:"endpoint"`
}

type GitHubConfig struct {
	Token string `json:"token" mapstructure:"token"`
}

type Config struct {
	Version int            `json:"version" mapstructure:"version"`
	Scanner ScannerConfig  `json:"scanner" mapstructure:"scanner"`
	AI      AIConfig       `json:"ai" mapstructure:"ai"`
	GitHub  GitHubConfig   `json:"github" mapstructure:"github"`
}

func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Scanner: ScannerConfig{
			Semgrep: SemgrepConfig{
				Enabled: true,
				Ruleset: "p/default",
			},
			Gitleaks: GitleaksConfig{
				Enabled: true,
			},
			Trivy: TrivyConfig{
				Enabled:  true,
				Severity: "CRITICAL,HIGH",
			},
		},
		AI: AIConfig{
			Provider: AIProviderGemini,
			Model:    "gemini-2.0-flash",
		},
		GitHub: GitHubConfig{},
	}
}
