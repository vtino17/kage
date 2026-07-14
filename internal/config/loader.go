package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	ConfigDir  = ".kage"
	ConfigFile = "config.json"
)

func ConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find home directory: %w", err)
	}
	return filepath.Join(home, ConfigDir, ConfigFile), nil
}

func ScannersDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ConfigDir, "scanners"), nil
}

func Load() (*Config, error) {
	configPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("json")

	if err := v.ReadInConfig(); err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}

func Save(cfg *Config) error {
	configPath, err := ConfigPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("json")

	for k, val := range toMap(cfg) {
		v.Set(k, val)
	}

	if err := v.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func toMap(cfg *Config) map[string]interface{} {
	return map[string]interface{}{
		"version": cfg.Version,
		"scanner": map[string]interface{}{
			"semgrep": map[string]interface{}{
				"enabled": cfg.Scanner.Semgrep.Enabled,
				"ruleset": cfg.Scanner.Semgrep.Ruleset,
			},
			"gitleaks": map[string]interface{}{
				"enabled": cfg.Scanner.Gitleaks.Enabled,
			},
			"trivy": map[string]interface{}{
				"enabled":  cfg.Scanner.Trivy.Enabled,
				"severity": cfg.Scanner.Trivy.Severity,
			},
		},
		"ai": map[string]interface{}{
			"provider": cfg.AI.Provider,
			"model":    cfg.AI.Model,
			"api_key":  cfg.AI.APIKey,
			"endpoint": cfg.AI.Endpoint,
		},
		"github": map[string]interface{}{
			"token": cfg.GitHub.Token,
		},
	}
}
