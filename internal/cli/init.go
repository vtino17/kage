package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vtino17/kage/internal/config"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize KAGE configuration and download scanner dependencies",
		Long: `Sets up ~/.kage/config.json and downloads required scanner binaries
(Semgrep, Gitleaks, Trivy) to ~/.kage/scanners/`,
		RunE: runInit,
	}
}

func runInit(cmd *cobra.Command, args []string) error {
	cfg := config.DefaultConfig()

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("Configuration created: " + mustConfigPath())

	scannersDir, err := config.ScannersDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(scannersDir, 0755); err != nil {
		return fmt.Errorf("failed to create scanners directory: %w", err)
	}

	fmt.Println("Scanner directory: " + scannersDir)
	fmt.Println()
	fmt.Println("KAGE is ready. Run 'kage scan' to get started.")
	fmt.Println("Optional: configure AI in ~/.kage/config.json for AI-powered analysis.")
	fmt.Println("  Providers: openai, anthropic, gemini, ollama")

	return nil
}

func mustConfigPath() string {
	p, err := config.ConfigPath()
	if err != nil {
		return "~/.kage/config.json"
	}
	return p
}
