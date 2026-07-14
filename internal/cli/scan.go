package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vtino17/kage/internal/ai"
	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/engine"
	"github.com/vtino17/kage/internal/fixer"
	"github.com/vtino17/kage/internal/git"
	"github.com/vtino17/kage/internal/model"
	"github.com/vtino17/kage/internal/reporter"
	"github.com/vtino17/kage/internal/scanner"
)

var (
	scanDir      string
	scanFix      bool
	scanCI       bool
	scanFormat   string
	scanAI       bool
	scanProvider string
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [path|repo-url]",
		Short: "Scan a codebase for security vulnerabilities",
		Long: `Scan a local directory or GitHub repository for security issues.

Examples:
  kage scan ./my-project
  kage scan github.com/owner/repo
  kage scan . --fix
  kage scan . --ci --format sarif`,
		Args: cobra.ExactArgs(1),
		RunE: runScan,
	}

	cmd.Flags().StringVar(&scanDir, "dir", "", "Target directory (default: use argument)")
	cmd.Flags().BoolVar(&scanFix, "fix", false, "Create GitHub PR with auto-generated fixes")
	cmd.Flags().BoolVar(&scanCI, "ci", false, "CI mode: exit 1 if findings exist")
	cmd.Flags().StringVar(&scanFormat, "format", "terminal", "Output format: terminal, json, sarif")
	cmd.Flags().BoolVar(&scanAI, "ai", false, "Enable AI-powered analysis and fix generation")
	cmd.Flags().StringVar(&scanProvider, "ai-provider", "", "AI provider override (openai, anthropic, gemini, ollama)")

	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: false})

	target := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if scanProvider != "" {
		cfg.AI.Provider = config.AIProvider(scanProvider)
	}

	var targetInfo model.ScanTarget

	if strings.HasPrefix(target, "github.com/") || strings.HasPrefix(target, "https://github.com/") {
		repoPath := strings.TrimPrefix(target, "https://")
		repoPath = strings.TrimPrefix(repoPath, "github.com/")

		log.Info().Str("repo", repoPath).Msg("cloning repository")

		cloneDir, err := os.MkdirTemp("", "kage-scan-*")
		if err != nil {
			return fmt.Errorf("failed to create temp dir: %w", err)
		}
		defer os.RemoveAll(cloneDir)

		info, err := git.Clone("https://github.com/"+repoPath, cloneDir)
		if err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}

		targetInfo = model.ScanTarget{
			Type:   "github",
			Path:   cloneDir,
			Branch: info.Branch,
			Commit: info.Commit,
		}
	} else {
		absPath, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("path does not exist: %s", absPath)
		}
		targetInfo = model.ScanTarget{
			Type: "directory",
			Path: absPath,
		}
	}

	result := model.NewScanResult(targetInfo)

	registry := scanner.NewRegistry()
	registry.Register(scanner.NewSemgrepScanner(cfg))
	registry.Register(scanner.NewGitleaksScanner(cfg))
	registry.Register(scanner.NewTrivyScanner(cfg))

	log.Info().Str("target", targetInfo.Path).Msg("starting scan")

	scannerResults, scanErrors := registry.RunAll(targetInfo.Path)
	result.Errors = scanErrors

	eng := engine.NewEngine()
	result.Findings = eng.Process(scannerResults)
	result.Finalize()
	result.Scanners = registry.Names()
	result.Duration = result.CreatedAt.Sub(result.CreatedAt)

	if scanAI && len(result.Findings) > 0 {
		log.Info().Msg("running AI analysis")

		aiClient := ai.NewClient(cfg)
		enhanced, err := aiClient.Analyze(result.Findings)
		if err != nil {
			log.Warn().Err(err).Msg("AI analysis failed, using raw findings")
		} else {
			result.Findings = enhanced
		}

		if scanFix {
			log.Info().Msg("generating fixes")

			fixerClient := fixer.NewFixer(cfg, aiClient)
			proposal, err := fixerClient.GenerateFixes(result.Findings)
			if err != nil {
				return fmt.Errorf("fix generation failed: %w", err)
			}

			if len(proposal.Patches) > 0 {
				fixer.PrintProposal(proposal)

				if targetInfo.Type == "github" {
					fmt.Print("\nCreate PR with these fixes? [y/N]: ")
					var confirm string
					fmt.Scanln(&confirm)
					if strings.EqualFold(confirm, "y") {
						pr, err := fixerClient.CreatePR(proposal, target)
						if err != nil {
							return fmt.Errorf("failed to create PR: %w", err)
						}
						log.Info().Str("url", pr).Msg("pull request created")
					}
				}
			}
		}
	}

	output, err := reporter.Format(result, scanFormat)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}
	fmt.Println(output)

	if scanCI && result.Summary.Total > 0 {
		os.Exit(1)
	}

	return nil
}
