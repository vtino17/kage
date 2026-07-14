package fixer

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/google/go-github/v69/github"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"github.com/vtino17/kage/internal/ai"
	"github.com/vtino17/kage/internal/config"
	"github.com/vtino17/kage/internal/model"
)

type Fixer struct {
	cfg      *config.Config
	aiClient *ai.Client
}

func NewFixer(cfg *config.Config, aiClient *ai.Client) *Fixer {
	return &Fixer{cfg: cfg, aiClient: aiClient}
}

func (f *Fixer) GenerateFixes(findings []model.Finding) (*model.FixProposal, error) {
	proposal := &model.FixProposal{
		Findings: findings,
		Patches:  make([]model.Patch, 0),
	}

	for _, finding := range findings {
		if finding.Fix == "" {
			continue
		}

		patch := model.Patch{
			FilePath:    finding.FilePath,
			FindingID:   finding.ID,
			Replacement: finding.Fix,
		}

		if finding.CodeSnippet != "" {
			patch.Original = finding.CodeSnippet
		}

		proposal.Patches = append(proposal.Patches, patch)
	}

	proposal.Summary = fmt.Sprintf("KAGE found %d vulnerabilities and generated %d patches", len(findings), len(proposal.Patches))

	return proposal, nil
}

func PrintProposal(proposal *model.FixProposal) {
	fmt.Printf("\nFix Proposal Summary: %s\n\n", proposal.Summary)
	for _, patch := range proposal.Patches {
		fmt.Printf("File: %s\n", patch.FilePath)
		if patch.Original != "" {
			fmt.Printf("  - Original: %s\n", truncateLine(patch.Original))
		}
		if patch.Replacement != "" {
			fmt.Printf("  + Fixed:    %s\n", truncateLine(patch.Replacement))
		}
		fmt.Println()
	}
}

func (f *Fixer) CreatePR(proposal *model.FixProposal, repoURL string) (string, error) {
	owner, repo := parseRepo(repoURL)
	if owner == "" || repo == "" {
		return "", fmt.Errorf("invalid repository URL: %s", repoURL)
	}

	token := f.cfg.GitHub.Token
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return "", fmt.Errorf("github token not configured. Set it in ~/.kage/config.json or GH_TOKEN")
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	branchName := "kage-fix-" + randSuffix(8)

	ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/main")
	if err != nil {
		ref, _, err = client.Git.GetRef(ctx, owner, repo, "refs/heads/master")
		if err != nil {
			return "", fmt.Errorf("failed to get base branch: %w", err)
		}
	}

	newRef := &github.Reference{
		Ref:    github.String("refs/heads/" + branchName),
		Object: &github.GitObject{SHA: ref.Object.SHA},
	}
	if _, _, err := client.Git.CreateRef(ctx, owner, repo, newRef); err != nil {
		return "", fmt.Errorf("failed to create branch: %w", err)
	}

	for _, patch := range proposal.Patches {
		content, _, _, err := client.Repositories.GetContents(ctx, owner, repo, patch.FilePath, &github.RepositoryContentGetOptions{Ref: "main"})
		if err != nil {
			log.Warn().Err(err).Str("file", patch.FilePath).Msg("failed to get file content")
			continue
		}

		decoded, _ := content.GetContent()

		newContent := strings.Replace(decoded, patch.Original, patch.Replacement, 1)
		if newContent == decoded {
			continue
		}

		opts := &github.RepositoryContentFileOptions{
			Message: github.String("fix: " + patch.FindingID),
			Content: []byte(newContent),
			SHA:     content.SHA,
			Branch:  github.String(branchName),
		}
		if _, _, err := client.Repositories.UpdateFile(ctx, owner, repo, patch.FilePath, opts); err != nil {
			log.Warn().Err(err).Str("file", patch.FilePath).Msg("failed to update file")
		}
	}

	pr := &github.NewPullRequest{
		Title: github.String("fix: security vulnerabilities found by KAGE"),
		Body:  github.String(proposal.Summary + "\n\nAutomated fix by KAGE."),
		Head:  github.String(branchName),
		Base:  github.String("main"),
	}

	createdPR, _, err := client.PullRequests.Create(ctx, owner, repo, pr)
	if err != nil {
		return "", fmt.Errorf("failed to create PR: %w", err)
	}

	return createdPR.GetHTMLURL(), nil
}

func parseRepo(url string) (string, string) {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "github.com/")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimSuffix(url, ".git")

	parts := strings.SplitN(url, "/", 3)
	if len(parts) >= 2 {
		return parts[0], strings.TrimSuffix(parts[1], ".git")
	}
	return "", ""
}

func truncateLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

func randSuffix(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}
