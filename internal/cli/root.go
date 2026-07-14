package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kage",
	Short: "KAGE - AI-powered security scanner and fixer",
	Long: `KAGE is an open-source security co-pilot that scans codebases
for vulnerabilities, secrets, and dependency issues, explains risks
in plain language, and can generate fixes automatically.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newVersionCmd())
}
