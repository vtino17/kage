package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "0.1.0"

var CommitSHA = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print KAGE version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("kage %s (commit: %s)\n", Version, CommitSHA)
		},
	}
}
