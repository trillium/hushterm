package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP redaction server",
	Long:  "Expose an HTTP endpoint for programmatic text redaction.",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		fmt.Fprintf(cmd.OutOrStderr(), "hushterm serve: not yet implemented (port %d)\n", port)
		return nil
	},
}

func init() {
	serveCmd.Flags().Int("port", 8080, "port to listen on")
}
