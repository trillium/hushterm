package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile      string
	blocklistDir string
)

var rootCmd = &cobra.Command{
	Use:   "hushterm [flags] -- <command> [args...]",
	Short: "Real-time terminal output redaction",
	Long:  "PTY-based wrapper that intercepts terminal output and redacts secrets and PII in real-time.",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runWrap,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&cfgFile, "config", "", "config file (default: ~/.config/hushterm/config.yaml)")
	rootCmd.Flags().String("style", "placeholder", "redaction style: mask, placeholder, or hash")
	rootCmd.Flags().StringVar(&blocklistDir, "blocklist-dir", "", "directory of blocklist YAML files for literal string redaction (supports symlinks)")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("hushterm v0.1.0-dev")
	},
}
