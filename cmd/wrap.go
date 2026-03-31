package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"github.com/spf13/cobra"
	"github.com/trilliumsmith/hushterm/internal/redact"
	"golang.org/x/term"
)

func runWrap(cmd *cobra.Command, args []string) error {
	style, _ := cmd.Flags().GetString("style")

	engine, err := redact.NewEngine(redact.Style(style))
	if err != nil {
		return fmt.Errorf("init redaction engine: %w", err)
	}

	// Load config file if provided.
	if cfgFile != "" {
		cfg, err := redact.LoadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		engine.ApplyConfig(cfg)
	}

	// Load blocklist directory if provided.
	if blocklistDir != "" {
		bl, err := redact.LoadBlocklistDir(blocklistDir)
		if err != nil {
			return fmt.Errorf("load blocklist: %w", err)
		}
		engine.SetBlocklist(bl)

		// Start live-reload watcher.
		stop, err := redact.WatchBlocklistDir(blocklistDir, engine.Blocklist())
		if err != nil {
			fmt.Fprintf(os.Stderr, "hushterm: blocklist watcher: %v (continuing without live reload)\n", err)
		} else {
			defer stop()
		}
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		return runPTY(args, engine)
	}
	return runPipe(args, engine)
}

// runPTY wraps the command in a PTY for full TUI support.
func runPTY(args []string, engine *redact.Engine) error {
	c := commandFromArgs(args)

	ptmx, err := pty.Start(c)
	if err != nil {
		return fmt.Errorf("start pty: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

	// Handle terminal resize.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
				fmt.Fprintf(os.Stderr, "hushterm: resize: %v\n", err)
			}
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.
	defer func() { signal.Stop(ch); close(ch) }()

	// Set stdin to raw mode.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("set raw mode: %w", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	// Proxy stdin → pty (user input).
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				_, _ = ptmx.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Proxy pty → stdout with redaction.
	buf := make([]byte, 4096)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			redacted := engine.Redact(buf[:n])
			_, _ = os.Stdout.Write(redacted)
		}
		if err != nil {
			break
		}
	}

	return c.Wait()
}

// runPipe handles the non-TTY case: stdin is piped, so run the command
// normally and filter its stdout/stderr through the redaction engine.
func runPipe(args []string, engine *redact.Engine) error {
	c := commandFromArgs(args)
	c.Stdin = os.Stdin

	stdout, err := c.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := c.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := c.Start(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	done := make(chan struct{}, 2)
	copyRedacted := func(dst *os.File, src io.Reader) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				redacted := engine.Redact(buf[:n])
				_, _ = dst.Write(redacted)
			}
			if err != nil {
				return
			}
		}
	}

	go copyRedacted(os.Stdout, stdout)
	go copyRedacted(os.Stderr, stderr)

	<-done
	<-done

	return c.Wait()
}

func commandFromArgs(args []string) *exec.Cmd {
	if len(args) == 1 {
		return exec.Command(args[0])
	}
	return exec.Command(args[0], args[1:]...)
}
