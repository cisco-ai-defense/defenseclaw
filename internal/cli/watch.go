package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

var (
	watchSkillDirs []string
	watchMCPDirs   []string
	watchDebounce  int
	watchNoBlock   bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor OpenClaw for new skill and MCP server installations",
	Long: `Start a long-running watcher that monitors OpenClaw's skill and MCP server
directories for new installations. Each detected install is run through the
admission gate (block list → allow list → scan) in real time.

HIGH/CRITICAL findings are auto-blocked and quarantined unless --no-auto-block
is set. The watcher logs all events to the audit store.

Override watched directories with flags or configure permanently in
~/.defenseclaw/config.yaml under the "watch" section.`,
	RunE: runWatch,
}

func init() {
	watchCmd.Flags().StringSliceVar(&watchSkillDirs, "skill-dirs", nil, "Override skill directories to watch (comma-separated)")
	watchCmd.Flags().StringSliceVar(&watchMCPDirs, "mcp-dirs", nil, "Override MCP directories to watch (comma-separated)")
	watchCmd.Flags().IntVar(&watchDebounce, "debounce", 0, "Debounce interval in milliseconds (default: from config)")
	watchCmd.Flags().BoolVar(&watchNoBlock, "no-auto-block", false, "Disable auto-blocking of HIGH/CRITICAL findings")
	rootCmd.AddCommand(watchCmd)
}

func runWatch(_ *cobra.Command, _ []string) error {
	if len(watchSkillDirs) > 0 {
		cfg.Watch.SkillDirs = watchSkillDirs
	}
	if len(watchMCPDirs) > 0 {
		cfg.Watch.MCPDirs = watchMCPDirs
	}
	if watchDebounce > 0 {
		cfg.Watch.DebounceMs = watchDebounce
	}
	if watchNoBlock {
		cfg.Watch.AutoBlock = false
	}

	allDirs := append(cfg.Watch.SkillDirs, cfg.Watch.MCPDirs...)
	if len(allDirs) == 0 {
		return fmt.Errorf("no directories configured — set watch.skill_dirs or watch.mcp_dirs in config")
	}

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)

	w := watcher.New(cfg, auditStore, auditLog, shell, func(r watcher.AdmissionResult) {
		printAdmissionResult(r)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[watch] shutting down...")
		cancel()
	}()

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║       DefenseClaw Install Watcher            ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Auto-block:  %v\n", cfg.Watch.AutoBlock)
	fmt.Printf("  Debounce:    %dms\n", cfg.Watch.DebounceMs)
	fmt.Printf("  Skill dirs:  %s\n", strings.Join(cfg.Watch.SkillDirs, ", "))
	fmt.Printf("  MCP dirs:    %s\n", strings.Join(cfg.Watch.MCPDirs, ", "))
	fmt.Println()

	return w.Run(ctx)
}

func printAdmissionResult(r watcher.AdmissionResult) {
	ts := r.Event.Timestamp.Format(time.RFC3339)
	var icon string
	switch r.Verdict {
	case watcher.VerdictBlocked:
		icon = "BLOCKED"
	case watcher.VerdictRejected:
		icon = "REJECTED"
	case watcher.VerdictAllowed:
		icon = "ALLOWED"
	case watcher.VerdictClean:
		icon = "CLEAN"
	case watcher.VerdictWarning:
		icon = "WARNING"
	case watcher.VerdictScanError:
		icon = "ERROR"
	}
	fmt.Printf("[%s] [%s] %s %s — %s\n", ts, icon, r.Event.Type, r.Event.Name, r.Reason)
}
