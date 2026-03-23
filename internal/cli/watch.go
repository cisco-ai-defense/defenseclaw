package cli

import (
	"context"
	"encoding/json"
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
	watchSkillDirs  []string
	watchMCPDirs    []string
	watchDebounce   int
	watchNoBlock    bool
	watchJSONEvents bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor OpenClaw for new skill and MCP server installations",
	Long: `Start a long-running watcher that monitors OpenClaw's skill and MCP server
directories for new installations. Each detected install is run through the
admission gate (block list → allow list → scan) in real time.

HIGH/CRITICAL findings are auto-blocked and quarantined unless --no-auto-block
is set. The watcher logs all events to the audit store.

Watch directories are derived from claw.mode (default: openclaw). Override
with --skill-dirs and --mcp-dirs flags, or change claw.mode in config.`,
	RunE: runWatch,
}

func init() {
	watchCmd.Flags().StringSliceVar(&watchSkillDirs, "skill-dirs", nil, "Override skill directories to watch (comma-separated)")
	watchCmd.Flags().StringSliceVar(&watchMCPDirs, "mcp-dirs", nil, "Override MCP directories to watch (comma-separated)")
	watchCmd.Flags().IntVar(&watchDebounce, "debounce", 0, "Debounce interval in milliseconds (default: from config)")
	watchCmd.Flags().BoolVar(&watchNoBlock, "no-auto-block", false, "Disable auto-blocking of HIGH/CRITICAL findings")
	watchCmd.Flags().BoolVar(&watchJSONEvents, "json-events", false, "Emit admission results as NDJSON (one JSON object per line)")
	rootCmd.AddCommand(watchCmd)
}

func runWatch(_ *cobra.Command, _ []string) error {
	if watchDebounce > 0 {
		cfg.Watch.DebounceMs = watchDebounce
	}
	if watchNoBlock {
		cfg.Watch.AutoBlock = false
	}

	// Use claw-mode-aware directories, with flag overrides
	skillDirs := cfg.SkillDirs()
	if len(watchSkillDirs) > 0 {
		skillDirs = watchSkillDirs
	}
	mcpDirs := cfg.MCPDirs()
	if len(watchMCPDirs) > 0 {
		mcpDirs = watchMCPDirs
	}

	allDirs := append(skillDirs, mcpDirs...)
	if len(allDirs) == 0 {
		return fmt.Errorf("no directories configured — check claw.mode and claw.home_dir in config")
	}

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)

	w := watcher.New(cfg, skillDirs, mcpDirs, auditStore, auditLog, shell, func(r watcher.AdmissionResult) {
		if watchJSONEvents {
			emitAdmissionJSON(r)
		} else {
			printAdmissionResult(r)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if !watchJSONEvents {
			fmt.Println("\n[watch] shutting down...")
		}
		cancel()
	}()

	if !watchJSONEvents {
		fmt.Println("╔══════════════════════════════════════════════╗")
		fmt.Println("║       DefenseClaw Install Watcher            ║")
		fmt.Println("╚══════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Printf("  Claw mode:   %s\n", cfg.Claw.Mode)
		fmt.Printf("  Auto-block:  %v\n", cfg.Watch.AutoBlock)
		fmt.Printf("  Debounce:    %dms\n", cfg.Watch.DebounceMs)
		fmt.Printf("  Skill dirs:  %s\n", strings.Join(skillDirs, ", "))
		fmt.Printf("  MCP dirs:    %s\n", strings.Join(mcpDirs, ", "))
		fmt.Println()
	}

	return w.Run(ctx)
}

type admissionEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
}

func emitAdmissionJSON(r watcher.AdmissionResult) {
	evt := admissionEvent{
		Timestamp: r.Event.Timestamp.Format(time.RFC3339),
		Type:      string(r.Event.Type),
		Name:      r.Event.Name,
		Path:      r.Event.Path,
		Verdict:   string(r.Verdict),
		Reason:    r.Reason,
	}
	data, _ := json.Marshal(evt)
	fmt.Println(string(data))
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
