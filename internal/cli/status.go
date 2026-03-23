package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show DefenseClaw status",
	Long:  "Display environment, sandbox health, and counts for skills, MCPs, and alerts.",
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(_ *cobra.Command, _ []string) error {
	fmt.Println("DefenseClaw Status")
	fmt.Println("══════════════════")

	fmt.Printf("  Environment:  %s\n", cfg.Environment)
	fmt.Printf("  Data dir:     %s\n", cfg.DataDir)
	fmt.Printf("  Config:       %s/config.yaml\n", cfg.DataDir)
	fmt.Printf("  Audit DB:     %s\n", cfg.AuditDB)
	fmt.Println()

	// Sandbox
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	if shell.IsAvailable() {
		if shell.IsRunning() {
			fmt.Println("  Sandbox:      running")
		} else {
			fmt.Println("  Sandbox:      stopped (OpenShell available but not running)")
		}
	} else {
		fmt.Println("  Sandbox:      not available (OpenShell not found)")
	}

	// Scanners
	fmt.Println()
	fmt.Println("  Scanners:")
	scannerBins := []struct{ name, bin string }{
		{"skill-scanner", cfg.Scanners.SkillScanner.Binary},
		{"mcp-scanner", cfg.Scanners.MCPScanner},
		{"cisco-aibom", cfg.Scanners.AIBOM},
		{"codeguard", "built-in"},
	}
	for _, s := range scannerBins {
		if s.bin == "built-in" {
			fmt.Printf("    %-16s built-in\n", s.name)
			continue
		}
		if _, err := exec.LookPath(s.bin); err == nil {
			fmt.Printf("    %-16s installed\n", s.name)
		} else {
			fmt.Printf("    %-16s not found\n", s.name)
		}
	}

	// Counts
	if auditStore != nil {
		counts, err := auditStore.GetCounts()
		if err == nil {
			fmt.Println()
			fmt.Println("  Enforcement:")
			fmt.Printf("    Blocked skills:  %d\n", counts.BlockedSkills)
			fmt.Printf("    Allowed skills:  %d\n", counts.AllowedSkills)
			fmt.Printf("    Blocked MCPs:    %d\n", counts.BlockedMCPs)
			fmt.Printf("    Allowed MCPs:    %d\n", counts.AllowedMCPs)
			fmt.Println()
			fmt.Println("  Activity:")
			fmt.Printf("    Total scans:     %d\n", counts.TotalScans)
			fmt.Printf("    Active alerts:   %d\n", counts.Alerts)
		}
	}

	return nil
}
