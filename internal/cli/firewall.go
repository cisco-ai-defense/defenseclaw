package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
	"github.com/defenseclaw/defenseclaw/internal/firewall/platform"
)

var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Manage egress firewall policy",
	Long: `Generate, validate, and inspect DefenseClaw egress firewall rules.

DefenseClaw generates rules — applying them is a one-time admin step.
Run 'defenseclaw firewall init --observe' to get started.`,
}

var fwObserve bool

var fwInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate initial firewall config (optionally from observed connections)",
	RunE:  runFirewallInit,
}

var fwValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate firewall.yaml for errors",
	RunE:  runFirewallValidate,
}

var fwGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Compile firewall.yaml into platform rules and print the apply command",
	RunE:  runFirewallGenerate,
}

var fwStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether firewall rules are currently loaded",
	RunE:  runFirewallStatus,
}

func init() {
	fwInitCmd.Flags().BoolVar(&fwObserve, "observe", false, "Build initial allowlist from active connections and skill scans")
	firewallCmd.AddCommand(fwInitCmd, fwValidateCmd, fwGenerateCmd, fwStatusCmd)
	rootCmd.AddCommand(firewallCmd)
}

// ── init ─────────────────────────────────────────────────────────────────────

func runFirewallInit(_ *cobra.Command, _ []string) error {
	configPath := cfg.Firewall.ConfigFile
	rulesPath := cfg.Firewall.RulesFile
	compiler := platform.NewCompiler()

	var fwCfg *firewall.FirewallConfig

	if fwObserve {
		fmt.Println("  Observing active connections and scanning skills...")
		result, err := firewall.Observe(context.Background(), cfg.Watch.SkillDirs)
		if err != nil {
			return fmt.Errorf("firewall init: observe: %w", err)
		}

		// Show what was found.
		fmt.Printf("  Active connections observed: %d\n", len(result.Connections))
		for _, c := range result.Connections {
			label := c.RemoteIP
			if c.Domain != "" {
				label = c.Domain
			}
			fmt.Printf("    %-40s :%s  (%s)\n", label, c.RemotePort, c.Command)
		}

		if len(result.SkillDomains) > 0 {
			fmt.Printf("  Domains found in skills: %d\n", len(result.SkillDomains))
			for _, d := range result.SkillDomains {
				fmt.Printf("    %s\n", d)
			}
		}

		fwCfg = result.ProposedConfig

		// Warn about connections that would be blocked.
		if len(result.WouldBlock) > 0 {
			fmt.Println()
			fmt.Printf("  ⚠  %d active connection(s) NOT covered by the proposed allowlist:\n", len(result.WouldBlock))
			for _, c := range result.WouldBlock {
				label := c.RemoteIP
				if c.Domain != "" {
					label = c.Domain
				}
				fmt.Printf("    %s:%s  (%s)\n", label, c.RemotePort, c.Command)
			}
			fmt.Println("  Review firewall.yaml and add them before activating if needed.")
		}
	} else {
		fwCfg = firewall.DefaultFirewallConfig()
		fmt.Println("  Using default deny-by-default config.")
		fmt.Println("  Tip: run with --observe to auto-detect your active connections.")
	}

	// Write firewall.yaml.
	if err := firewall.Save(fwCfg, configPath); err != nil {
		return fmt.Errorf("firewall init: save config: %w", err)
	}
	fmt.Printf("\n  Config written: %s\n", configPath)

	// Generate and write rules.
	rules, err := compiler.Compile(fwCfg)
	if err != nil {
		return fmt.Errorf("firewall init: compile: %w", err)
	}
	content := strings.Join(rules, "\n") + "\n"
	if err := os.WriteFile(rulesPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("firewall init: write rules: %w", err)
	}
	fmt.Printf("  Rules written: %s\n", rulesPath)

	printApplyInstructions(compiler, rulesPath)
	return nil
}

// ── validate ─────────────────────────────────────────────────────────────────

func runFirewallValidate(_ *cobra.Command, _ []string) error {
	configPath := cfg.Firewall.ConfigFile

	fwCfg, err := firewall.Load(configPath)
	if err != nil {
		return fmt.Errorf("firewall validate: %w", err)
	}
	if err := fwCfg.Validate(); err != nil {
		return fmt.Errorf("firewall validate: %w", err)
	}

	fmt.Printf("  %s — valid\n", configPath)
	fmt.Printf("  default_action: %s\n", fwCfg.DefaultAction)
	fmt.Printf("  rules: %d\n", len(fwCfg.Rules))
	fmt.Printf("  allowlist domains: %d\n", len(fwCfg.Allowlist.Domains))
	fmt.Printf("  allowlist IPs: %d\n", len(fwCfg.Allowlist.IPs))
	return nil
}

// ── generate ─────────────────────────────────────────────────────────────────

func runFirewallGenerate(_ *cobra.Command, _ []string) error {
	configPath := cfg.Firewall.ConfigFile
	rulesPath := cfg.Firewall.RulesFile
	compiler := platform.NewCompiler()

	fwCfg, err := firewall.Load(configPath)
	if err != nil {
		return fmt.Errorf("firewall generate: %w", err)
	}
	if err := fwCfg.Validate(); err != nil {
		return fmt.Errorf("firewall generate: invalid config: %w", err)
	}

	rules, err := compiler.Compile(fwCfg)
	if err != nil {
		return fmt.Errorf("firewall generate: compile: %w", err)
	}

	content := strings.Join(rules, "\n") + "\n"
	if err := os.WriteFile(rulesPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("firewall generate: write rules: %w", err)
	}

	hash := firewall.RulesHash(rules)
	fmt.Printf("  Rules written: %s  [%s]\n", rulesPath, hash)
	fmt.Printf("  Platform: %s\n", compiler.Platform())
	fmt.Printf("  Domains: %d  IPs: %d  Rules: %d\n",
		len(fwCfg.Allowlist.Domains), len(fwCfg.Allowlist.IPs), len(fwCfg.Rules))

	printApplyInstructions(compiler, rulesPath)
	return nil
}

// ── status ────────────────────────────────────────────────────────────────────

func runFirewallStatus(_ *cobra.Command, _ []string) error {
	compiler := platform.NewCompiler()
	status := firewall.GetStatus(compiler, cfg.Firewall.AnchorName)

	if status.Error != "" {
		fmt.Printf("  Firewall: unknown  (%s)\n", status.Error)
		fmt.Println("  (pfctl may need sudo to read rule counts — this is normal)")
		return nil
	}

	if status.Active {
		fmt.Printf("  Firewall: ✓ active  platform: %s  rules loaded: %d\n",
			compiler.Platform(), status.RuleCount)
	} else {
		fmt.Printf("  Firewall: ✗ not active  (no rules loaded for anchor %q)\n", status.AnchorName)
		fmt.Printf("  Run: defenseclaw firewall generate\n")
		fmt.Printf("  Then: %s\n", compiler.ApplyCommand(cfg.Firewall.RulesFile))
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func printApplyInstructions(compiler firewall.Compiler, rulesPath string) {
	fmt.Println()
	fmt.Println("  To activate (run once as admin):")
	fmt.Printf("    %s\n", compiler.ApplyCommand(rulesPath))
	fmt.Println()
	fmt.Println("  To remove rules:")
	fmt.Printf("    %s\n", compiler.RemoveCommand())
	fmt.Println()
	fmt.Println("  After editing firewall.yaml, regenerate and re-apply:")
	fmt.Println("    defenseclaw firewall generate")
	fmt.Printf("    %s\n", compiler.ApplyCommand(rulesPath))
}

// firewallConfigPreview returns a human-readable summary of firewall.yaml for
// use in other commands (e.g. scan drift warning). Returns "" if not configured.
func firewallConfigPreview() string {
	if cfg == nil || cfg.Firewall.ConfigFile == "" {
		return ""
	}
	fwCfg, err := firewall.Load(cfg.Firewall.ConfigFile)
	if err != nil {
		return ""
	}
	data, err := yaml.Marshal(fwCfg.Allowlist)
	if err != nil {
		return ""
	}
	return string(data)
}
