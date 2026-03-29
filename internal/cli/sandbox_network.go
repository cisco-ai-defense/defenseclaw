package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

var validPolicyName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

var sandboxNetworkPolicyFile string

var sandboxNetworkCmd = &cobra.Command{
	Use:   "network",
	Short: "Manage sandbox network policies",
	Long: `View and modify the network_policies section of the OpenShell
sandbox policy YAML. Changes require a sandbox restart to take effect.`,
}

var sandboxNetworkListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all network policy entries",
	RunE:  runSandboxNetworkList,
}

var sandboxNetworkAllowCmd = &cobra.Command{
	Use:   "allow <name>",
	Short: "Add or update a named network policy entry",
	Args:  cobra.ExactArgs(1),
	RunE:  runSandboxNetworkAllow,
}

var sandboxNetworkRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a network policy entry",
	Long: `Remove a network policy entry by name. Use --host to remove any
entry containing a specific host instead.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSandboxNetworkRemove,
}

func init() {
	sandboxNetworkCmd.PersistentFlags().StringVar(&sandboxNetworkPolicyFile, "policy-file", "", "Override the OpenShell policy YAML path")

	sandboxNetworkListCmd.Flags().Bool("json", false, "Output in JSON format")

	sandboxNetworkAllowCmd.Flags().StringSlice("host", nil, "Endpoint host (repeatable, required)")
	sandboxNetworkAllowCmd.Flags().IntSlice("port", nil, "Endpoint port (repeatable, default [443])")
	sandboxNetworkAllowCmd.Flags().StringSlice("binary", nil, "Binary path allowed to reach this endpoint (repeatable)")
	sandboxNetworkAllowCmd.Flags().Bool("dry-run", false, "Print changes without writing")
	_ = sandboxNetworkAllowCmd.MarkFlagRequired("host")

	sandboxNetworkRemoveCmd.Flags().String("host", "", "Remove entries matching this host instead of by name")
	sandboxNetworkRemoveCmd.Flags().Bool("dry-run", false, "Print changes without writing")

	sandboxNetworkCmd.AddCommand(sandboxNetworkListCmd)
	sandboxNetworkCmd.AddCommand(sandboxNetworkAllowCmd)
	sandboxNetworkCmd.AddCommand(sandboxNetworkRemoveCmd)

	sandboxCmd.AddCommand(sandboxNetworkCmd)
}

func resolvePolicyPath() string {
	if sandboxNetworkPolicyFile != "" {
		return sandboxNetworkPolicyFile
	}
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	return shell.EffectivePolicyPath()
}

func loadOpenShellPolicy() (*sandbox.OpenShellPolicy, string, error) {
	path := resolvePolicyPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, path, fmt.Errorf("sandbox network: policy file not found at %s", path)
		}
		return nil, path, fmt.Errorf("sandbox network: read policy: %w", err)
	}

	policy, err := sandbox.ParseOpenShellPolicy(data)
	if err != nil {
		return nil, path, err
	}
	return policy, path, nil
}

func requireStandalone() error {
	if !cfg.OpenShell.IsStandalone() {
		return fmt.Errorf("sandbox network: openshell.mode is not 'standalone' — run 'defenseclaw setup sandbox' first")
	}
	return nil
}

func writePolicy(policy *sandbox.OpenShellPolicy, path string) error {
	data, err := policy.Marshal()
	if err != nil {
		return fmt.Errorf("sandbox network: marshal policy: %w", err)
	}
	return sandbox.AtomicWriteWithLock(path, data, 0o600)
}

// ---------------------------------------------------------------------------
// sandbox network list
// ---------------------------------------------------------------------------

func runSandboxNetworkList(cmd *cobra.Command, _ []string) error {
	if err := requireStandalone(); err != nil {
		return err
	}

	policy, path, err := loadOpenShellPolicy()
	if err != nil {
		return err
	}

	entries := policy.NetworkPolicyEntries()
	jsonOut, _ := cmd.Flags().GetBool("json")

	if jsonOut {
		out, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return fmt.Errorf("sandbox network: json marshal: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	if len(entries) == 0 {
		fmt.Printf("No network policies in %s\n", path)
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	fmt.Printf("Network policies (%s):\n", path)
	for _, e := range entries {
		fmt.Printf("  %s\n", e.Name)

		var epStrs []string
		for _, ep := range e.Endpoints {
			if ep.Port > 0 {
				epStrs = append(epStrs, fmt.Sprintf("%s:%d", ep.Host, ep.Port))
			} else {
				epStrs = append(epStrs, ep.Host)
			}
		}
		if len(epStrs) > 0 {
			fmt.Printf("    endpoints: %s\n", strings.Join(epStrs, ", "))
		}

		if len(e.Binaries) > 0 {
			fmt.Printf("    binaries:  %s\n", strings.Join(e.Binaries, ", "))
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// sandbox network allow
// ---------------------------------------------------------------------------

func runSandboxNetworkAllow(cmd *cobra.Command, args []string) error {
	if err := requireStandalone(); err != nil {
		return err
	}

	name := args[0]
	if err := validatePolicyName(name); err != nil {
		return err
	}

	hosts, _ := cmd.Flags().GetStringSlice("host")
	ports, _ := cmd.Flags().GetIntSlice("port")
	binaries, _ := cmd.Flags().GetStringSlice("binary")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	if err := validatePorts(ports); err != nil {
		return err
	}

	policy, path, err := loadOpenShellPolicy()
	if err != nil {
		return err
	}

	existed := policy.HasNetworkPolicyName(name)
	policy.AddNetworkPolicy(name, hosts, ports, binaries)

	effectivePorts := ports
	if len(effectivePorts) == 0 {
		effectivePorts = []int{443}
	}

	if dryRun {
		action := "add"
		if existed {
			action = "update"
		}
		fmt.Printf("Would %s network policy %q in %s:\n", action, name, path)
		for _, h := range hosts {
			fmt.Printf("  + %s  ports: %s\n", h, formatPorts(effectivePorts))
		}
		return nil
	}

	if err := writePolicy(policy, path); err != nil {
		return err
	}

	if existed {
		fmt.Printf("Updated network policy %q in %s\n", name, path)
	} else {
		fmt.Printf("Added network policy %q to %s\n", name, path)
	}
	fmt.Println("Policy updated. Restart the sandbox for changes to take effect.")
	return nil
}

func validatePolicyName(name string) error {
	if !validPolicyName.MatchString(name) {
		return fmt.Errorf("sandbox network: invalid policy name %q — must match [a-zA-Z0-9][a-zA-Z0-9_-]*", name)
	}
	return nil
}

func validatePorts(ports []int) error {
	for _, p := range ports {
		if p < 0 || p > 65535 {
			return fmt.Errorf("sandbox network: invalid port %d — must be 0-65535", p)
		}
	}
	return nil
}

func formatPorts(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(strs, ", ")
}

// ---------------------------------------------------------------------------
// sandbox network remove
// ---------------------------------------------------------------------------

func runSandboxNetworkRemove(cmd *cobra.Command, args []string) error {
	if err := requireStandalone(); err != nil {
		return err
	}

	host, _ := cmd.Flags().GetString("host")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	if len(args) == 0 && host == "" {
		return fmt.Errorf("sandbox network remove: provide a policy name or --host")
	}

	policy, path, err := loadOpenShellPolicy()
	if err != nil {
		return err
	}

	if host != "" {
		removed := policy.RemoveEndpointsByHost(host)
		if len(removed) == 0 {
			return fmt.Errorf("sandbox network remove: no entries found for host %q", host)
		}
		if dryRun {
			for _, r := range removed {
				fmt.Printf("Would remove: %s\n", r.Reason)
			}
			return nil
		}
		if err := writePolicy(policy, path); err != nil {
			return err
		}
		for _, r := range removed {
			fmt.Println(r.Reason)
		}
		fmt.Println("Policy updated. Restart the sandbox for changes to take effect.")
		return nil
	}

	name := args[0]
	if err := validatePolicyName(name); err != nil {
		return err
	}
	if !policy.RemoveNetworkPolicyByName(name) {
		return fmt.Errorf("sandbox network remove: no entry named %q", name)
	}

	if dryRun {
		fmt.Printf("Would remove network policy %q from %s\n", name, path)
		return nil
	}

	if err := writePolicy(policy, path); err != nil {
		return err
	}
	fmt.Printf("Removed network policy %q from %s\n", name, path)
	fmt.Println("Policy updated. Restart the sandbox for changes to take effect.")
	return nil
}
