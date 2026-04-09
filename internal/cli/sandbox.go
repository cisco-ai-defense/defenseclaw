package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Manage the openshell-sandbox instance",
	Long: `Manage the openshell-sandbox standalone instance.

These are convenience wrappers around systemd. The sandbox and sidecar
are independent systemd services grouped by defenseclaw-sandbox.target.`,
}

var sandboxStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the sandbox and sidecar via systemd",
	RunE:  runSandboxStart,
}

var sandboxStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the sandbox and sidecar via systemd",
	RunE:  runSandboxStop,
}

var sandboxRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the sandbox (sidecar reconnects automatically)",
	RunE:  runSandboxRestart,
}

var sandboxStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sandbox and sidecar systemd status",
	RunE:  runSandboxStatus,
}

var (
	sandboxExecNetns bool
)

var sandboxExecCmd = &cobra.Command{
	Use:   "exec -- <command> [args...]",
	Short: "Run a command as the sandbox user",
	Long: `Run a command as the sandbox user on the host.

By default, runs via 'sudo -u sandbox <command>' on the host filesystem.
The sandbox home directory is shared (Landlock restricts, doesn't overlay),
so all changes persist.

Use --netns to run inside the sandbox's network namespace (for debugging).`,
	DisableFlagParsing: true,
	RunE:               runSandboxExec,
}

var sandboxShellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Open an interactive shell as the sandbox user",
	RunE:  runSandboxShell,
}

func init() {
	sandboxExecCmd.Flags().BoolVar(&sandboxExecNetns, "netns", false, "Run inside the sandbox network namespace")

	sandboxCmd.AddCommand(sandboxStartCmd)
	sandboxCmd.AddCommand(sandboxStopCmd)
	sandboxCmd.AddCommand(sandboxRestartCmd)
	sandboxCmd.AddCommand(sandboxStatusCmd)
	sandboxCmd.AddCommand(sandboxExecCmd)
	sandboxCmd.AddCommand(sandboxShellCmd)

	rootCmd.AddCommand(sandboxCmd)
}

func runSandboxStart(_ *cobra.Command, _ []string) error {
	if !cfg.OpenShell.IsStandalone() {
		return fmt.Errorf("sandbox: openshell.mode is not 'standalone' — run 'defenseclaw setup sandbox' first")
	}

	fmt.Println("Starting defenseclaw-sandbox.target ...")
	return systemctl("start", "defenseclaw-sandbox.target")
}

func runSandboxStop(_ *cobra.Command, _ []string) error {
	fmt.Println("Stopping defenseclaw-sandbox.target ...")
	return systemctl("stop", "defenseclaw-sandbox.target")
}

func runSandboxRestart(_ *cobra.Command, _ []string) error {
	fmt.Println("Restarting openshell-sandbox.service (sidecar will reconnect) ...")
	return systemctl("restart", "openshell-sandbox.service")
}

func runSandboxStatus(_ *cobra.Command, _ []string) error {
	for _, unit := range []string{"openshell-sandbox.service", "defenseclaw-gateway.service"} {
		cmd := exec.Command("systemctl", "status", "--no-pager", unit)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		fmt.Println()
	}
	return nil
}

func runSandboxExec(_ *cobra.Command, args []string) error {
	// Strip leading "--" if present
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	// Check for --netns flag manually since we disabled flag parsing
	netns := false
	var cmdArgs []string
	for _, a := range args {
		if a == "--netns" {
			netns = true
		} else {
			cmdArgs = append(cmdArgs, a)
		}
	}

	if len(cmdArgs) == 0 {
		return fmt.Errorf("sandbox exec: no command specified")
	}

	if netns {
		return sandboxExecInNetns(cmdArgs)
	}

	cmd := exec.Command("sudo", append([]string{"-u", "sandbox"}, cmdArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runSandboxShell(_ *cobra.Command, _ []string) error {
	cmd := exec.Command("sudo", "-u", "sandbox", "bash")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func sandboxExecInNetns(args []string) error {
	ns, err := findSandboxNamespace()
	if err != nil {
		return err
	}

	nsArgs := []string{"netns", "exec", ns, "sudo", "-u", "sandbox"}
	nsArgs = append(nsArgs, args...)
	cmd := exec.Command("ip", nsArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func findSandboxNamespace() (string, error) {
	out, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		return "", fmt.Errorf("sandbox: failed to list namespaces: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		name := strings.Fields(line)
		if len(name) > 0 && strings.Contains(name[0], "openshell") {
			return name[0], nil
		}
	}
	return "", fmt.Errorf("sandbox: no openshell namespace found (is the sandbox running?)")
}

func systemctl(action, unit string) error {
	cmd := exec.Command("systemctl", action, unit)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
