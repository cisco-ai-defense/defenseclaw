package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

const defaultStopTimeout = 10 * time.Second

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the gateway sidecar as a background daemon",
	Long: `Start the DefenseClaw gateway sidecar as a background daemon.

The daemon process runs independently and survives terminal close.
Use 'status' to check health and 'stop' to shut it down.

Logs are written to ~/.defenseclaw/gateway.log
PID is stored in ~/.defenseclaw/gateway.pid`,
	RunE:              runStart,
	PersistentPreRunE: nil, // Skip config loading for daemon commands
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running gateway sidecar daemon",
	Long: `Stop the DefenseClaw gateway sidecar daemon.

Sends SIGTERM for graceful shutdown, then SIGKILL if needed.`,
	RunE:              runStop,
	PersistentPreRunE: nil,
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the gateway sidecar daemon",
	Long: `Restart the DefenseClaw gateway sidecar daemon.

Equivalent to 'stop' followed by 'start'.`,
	RunE:              runRestart,
	PersistentPreRunE: nil,
}

func init() {
	// Override PersistentPreRunE to skip config/audit loading for daemon management commands
	startCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error { return nil }
	stopCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error { return nil }
	restartCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error { return nil }

	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(restartCmd)
}

func runStart(cmd *cobra.Command, _ []string) error {
	d := daemon.New(config.DefaultDataPath())

	if running, pid := d.IsRunning(); running {
		fmt.Printf("Gateway sidecar is already running (PID %d)\n", pid)
		fmt.Println("Use 'defenseclaw-gateway status' to check health")
		return nil
	}

	fmt.Print("Starting gateway sidecar daemon... ")

	// Pass through relevant flags to the daemon process
	args := collectDaemonArgs(cmd)

	pid, err := d.Start(args)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("start daemon: %w", err)
	}

	fmt.Printf("OK (PID %d)\n", pid)
	fmt.Println()
	fmt.Printf("  Log file: %s\n", d.LogFile())
	fmt.Printf("  PID file: %s\n", d.PIDFile())
	fmt.Println()
	fmt.Println("Use 'defenseclaw-gateway status' to check health")
	fmt.Println("Use 'defenseclaw-gateway stop' to stop the daemon")

	return nil
}

func runStop(_ *cobra.Command, _ []string) error {
	d := daemon.New(config.DefaultDataPath())

	running, pid := d.IsRunning()
	if !running {
		fmt.Println("Gateway sidecar is not running")
		return nil
	}

	fmt.Printf("Stopping gateway sidecar (PID %d)... ", pid)

	if err := d.Stop(defaultStopTimeout); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("stop daemon: %w", err)
	}

	fmt.Println("OK")
	return nil
}

func runRestart(cmd *cobra.Command, _ []string) error {
	d := daemon.New(config.DefaultDataPath())

	if running, pid := d.IsRunning(); running {
		fmt.Printf("Stopping gateway sidecar (PID %d)... ", pid)
		if err := d.Stop(defaultStopTimeout); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("stop for restart: %w", err)
		}
		fmt.Println("OK")
	}

	fmt.Print("Starting gateway sidecar daemon... ")

	args := collectDaemonArgs(cmd)
	pid, err := d.Start(args)
	if err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("start daemon: %w", err)
	}

	fmt.Printf("OK (PID %d)\n", pid)
	fmt.Println()
	fmt.Println("Use 'defenseclaw-gateway status' to check health")

	return nil
}

func collectDaemonArgs(cmd *cobra.Command) []string {
	// When starting as daemon, we run the root command (sidecar mode)
	// Pass through any flags that were set
	var args []string

	if sidecarToken != "" {
		args = append(args, "--token", sidecarToken)
	}
	if sidecarHost != "" {
		args = append(args, "--host", sidecarHost)
	}
	if sidecarPort > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", sidecarPort))
	}

	return args
}

func checkDaemonMode() bool {
	if !daemon.IsDaemonChild() {
		return false
	}
	// Running as daemon child — suppress banner output
	fmt.Fprintln(os.Stderr, "[daemon] starting as background process")
	return true
}
