package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

var (
	sidecarToken string
	sidecarHost  string
	sidecarPort  int
)

var sidecarCmd = &cobra.Command{
	Use:   "sidecar",
	Short: "Run the gateway sidecar — connect to the OpenClaw gateway and enforce policy in real time",
	Long: `Start a long-running sidecar process that connects to the OpenClaw gateway
WebSocket as an operator client. The sidecar monitors tool_call and tool_result
events, handles exec.approval requests, and can disable skills via the gateway
RPC protocol.

Configure the gateway address and token in ~/.defenseclaw/config.yaml under the
"gateway" section, or use the --token, --host, and --port flags.`,
	RunE: runSidecar,
}

func init() {
	sidecarCmd.Flags().StringVar(&sidecarToken, "token", "", "Gateway auth token (overrides config)")
	sidecarCmd.Flags().StringVar(&sidecarHost, "host", "", "Gateway host (default: from config)")
	sidecarCmd.Flags().IntVar(&sidecarPort, "port", 0, "Gateway port (default: from config)")
	rootCmd.AddCommand(sidecarCmd)
}

func runSidecar(_ *cobra.Command, _ []string) error {
	if sidecarToken != "" {
		cfg.Gateway.Token = sidecarToken
	}
	if sidecarHost != "" {
		cfg.Gateway.Host = sidecarHost
	}
	if sidecarPort > 0 {
		cfg.Gateway.Port = sidecarPort
	}

	if cfg.Gateway.Token == "" {
		token := os.Getenv("OPENCLAW_GATEWAY_TOKEN")
		if token != "" {
			cfg.Gateway.Token = token
		}
	}

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║       DefenseClaw Gateway Sidecar             ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Gateway:      %s:%d\n", cfg.Gateway.Host, cfg.Gateway.Port)
	fmt.Printf("  Auto-approve: %v\n", cfg.Gateway.AutoApprove)
	fmt.Printf("  Auth:         %s\n", tokenStatus(cfg.Gateway.Token))
	fmt.Println()

	sc, err := gateway.NewSidecar(cfg, auditStore, auditLog)
	if err != nil {
		return fmt.Errorf("sidecar: init: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[sidecar] shutting down...")
		cancel()
	}()

	return sc.Run(ctx)
}

func tokenStatus(token string) string {
	if token == "" {
		return "none (will use device identity only)"
	}
	if len(token) > 8 {
		return token[:4] + "..." + token[len(token)-4:]
	}
	return "***"
}
