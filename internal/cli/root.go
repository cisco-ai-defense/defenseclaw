package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

var (
	cfg        *config.Config
	auditStore *audit.Store
	auditLog   *audit.Logger
)

func SetVersion(v string) {
	rootCmd.Version = v
}

var rootCmd = &cobra.Command{
	Use:   "defenseclaw",
	Short: "Enterprise governance layer for OpenClaw",
	Long: `DefenseClaw secures OpenClaw deployments by scanning skills, MCP servers,
and code before they run, enforcing block/allow lists, and providing a
terminal dashboard for governance.`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		switch cmd.Name() {
		case "init", "help", "completion":
			return nil
		}

		var err error
		cfg, err = config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config — run 'defenseclaw init' first: %w", err)
		}

		auditStore, err = audit.NewStore(cfg.AuditDB)
		if err != nil {
			return fmt.Errorf("failed to open audit store: %w", err)
		}

		auditLog = audit.NewLogger(auditStore)
		initSplunkForwarder()
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {
		if auditLog != nil {
			auditLog.Close()
		}
		if auditStore != nil {
			auditStore.Close()
		}
	},
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initSplunkForwarder() {
	if cfg == nil || !cfg.Splunk.Enabled {
		return
	}

	token := cfg.Splunk.HECToken
	if token == "" {
		token = os.Getenv("DEFENSECLAW_SPLUNK_HEC_TOKEN")
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "warning: splunk.enabled=true but no HEC token configured")
		return
	}

	splunkCfg := audit.SplunkConfig{
		HECEndpoint:   cfg.Splunk.HECEndpoint,
		HECToken:      token,
		Index:         cfg.Splunk.Index,
		Source:        cfg.Splunk.Source,
		SourceType:    cfg.Splunk.SourceType,
		VerifyTLS:     cfg.Splunk.VerifyTLS,
		Enabled:       true,
		BatchSize:     cfg.Splunk.BatchSize,
		FlushInterval: cfg.Splunk.FlushInterval,
	}

	fwd, err := audit.NewSplunkForwarder(splunkCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: splunk init: %v\n", err)
		return
	}

	auditLog.SetSplunkForwarder(fwd)
}
