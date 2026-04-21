package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/agentotel"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "defenseclaw-agent-otel",
		Short:   "Direct OTLP launcher and config helper for Claude Code and Codex",
		Version: version,
	}

	root.AddCommand(configureCmd(), runCmd(), unconfigureCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func configureCmd() *cobra.Command {
	var opts agentotel.ConfigureOpts
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Write persistent OTLP configuration for Claude Code and Codex",
		Long: `Writes persistent configuration into ~/.claude/settings.json (for Claude Code)
and ~/.codex/config.toml (for Codex) so normal desktop launches send telemetry
directly to Splunk Observability Cloud or another OTLP/HTTP endpoint.

Example:

  defenseclaw-agent-otel configure \
    --tool all \
    --splunk-host us1 \
    --token "$SPLUNK_OBSERVABILITY_TOKEN" \
    --environment defenseclaw-direct-test

Or configure a generic OTLP/HTTP endpoint:

  defenseclaw-agent-otel configure \
    --tool all \
    --endpoint http://collector.internal:4318 \
    --token "$OTLP_AUTH_TOKEN" \
    --header-name Authorization \
    --header-prefix "Bearer "

Tool-specific overrides are also available when Claude and Codex should be
tracked as distinct desktop agents in the same command, for example
--claude-agent-name / --codex-agent-name and
--claude-environment / --codex-environment.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateToolValue(opts.Tool)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return agentotel.Configure(opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Tool, "tool", agentotel.ToolAll, "Tool to configure: claude, codex, or all")
	f.StringVar(&opts.Endpoint, "endpoint", "", "Base OTLP/HTTP endpoint, for example http://collector:4318")
	f.StringVar(&opts.Token, "token", "", "Auth token for direct OTLP export (or set OTLP_AUTH_TOKEN / SPLUNK_OBSERVABILITY_TOKEN)")
	f.StringVar(&opts.DeprecatedSplunkToken, "splunk-token", "", "Deprecated alias for --token")
	_ = f.MarkDeprecated("splunk-token", "use --token instead")
	f.StringVar(&opts.HeaderName, "header-name", "", "HTTP header name for direct auth; defaults to Authorization or X-SF-Token")
	f.StringVar(&opts.HeaderPrefix, "header-prefix", "", "Prefix added before --token, for example 'Bearer '")
	f.StringVar(&opts.SplunkHost, "splunk-host", "", "Splunk Observability host or realm for direct Splunk mode")
	f.StringVar(&opts.TenantID, "tenant-id", "", "Tenant identifier for resource attributes where supported")
	f.StringVar(&opts.WorkspaceID, "workspace-id", "", "Workspace identifier for resource attributes where supported")
	f.StringVar(&opts.AgentName, "agent-name", "", "Logical agent name for resource attributes where supported")
	f.StringVar(&opts.Environment, "environment", "dev", "Environment tag")
	f.StringVar(&opts.ClaudeTenantID, "claude-tenant-id", "", "Claude-specific tenant identifier override")
	f.StringVar(&opts.ClaudeWorkspaceID, "claude-workspace-id", "", "Claude-specific workspace identifier override")
	f.StringVar(&opts.ClaudeAgentName, "claude-agent-name", "", "Claude-specific agent name override")
	f.StringVar(&opts.ClaudeEnvironment, "claude-environment", "", "Claude-specific environment override")
	f.StringVar(&opts.CodexTenantID, "codex-tenant-id", "", "Codex-specific tenant identifier override")
	f.StringVar(&opts.CodexWorkspaceID, "codex-workspace-id", "", "Codex-specific workspace identifier override")
	f.StringVar(&opts.CodexAgentName, "codex-agent-name", "", "Codex-specific agent name override")
	f.StringVar(&opts.CodexEnvironment, "codex-environment", "", "Codex-specific environment override")
	return cmd
}

func runCmd() *cobra.Command {
	var opts agentotel.RunOpts
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Launch Claude Code or Codex once with direct OTEL settings injected",
		Long: `Runs Claude Code or Codex once with direct OTLP settings applied for the
session.

Claude uses runtime OTEL environment variables only in one-shot mode. Codex
uses runtime OTEL environment variables plus one-shot otel.* command-line
overrides. The command does not create a temporary home directory or persist
changes into the user's real desktop settings files.

Examples:

  defenseclaw-agent-otel run \
    --tool codex \
    --splunk-host us1 \
    --token "$SPLUNK_OBSERVABILITY_TOKEN" \
    --environment defenseclaw-run-test \
    -- exec --skip-git-repo-check --json "Reply with ok only"

  defenseclaw-agent-otel run \
    --tool claude \
    --splunk-host us1 \
    --token "$SPLUNK_OBSERVABILITY_TOKEN" \
    --claude-agent-name claude-desktop \
    -- -p --model haiku --output-format json "Reply with ok only"`,
		Args: cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateToolValue(opts.Tool); err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(opts.Tool)) {
			case agentotel.ToolClaude, agentotel.ToolCodex:
				return nil
			default:
				return fmt.Errorf("run requires --tool %q or %q", agentotel.ToolClaude, agentotel.ToolCodex)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return agentotel.Run(context.Background(), opts, args)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Tool, "tool", "", "Tool to run: claude or codex")
	f.StringVar(&opts.Binary, "binary", "", "Optional path to the claude/codex binary; defaults to the tool name")
	f.StringVar(&opts.Endpoint, "endpoint", "", "Base OTLP/HTTP endpoint, for example http://collector:4318")
	f.StringVar(&opts.Token, "token", "", "Auth token for direct OTLP export (or set OTLP_AUTH_TOKEN / SPLUNK_OBSERVABILITY_TOKEN)")
	f.StringVar(&opts.DeprecatedSplunkToken, "splunk-token", "", "Deprecated alias for --token")
	_ = f.MarkDeprecated("splunk-token", "use --token instead")
	f.StringVar(&opts.HeaderName, "header-name", "", "HTTP header name for direct auth; defaults to Authorization or X-SF-Token")
	f.StringVar(&opts.HeaderPrefix, "header-prefix", "", "Prefix added before --token, for example 'Bearer '")
	f.StringVar(&opts.SplunkHost, "splunk-host", "", "Splunk Observability host or realm for direct Splunk mode")
	f.StringVar(&opts.TenantID, "tenant-id", "", "Tenant identifier for resource attributes where supported")
	f.StringVar(&opts.WorkspaceID, "workspace-id", "", "Workspace identifier for resource attributes where supported")
	f.StringVar(&opts.AgentName, "agent-name", "", "Logical agent name for resource attributes where supported")
	f.StringVar(&opts.Environment, "environment", "dev", "Environment tag")
	f.StringVar(&opts.ClaudeTenantID, "claude-tenant-id", "", "Claude-specific tenant identifier override")
	f.StringVar(&opts.ClaudeWorkspaceID, "claude-workspace-id", "", "Claude-specific workspace identifier override")
	f.StringVar(&opts.ClaudeAgentName, "claude-agent-name", "", "Claude-specific agent name override")
	f.StringVar(&opts.ClaudeEnvironment, "claude-environment", "", "Claude-specific environment override")
	f.StringVar(&opts.CodexTenantID, "codex-tenant-id", "", "Codex-specific tenant identifier override")
	f.StringVar(&opts.CodexWorkspaceID, "codex-workspace-id", "", "Codex-specific workspace identifier override")
	f.StringVar(&opts.CodexAgentName, "codex-agent-name", "", "Codex-specific agent name override")
	f.StringVar(&opts.CodexEnvironment, "codex-environment", "", "Codex-specific environment override")
	return cmd
}

func unconfigureCmd() *cobra.Command {
	var tool string
	cmd := &cobra.Command{
		Use:   "unconfigure",
		Short: "Remove OTLP configuration previously written by configure",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateToolValue(tool)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return agentotel.Unconfigure(tool)
		},
	}
	cmd.Flags().StringVar(&tool, "tool", agentotel.ToolAll, "Tool to unconfigure: claude, codex, or all")
	return cmd
}

func validateToolValue(tool string) error {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "", agentotel.ToolAll, agentotel.ToolClaude, agentotel.ToolCodex:
		return nil
	default:
		return fmt.Errorf("unsupported --tool %q: expected %q, %q, or %q", tool, agentotel.ToolClaude, agentotel.ToolCodex, agentotel.ToolAll)
	}
}
