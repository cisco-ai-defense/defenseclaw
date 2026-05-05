// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Gateway status command output — layout and colors mirror
// cli/defenseclaw/commands/cmd_status.py where applicable.

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const gatewayStatusLabelWidth = 14

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show health of the running sidecar's subsystems",
	Long: `Query the sidecar's REST API to display the health of all three subsystems:
gateway connection, skill watcher, and API server.

The sidecar must be running for this command to work.`,
	RunE: runSidecarStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func printGatewayStatusBanner() {
	fmt.Println()
	title := "DefenseClaw Gateway Status"
	fmt.Println("  " + Style(title, "fg=cyan", "bold"))
	under := strings.Repeat("═", utf8.RuneCountInString(title))
	fmt.Println("  " + Style(under, "fg=cyan"))
}

func printGatewayKV(key, value string) {
	label := fmt.Sprintf("%-*s", gatewayStatusLabelWidth, key+":")
	rendered := value
	if rendered == "" {
		rendered = Dim("—")
	}
	fmt.Printf("  %s%s\n", Style(label, "fg=bright_black", "bold"), rendered)
}

func styledSubsystemState(state gateway.SubsystemState) string {
	s := strings.ToUpper(string(state))
	switch state {
	case gateway.StateRunning:
		return Style(s, "fg=green")
	case gateway.StateDisabled:
		return Style(s, "fg=bright_black")
	default:
		return Style(s, "fg=yellow")
	}
}

func styledConnectorStateVerb(state string) string {
	u := strings.ToUpper(strings.TrimSpace(state))
	if u == "" {
		return ""
	}
	switch u {
	case "RUNNING", "ACTIVE", "READY", "UP":
		return " — " + Style(u, "fg=green")
	default:
		return " — " + Style(u, "fg=yellow")
	}
}

func runSidecarStatus(_ *cobra.Command, _ []string) error {
	bind := "127.0.0.1"
	if cfg.Gateway.APIBind != "" {
		bind = cfg.Gateway.APIBind
	} else if cfg.OpenShell.IsStandalone() && cfg.Guardrail.Host != "" && cfg.Guardrail.Host != "localhost" {
		bind = cfg.Guardrail.Host
	}
	addr := fmt.Sprintf("http://%s:%d/health", bind, cfg.Gateway.APIPort)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(addr)
	if err != nil {
		fmt.Println()
		Warn("Sidecar Status: NOT RUNNING")
		printGatewayKV("Endpoint", addr)
		Subhead("Start the sidecar with: defenseclaw-gateway start")
		return fmt.Errorf("sidecar unreachable")
	}
	defer resp.Body.Close()

	var snap gateway.HealthSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return fmt.Errorf("sidecar status: parse response: %w", err)
	}

	uptime := time.Duration(snap.UptimeMs) * time.Millisecond

	printGatewayStatusBanner()
	printGatewayKV("Started", snap.StartedAt.Format(time.RFC3339))
	printGatewayKV("Uptime", formatDuration(uptime))
	fmt.Println()

	if mode := fetchConnectorMode(client, bind, cfg.Gateway.APIPort); mode != nil {
		printConnectorMode(mode)
	}

	Section("Subsystems")
	printSubsystem("Gateway", snap.Gateway)
	printSubsystem("Watcher", snap.Watcher)
	printSubsystem("API", snap.API)
	printSubsystem("Guardrail", snap.Guardrail)
	printSubsystem("Telemetry", snap.Telemetry)
	printSubsystem("Sinks", snap.Sinks)
	if snap.Sandbox != nil {
		printSubsystem("Sandbox", *snap.Sandbox)
	}

	printConnector(snap.Connector)

	return nil
}

func printConnector(c *gateway.ConnectorHealth) {
	if c == nil {
		printGatewayKV("Agent", Dim("(no active connector)"))
		fmt.Println()
		return
	}

	stateStr := strings.ToUpper(string(c.State))
	line := fmt.Sprintf("%s (%s)%s", friendlyConnectorName(c.Name), c.Name, styledConnectorStateVerb(stateStr))
	printGatewayKV("Agent", line)

	if !c.Since.IsZero() {
		fmt.Printf("             %s%s\n", Dim("since "), c.Since.Format(time.RFC3339))
	}
	if c.ToolInspectionMode != "" || c.SubprocessPolicy != "" {
		fmt.Printf("                %s %s    %s %s\n",
			Dim("tool inspection:"), defaultStr(string(c.ToolInspectionMode), "n/a"),
			Dim("subprocess:"), defaultStr(string(c.SubprocessPolicy), "n/a"))
	}

	reqs := c.Requests
	errs := c.Errors
	insp := c.ToolInspections
	tb := c.ToolBlocks
	sb := c.SubprocessBlocks

	errPart := Dim(fmt.Sprintf("errors: %d", errs))
	if errs != 0 {
		errPart = Style(fmt.Sprintf("errors: %d", errs), "fg=red", "bold")
	}
	toolBlk := Dim(fmt.Sprintf("tool blocks: %d", tb))
	if tb != 0 {
		toolBlk = Style(fmt.Sprintf("tool blocks: %d", tb), "fg=yellow")
	}
	subBlk := Dim(fmt.Sprintf("subprocess blocks: %d", sb))
	if sb != 0 {
		subBlk = Style(fmt.Sprintf("subprocess blocks: %d", sb), "fg=yellow")
	}
	fmt.Printf("                %s  %s  %s  %s  %s\n",
		Dim(fmt.Sprintf("requests: %d", reqs)),
		errPart,
		Dim(fmt.Sprintf("tool inspections: %d", insp)),
		toolBlk,
		subBlk)
	fmt.Println()
}

// friendlyConnectorName mirrors internal/tui/connector_label.go::FriendlyConnectorName
// for the CLI text output. Kept duplicated to avoid pulling the TUI
// package (and Bubble Tea) into the CLI binary import graph.
func friendlyConnectorName(name string) string {
	switch strings.TrimSpace(name) {
	case "", "openclaw":
		return "OpenClaw"
	case "zeptoclaw":
		return "ZeptoClaw"
	case "claudecode":
		return "Claude Code"
	case "codex":
		return "Codex"
	default:
		s := strings.TrimSpace(name)
		if s == "" {
			return name
		}
		return strings.ToUpper(s[:1]) + s[1:]
	}
}

func defaultStr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

type connectorModeSummary struct {
	Connector      string   `json:"connector"`
	Mode           string   `json:"mode"`
	Telemetry      []string `json:"telemetry"`
	ProxyIntercept bool     `json:"proxy_intercept"`
}

func fetchConnectorMode(client *http.Client, bind string, port int) *connectorModeSummary {
	addr := fmt.Sprintf("http://%s:%d/status", bind, port)
	resp, err := client.Get(addr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var envelope struct {
		ConnectorMode *connectorModeSummary `json:"connector_mode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil
	}
	return envelope.ConnectorMode
}

func printConnectorMode(m *connectorModeSummary) {
	Section("Connector Mode")
	modeLabel := Style(fmt.Sprintf("%-18s", "Connector:"), "fg=bright_black", "bold")
	fmt.Printf("    %s%s\n", modeLabel, m.Connector)
	modeLine := Style(fmt.Sprintf("%-18s", "Mode:"), "fg=bright_black", "bold")
	fmt.Printf("    %s%s\n", modeLine, m.Mode)
	if len(m.Telemetry) > 0 {
		telLabel := Style(fmt.Sprintf("%-18s", "Telemetry:"), "fg=bright_black", "bold")
		fmt.Printf("    %s%s\n", telLabel, strings.Join(m.Telemetry, ", "))
	}
	intercept := "no (traffic flows directly to upstream)"
	if m.ProxyIntercept {
		intercept = "yes (proxy in data path)"
	}
	pxLabel := Style(fmt.Sprintf("%-18s", "Proxy intercept:"), "fg=bright_black", "bold")
	fmt.Printf("    %s%s\n", pxLabel, intercept)
	fmt.Println()
}

func printSubsystem(name string, h gateway.SubsystemHealth) {
	label := fmt.Sprintf("%-*s", 10, name+":")
	fmt.Printf("  %s%s", Style(label, "fg=bright_black", "bold"), styledSubsystemState(h.State))
	if !h.Since.IsZero() {
		fmt.Printf("%s%s%s", Dim(" (since "), h.Since.Format(time.RFC3339), Dim(")"))
	}
	fmt.Println()

	if h.LastError != "" {
		fmt.Printf("             %s %s\n", Dim("last error:"), h.LastError)
	}
	if len(h.Details) > 0 {
		keys := make([]string, 0, len(h.Details))
		for k := range h.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token") {
				continue
			}
			line, ok := formatDetailValue(h.Details[k])
			if !ok {
				continue
			}
			fmt.Printf("             %s %s\n", Dim(k+":"), line)
		}
	}
	fmt.Println()
}

func formatDetailValue(v interface{}) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case bool:
		return fmt.Sprintf("%t", val), true
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val)), true
		}
		return fmt.Sprintf("%g", val), true
	case int, int32, int64:
		return fmt.Sprintf("%d", val), true
	case fmt.Stringer:
		return val.String(), true
	case nil:
		return "", false
	default:
		return "", false
	}
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}
