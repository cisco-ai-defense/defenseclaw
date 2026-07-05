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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const (
	gatewayStatusLabelWidth       = 14
	gatewayHealthDocumentMaxBytes = 1 << 20
)

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

func gatewayBindHost(c *config.Config) string {
	if c == nil {
		c = config.DefaultConfig()
	}
	bind := "127.0.0.1"
	if c.Gateway.APIBind != "" {
		bind = c.Gateway.APIBind
	} else if c.OpenShell.IsStandalone() && c.Guardrail.Host != "" && c.Guardrail.Host != "localhost" {
		bind = c.Guardrail.Host
	}
	return bind
}

func sidecarHealthURL(c *config.Config) string {
	if c == nil {
		c = config.DefaultConfig()
	}
	return "http://" + net.JoinHostPort(gatewayClientHost(c), strconv.Itoa(c.Gateway.APIPort)) + "/health"
}

func gatewayClientHost(c *config.Config) string {
	bind := strings.Trim(strings.TrimSpace(gatewayBindHost(c)), "[]")
	switch bind {
	case "", "*", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	default:
		return bind
	}
}

func sidecarStatusURL(c *config.Config) string {
	if c == nil {
		c = config.DefaultConfig()
	}
	return "http://" + net.JoinHostPort(gatewayClientHost(c), strconv.Itoa(c.Gateway.APIPort)) + "/status"
}

// fetchSidecarHealth reads one complete, bounded health document. Keeping the
// byte bound here protects both status and daemon-readiness callers from an
// unbounded local response without truncating valid multi-connector JSON before
// it is parsed.
func fetchSidecarHealth(client *http.Client, addr string) (gateway.HealthSnapshot, error) {
	var snap gateway.HealthSnapshot
	resp, err := client.Get(addr)
	if err != nil {
		return snap, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return snap, fmt.Errorf("health endpoint returned %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, gatewayHealthDocumentMaxBytes+1))
	if err != nil {
		return snap, fmt.Errorf("read response: %w", err)
	}
	if len(body) > gatewayHealthDocumentMaxBytes {
		return snap, fmt.Errorf("health response exceeds %d bytes", gatewayHealthDocumentMaxBytes)
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		return snap, fmt.Errorf("parse response: %w", err)
	}
	return snap, nil
}

func runSidecarStatus(_ *cobra.Command, _ []string) error {
	addr := sidecarHealthURL(cfg)

	client := &http.Client{Timeout: 5 * time.Second}
	snap, err := fetchSidecarHealth(client, addr)
	if err != nil {
		var requestErr *url.Error
		if errors.As(err, &requestErr) {
			fmt.Println()
			Warn("Sidecar Status: NOT RUNNING")
			printGatewayKV("Endpoint", addr)
			Subhead("Start the sidecar with: defenseclaw-gateway start")
			return fmt.Errorf("sidecar unreachable")
		}
		return fmt.Errorf("sidecar status: %w", err)
	}

	uptime := time.Duration(snap.UptimeMs) * time.Millisecond

	printGatewayStatusBanner()
	printGatewayKV("Started", snap.StartedAt.Format(time.RFC3339))
	printGatewayKV("Uptime", formatDuration(uptime))
	fmt.Println()

	bind := gatewayBindHost(cfg)
	if modes := fetchConnectorModes(client, bind, cfg.Gateway.APIPort); len(modes) > 0 {
		printConnectorModes(modes)
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

	printConnectors(&snap)
	if isLocalStatusTarget(bind) {
		printHookGuardianStatus()
	}

	return nil
}

func isLocalStatusTarget(host string) bool {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if hostname, err := os.Hostname(); err == nil && strings.EqualFold(host, hostname) {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	for _, addr := range addrs {
		switch local := addr.(type) {
		case *net.IPNet:
			if local.IP.Equal(ip) {
				return true
			}
		case *net.IPAddr:
			if local.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// printConnectors renders the active-connector roster. The HealthSnapshot
// carries every active connector in Connectors; Connector is retained only
// as a back-compat pointer for older sidecars that populated the singular
// field. The roster is rendered the SAME way regardless of how many
// connectors are active — one connector and N connectors share an identical
// "Agents: N active" header and per-connector body — so operators never have
// to reason about a "single vs multi" distinction. Each connector lists its
// own live counters, keeping the Agent view consistent with the Guardrail
// "N active" summary instead of showing only an arbitrary primary.
func printConnectors(snap *gateway.HealthSnapshot) {
	conns := snap.Connectors
	// Back-compat: older sidecars only populate the singular Connector
	// pointer. Promote it into the roster so the rendering path is
	// count-agnostic and identical regardless of which field was filled.
	if len(conns) == 0 && snap.Connector != nil {
		conns = []gateway.ConnectorHealth{*snap.Connector}
	}

	if len(conns) == 0 {
		printGatewayKV("Agents", Dim("(no active connector)"))
		fmt.Println()
		return
	}

	printGatewayKV("Agents", fmt.Sprintf("%d active", len(conns)))
	for i := range conns {
		c := conns[i]
		stateStr := strings.ToUpper(string(c.State))
		header := fmt.Sprintf("%s (%s)%s",
			friendlyConnectorName(c.Name), c.Name, styledConnectorStateVerb(stateStr))
		fmt.Printf("             %s\n", header)
		printConnectorBody(&c)
	}
	fmt.Println()
}

// printConnectorBody renders the per-connector since/mode/counter lines
// under each "Agents:" roster entry.
func printConnectorBody(c *gateway.ConnectorHealth) {
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
}

type hookGuardianStatus struct {
	Configured   bool                       `json:"-"`
	StateFile    string                     `json:"state_file,omitempty"`
	OK           bool                       `json:"ok"`
	UpdatedAt    string                     `json:"updated_at,omitempty"`
	Manifest     string                     `json:"manifest,omitempty"`
	TargetCount  int                        `json:"target_count,omitempty"`
	SuccessCount int                        `json:"success_count,omitempty"`
	FailureCount int                        `json:"failure_count,omitempty"`
	Results      []hookGuardianStatusResult `json:"results,omitempty"`
}

type hookGuardianStatusResult struct {
	User      string `json:"user,omitempty"`
	UserHome  string `json:"user_home,omitempty"`
	Connector string `json:"connector,omitempty"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

func loadHookGuardianStatus() hookGuardianStatus {
	state := hookGuardianStatus{}
	if cfg == nil || strings.TrimSpace(cfg.DataDir) == "" {
		state.StateFile = "hook_guardian_state.json"
		return state
	}
	state.StateFile = filepath.Join(cfg.DataDir, "hook_guardian_state.json")
	data, err := os.ReadFile(state.StateFile)
	if err != nil {
		return state
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return hookGuardianStatus{StateFile: state.StateFile}
	}
	state.Configured = true
	if state.TargetCount == 0 {
		state.TargetCount = len(state.Results)
	}
	if state.SuccessCount == 0 {
		for _, row := range state.Results {
			if row.OK {
				state.SuccessCount++
			}
		}
	}
	if state.FailureCount == 0 && state.TargetCount >= state.SuccessCount {
		state.FailureCount = state.TargetCount - state.SuccessCount
	}
	return state
}

func printHookGuardianStatus() {
	state := loadHookGuardianStatus()
	managed := cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.DeploymentMode), "managed_enterprise")
	if !managed && !state.Configured {
		return
	}

	if !state.Configured {
		printGatewayKV("Hook guardian", Style("not reconciled", "fg=yellow"))
		fmt.Printf("                %s\n\n", Dim("(no hook_guardian_state.json yet)"))
		return
	}

	statusText := Style("healthy", "fg=green")
	if !state.OK {
		statusText = Style("attention", "fg=yellow")
	}
	statusText += Dim(fmt.Sprintf(" (%d/%d targets ok)", state.SuccessCount, state.TargetCount))
	if state.FailureCount > 0 {
		statusText += Dim(fmt.Sprintf(", %d failed", state.FailureCount))
	}
	printGatewayKV("Hook guardian", statusText)

	var details []string
	if state.UpdatedAt != "" {
		details = append(details, "last run: "+state.UpdatedAt)
	}
	if state.Manifest != "" {
		details = append(details, "manifest: "+state.Manifest)
	}
	if len(details) > 0 {
		fmt.Printf("                %s\n", Dim(strings.Join(details, "  ")))
	}
	for i, row := range state.Results {
		if i >= 8 {
			break
		}
		conn := strings.TrimSpace(row.Connector)
		label := fmt.Sprintf("%s (%s)", friendlyConnectorName(conn), conn)
		if user := strings.TrimSpace(row.User); user != "" {
			label += " for " + user
		} else if home := strings.TrimSpace(row.UserHome); home != "" {
			label += " for " + home
		}
		if row.OK {
			fmt.Printf("                  %s — ok\n", label)
		} else {
			errText := row.Error
			if errText == "" {
				errText = "failed"
			}
			fmt.Printf("                  %s — %s\n", label, Style(errText, "fg=yellow"))
		}
	}
	fmt.Println()
}

// friendlyConnectorName renders a human-friendly connector label for the
// CLI text output. The table is kept in sync with the Python CLI's
// _FRIENDLY_CONNECTOR_NAMES (cli/defenseclaw/commands/cmd_status.py) so the
// Go gateway status and the Python `defenseclaw status` agree on every
// connector's display name instead of title-casing the raw id (e.g.
// "geminicli" -> "Gemini CLI", not "Geminicli"). Duplicated rather than
// shared to avoid pulling the TUI/Bubble Tea graph into the CLI binary.
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
	case "hermes":
		return "Hermes"
	case "cursor":
		return "Cursor"
	case "windsurf":
		return "Windsurf"
	case "geminicli":
		return "Gemini CLI"
	case "copilot":
		return "GitHub Copilot CLI"
	case "openhands":
		return "OpenHands"
	case "antigravity":
		return "Antigravity"
	case "omnigent":
		return "OmniGent"
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
	Connector          string   `json:"connector"`
	Mode               string   `json:"mode"`
	PolicyMode         string   `json:"policy_mode"`
	EnforcementSurface string   `json:"enforcement_surface"`
	Telemetry          []string `json:"telemetry"`
	ProxyIntercept     bool     `json:"proxy_intercept"`
	GuardrailMode      string   `json:"guardrail_mode"`
	HookEnforcement    bool     `json:"hook_enforcement"`
}

// fetchConnectorModes returns one mode summary per active connector. It
// prefers the gateway's plural connector_modes roster (every active
// connector) and falls back to the singular connector_mode field for older
// sidecars that predate the roster — so a single-connector install and an
// N-connector install both yield a non-empty slice rendered the same way.
func fetchConnectorModes(client *http.Client, bind string, port int) []connectorModeSummary {
	addr := fmt.Sprintf("http://%s:%d/status", bind, port)
	req, err := http.NewRequest(http.MethodGet, addr, nil)
	if err != nil {
		return nil
	}
	// ("Connector mode status fetch omits required
	// API token"): /status sits behind tokenAuth, which only
	// exempts GET /health. The previous client.Get call sent no
	// auth headers and silently swallowed the resulting 401, so
	// the CLI status command always omitted the connector_mode
	// section against a normally-configured sidecar. Attach the
	// resolved gateway token (under both the bearer and the
	// X-DefenseClaw-Token aliases for compatibility); when the
	// token cannot be resolved, fall back to the previous
	// best-effort behaviour rather than error out -- the rest of
	// `defenseclaw status` is still useful without this section.
	if cfg != nil {
		if token := strings.TrimSpace(cfg.Gateway.ResolvedToken()); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-DefenseClaw-Token", token)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var envelope struct {
		ConnectorMode  *connectorModeSummary  `json:"connector_mode"`
		ConnectorModes []connectorModeSummary `json:"connector_modes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil
	}
	if len(envelope.ConnectorModes) > 0 {
		return envelope.ConnectorModes
	}
	if envelope.ConnectorMode != nil {
		return []connectorModeSummary{*envelope.ConnectorMode}
	}
	return nil
}

// printConnectorModes renders the "Connector Mode" section for EVERY active
// connector. One connector and N connectors share the identical per-entry
// layout (the section header appears once), so operators never reason about
// a "single vs multi" distinction — mirroring the "Agents" roster above.
func printConnectorModes(modes []connectorModeSummary) {
	Section("Connector Mode")
	for i := range modes {
		if i > 0 {
			fmt.Println()
		}
		printConnectorModeEntry(&modes[i])
	}
	fmt.Println()
}

func printConnectorModeEntry(m *connectorModeSummary) {
	modeLabel := Style(fmt.Sprintf("%-18s", "Connector:"), "fg=bright_black", "bold")
	connectorName := m.Connector
	if connectorName != "" {
		connectorName = fmt.Sprintf("%s (%s)", friendlyConnectorName(m.Connector), m.Connector)
	}
	fmt.Printf("    %s%s\n", modeLabel, connectorName)
	dataPath := m.Mode
	if m.Mode == "observability" {
		dataPath = "direct-to-upstream"
	} else if m.Mode == "guardrail" {
		dataPath = "DefenseClaw proxy"
	}
	dataPathLine := Style(fmt.Sprintf("%-18s", "Data path:"), "fg=bright_black", "bold")
	fmt.Printf("    %s%s\n", dataPathLine, dataPath)
	if m.PolicyMode != "" {
		policyLine := Style(fmt.Sprintf("%-18s", "Policy mode:"), "fg=bright_black", "bold")
		fmt.Printf("    %s%s\n", policyLine, m.PolicyMode)
	}
	if m.EnforcementSurface != "" {
		surface := strings.ReplaceAll(m.EnforcementSurface, "_", " ")
		surfaceLine := Style(fmt.Sprintf("%-18s", "Enforcement:"), "fg=bright_black", "bold")
		fmt.Printf("    %s%s\n", surfaceLine, surface)
	}
	if len(m.Telemetry) > 0 {
		telLabel := Style(fmt.Sprintf("%-18s", "Telemetry:"), "fg=bright_black", "bold")
		fmt.Printf("    %s%s\n", telLabel, strings.Join(m.Telemetry, ", "))
	}
	if m.GuardrailMode != "" {
		modeLabel := Style(fmt.Sprintf("%-18s", "Guardrail mode:"), "fg=bright_black", "bold")
		fmt.Printf("    %s%s\n", modeLabel, m.GuardrailMode)
	}
	if !m.ProxyIntercept {
		hookLabel := Style(fmt.Sprintf("%-18s", "Hook enforcement:"), "fg=bright_black", "bold")
		hookState := "no"
		if m.HookEnforcement {
			hookState = "yes (action-mode hooks can block)"
		}
		fmt.Printf("    %s%s\n", hookLabel, hookState)
	}
	intercept := "no (traffic flows directly to upstream)"
	if m.ProxyIntercept {
		intercept = "yes (proxy in data path)"
	}
	pxLabel := Style(fmt.Sprintf("%-18s", "Proxy intercept:"), "fg=bright_black", "bold")
	fmt.Printf("    %s%s\n", pxLabel, intercept)
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
		// Slices/maps (e.g. Guardrail's "connectors" roster or the
		// per-sink array) are intentionally not rendered here: the
		// authoritative per-connector enumeration lives in the "Agents"
		// section, so re-listing names in every subsystem would just
		// duplicate it. Subsystems convey multi-connector state via a
		// count/scope detail instead.
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
