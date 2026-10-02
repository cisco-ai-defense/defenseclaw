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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
	// Status only needs the strict runtime config to locate the health API.
	// Do not inherit root's audit-store lifecycle: a second short-lived Store
	// can unlink the running daemon's WAL/SHM and strand later audit writes.
	// On a standalone managed host an administrator's status reads the
	// managed deployment without extra environment variables.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		applyManagedStandaloneAdminEnv(cmd.ErrOrStderr())
		gatewayStatusConfigProblem = nil
		err := loadGatewayCommandConfigFor(cmd)
		if relaxed := gatewayStatusRelaxedConfig(err); relaxed != nil {
			// GAP-1788: a missing destination secret does not hide the
			// running gateway; show its status, then the config problem.
			cfg = relaxed
			gatewayStatusConfigProblem = gatewayStatusConfigLoadError(err)
			return nil
		}
		return gatewayStatusConfigLoadError(err)
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := runSidecarStatus(cmd, args)
		if gatewayStatusConfigProblem != nil {
			return gatewayStatusConfigProblem
		}
		return err
	},
}

// gatewayStatusConfigProblem is the config.yaml error that status reports
// after the gateway's health when only a destination secret is missing.
var gatewayStatusConfigProblem error

// gatewayStatusRelaxedConfig loads config.yaml without compiling the
// observability destinations when err is only a missing destination secret,
// so status can still find and query the gateway. It returns nil otherwise.
func gatewayStatusRelaxedConfig(err error) *config.Config {
	var secretErr *config.V8SecretReferenceError
	if err == nil || !errors.As(err, &secretErr) || secretErr.Credential {
		return nil
	}
	path := config.ConfigPath()
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil
	}
	relaxed, loadErr := config.LoadRuntimeV8FromBytes(path, raw)
	if loadErr != nil {
		return nil
	}
	return relaxed
}

// gatewayStatusJSON selects the machine-readable status (GAP-1609).
var gatewayStatusJSON bool

func init() {
	statusCmd.Flags().BoolVar(&gatewayStatusJSON, "json", false, "Print the gateway health as JSON")
	rootCmd.AddCommand(statusCmd)
}

// gatewayStatusDocument is the --json form of gateway status: the /health
// snapshot when the gateway answers, otherwise why not and the next step.
type gatewayStatusDocument struct {
	Running  bool                    `json:"running"`
	Endpoint string                  `json:"endpoint"`
	Health   *gateway.HealthSnapshot `json:"health,omitempty"`
	Error    string                  `json:"error,omitempty"`
	Hint     string                  `json:"hint,omitempty"`
}

func runSidecarStatusJSON(w io.Writer) error {
	addr := sidecarHealthURL(cfg)
	doc := gatewayStatusDocument{Endpoint: addr}
	var failure error
	if problem := foreignGatewayListener(cfg); problem != "" {
		doc.Error = problem
		doc.Hint = foreignGatewayListenerFix(cfg)
		failure = errors.New("the gateway port is held by another process")
	} else if snap, err := fetchSidecarHealth(&http.Client{Timeout: 5 * time.Second}, addr); err != nil {
		doc.Error = err.Error()
		doc.Hint = sidecarNotRunningHint(cfg)
		failure = errors.New("sidecar unreachable")
		if running, pid := gatewayManagedState(); running && cfg != nil && !cfg.StandaloneEnterprise() {
			doc.Hint = fmt.Sprintf("The gateway process (PID %d) is running but does not answer /health. "+
				"Restart it with: defenseclaw-gateway restart", pid)
			failure = errors.New("sidecar not answering")
		}
	} else {
		doc.Running = true
		doc.Health = &snap
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return err
	}
	return failure
}

// gatewayStatusConfigLoadError adds the daemon state and the next step when
// config.yaml does not load: a running gateway keeps enforcing the config it
// started with, and start/restart already name the same repair (GAP-1431).
func gatewayStatusConfigLoadError(err error) error {
	if err == nil || !strings.HasPrefix(err.Error(), "failed to load config:") {
		return err
	}
	state := "The gateway is not running."
	if running, pid := daemon.New(config.DefaultDataPath()).IsRunning(); running {
		state = fmt.Sprintf("The gateway (PID %d) is still running with the config it started with.", pid)
	}
	if message, empty := emptyConfigFileMessage(config.ConfigPath()); empty {
		return fmt.Errorf("%s %s", message, state)
	}
	var secretErr *config.V8SecretReferenceError
	if errors.As(err, &secretErr) && !secretErr.Credential {
		// Same next step start and restart print (GAP-1353).
		// `setup <destination> disable` validates the whole file too, so
		// name the edit that works (GAP-1788).
		dest := "that destination"
		if secretErr.Destination != "" {
			dest = fmt.Sprintf("destination %q", secretErr.Destination)
		}
		return fmt.Errorf("%w. %s Set it with: defenseclaw keys set %s (or remove %s from %s), "+
			"then run: defenseclaw-gateway restart", err, state, secretErr.Reference, dest, config.ConfigPath())
	}
	return fmt.Errorf("%w. %s Fix the file (check it with: defenseclaw config validate)", err, state)
}

func printGatewayStatusBanner() {
	fmt.Println()
	title := "DefenseClaw Gateway Status"
	fmt.Println("  " + Style(title, "fg=cyan", "bold"))
	under := strings.Repeat(glyph("═", "="), utf8.RuneCountInString(title))
	fmt.Println("  " + Style(under, "fg=cyan"))
}

func printGatewayKV(key, value string) {
	label := fmt.Sprintf("%-*s", gatewayStatusLabelWidth, key+":")
	rendered := value
	if rendered == "" {
		rendered = Dim(glyph("—", "-"))
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
		return " " + glyph("—", "-") + " " + Style(u, "fg=green")
	default:
		return " " + glyph("—", "-") + " " + Style(u, "fg=yellow")
	}
}

func gatewayBindHost(c *config.Config) string {
	if c == nil {
		c = config.DefaultConfig()
	}
	return config.APIBindHost(c)
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
		if ip := net.ParseIP(bind); ip != nil && ip.IsUnspecified() {
			if ip.To4() != nil {
				return "127.0.0.1"
			}
			return "::1"
		}
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
	if gatewayStatusJSON {
		return runSidecarStatusJSON(os.Stdout)
	}
	addr := sidecarHealthURL(cfg)
	// /health is public: any process on the port answers it. Never present
	// another home's or account's gateway as this one.
	if problem := foreignGatewayListener(cfg); problem != "" {
		fmt.Println()
		Warn("Sidecar Status: NOT THIS ACCOUNT'S GATEWAY")
		printGatewayKV("Endpoint", addr)
		Subhead(problem + ". Its status is not shown.")
		Subhead(foreignGatewayListenerFix(cfg))
		return fmt.Errorf("the gateway port is held by another process")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	snap, err := fetchSidecarHealth(client, addr)
	if err != nil {
		var requestErr *url.Error
		if errors.As(err, &requestErr) {
			if running, pid := gatewayManagedState(); running && cfg != nil && !cfg.StandaloneEnterprise() {
				// A live but hung gateway (GAP-1342): "start" only says it
				// is already running, so name restart here.
				fmt.Println()
				Warn("Sidecar Status: NOT ANSWERING")
				printGatewayKV("Endpoint", addr)
				printGatewayKV("PID", strconv.Itoa(pid))
				Subhead(fmt.Sprintf("The gateway process (PID %d) is running but does not answer /health.", pid))
				Subhead("Restart it with: defenseclaw-gateway restart")
				return fmt.Errorf("sidecar not answering")
			}
			fmt.Println()
			Warn("Sidecar Status: NOT RUNNING")
			printGatewayKV("Endpoint", addr)
			if reason := lastGatewayExitError(cfg); reason != "" {
				printGatewayKV("Last exit", reason)
			}
			Subhead(sidecarNotRunningHint(cfg))
			return fmt.Errorf("sidecar unreachable")
		}
		return fmt.Errorf("sidecar status: %w", err)
	}

	uptime := time.Duration(snap.UptimeMs) * time.Millisecond

	printGatewayStatusBanner()
	printGatewayKV("Started", snap.StartedAt.Format(time.RFC3339))
	printGatewayKV("Uptime", formatDuration(uptime))
	if !cfg.StandaloneEnterprise() && !managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) &&
		gatewayRunsReplacedBinary() {
		Warn("This account's gateway is running a binary that was replaced after it started")
		Subhead("Load the installed one with: defenseclaw-gateway restart")
	}
	fmt.Println()

	bind := gatewayBindHost(cfg)
	if modes := fetchConnectorModes(client, cfg); len(modes) > 0 {
		printConnectorModes(modes)
	}

	printSubsystems(&snap)

	printConnectors(&snap)
	if isLocalStatusTarget(bind) {
		printHookGuardianStatus()
		printMovedCorruptAuditStores(cfg, time.Time{})
	}

	return nil
}

// printMovedCorruptAuditStores tells the operator when the gateway replaced a
// corrupt audit store (moved at or after since); otherwise only the gateway
// log said so and status looked like a healthy, empty history.
func printMovedCorruptAuditStores(cfg *config.Config, since time.Time) {
	if cfg == nil {
		return
	}
	var moved []audit.MovedCorruptStore
	for _, store := range audit.MovedCorruptStores(cfg.AuditDB) {
		if !store.MovedAt.Before(since) {
			moved = append(moved, store)
		}
	}
	if len(moved) == 0 {
		return
	}
	newest := moved[len(moved)-1]
	fmt.Println()
	Warn(fmt.Sprintf("The audit store was corrupt and was moved to %s on %s; a new store was started and the block/allow lists were kept.",
		newest.Path, newest.MovedAt.Local().Format(time.RFC3339)))
	Subhead("Recover older audit records with: sqlite3 " + newest.Path + " .recover")
	Subhead("Delete the moved file and its -wal/-shm files when they are no longer needed.")
}

// lastGatewayExitError returns the error a per-user gateway printed as the
// last line of gateway.log before it exited (for example a refused plugin
// folder or audit store), so a stopped gateway says why it stopped.
func lastGatewayExitError(c *config.Config) string {
	if c == nil || c.StandaloneEnterprise() {
		return ""
	}
	path := filepath.Join(config.DefaultDataPath(), daemon.LogFileName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	const tailBytes = 16 << 10
	if info.Size() > tailBytes {
		if _, err := f.Seek(info.Size()-tailBytes, io.SeekStart); err != nil {
			return ""
		}
	}
	tail, err := io.ReadAll(io.LimitReader(f, tailBytes))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(tail), "\r\n"), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	reason, ok := strings.CutPrefix(last, "Error: ")
	if !ok || !utf8.ValidString(reason) {
		return ""
	}
	if len(reason) > 400 {
		reason = reason[:400] + "..."
	}
	return reason
}

// sidecarNotRunningHint names how to bring the gateway back. The per-user
// gateway is started with `start`; a unix standalone deployment's gateway
// is a system service that `start` refuses to touch.
func sidecarNotRunningHint(c *config.Config) string {
	if c != nil && c.StandaloneEnterprise() && runtime.GOOS != "windows" {
		return "The managed gateway runs as a system service; an administrator can restart it with: " +
			managedHostServiceRestartCommand()
	}
	return "Start the sidecar with: defenseclaw-gateway start"
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

	notStarted := guardrailConnectorsNotStarted(snap.Guardrail.Details)
	if len(conns) == 0 && len(notStarted) == 0 {
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
	// A connector whose setup failed at start is not enforced (GAP-1714).
	for _, name := range notStarted {
		fmt.Printf("             %s (%s)%s\n", friendlyConnectorName(name), name, styledConnectorStateVerb("NOT RUNNING"))
		fmt.Printf("               %s\n", Dim("setup failed when the gateway started, so it is not enforced; "+
			"see gateway.log, then run: defenseclaw-gateway restart"))
	}
	fmt.Println()
}

// guardrailConnectorsNotStarted reads the guardrail's connectors_not_started
// detail, a []string in process and a []interface{} after a JSON round trip.
func guardrailConnectorsNotStarted(details map[string]interface{}) []string {
	var names []string
	switch raw := details["connectors_not_started"].(type) {
	case []string:
		names = append(names, raw...)
	case []interface{}:
		for _, value := range raw {
			if name, ok := value.(string); ok && strings.TrimSpace(name) != "" {
				names = append(names, name)
			}
		}
	}
	return names
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
			fmt.Printf("                  %s %s ok\n", label, glyph("—", "-"))
		} else {
			errText := row.Error
			if errText == "" {
				errText = "failed"
			}
			fmt.Printf("                  %s %s %s\n", label, glyph("—", "-"), Style(errText, "fg=yellow"))
		}
	}
	fmt.Println()
}

// friendlyConnectorName renders a human-friendly connector label for the
// CLI text output. The table is kept in sync with the Python CLI's
// _FRIENDLY_CONNECTOR_NAMES (cli/defenseclaw/commands/cmd_status.py) so the
// Go gateway status and the Python `defenseclaw status` agree on every
// connector's display name instead of title-casing the raw id (e.g.
// "claudecode" -> "Claude Code", not "Claudecode"). Duplicated rather than
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
	case "devin":
		return "Devin"
	case "copilot":
		return "GitHub Copilot CLI"
	case "openhands":
		return "OpenHands"
	case "antigravity":
		return "Antigravity"
	case "opencode":
		return "OpenCode"
	case "amp":
		return "Amp"
	case "omnigent":
		return "OmniGent"
	case "kiro":
		return "Kiro"
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
	// Enabled is the connector's guardrail.connectors.<name>.enabled
	// switch; nil from sidecars that predate the field means enabled.
	Enabled *bool `json:"enabled,omitempty"`
}

// disabled reports a connector the config turned off: it is listed but
// nothing enforces it.
func (m *connectorModeSummary) disabled() bool {
	return m != nil && m.Enabled != nil && !*m.Enabled
}

// fetchConnectorModes returns one mode summary per active connector. It
// prefers the gateway's plural connector_modes roster (every active
// connector) and falls back to the singular connector_mode field for older
// sidecars that predate the roster — so a single-connector install and an
// N-connector install both yield a non-empty slice rendered the same way.
func fetchConnectorModes(client *http.Client, c *config.Config) []connectorModeSummary {
	addr := sidecarStatusURL(c)
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
	if c != nil {
		if token := strings.TrimSpace(c.Gateway.ResolvedToken()); token != "" {
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
	if m.Connector == "" {
		// GAP-1386: no connector configured (init --connector none) used
		// to print a blank "Connector:" value and "Data path: unconfigured".
		fmt.Printf("    %s%s\n", modeLabel, Dim("none (no active connector)"))
		return
	}
	connectorName := fmt.Sprintf("%s (%s)", friendlyConnectorName(m.Connector), m.Connector)
	fmt.Printf("    %s%s\n", modeLabel, connectorName)
	if m.disabled() {
		// A configured but disabled connector has no hooks or proxy in
		// its data path; its policy fields would read as enforced.
		statusLine := Style(fmt.Sprintf("%-18s", "Status:"), "fg=bright_black", "bold")
		fmt.Printf("    %s%s\n", statusLine, Dim("disabled, not enforced"))
		return
	}
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

// printSubsystems renders the Subsystems section. "Gateway" is the OpenClaw
// fleet uplink: when it is disabled and no rostered connector is a proxy
// connector (OpenClaw, ZeptoClaw), nothing uses it, so its DISABLED state and
// OpenClaw upstream advice are left out (the TUI does the same).
func printSubsystems(snap *gateway.HealthSnapshot) {
	Section("Subsystems")
	if !fleetUplinkUnused(snap) {
		printSubsystem("Gateway", snap.Gateway)
	}
	printSubsystem("Watcher", snap.Watcher)
	printSubsystem("API", snap.API)
	printSubsystem("Guardrail", snap.Guardrail)
	printSubsystem("Routing", snap.Routing)
	printSubsystem("Telemetry", snap.Telemetry)
	if snap.Sandbox != nil {
		printSubsystem("Sandbox", *snap.Sandbox)
	}
}

func fleetUplinkUnused(snap *gateway.HealthSnapshot) bool {
	if snap.Gateway.State != gateway.StateDisabled {
		return false
	}
	conns := snap.Connectors
	if len(conns) == 0 && snap.Connector != nil {
		conns = []gateway.ConnectorHealth{*snap.Connector}
	}
	if len(conns) == 0 {
		return false
	}
	for _, c := range conns {
		if connector.IsProxyConnector(c.Name) {
			return false
		}
	}
	return true
}

func printSubsystem(name string, h gateway.SubsystemHealth) {
	// One column wider than the longest label ("Telemetry:"), so the state
	// never runs into it and lines up with the detail rows below.
	label := fmt.Sprintf("%-*s", 11, name+":")
	fmt.Printf("  %s%s", Style(label, "fg=bright_black", "bold"), styledSubsystemState(h.State))
	if !h.Since.IsZero() {
		fmt.Printf("%s%s%s", Dim(" (since "), h.Since.Format(time.RFC3339), Dim(")"))
	}
	fmt.Println()

	if h.LastError != "" {
		fmt.Printf("             %s %s\n", Dim("last error:"), asciiText(h.LastError))
	}
	problem := eventHistoryProblem(h.Details)
	if problem != "" {
		fmt.Printf("             %s %s\n", Dim("problem:"), problem)
	}
	judge := judgeProblem(h.Details)
	if judge != "" {
		fmt.Printf("             %s %s\n", Dim("problem:"), asciiText(judge))
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
			if problem != "" && strings.HasPrefix(k, "event_history_") {
				continue // already said in plain words above
			}
			if judge != "" && strings.HasPrefix(k, "judge_") {
				continue
			}
			line, ok := formatDetailValue(h.Details[k])
			if !ok {
				continue
			}
			fmt.Printf("             %s %s\n", Dim(k+":"), asciiText(line))
		}
	}
	fmt.Println()
}

// eventHistoryProblem says in plain words why audit events cannot be
// written, instead of the raw event_history_* tokens (GAP-1308).
func eventHistoryProblem(details map[string]interface{}) string {
	if failure, _ := details["event_history_failure"].(string); failure != "sqlite_write_failed" {
		return ""
	}
	class, _ := details["event_history_last_sqlite_class"].(string)
	switch class {
	case "full":
		return "audit events cannot be written because the disk holding the audit database is full; " +
			"free space on that disk (the gateway resumes writing once there is room)"
	case "busy_locked":
		return "audit events cannot be written because another process keeps the audit database locked"
	case "readonly_cantopen":
		return "audit events cannot be written because the audit database is read-only or cannot be opened"
	case "constraint_corrupt":
		return "audit events cannot be written because the audit database is damaged; run 'defenseclaw doctor'"
	case "io", "deadline":
		return "audit events cannot be written because reading or writing the audit database failed or timed out " +
			"(another program, such as an antivirus scan, may hold the file); try again in a minute"
	default:
		return "audit events cannot be written to the audit database; run 'defenseclaw doctor'"
	}
}

// judgeProblem says in plain words that recent LLM judge calls failed
// (gateway judge_* details), or returns "". The hook lane then keeps the
// rule verdicts, which used to show nowhere but the gateway log (GAP-1288).
func judgeProblem(details map[string]interface{}) string {
	state, _ := details["judge_state"].(string)
	if state != "failing" && state != "degraded" {
		return ""
	}
	failed, _ := formatDetailValue(details["judge_failed_calls"])
	total, _ := formatDetailValue(details["judge_recent_calls"])
	lastError, _ := details["judge_last_error"].(string)
	lead := "the LLM judge failed " + failed + " of its last " + total + " calls"
	if state == "failing" {
		lead = "the LLM judge failed all of its last " + total + " calls, so only the rules decide"
	}
	if lastError != "" {
		lead += "; last error: " + lastError
	}
	if judgeErrorIsNetwork(lastError) {
		return lead + "; " + judgeNetworkNextStep
	}
	return lead + "; run 'defenseclaw doctor' and 'defenseclaw setup llm --role judge'"
}

// judgeNetworkNextStep is the next step for a judge that cannot reach its
// provider or credential source. Re-running 'setup llm' cannot fix a dead
// proxy or a blocked network (GAP-1669).
const judgeNetworkNextStep = "the judge cannot reach its provider or credential source: check the network and " +
	"the gateway's proxy settings (HTTPS_PROXY, NO_PROXY; an instance role also needs 169.254.169.254 in NO_PROXY), " +
	"then restart the gateway (defenseclaw-gateway restart) and run 'defenseclaw doctor'"

// judgeNetworkErrorMarkers are lower-case fragments of transport and
// credential-fetch failures (Go net errors, proxies, AWS credential chain).
var judgeNetworkErrorMarkers = []string{
	"proxyconnect", "proxy", "connection refused", "connection reset", "no such host",
	"network is unreachable", "i/o timeout", "dial tcp", "tls handshake",
	"failed to retrieve aws credentials", "failed to refresh cached credentials",
	"ec2 imds", "no route to host",
}

// judgeErrorIsNetwork reports whether a judge error is a transport or
// credential-fetch failure rather than a configuration or auth error.
func judgeErrorIsNetwork(lastError string) bool {
	text := strings.ToLower(lastError)
	for _, marker := range judgeNetworkErrorMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
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
