// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// enterpriseDiscoveryReadRecord is replaceable in tests (the spool records
// must be root-owned).
var enterpriseDiscoveryReadRecord = inventory.ReadUserScanRecord

// enterpriseDiscoveryRuntime reads the gateway's runtime discovery snapshot;
// replaceable in tests.
var enterpriseDiscoveryRuntime = fetchEnterpriseDiscoveryRuntime

// newUnixDiscoveryCommand is `enterprise linux|macos discovery`: a read-only
// view of the AI Discovery inventory (agents, skills, MCP servers, plugins,
// running AI processes) the hook guardian's per-user scans recorded for each
// enrolled account, plus the gateway's runtime discovery planes and findings.
// Before it the data was only in root-only JSON, behind the gateway API's
// token or in exported telemetry (GAP-1144).
func newUnixDiscoveryCommand(platform string) *cobra.Command {
	var user string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "discovery",
		Short: "Show AI Discovery per enrolled account and the runtime discovery planes (read-only)",
		Long: `Show the AI Discovery inventory the hook guardian's per-user scans recorded
for each enrolled account: AI agents and apps, skills, MCP servers, plugins
and AI processes that were running at scan time. It reads the guardian's
spool (ai-discovery/ in the authorization ledger) and changes nothing.

It then shows runtime discovery (ai_discovery.runtime): each plane
(inference heartbeat, shadow egress, agent actions) with its state, the
last poll and the scored findings, read from the local gateway. Run as root.

The records exist only while ai_discovery.enabled is true in the deployment
config. Skills and MCP servers are inventoried here; a managed deployment
does not run the skill or MCP scanners.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			goos := platform
			if platform == "macos" {
				goos = "darwin"
			}
			if runtime.GOOS != goos {
				return invalidLifecycleArguments(fmt.Errorf("`enterprise %s discovery` reads %s hosts; this host is %s", platform, goos, runtime.GOOS))
			}
			layout, err := managed.StandaloneLayoutFor(goos)
			if err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			dir := filepath.Join(layout.GuardianAuthDir, inventory.UserScanDirName)
			runtimeCommand = cmd
			if err := writeEnterpriseDiscovery(cmd.OutOrStdout(), dir, user, asJSON); err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "list one account's signals (account name or uid)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print every record as JSON")
	return cmd
}

type enterpriseDiscoveryAccount struct {
	User string `json:"user"`
	// UID is the Linux or macOS account; SID the Windows one.
	UID       *int                 `json:"uid,omitempty"`
	SID       string               `json:"sid,omitempty"`
	UpdatedAt time.Time            `json:"updated_at"`
	Result    string               `json:"result"`
	Signals   []inventory.AISignal `json:"signals"`
}

type enterpriseDiscoveryReport struct {
	// Spool is the guardian's per-user scan records (Linux, macOS);
	// Gateway the gateway whose own scan was read (Windows).
	Spool    string                       `json:"spool,omitempty"`
	Gateway  string                       `json:"gateway,omitempty"`
	Accounts []enterpriseDiscoveryAccount `json:"accounts"`
	Errors   []string                     `json:"errors,omitempty"`
	// Runtime is the gateway's runtime discovery snapshot; RuntimeError
	// says why it could not be read.
	Runtime      *enterpriseRuntimeView `json:"runtime,omitempty"`
	RuntimeError string                 `json:"runtime_error,omitempty"`
}

// enterpriseRuntimeView is the part of GET /api/v1/ai-usage/runtime an
// administrator needs: plane health, the last poll and the findings.
type enterpriseRuntimeView struct {
	Gateway         string                     `json:"gateway"`
	Enabled         bool                       `json:"enabled"`
	ScannedAt       string                     `json:"scanned_at,omitempty"`
	Planes          []enterpriseRuntimePlane   `json:"planes"`
	Findings        []enterpriseRuntimeFinding `json:"findings"`
	Degraded        bool                       `json:"degraded"`
	DegradedReasons []string                   `json:"degraded_reasons,omitempty"`
}

type enterpriseRuntimePlane struct {
	Plane     string `json:"plane"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Running   bool   `json:"running"`
	Mechanism string `json:"mechanism,omitempty"`
	Reason    string `json:"reason,omitempty"`
	// Backend is the kernel event backend of agent actions (plane c) on
	// managed Linux: the host's Tetragon, or cn_proc and fanotify with the
	// reason Tetragon is not used. Other hosts omit it.
	Backend *enterpriseRuntimeBackend `json:"backend,omitempty"`
}

// enterpriseRuntimeBackend is the plane's backend as the runtime API reports
// it.
type enterpriseRuntimeBackend struct {
	Kind           string `json:"kind"`
	Version        string `json:"version,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Socket         string `json:"socket,omitempty"`
	EventsLost     *int64 `json:"events_lost,omitempty"`
	LossKnown      *bool  `json:"loss_known,omitempty"`
	FallbackReason string `json:"fallback_reason,omitempty"`
	Policies       []struct {
		Name  string `json:"name"`
		Mode  string `json:"mode,omitempty"`
		State string `json:"state,omitempty"`
		Error string `json:"error,omitempty"`
	} `json:"policies,omitempty"`
	KernelFloor *struct {
		Mode           string   `json:"mode,omitempty"`
		EnforcedUsers  int      `json:"enforced_users"`
		EnrolledUsers  int      `json:"enrolled_users"`
		BurnInUsers    int      `json:"burn_in_users"`
		PausedUntil    string   `json:"paused_until,omitempty"`
		Approval       string   `json:"approval,omitempty"`
		NextReadyHours *float64 `json:"next_ready_hours,omitempty"`
	} `json:"kernel_floor,omitempty"`
	// CustomerPolicies and CustomerEvents are the customer's own Tetragon
	// policies and their event counts: DefenseClaw reads their events and
	// never changes them.
	CustomerPolicies []struct {
		Name  string `json:"name"`
		Mode  string `json:"mode,omitempty"`
		State string `json:"state,omitempty"`
	} `json:"customer_policies,omitempty"`
	// Attributed are the events the gateway recorded below an AI agent;
	// Capped the ones the helper did not forward over the volume budget.
	CustomerEvents *struct {
		Attributed int64 `json:"attributed"`
		Capped     int64 `json:"capped"`
	} `json:"customer_events,omitempty"`
}

// tetragonFallbackWords say why the native backend runs although Tetragon is
// wanted, in the words of defenseclaw.kernel_sensor.fallback_text.
var tetragonFallbackWords = map[string]string{
	"tetragon_unavailable":         "Tetragon is not running or its info file is missing",
	"tetragon_tcp_api":             "its API listens on TCP instead of a local socket",
	"tetragon_untrusted_endpoint":  "its socket or info file is not owned by root",
	"tetragon_unsupported_version": "this Tetragon version is not supported",
}

func tetragonFallback(reason string) string {
	code, detail, _ := strings.Cut(strings.TrimSpace(reason), ":")
	if words, ok := tetragonFallbackWords[strings.TrimSpace(code)]; ok {
		return words
	}
	text := strings.Join(strings.Fields(defaultStr(strings.TrimSpace(detail), strings.ReplaceAll(code, "_", " "))), " ")
	if len(text) > 80 {
		text = text[:77] + "..."
	}
	return defaultStr(text, "no reason reported")
}

// readyETA is "~9 days" for a number of hours, as the Python shared module
// words it; "" for no estimate.
func readyETA(hours *float64) string {
	switch {
	case hours == nil || *hours <= 0:
		return ""
	case *hours < 1:
		return "~1 hour"
	case *hours < 48:
		if n := int(*hours + 0.5); n != 1 {
			return fmt.Sprintf("~%d hours", n)
		}
		return "~1 hour"
	}
	return fmt.Sprintf("~%d days", int(*hours/24+0.5))
}

func usersNoun(n int) string {
	if n == 1 {
		return "1 user"
	}
	return fmt.Sprintf("%d users", n)
}

// lines are the backend's lines under its plane, in the words of
// `defenseclaw agent discovery runtime status` (defenseclaw.kernel_sensor).
func (b *enterpriseRuntimeBackend) lines() []string {
	if b == nil {
		return nil
	}
	var out []string
	switch {
	case strings.EqualFold(b.Kind, "tetragon"):
		version := strings.TrimSpace(b.Version)
		if version != "" && version[0] >= '0' && version[0] <= '9' {
			version = "v" + version
		}
		parts := []string{strings.TrimSpace("Tetragon " + version)}
		if b.Mode != "" {
			parts = append(parts, b.Mode)
		}
		if (b.LossKnown != nil && !*b.LossKnown) || b.EventsLost == nil {
			parts = append(parts, "events lost unknown")
		} else {
			parts = append(parts, fmt.Sprintf("%d events lost", *b.EventsLost))
		}
		out = append(out, "kernel sensor: "+strings.Join(parts, ", "))
	case b.FallbackReason != "":
		out = append(out, "kernel sensor: cn_proc and fanotify (Tetragon not used: "+tetragonFallback(b.FallbackReason)+")")
	}
	if floor := b.KernelFloor; floor != nil {
		var text string
		switch {
		case !strings.EqualFold(defaultStr(floor.Mode, "monitor"), "enforce"):
			text = "monitoring " + usersNoun(floor.EnrolledUsers) + ", not enforcing"
		case floor.Approval == "missing":
			text = "monitoring " + usersNoun(floor.EnrolledUsers) + "; enforce is not approved yet"
		case floor.Approval == "stale":
			text = "monitoring " + usersNoun(floor.EnrolledUsers) + "; the approval is for another build"
		default:
			text = fmt.Sprintf("enforcing %d of %s", floor.EnforcedUsers, usersNoun(floor.EnrolledUsers))
			if floor.BurnInUsers > 0 {
				text += fmt.Sprintf("; %d in burn-in", floor.BurnInUsers)
				if eta := readyETA(floor.NextReadyHours); eta != "" {
					text += ", next ready " + eta
				}
			}
		}
		if floor.PausedUntil != "" {
			text += "; paused until " + floor.PausedUntil
		}
		out = append(out, "kernel controls: "+text)
	}
	if len(b.CustomerPolicies) > 0 || b.CustomerEvents != nil {
		enforcing := 0
		for _, policy := range b.CustomerPolicies {
			if strings.EqualFold(policy.Mode, "enforce") {
				enforcing++
			}
		}
		text := fmt.Sprintf("%d loaded (%d enforcing)", len(b.CustomerPolicies), enforcing)
		if events := b.CustomerEvents; events != nil {
			noun := "events"
			if events.Attributed == 1 {
				noun = "event"
			}
			text += fmt.Sprintf("; %d agent %s forwarded", events.Attributed, noun)
			if events.Capped > 0 {
				text += fmt.Sprintf(", %d over the budget", events.Capped)
			}
		}
		out = append(out, "your Tetragon policies: "+text+" (DefenseClaw never changes them)")
	}
	return out
}

type enterpriseRuntimeFinding struct {
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	User      string `json:"user,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	Score     int    `json:"score"`
	Severity  string `json:"severity"`
	LastSeen  string `json:"last_seen,omitempty"`
}

// runtimeCommand is the running discovery command, for the config load.
var runtimeCommand *cobra.Command

// enterpriseDiscoveryPinManagedEnv points the gateway reads at the managed
// deployment's config and data dir; replaceable in tests. Without it an
// administrator's shell read its own ~/.defenseclaw/config.yaml and the
// runtime section said to run the command just run (GAP-1144).
var enterpriseDiscoveryPinManagedEnv = pinEnterpriseDiscoveryEnv

// fetchEnterpriseDiscoveryRuntime reads the runtime snapshot from the local
// gateway with the deployment's gateway token, which root can read.
func fetchEnterpriseDiscoveryRuntime() (*enterpriseRuntimeView, error) {
	view := &enterpriseRuntimeView{}
	host, err := enterpriseGatewayGet("/api/v1/ai-usage/runtime", view)
	if err != nil {
		return nil, err
	}
	view.Gateway = host
	return view, nil
}

// enterpriseGatewayGet decodes one GET of the managed deployment's local
// gateway API into out and returns the gateway's host:port.
func enterpriseGatewayGet(path string, out any) (string, error) {
	if err := enterpriseDiscoveryPinManagedEnv(); err != nil {
		return "", err
	}
	if err := loadGatewayCommandConfigFor(runtimeCommand); err != nil {
		return "", err
	}
	host := net.JoinHostPort(gatewayClientHost(cfg), strconv.Itoa(cfg.Gateway.APIPort))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+path, nil)
	if err != nil {
		return "", err
	}
	token := daemonGatewayToken(cfg)
	if token == "" {
		token = strings.TrimSpace(cfg.Gateway.ResolvedToken())
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-DefenseClaw-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("the gateway at %s did not answer; check the deployment with: %s", host, enterpriseDiscoveryStatusHint())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the gateway at %s answered %s", host, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out); err != nil {
		return "", fmt.Errorf("read the gateway's answer to %s: %w", path, err)
	}
	return host, nil
}

// writeManagedViewRefusalJSON gives a --json caller a "code: message"
// refusal with its exit code (elevation_required) as JSON on stdout, in the
// errors[] form `enterprise windows status --json` uses, so a script reads
// the code instead of an empty document (GAP-2114). A managedViewRefusal
// carries its code beside the sentence (GAP-2262).
func writeManagedViewRefusalJSON(w io.Writer, err error) {
	code, message, ok := strings.Cut(err.Error(), ": ")
	if !ok || strings.ContainsAny(code, " \t") {
		code, message = "error", err.Error()
	}
	var refusal *managedViewRefusal
	if errors.As(err, &refusal) {
		code, message = refusal.code, refusal.message
	}
	_ = newEnterpriseJSONEncoder(w).Encode(struct {
		OK       bool                       `json:"ok"`
		Errors   []enterprisestatus.Message `json:"errors"`
		ExitCode int                        `json:"exit_code"`
	}{Errors: []enterprisestatus.Message{{Code: code, Message: message}}, ExitCode: commandExitCode(err)})
}

// enterpriseDiscoveryStatusHint is the status command for this platform.
func enterpriseDiscoveryStatusHint() string {
	switch runtime.GOOS {
	case "windows":
		return "defenseclaw enterprise windows status"
	case "darwin":
		return "defenseclaw-gateway enterprise macos status"
	default:
		return "defenseclaw-gateway enterprise linux status"
	}
}

// enterpriseGatewayAIUsage is GET /api/v1/ai-usage: the gateway's own AI
// Discovery report.
type enterpriseGatewayAIUsage struct {
	Enabled bool                         `json:"enabled"`
	Summary inventory.AIDiscoverySummary `json:"summary"`
	Signals []inventory.AISignal         `json:"signals"`
}

// enterpriseDiscoveryGatewayReport reads the gateway's AI Discovery report;
// replaceable in tests.
var enterpriseDiscoveryGatewayReport = func() (enterpriseGatewayAIUsage, string, error) {
	var usage enterpriseGatewayAIUsage
	host, err := enterpriseGatewayGet("/api/v1/ai-usage", &usage)
	return usage, host, err
}

// writeWindowsEnterpriseDiscovery is `enterprise windows discovery`. On
// Windows the gateway service scans every profile itself, so the inventory
// is its own report, grouped by the account each signal was found in
// (GAP-1964).
func writeWindowsEnterpriseDiscovery(w io.Writer, user string, asJSON bool) error {
	usage, host, err := enterpriseDiscoveryGatewayReport()
	if err != nil {
		// A refusal with its own exit code (elevation_required) is already
		// the whole answer (GAP-2039).
		var coded *exitCodeError
		if !errors.As(err, &coded) {
			err = withExitCode(fmt.Errorf("read the AI Discovery inventory: %w", err), 1)
		}
		if asJSON {
			writeManagedViewRefusalJSON(w, err)
		}
		return err
	}
	report := enterpriseDiscoveryReport{Gateway: host, Accounts: []enterpriseDiscoveryAccount{}}
	byUser := map[string]int{}
	for _, signal := range usage.Signals {
		name := signal.UserName
		if user != "" && !useridentity.AccountFilterMatches(user, signal.UserID, name) {
			continue
		}
		index, ok := byUser[strings.ToLower(name)]
		if !ok {
			index = len(report.Accounts)
			byUser[strings.ToLower(name)] = index
			report.Accounts = append(report.Accounts, enterpriseDiscoveryAccount{
				User: name, SID: signal.UserID, UpdatedAt: usage.Summary.ScannedAt, Result: usage.Summary.Result,
			})
		}
		report.Accounts[index].Signals = append(report.Accounts[index].Signals, signal)
	}
	sort.Slice(report.Accounts, func(i, j int) bool {
		return strings.ToLower(report.Accounts[i].User) < strings.ToLower(report.Accounts[j].User)
	})
	if user != "" && len(report.Accounts) == 0 {
		// A --json caller reads this as JSON too, not an empty stdout (GAP-2456).
		err := withExitCode(&managedViewRefusal{code: "account_not_found",
			message: windowsDiscoveryAccountNotFound(user, usage)}, 1)
		if asJSON {
			writeManagedViewRefusalJSON(w, err)
		}
		return err
	}
	heading := fmt.Sprintf("AI Discovery inventory from the gateway's scan of each user profile (gateway %s)", host)
	return writeEnterpriseDiscoveryReport(w, report, user, asJSON, heading)
}

// windowsDiscoveryAccountNotFound says why --user selected nothing: the
// scan is off, found nothing yet, or found other accounts only (GAP-0079).
func windowsDiscoveryAccountNotFound(user string, usage enterpriseGatewayAIUsage) string {
	message := fmt.Sprintf("no AI Discovery signal for account %q in the gateway's last scan", user)
	accounts := map[string]struct{}{}
	for _, signal := range usage.Signals {
		if signal.UserName != "" {
			accounts[strings.ToLower(signal.UserName)] = struct{}{}
		}
	}
	switch {
	case !usage.Enabled:
		return message + "; ai_discovery is off on this gateway"
	case len(accounts) == 0:
		return message + "; the scan has not found an AI agent, skill or MCP server in any profile yet"
	}
	return message + fmt.Sprintf("; it found signals for %d other account(s): pass the account name, DOMAIN\\name or SID, or run without --user to list them", len(accounts))
}

func writeEnterpriseDiscovery(w io.Writer, dir, user string, asJSON bool) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		entries = nil
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("read %s: permission denied; run as root", dir)
	case err != nil:
		return err
	}
	report := enterpriseDiscoveryReport{Spool: dir, Accounts: []enterpriseDiscoveryAccount{}}
	for _, entry := range entries {
		uid, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || uid == "" || strings.Trim(uid, "0123456789") != "" {
			continue // pass.json and anything else that is not a record
		}
		record, err := enterpriseDiscoveryReadRecord(filepath.Join(dir, entry.Name()))
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("uid %s: %v", uid, err))
			continue
		}
		if user != "" && user != record.User && user != strconv.Itoa(record.UID) {
			continue
		}
		accountUID := record.UID
		report.Accounts = append(report.Accounts, enterpriseDiscoveryAccount{
			User: record.User, UID: &accountUID, UpdatedAt: record.UpdatedAt,
			Result: record.Report.Summary.Result, Signals: record.Report.Signals,
		})
	}
	sort.Slice(report.Accounts, func(i, j int) bool { return *report.Accounts[i].UID < *report.Accounts[j].UID })
	if user != "" && len(report.Accounts) == 0 && len(report.Errors) == 0 {
		return fmt.Errorf("no AI Discovery record for account %q in %s; the account is not enrolled or has not been scanned yet", user, dir)
	}
	return writeEnterpriseDiscoveryReport(w, report, user, asJSON,
		fmt.Sprintf("AI Discovery inventory from the hook guardian's per-user scans (%s)", dir))
}

// writeEnterpriseDiscoveryReport adds the runtime discovery section to the
// accounts' inventory and prints both.
func writeEnterpriseDiscoveryReport(w io.Writer, report enterpriseDiscoveryReport, user string, asJSON bool, heading string) error {
	for i := range report.Accounts {
		report.Accounts[i].Signals = enterpriseDiscoveryAdminSignals(report.Accounts[i].Signals)
	}
	if view, err := enterpriseDiscoveryRuntime(); err != nil {
		report.RuntimeError = err.Error()
	} else if view != nil {
		if user != "" {
			findings := view.Findings[:0]
			for _, finding := range view.Findings {
				if strings.EqualFold(finding.User, user) {
					findings = append(findings, finding)
				}
			}
			view.Findings = findings
		}
		report.Runtime = view
	}
	if asJSON {
		encoder := newEnterpriseJSONEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintln(w, heading)
	if len(report.Accounts) == 0 && len(report.Errors) == 0 {
		fmt.Fprintln(w, "  no records yet: ai_discovery is off in the deployment config, no account is enrolled, or the first scan has not finished")
	}
	for _, account := range report.Accounts {
		name := account.User
		switch {
		case name == "":
			name = "machine-wide (no account)"
		case account.UID != nil:
			name = fmt.Sprintf("%s (uid %d)", name, *account.UID)
		}
		fmt.Fprintf(w, "%s: scanned %s, result %s, %d signal(s)\n",
			name, account.UpdatedAt.UTC().Format(time.RFC3339), account.Result, len(account.Signals))
		if user == "" {
			counts := map[string]int{}
			for _, signal := range account.Signals {
				counts[signal.Category]++
			}
			categories := make([]string, 0, len(counts))
			for category, count := range counts {
				categories = append(categories, fmt.Sprintf("%s %d", category, count))
			}
			sort.Strings(categories)
			if len(categories) > 0 {
				fmt.Fprintf(w, "  %s\n", strings.Join(categories, ", "))
			}
			continue
		}
		table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "  CATEGORY\tNAME\tCONNECTOR\tSTATE\tLAST SEEN\tFILES")
		for _, signal := range account.Signals {
			connector := signal.SupportedConnector
			if connector == "" {
				connector = "-"
			}
			files := enterpriseDiscoverySignalFiles(signal)
			fmt.Fprintf(table, "  %s\t%s\t%s\t%s\t%s\t%s\n", signal.Category, signal.Name, connector, signal.State,
				signal.LastSeen.UTC().Format(time.RFC3339), files)
		}
		_ = table.Flush()
	}
	for _, problem := range report.Errors {
		fmt.Fprintf(w, "unreadable record: %s\n", problem)
	}
	writeEnterpriseRuntime(w, report)
	if user == "" && len(report.Accounts) > 0 {
		fmt.Fprintln(w, "Run with --user <account> to list one account's signals, or --json for every field.")
	}
	return nil
}

// enterpriseDiscoveryAdminSignals makes each signal's basenames name what
// it found. Evidence keeps the scanned folder or config file as its first
// row, so the view named "skills" in every skill row (GAP-2263) and each
// MCP config file as a server (GAP-2337). A skill, plugin or rule signal
// lists its *_entry names and an MCP signal its mcp_server names. An MCP
// config file read in full that declares no server is not an MCP server:
// it is left out. Signals without evidence are kept as they are.
func enterpriseDiscoveryAdminSignals(signals []inventory.AISignal) []inventory.AISignal {
	out := make([]inventory.AISignal, 0, len(signals))
	for _, signal := range signals {
		if len(signal.Evidence) == 0 {
			out = append(out, signal)
			continue
		}
		var names []string
		for _, evidence := range signal.Evidence {
			named := strings.HasSuffix(evidence.Type, "_entry") || evidence.Type == "mcp_server"
			if named && evidence.Basename != "" && !slices.Contains(names, evidence.Basename) {
				names = append(names, evidence.Basename)
			}
		}
		switch {
		case len(names) > 0:
			sort.Strings(names)
			signal.Basenames = names
		case signal.Category == inventory.SignalMCPServer && !signal.Partial:
			continue
		}
		out = append(out, signal)
	}
	return out
}

// enterpriseDiscoverySignalFiles is a signal's FILES cell; a partial scan
// says so, so an unread folder is not taken for an empty one.
func enterpriseDiscoverySignalFiles(signal inventory.AISignal) string {
	files := strings.Join(signal.Basenames, ",")
	if files == "" {
		files = "-"
	}
	if signal.Partial {
		reason := signal.CoverageReason
		if reason == "" {
			reason = "incomplete"
		}
		files += " (partial: " + reason + ")"
	}
	return files
}

// writeEnterpriseRuntime prints the runtime discovery section.
func writeEnterpriseRuntime(w io.Writer, report enterpriseDiscoveryReport) {
	view := report.Runtime
	switch {
	case report.RuntimeError != "":
		fmt.Fprintf(w, "Runtime discovery: not read: %s\n", report.RuntimeError)
		return
	case view == nil:
		return
	case !view.Enabled:
		fmt.Fprintf(w, "Runtime discovery (gateway %s): off; ai_discovery.runtime is not enabled in the deployment config\n", view.Gateway)
		return
	}
	scanned := view.ScannedAt
	if scanned == "" {
		scanned = "no poll yet"
	}
	state := "healthy"
	if view.Degraded {
		state = "degraded"
	}
	fmt.Fprintf(w, "Runtime discovery (gateway %s): %s, last poll %s, %d finding(s)\n", view.Gateway, state, scanned, len(view.Findings))
	for _, plane := range view.Planes {
		switch {
		case plane.Running && plane.Reason != "":
			fmt.Fprintf(w, "  %s: partial, running via %s -- %s\n", plane.Name, plane.Mechanism, plane.Reason)
		case plane.Running:
			fmt.Fprintf(w, "  %s: running via %s\n", plane.Name, plane.Mechanism)
		case plane.Available:
			fmt.Fprintf(w, "  %s: not running -- %s\n", plane.Name, plane.Reason)
		default:
			fmt.Fprintf(w, "  %s: unavailable -- %s\n", plane.Name, plane.Reason)
		}
		for _, line := range plane.Backend.lines() {
			fmt.Fprintf(w, "    %s\n", line)
		}
	}
	if len(view.Findings) == 0 {
		return
	}
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  SEVERITY\tSCORE\tPROCESS\tPID\tUSER\tAGENT\tLAST SEEN")
	for _, finding := range view.Findings {
		fmt.Fprintf(table, "  %s\t%d\t%s\t%d\t%s\t%s\t%s\n", finding.Severity, finding.Score, finding.Process, finding.PID,
			defaultStr(finding.User, "-"), defaultStr(finding.AgentName, "-"), defaultStr(finding.LastSeen, "-"))
	}
	_ = table.Flush()
}
