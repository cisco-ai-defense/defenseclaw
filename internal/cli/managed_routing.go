// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// managedRoutingRead reads one own-routing path from the managed gateway
// (the hook socket on Linux and macOS, the own-status pipe on Windows); a
// seam for tests.
var managedRoutingRead = readOwnRouting

const managedRoutingReads = "`defenseclaw routing status`, `defenseclaw routing rules list`, `defenseclaw routing budgets list` and `defenseclaw routing explain <id>`"

// managedRoutingKeys names the config key each routing writer changes, for
// the refusal text.
var managedRoutingKeys = map[string]string{
	"enable": "routing.enabled", "disable": "routing.enabled", "setup": "routing",
	"models": "routing.models", "rules": "routing.admin.rules", "budgets": "routing.admin.budgets",
	"pricing": "observability.pricing", "test": "routing",
}

// managedRoutingRefusal is the answer to a routing command a managed computer
// does not run for the caller: it names the config key the administrator
// config owns, says nothing was changed and points to the reads. words are
// the words after routing.
func managedRoutingRefusal(words []string) string {
	key := "model routing"
	if len(words) > 0 {
		if k, ok := managedRoutingKeys[words[0]]; ok {
			key = k
		}
	}
	return "this computer's DefenseClaw is managed by your organization: " + key + " is set by your administrator in the " +
		"administrator config (model routing, its rules and budgets). You can read your own routing with " + managedRoutingReads +
		". Nothing was changed."
}

// newManagedRoutingCmd is `defenseclaw routing` on a managed computer, where
// a standard account has no per-user (Python) CLI: the managed Windows
// defenseclaw.exe and the Linux and macOS launcher run it. Its four reads
// ask the managed gateway, which answers for the caller's own account only
// and refuses when routing.admin.visibility.users_see is none. Every other
// routing command changes the administrator's config and gets the managed
// answer (exit 3), reaching no gateway. Before it, routing was the generic
// "not available on this computer" answer on Windows and a launcher refusal
// on Linux and macOS (REVIEW-s13-p1-merge F1).
func newManagedRoutingCmd() *cobra.Command {
	refuse := func(cmd *cobra.Command, args []string) error {
		// A refused routing write is a row in the managed audit log, as the
		// per-user CLI's refusal is (REVIEW-final F2). The launcher refuses
		// the writes before this tree runs, so this reports on Windows.
		words := append(strings.Fields(cmd.CommandPath())[1:], args...)
		if command, ok := launcherAuditedWriter(words); ok {
			reportManagedCommandRefusal(command, "")
		}
		return withExitCode(managedDeviceAnswer(managedRoutingRefusal(words[1:])), 3)
	}
	read := func(path string) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error { return runManagedRoutingRead(cmd, path) }
	}
	annotations := map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"}
	// The refused writes carry the per-user CLI's flags (budgets add
	// --limit-usd ...): they get the managed answer, not "unknown flag".
	writes := cobra.FParseErrWhitelist{UnknownFlags: true}
	routing := &cobra.Command{
		Use:          "routing",
		Short:        "Read your own model routing decisions and budgets (managed computers)",
		Hidden:       true, // the per-user CLI owns defenseclaw routing everywhere else
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		Annotations:  annotations,
		RunE:         refuse,

		FParseErrWhitelist: writes,
	}
	status := &cobra.Command{
		Use: "status", Short: "Your routing profile and recent decisions", Args: cobra.NoArgs,
		Annotations: annotations, SilenceUsage: true, RunE: read("/api/v1/routing/effective?recent=5"),
	}
	budgets := &cobra.Command{
		Use: "budgets", Short: "Your budgets", Args: cobra.ArbitraryArgs,
		Annotations: annotations, SilenceUsage: true, RunE: refuse, FParseErrWhitelist: writes,
	}
	list := &cobra.Command{
		Use: "list", Short: "The budgets that count your spend", Args: cobra.NoArgs,
		Annotations: annotations, SilenceUsage: true, RunE: read("/api/v1/routing/budgets"),
	}
	explain := &cobra.Command{
		Use: "explain ID", Short: "Why one of your recent calls went where it went", Args: cobra.ExactArgs(1),
		Annotations: annotations, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runManagedRoutingRead(cmd, "/api/v1/routing/explain/"+url.PathEscape(args[0]))
		},
	}
	rules := &cobra.Command{
		Use: "rules", Short: "The routing rules that apply to you", Args: cobra.ArbitraryArgs,
		Annotations: annotations, SilenceUsage: true, RunE: refuse, FParseErrWhitelist: writes,
	}
	rulesList := &cobra.Command{
		Use: "list", Short: "The routing rules (all of them for an administrator, none for a user)", Args: cobra.NoArgs,
		Annotations: annotations, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return runManagedRoutingRules(cmd) },
	}
	for _, c := range []*cobra.Command{status, list, explain, rulesList} {
		// The output is JSON either way; --json is accepted for the per-user spelling.
		c.Flags().Bool("json", false, "Print JSON (the default here).")
	}
	budgets.AddCommand(list)
	rules.AddCommand(rulesList)
	routing.AddCommand(status, rules, budgets, explain)
	return routing
}

// managedRoutingWriters are the routing commands that change the
// administrator's config (the per-user CLI's writers): enable, disable and
// setup, and the writers of each group. Reads (status, explain, usage, the
// list and show of a group) and the dry run (test) are not here.
var managedRoutingWriters = map[string]map[string]bool{
	"enable": nil, "disable": nil, "setup": nil,
	"models":  {"add": true, "remove": true, "set-default": true},
	"rules":   {"add": true, "remove": true, "move": true},
	"budgets": {"add": true, "remove": true},
	"pricing": {"set": true, "import": true},
}

// managedRoutingWriter returns the command words of a routing writer from
// the words after "routing"; the words come from the table, never from the
// arguments.
func managedRoutingWriter(words []string) (string, bool) {
	if len(words) == 0 {
		return "", false
	}
	group, ok := managedRoutingWriters[words[0]]
	if !ok {
		return "", false
	}
	if group == nil {
		return "routing " + words[0], true
	}
	if len(words) > 1 && group[words[1]] {
		return "routing " + words[0] + " " + words[1], true
	}
	return "", false
}

// managedRoutingNamedRefusal reports whether args are a routing writer or the
// dry run: the commands whose refusal names the config key that owns them.
// Any other routing command the launcher does not offer keeps the generic
// launcher refusal (exit 2).
func managedRoutingNamedRefusal(args []string) bool {
	if len(args) < 2 || args[0] != "routing" {
		return false
	}
	if args[1] == "test" {
		return true
	}
	_, ok := managedRoutingWriter(args[1:])
	return ok
}

// runManagedRoutingRules prints the routing rules the managed gateway shows
// the caller: an administrator reads routing.admin.rules, a standard account
// none (the rules are administrator policy; a user reads the outcome with
// routing status and routing explain).
func runManagedRoutingRules(cmd *cobra.Command) error {
	status, body, err := managedRoutingRead(cmd.Context(), "/api/v1/routing/effective")
	if err != nil {
		return fmt.Errorf("the managed gateway did not answer (%v); try again, and if it keeps failing contact your IT help desk", err)
	}
	if status != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return &routingReadError{status: status, message: e.Error}
	}
	var eff struct {
		Admin bool            `json:"admin"`
		Rules json.RawMessage `json:"rules"`
	}
	_ = json.Unmarshal(body, &eff)
	rules := bytes.TrimSpace(eff.Rules)
	if len(rules) == 0 || string(rules) == "null" {
		rules = []byte("[]")
	}
	scope := "own"
	if eff.Admin {
		scope = "all"
	}
	out, err := json.MarshalIndent(map[string]any{"scope": scope, "rules": json.RawMessage(rules)}, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(out))
	return err
}

func runManagedRoutingRead(cmd *cobra.Command, path string) error {
	if !refusalpipe.ValidRoutingReadPath(path) {
		return fmt.Errorf("routing: %q is not a decision id", path)
	}
	status, body, err := managedRoutingRead(cmd.Context(), path)
	if err != nil {
		return fmt.Errorf("the managed gateway did not answer (%v); try again, and if it keeps failing contact your IT help desk", err)
	}
	if status != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return &routingReadError{status: status, message: e.Error}
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, bytes.TrimSpace(body), "", "  ") != nil {
		pretty.Reset()
		pretty.Write(bytes.TrimSpace(body))
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), pretty.String())
	return err
}

func init() {
	rootCmd.AddCommand(newManagedRoutingCmd())
}
