// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// ActivityOptions are the `sandbox activity` flags.
type ActivityOptions struct {
	Sandbox string
	Follow  bool
	Since   uint64
	Output  OutputFormat
}

// Activity prints the live activity feed: destinations, blocks, asks,
// tool blocks and findings.
func (a *App) Activity(ctx context.Context, o ActivityOptions) error {
	a.defaults()
	api, err := a.api()
	if err != nil {
		return err
	}
	if o.Output == OutputJSON && !o.Follow {
		var events []sandboxapi.ActivityEvent
		err := api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: o.Sandbox, Since: o.Since}, func(ev sandboxapi.ActivityEvent) error {
			events = append(events, ev)
			return nil
		})
		if err != nil {
			return apiError(err)
		}
		if events == nil {
			events = []sandboxapi.ActivityEvent{}
		}
		return writeJSON(a.IO.Out, map[string]any{"events": events})
	}
	enc := json.NewEncoder(a.IO.Out)
	enc.SetEscapeHTML(false)
	n := 0
	// The last event shown: a feed lives in the daemon's memory, and one
	// that restarted starts another, numbered from one under a new epoch.
	var epoch string
	var seq uint64
	show := func(ev sandboxapi.ActivityEvent) error {
		if epoch != "" && ev.Epoch == epoch && ev.Seq <= seq {
			// Replayed after a reconnect to the same feed.
			return nil
		}
		if epoch != "" && ev.Epoch != "" && ev.Epoch != epoch && o.Output != OutputJSON {
			a.note("the DefenseClaw daemon restarted; following its new feed")
		}
		if ev.Epoch != "" {
			epoch, seq = ev.Epoch, ev.Seq
		}
		n++
		if o.Output == OutputJSON {
			return enc.Encode(ev)
		}
		a.println(a.activityLine(ev, o.Sandbox == ""))
		return nil
	}
	err = api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: o.Sandbox, Since: o.Since, Follow: o.Follow}, show)
	// A followed stream ends when the daemon restarts or lets go of its
	// sandboxes: follow the feed it serves next (from its start; what this
	// one showed is skipped), or say why the feed stopped.
	// A daemon whose events name no epoch cannot be followed across its
	// restarts: what it replays could not be told from what is new.
	for quiet := 0; o.Follow && epoch != "" && ctx.Err() == nil && (err == nil || sandboxapi.IsCode(err, sandboxapi.CodeUnavailable)); {
		if quiet++; quiet > followQuietReconnects {
			return &ExitError{Code: 1, Err: errors.New("the activity feed stopped: the DefenseClaw daemon keeps ending the stream")}
		}
		if err = a.awaitDaemon(ctx, api); err != nil {
			return err
		}
		shown := n
		err = api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: o.Sandbox, Follow: true}, show)
		if n > shown {
			quiet = 0
		}
	}
	if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return apiError(err)
	}
	if n == 0 && !o.Follow && o.Output != OutputJSON {
		a.note("no activity yet")
	}
	return nil
}

// followRetry bounds how long `activity -f` waits for the daemon to answer
// again after its stream ended; followQuietReconnects how many streams in a
// row may end with nothing new.
const (
	followRetry           = time.Minute
	followQuietReconnects = 5
)

// awaitDaemon waits until the daemon serves sandboxes again, at most
// followRetry; an error says the feed stopped.
func (a *App) awaitDaemon(ctx context.Context, api API) error {
	deadline := a.Now().Add(followRetry)
	const poll = 2 * time.Second
	for polls := 0; ; polls++ {
		if err := a.Sleep(ctx, poll); err != nil {
			return err
		}
		st, err := api.Status(ctx)
		if err == nil && st.Enabled && st.Available {
			return nil
		}
		if a.Now().After(deadline) || time.Duration(polls)*poll >= followRetry {
			why := "it does not answer"
			switch {
			case err != nil:
				why = apiError(err).Error()
			case !st.Enabled:
				why = "sandboxes are off"
			case !st.Available:
				why = "sandboxes are unavailable: " + firstNonEmpty(st.Reason, "not connected to OpenShell")
			}
			return &ExitError{Code: 1, Err: fmt.Errorf("the activity feed stopped: the DefenseClaw daemon went away and is not back after %s (%s)", followRetry, why)}
		}
	}
}

// activityLine renders one feed item: "15:04:05 ✓ registry.npmjs.org" or
// "15:04:05 ✗ webhook.site (exfil destination) → unblock: …".
func (a *App) activityLine(ev sandboxapi.ActivityEvent, withSandbox bool) string {
	var b strings.Builder
	b.WriteString(a.dim(ev.Time.Local().Format("15:04:05")))
	b.WriteByte(' ')
	if withSandbox && ev.Sandbox != "" {
		b.WriteString(a.dim(ev.Sandbox) + " ")
	}
	switch ev.Kind {
	case sandboxapi.ActivityEgressAllowed:
		b.WriteString(a.style("✓", ansiGreen) + " " + hostPort(ev))
	case sandboxapi.ActivityEgressBlocked:
		b.WriteString(a.style("✗", ansiRed) + " " + hostPort(ev))
		switch why := firstNonEmpty(ev.Category, ev.Reason); {
		case sshPort(ev):
			b.WriteString(" (" + sshBlockedText(ev.Host) + ")")
		case ev.Category == sandboxapi.CategoryLargeUpload:
			// The proxy's reason names the threshold the upload crossed.
			b.WriteString(" (" + sandboxapi.LargeUploadBlockedText(ev.Reason) + ")")
		case why != "":
			b.WriteString(" (" + reasonText(why) + ")")
		}
		if ev.Unblockable && ev.Host != "" && !sshPort(ev) {
			scope := ""
			if ev.Sandbox != "" {
				scope = " --sandbox " + ev.Sandbox
			}
			b.WriteString(a.dim("  → unblock: " + CommandName + " unblock " + ev.Host + scope))
		}
	case sandboxapi.ActivityEgressLargeUpload:
		b.WriteString(a.style("⚠", ansiYellow) + " " + largeUploadText(hostPort(ev), ev))
	case sandboxapi.ActivityApprovalRequested:
		// The destination always shows: nobody should approve one they
		// cannot see. The daemon's message says why it is an ask.
		what := firstNonEmpty(askDestination(ev), "a new destination")
		if why := strings.TrimSpace(ev.Message); why != "" && why != ev.Host {
			what += " (" + truncate(why, 120) + ")"
		}
		b.WriteString(a.style("?", ansiYellow, ansiBold) + " ask " + ev.ApprovalID + ": " + what)
		if ev.Sandbox != "" && ev.ApprovalID != "" {
			b.WriteString(a.dim("  → " + CommandName + " approve " + ev.Sandbox + " " + ev.ApprovalID))
		}
	case sandboxapi.ActivityToolBlocked:
		b.WriteString(a.style("✗", ansiRed) + " tool " + firstNonEmpty(ev.Tool, "call") + " blocked")
		if label := sandboxapi.VerdictRuleLabel(ev.Reason); label != "" {
			b.WriteString(": " + truncate(label, 120))
		}
	case sandboxapi.ActivityToolAsked:
		b.WriteString(a.style("?", ansiYellow, ansiBold) + " tool " + firstNonEmpty(ev.Tool, "call") + " asked for confirmation")
		if label := sandboxapi.VerdictRuleLabel(ev.Reason); label != "" {
			b.WriteString(": " + truncate(label, 120))
		}
	case sandboxapi.ActivityHookBlocked:
		b.WriteString(a.style("✗", ansiRed) + " " + firstNonEmpty(strings.TrimPrefix(ev.Message, "✗ "), "prompt blocked by DefenseClaw"))
	case sandboxapi.ActivityHookFailed:
		msg := strings.TrimPrefix(ev.Message, "✗ ")
		if msg == "" {
			msg = "a hook call failed (" + firstNonEmpty(ev.Reason, "error") + "), so the harness's action was blocked"
		}
		b.WriteString(a.style("✗", ansiRed) + " " + msg)
	case sandboxapi.ActivityFinding:
		switch msg := firstNonEmpty(ev.Message, ev.Reason); ev.Reason {
		case sandboxapi.ReasonHooksRestored:
			b.WriteString(a.style("✓", ansiGreen) + " " + msg)
		case sandboxapi.ReasonHooksUnreachable:
			b.WriteString(a.style("✗", ansiRed) + " " + strings.TrimPrefix(msg, "⚠ "))
		default:
			b.WriteString(a.style("⚠", ansiYellow) + " " + strings.TrimPrefix(msg, "⚠ "))
		}
	case sandboxapi.ActivityDropped:
		b.WriteString(a.dim("… " + firstNonEmpty(ev.Message, "some events were skipped")))
	default:
		b.WriteString(firstNonEmpty(ev.Message, ev.Kind))
	}
	if ev.Replayed {
		// OpenShell replays what it recorded while the daemon was down,
		// after newer events.
		b.WriteString(a.dim(" (while DefenseClaw was down)"))
	}
	return b.String()
}

// reasonTexts explain the reason tokens the feed carries for blocked
// egress: OpenShell's own for the connections it denies, and the egress
// proxy's categories.
var reasonTexts = map[string]string{
	"transparent_tcp_policy_denied":  "no OpenShell rule allows it",
	"transparent_tcp_mapping_denied": "no OpenShell rule allows this port",
	"policy_dns_ineligible":          "no OpenShell rule allows the name",
	"paste_site":                     "paste site",
	"file_drop":                      "file-sharing site",
	"webhook_catcher":                "webhook catcher",
	"tunnel":                         "tunnel service",
	"anonymizer":                     "anonymizer",
	"host_internal":                  "this machine",
	"private_network":                "private network",
	"port_not_allowed":               "port not allowed",
	"invalid_destination":            "invalid destination",
	"admin_block":                    "blocked by your organization",
	"admin_allow_only":               "not on your organization's allowed list",
	"operator_block":                 "on your block list",
	"not_allowlisted":                "not on the allowlist",
	"rate_limited":                   "rate limited",
	"ip_literal":                     "IP address instead of a name",
	// Triage's verdicts on the rule OpenShell drafts for a denied
	// connection (triage.Reason).
	"unsupported_rule":         "no OpenShell rule allows it, and DefenseClaw does not approve the rule drafted for it",
	"no_endpoints":             "the rule drafted for it names no destination",
	"wildcard_destination":     "wildcard destination",
	"policy_refused":           "the sandbox policy refuses it",
	"admin_violation":          "blocked by your organization",
	"blocklisted":              "on the block list",
	"agent_proposals_disabled": "no OpenShell rule allows it, and this sandbox takes no new rules",
	"resolves_to_host":         "the name leads to this machine",
	"unresolved":               "the name does not resolve",
	"multiple_hosts":           "the rule drafted for it names several hosts",
	"harness_background_fetch": "a background fetch of the harness, which it does without",
	"rule_limit":               "the sandbox added its limit of rules this session",
	"too_many_pending":         "too many approvals are waiting",
}

// sshPort reports a refused connection to port 22: git over SSH, ssh.
// OpenShell opens no SSH out of a sandbox, which no unblock changes.
func sshPort(ev sandboxapi.ActivityEvent) bool { return ev.Port == 22 }

// sshBlockedText says what to do instead of SSH to host.
func sshBlockedText(host string) string {
	return "SSH does not leave a sandbox: use an HTTPS remote (https://" + host + "/…)"
}

// reasonText is the short explanation of a feed reason token; an unknown
// token reads with spaces for its underscores.
func reasonText(token string) string {
	if text, ok := reasonTexts[token]; ok {
		return text
	}
	return strings.ReplaceAll(token, "_", " ")
}

// largeUploadText is an egress.large_upload report to dest (the feed's
// hostPort, a session's host) without its ⚠: "large upload to
// files.example.net (more than 25 MiB)". It is reported as it crosses the
// threshold, before it ends: what had gone up then (the report's bytes) is
// not what it sent (RT U4).
func largeUploadText(dest string, ev sandboxapi.ActivityEvent) string {
	size := humanBytes(ev.BytesUp)
	if ev.Threshold > 0 {
		size = "more than " + egress.FormatThreshold(ev.Threshold)
	}
	return "large upload to " + dest + " (" + size + ")"
}

// hostPort is ev's destination as the feed names it (sandboxapi.HostPort):
// its port shows unless that is 443.
func hostPort(ev sandboxapi.ActivityEvent) string {
	return sandboxapi.HostPort(ev.Host, ev.Port)
}

// ApprovalsOptions are the `sandbox approvals` flags.
type ApprovalsOptions struct {
	Sandbox string
	Watch   bool
	Output  OutputFormat
}

// Approvals lists the rare asks waiting for the user.
func (a *App) Approvals(ctx context.Context, o ApprovalsOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	show := func() error {
		list, err := api.Approvals(ctx, o.Sandbox)
		if err != nil {
			return apiError(err)
		}
		if o.Output == OutputJSON {
			if list == nil {
				list = []sandboxapi.Approval{}
			}
			return writeJSON(a.IO.Out, map[string]any{"approvals": list})
		}
		if len(list) == 0 {
			a.note("no asks waiting")
			return nil
		}
		rows := make([][]string, 0, len(list))
		for _, ap := range list {
			dest := approvalDestination(ap)
			risk := ""
			if ap.Risky {
				risk = "risky"
			}
			rows = append(rows, []string{ap.ID, ap.Sandbox, ap.Kind, dest, firstNonEmpty(ap.Binary, "-"), risk, truncate(ap.Reason, 60)})
		}
		a.table([]string{"ID", "SANDBOX", "KIND", "DESTINATION", "BINARY", "RISK", "REASON"}, rows)
		a.note("approve: " + CommandName + " approve <sandbox> <id> [--always]   reject: " + CommandName + " reject <sandbox> <id>")
		return nil
	}
	if err := show(); err != nil || !o.Watch {
		return err
	}
	err = api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: o.Sandbox, Follow: true}, func(ev sandboxapi.ActivityEvent) error {
		if ev.Kind != sandboxapi.ActivityApprovalRequested && ev.Kind != sandboxapi.ActivityApprovalResolved {
			return nil
		}
		if o.Output != OutputJSON {
			a.println(a.activityLine(ev, o.Sandbox == ""))
		}
		return show()
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return apiError(err)
	}
	return nil
}

// approvalDestination is what approving an ask opens: its host with every
// port the proposal names (the daemon rejects proposals naming a second
// host).
func approvalDestination(ap sandboxapi.Approval) string {
	var ports []string
	for _, ep := range ap.Endpoints {
		if p := strconv.Itoa(ep.Port); ep.Port != 0 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 && ap.Port != 0 {
		ports = append(ports, strconv.Itoa(ap.Port))
	}
	if len(ports) == 0 {
		return ap.Host
	}
	return ap.Host + ":" + strings.Join(ports, ",")
}

// DecideOptions are the `sandbox approve|reject` arguments.
type DecideOptions struct {
	Sandbox string
	ID      string
	Always  bool
	Reason  string
	Approve bool
}

// Decide approves or rejects one ask of a sandbox.
func (a *App) Decide(ctx context.Context, o DecideOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	list, err := api.Approvals(ctx, o.Sandbox)
	if err != nil {
		return apiError(err)
	}
	found := false
	for _, ap := range list {
		if ap.ID == o.ID {
			found = ap.Sandbox == o.Sandbox
			break
		}
	}
	if !found {
		return fmt.Errorf("sandbox %s has no pending ask %s (see `%s approvals --sandbox %s`)", o.Sandbox, o.ID, CommandName, o.Sandbox)
	}
	d := sandboxapi.ApprovalDecision{Decision: sandboxapi.DecisionReject, Always: o.Always, Reason: o.Reason}
	if o.Approve {
		d.Decision = sandboxapi.DecisionApprove
	}
	res, err := api.Decide(ctx, o.ID, d)
	if err != nil {
		return apiError(err)
	}
	verb := "rejected"
	if o.Approve {
		verb = "approved"
	}
	// One line per decision: the daemon's message only when it says more
	// than the verb and the queueing.
	msg := verb + " " + o.ID + " (" + res.Approval.Host + ")"
	if res.Persisted {
		msg += ", kept for future sandboxes"
	}
	switch m := strings.TrimSpace(res.Message); {
	case res.Approval.Status == sandboxapi.ApprovalQueued:
		// The connection that asked was refused at once: nothing waits for
		// the answer, so the program has to try again.
		msg += "; it applies at the next quiet moment of the sandbox (usually within a minute), then retry the connection that asked"
	case m != "" && m != verb && !strings.HasPrefix(m, verb+";") && !strings.HasPrefix(m, verb+" "):
		msg += "; " + m
	}
	a.ok(msg)
	return nil
}

// UnblockOptions are the `sandbox unblock` flags.
type UnblockOptions struct {
	Host    string
	Sandbox string
	Always  bool
}

// Unblock lifts an egress block for one sandbox or for every sandbox.
func (a *App) Unblock(ctx context.Context, o UnblockOptions) error {
	if o.Sandbox == "" && !o.Always {
		return errors.New("choose where the unblock applies: --sandbox NAME, or --always for every sandbox")
	}
	if o.Sandbox != "" && o.Always {
		return errors.New("--sandbox and --always are exclusive")
	}
	api, err := a.api()
	if err != nil {
		return err
	}
	res, err := api.Unblock(ctx, sandboxapi.UnblockRequest{Host: o.Host, Sandbox: o.Sandbox, Always: o.Always})
	if err != nil {
		return apiError(err)
	}
	// One line: the daemon's message repeats where the unblock applies.
	msg := "unblocked " + res.Host + " in " + res.Sandbox
	if res.Scope == "always" {
		msg = "unblocked " + res.Host + " for every sandbox"
		if res.Persisted {
			msg += " (saved to openshell.egress.unblocked)"
		}
	}
	a.ok(msg)
	return nil
}
