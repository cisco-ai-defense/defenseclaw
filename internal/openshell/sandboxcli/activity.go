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
	"strconv"
	"strings"

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
	err = api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: o.Sandbox, Since: o.Since, Follow: o.Follow}, func(ev sandboxapi.ActivityEvent) error {
		n++
		if o.Output == OutputJSON {
			return enc.Encode(ev)
		}
		a.println(a.activityLine(ev, o.Sandbox == ""))
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return apiError(err)
	}
	if n == 0 && !o.Follow && o.Output != OutputJSON {
		a.note("no activity yet")
	}
	return nil
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
		if why := firstNonEmpty(ev.Category, ev.Reason); why != "" {
			b.WriteString(" (" + why + ")")
		}
		if ev.Unblockable && ev.Host != "" {
			scope := ""
			if ev.Sandbox != "" {
				scope = " --sandbox " + ev.Sandbox
			}
			b.WriteString(a.dim("  → unblock: " + CommandName + " unblock " + ev.Host + scope))
		}
	case sandboxapi.ActivityEgressLargeUpload:
		b.WriteString(a.style("⚠", ansiYellow) + " large upload to " + hostPort(ev) + " (" + humanBytes(ev.BytesUp) + ")")
	case sandboxapi.ActivityApprovalRequested:
		b.WriteString(a.style("?", ansiYellow, ansiBold) + " ask " + ev.ApprovalID + ": " + firstNonEmpty(ev.Message, hostPort(ev)))
		if ev.Sandbox != "" && ev.ApprovalID != "" {
			b.WriteString(a.dim("  → " + CommandName + " approve " + ev.Sandbox + " " + ev.ApprovalID))
		}
	case sandboxapi.ActivityToolBlocked:
		b.WriteString(a.style("✗", ansiRed) + " tool " + firstNonEmpty(ev.Tool, "call") + " blocked")
		if ev.Reason != "" {
			b.WriteString(": " + truncate(ev.Reason, 120))
		}
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
	return b.String()
}

func hostPort(ev sandboxapi.ActivityEvent) string {
	if ev.Port != 0 && ev.Port != 443 && ev.Port != 80 {
		return ev.Host + ":" + strconv.Itoa(ev.Port)
	}
	return ev.Host
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
			dest := ap.Host
			if ap.Port != 0 {
				dest += ":" + strconv.Itoa(ap.Port)
			}
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
	msg := verb + " " + o.ID + " (" + res.Approval.Host + ")"
	if res.Approval.Status == sandboxapi.ApprovalQueued {
		msg += "; it applies at the next quiet moment of the sandbox"
	}
	a.ok(msg)
	if res.Persisted {
		a.note("kept for future sandboxes")
	}
	if res.Message != "" {
		a.note(res.Message)
	}
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
	where := "in " + res.Sandbox
	if res.Scope == "always" {
		where = "for every sandbox"
	}
	a.ok("unblocked " + res.Host + " " + where)
	if res.Message != "" {
		a.note(res.Message)
	}
	return nil
}
