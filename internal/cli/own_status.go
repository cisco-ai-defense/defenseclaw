// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// ownStatusView is the managed gateway's own-status answer
// (handleOwnStatus on the Linux and macOS hook socket,
// ownStatusForWindowsAccount on the Windows own-status pipe).
type ownStatusView struct {
	Account struct {
		UID  string `json:"uid"`
		SID  string `json:"sid"`
		Name string `json:"name"`
	} `json:"account"`
	ClaudeCode struct {
		Protected bool `json:"protected"`
	} `json:"claude_code"`
	Connectors map[string]ownStatusRow `json:"connectors"`
	Cowork     struct {
		ownStatusRow
		LastEventAt string `json:"last_event_at"`
	} `json:"cowork"`
}

// ownStatusRow is one connector or Cowork row. State is one of protected, not
// protected, not confirmed (refused for Cowork); Reason and NextStep carry the
// text a not-protected row shows after it.
type ownStatusRow struct {
	Protected  bool   `json:"protected"`
	State      string `json:"state"`
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
	NextStep   string `json:"next_step"`
}

// showOwnStatus prints the caller's own protection state on a managed
// computer (cowork-1-0-8 GAP-0053 on Linux and macOS, GAP-0060 on Windows),
// which the managed gateway decides for the OS-verified caller: readOwnStatus
// sends nothing that names an account. The JSON always carries
// deployment_mode managed_enterprise, which tells an agent following the
// quickstart that the computer is managed, as the refusal did.
func showOwnStatus(cmd *cobra.Command, asJSON bool) error {
	out := cmd.OutOrStdout()
	fail := func(err error) error {
		failure := withExitCode(err, enterprisestatus.UnixExitFailure)
		if asJSON {
			writeOwnStatusJSON(out, map[string]any{"deployment_mode": "managed_enterprise", "managed_by": "your organization", "error": err.Error()})
			silenceJSONReportedError(cmd, true, failure)
		}
		return failure
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := readOwnStatus(ctx)
	if err != nil {
		return fail(err)
	}
	var answer map[string]any
	var view ownStatusView
	if json.Unmarshal(body, &answer) != nil || json.Unmarshal(body, &view) != nil {
		return fail(fmt.Errorf("the managed gateway did not report your status: %s", strings.TrimSpace(string(body))))
	}
	if asJSON {
		answer["deployment_mode"] = "managed_enterprise"
		writeOwnStatusJSON(out, answer)
		return nil
	}
	account := view.Account.Name
	switch {
	case account == "" && view.Account.UID != "":
		account = "uid " + view.Account.UID
	case account == "" && view.Account.SID != "":
		account = "SID " + view.Account.SID
	case view.Account.UID != "":
		account += " (uid " + view.Account.UID + ")"
	}
	last := "none from you yet"
	if at, err := time.Parse(time.RFC3339, view.Cowork.LastEventAt); err == nil {
		last = at.Local().Format("2006-01-02 15:04 MST")
	}
	fmt.Fprintln(out, "This computer is managed by your organization.")
	fmt.Fprintf(out, "  Account       %s\n", account)
	if row, ok := view.Connectors["claudecode"]; ok {
		fmt.Fprintf(out, "  Claude Code   %s\n", ownStateText(row))
	} else if view.Connectors == nil {
		// Older gateways use the legacy Claude Code field and do not send
		// a connector roster.
		fmt.Fprintf(out, "  Claude Code   %s\n", ownStateText(ownStatusRow{Protected: view.ClaudeCode.Protected}))
	}
	names := make([]string, 0, len(view.Connectors))
	for name := range view.Connectors {
		if name != "claudecode" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		row := view.Connectors[name]
		fmt.Fprintf(out, "  %-13s %s\n", ownConnectorLabel(name), ownStateText(row))
	}
	fmt.Fprintf(out, "  Cowork        %s\n", ownStateText(view.Cowork.ownStatusRow))
	fmt.Fprintf(out, "  Last Cowork   %s\n", last)
	fmt.Fprintln(out)
	for _, line := range ownStatusNextSteps() {
		fmt.Fprintln(out, line)
	}
	return nil
}

// ownStateNoReason is what a row says when the gateway sent no reason for it:
// an older gateway sends a bare state (or none). A not-protected row always
// carries a reason and the next step, whatever the gateway sent.
const ownStateNoReason = "your gateway did not say why. Run defenseclaw status again in a few minutes, and ask IT if it stays this way"

// ownStateText is the text of one status row: the state followed by the
// reason and the next step the gateway sent, "protected" for a protected row
// with no text, and the bare "not protected" or "not confirmed" (or no state)
// completed with a generic reason and the next step. Any other state with no
// reason prints as sent.
func ownStateText(row ownStatusRow) string {
	state, reason, next := strings.TrimSpace(row.State), strings.TrimSpace(row.Reason), strings.TrimSpace(row.NextStep)
	switch {
	case state == "" && row.Protected:
		return "protected"
	case state == "":
		return "not protected: " + ownStateNoReason
	case reason == "" && (state == "not protected" || state == "not confirmed"):
		return state + ": " + ownStateNoReason
	case state == "blocked" && reason != "":
		// The reason is the whole sentence the administrator's status uses.
		text := strings.TrimRight(reason, ". ")
		if next != "" {
			text += ". " + strings.TrimRight(next, ". ")
		}
		return text
	case reason == "":
		return state
	}
	text := state + ": " + strings.TrimRight(reason, ". ")
	if next != "" {
		text += ". " + strings.TrimRight(next, ". ")
	}
	return text
}

func ownConnectorLabel(name string) string {
	switch name {
	case "opencode":
		return "OpenCode"
	case "openclaw":
		return "OpenClaw"
	case "claudecode":
		return "Claude Code"
	}
	if name == "" {
		return ""
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func writeOwnStatusJSON(w io.Writer, value map[string]any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return
	}
	fmt.Fprintln(w, string(encoded))
}
