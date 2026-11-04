// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ownStatusFetch asks the managed gateway on the hook socket for the
// caller's own protection state; a seam for tests.
var ownStatusFetch = managed.OwnStatus

// ownStatusView is the gateway's own-status answer (handleOwnStatus).
type ownStatusView struct {
	Account struct {
		UID  string `json:"uid"`
		Name string `json:"name"`
	} `json:"account"`
	ClaudeCode struct {
		Protected bool `json:"protected"`
	} `json:"claude_code"`
	Cowork struct {
		Protected   bool   `json:"protected"`
		State       string `json:"state"`
		LastEventAt string `json:"last_event_at"`
	} `json:"cowork"`
}

// newLauncherStatusCommand is the launcher's `status`: the standard user's
// own protection state on a managed computer, which `defenseclaw status`
// refused (cowork-1-0-8 GAP-0053). It reads only the caller's own state from
// the managed gateway's hook socket, which answers for the kernel-verified
// caller (owner rule: users see only their own policy and state).
func newLauncherStatusCommand() *cobra.Command {
	var asJSON bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show whether DefenseClaw protects your Claude Code and Cowork sessions (read-only)",
		Long: `Show whether DefenseClaw, managed by your organization on this computer,
protects your Claude Code and Claude Cowork sessions, and when your last Cowork
event was. It reads only your own state and changes nothing; an administrator
sees every account.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return showOwnStatus(cmd, asJSON)
		},
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return status
}

// showOwnStatus prints the caller's own protection state. The JSON always
// carries deployment_mode managed_enterprise, which tells an agent following
// the quickstart that the computer is managed, as the refusal did.
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
	socket := ownProfileExplainSocket()
	if socket == "" {
		return fail(errors.New("this computer is managed, but the managed gateway's hook socket is not available; contact your IT help desk"))
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	code, body, err := ownStatusFetch(ctx, socket)
	if err != nil {
		return fail(fmt.Errorf("the managed gateway did not answer (%v); try again, and if it keeps failing contact your IT help desk", err))
	}
	var answer map[string]any
	var view ownStatusView
	if code != http.StatusOK || json.Unmarshal(body, &answer) != nil || json.Unmarshal(body, &view) != nil {
		return fail(fmt.Errorf("the managed gateway did not report your status (HTTP %d): %s", code, strings.TrimSpace(string(body))))
	}
	if asJSON {
		answer["deployment_mode"] = "managed_enterprise"
		writeOwnStatusJSON(out, answer)
		return nil
	}
	account := view.Account.Name
	if account == "" {
		account = "uid " + view.Account.UID
	} else if view.Account.UID != "" {
		account += " (uid " + view.Account.UID + ")"
	}
	protected := func(on bool) string {
		if on {
			return "protected"
		}
		return "not protected"
	}
	last := "none from you yet"
	if at, err := time.Parse(time.RFC3339, view.Cowork.LastEventAt); err == nil {
		last = at.Local().Format("2006-01-02 15:04 MST")
	}
	fmt.Fprintln(out, "This computer is managed by your organization.")
	fmt.Fprintf(out, "  Account       %s\n", account)
	fmt.Fprintf(out, "  Claude Code   %s\n", protected(view.ClaudeCode.Protected))
	fmt.Fprintf(out, "  Cowork        %s\n", view.Cowork.State)
	fmt.Fprintf(out, "  Last Cowork   %s\n", last)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Your guardrail profile: defenseclaw guardrail profile explain")
	fmt.Fprintln(out, "Your sandboxes:         defenseclaw sandbox status")
	return nil
}

func writeOwnStatusJSON(w io.Writer, value map[string]any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return
	}
	fmt.Fprintln(w, string(encoded))
}
