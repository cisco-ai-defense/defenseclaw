// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	Cowork struct {
		Protected   bool   `json:"protected"`
		State       string `json:"state"`
		LastEventAt string `json:"last_event_at"`
	} `json:"cowork"`
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
	for _, line := range ownStatusNextSteps() {
		fmt.Fprintln(out, line)
	}
	return nil
}

func writeOwnStatusJSON(w io.Writer, value map[string]any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return
	}
	fmt.Fprintln(w, string(encoded))
}
