// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ownStatusFetch asks the managed gateway on the hook socket for the
// caller's own protection state; a seam for tests.
var ownStatusFetch = managed.OwnStatus

// statusShowsOwnState is Windows only (GAP-0060): on Linux and macOS a
// standard user's `defenseclaw` is the launcher, whose own `status`
// (newLauncherStatusCommand) shows their state.
var statusShowsOwnState = func() bool { return false }

// newLauncherStatusCommand is the launcher's `status`: the standard user's
// own protection state on a managed computer, which `defenseclaw status`
// refused (cowork-1-0-8 GAP-0053). It reads only the caller's own state from
// the managed gateway's hook socket, which answers for the kernel-verified
// caller (owner rule: users see only their own policy and state).
func newLauncherStatusCommand() *cobra.Command {
	var asJSON bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show whether DefenseClaw protects your Claude Code and Cowork sessions and other managed connectors",
		Long: `Show whether DefenseClaw, managed by your organization on this computer,
protects your configured connectors and Claude Cowork sessions, and when your
last Cowork event was. It reads only your own state and changes nothing;
administrator status and verify show deployment-wide coverage.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return showOwnStatus(cmd, asJSON)
		},
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return status
}

// readOwnStatus reads the caller's own state from the hook socket, which
// the gateway answers for the socket's kernel-verified peer.
func readOwnStatus(ctx context.Context) ([]byte, error) {
	socket := ownProfileExplainSocket()
	if socket == "" {
		return nil, errors.New("this computer is managed, but the managed gateway's hook socket is not available; contact your IT help desk")
	}
	code, body, err := ownStatusFetch(ctx, socket)
	if err != nil {
		return nil, fmt.Errorf("the managed gateway did not answer (%v); try again, and if it keeps failing contact your IT help desk", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("the managed gateway did not report your status (HTTP %d): %s", code, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// ownStatusNextSteps are the launcher's own views that follow the state.
func ownStatusNextSteps() []string {
	return []string{
		"Your guardrail profile: defenseclaw guardrail profile explain",
		"Your sandboxes:         defenseclaw sandbox status",
	}
}
