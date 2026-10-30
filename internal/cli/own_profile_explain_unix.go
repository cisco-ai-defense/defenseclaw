// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ownProfileExplain asks the managed gateway on the hook socket for the
// caller's own guardrail profile, and ownProfileExplainSocket names that
// socket; seams for tests.
var (
	ownProfileExplain       = managed.ExplainOwnProfile
	ownProfileExplainSocket = managedRefusalSocket
)

// explainOwnGuardrailProfile answers a standard user's profile explain on a
// managed Linux or macOS computer. profile-explain reads the administrator's
// deployment with the service token, so a standard user was refused
// (elevation_required) and could not see the profile the hooks apply to
// them (GAP-0431, GAP-0422). The gateway explains the hook socket's
// kernel-verified caller instead: own profile only, decided there (owner
// rule: users see only their own policy). user is empty for the caller, or
// the caller's own spelling; the gateway refuses any other account, and
// refusal (which names the administrator command) is then the answer, as
// unavailable is when this computer names no hook socket.
func explainOwnGuardrailProfile(cmd *cobra.Command, user, connectorName, agent string, refusal, unavailable error, asJSON bool) error {
	socket := ownProfileExplainSocket()
	if socket == "" {
		return managedAdminViewRefusal(cmd, unavailable, asJSON)
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	status, body, err := ownProfileExplain(ctx, socket, strings.TrimSpace(user), connectorName, agent)
	if err != nil {
		return withExitCode(fmt.Errorf("the managed gateway did not explain your guardrail profile (%v); try again, and if it keeps failing contact your IT help desk", err), enterprisestatus.UnixExitFailure)
	}
	var refused struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if status == http.StatusForbidden && json.Unmarshal(body, &refused) == nil && refused.Error == "own_profile_only" {
		return managedAdminViewRefusal(cmd, fmt.Errorf("%s: %w", refused.Message, refusal), asJSON)
	}
	if status != http.StatusOK || !json.Valid(body) {
		return withExitCode(fmt.Errorf("the managed gateway did not explain your guardrail profile (HTTP %d): %s", status, strings.TrimSpace(string(body))), enterprisestatus.UnixExitFailure)
	}
	answer := json.RawMessage(body)
	if err := printEnterpriseIdentityView(cmd.OutOrStdout(), answer); err != nil {
		return err
	}
	if lookupErr := unresolvedProfileExplainAccount(answer); lookupErr != "" {
		failure := withExitCode(fmt.Errorf("user lookup failed: %s", lookupErr), enterprisestatus.UnixExitFailure)
		silenceJSONReportedError(cmd, asJSON, failure)
		return failure
	}
	return nil
}

// newLauncherGuardrailCommand is the launcher's `guardrail profile explain`:
// the guardrail profile that applies to the standard user, as the managed
// gateway explains it (explainOwnGuardrailProfile). It is the only guardrail
// command a managed computer offers its users, and it is left out of the
// launcher's command list, which stays the sandbox tree; the help text names
// it.
func newLauncherGuardrailCommand() *cobra.Command {
	var user, connectorName, agent string
	var asJSON bool
	explain := &cobra.Command{
		Use:   "explain",
		Short: "Show the guardrail profile that applies to you, and why (read-only)",
		Long: `Show the guardrail profile your organization's policy applies to your agents
on this computer, and why. It prints the managed gateway's JSON answer and
changes nothing. You can explain only your own profile; an administrator
explains other accounts.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			refusal := fmt.Errorf("an administrator runs `sudo %s enterprise %s profile-explain --user <account>`", managedHostGatewayCommand(), managedHostPlatform())
			unavailable := errors.New("the managed gateway's hook socket is not available on this computer; contact your IT help desk")
			return explainOwnGuardrailProfile(cmd, user, connectorName, agent, refusal, unavailable, asJSON)
		},
	}
	explain.Flags().StringVar(&user, "user", "", "your account name or uid (the default); other accounts are for administrators")
	explain.Flags().StringVar(&connectorName, "connector", "", "connector name, for example codex")
	explain.Flags().StringVar(&agent, "agent", "", "agent identity (agt- and 16 hex digits)")
	explain.Flags().BoolVar(&asJSON, "json", false, "print JSON (the default); a refusal is printed as JSON too")
	profile := &cobra.Command{Use: "profile", Short: "Your guardrail profile", Args: cobra.NoArgs}
	profile.AddCommand(explain)
	guardrail := &cobra.Command{Use: "guardrail", Short: "Your guardrail profile on this managed computer", Hidden: true, Args: cobra.NoArgs}
	guardrail.AddCommand(profile)
	return guardrail
}
