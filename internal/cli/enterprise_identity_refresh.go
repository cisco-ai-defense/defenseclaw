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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// `enterprise identity refresh`: a root or SYSTEM management
// agent asks the managed gateway to re-read directory facts now, for one
// account or every account the gateway has cached, and learns which
// accounts now get another guardrail profile. Order: the privilege check
// comes first, before any account name is resolved; then the optional OS
// cache flush (only the named account with --user); then the gateway call.
// Account names are printed to the root caller only; the gateway audit row
// carries counts.

const (
	identityRefreshSchemaVersion   = 1
	identityRefreshGatewayPath     = "/api/v1/identity/refresh"
	identityRefreshDefaultMaxUsers = 500
	identityRefreshMaxUsersCap     = 4096
)

// Seams, replaced in tests and per platform.
var (
	// identityRefreshPrivileged reports root (Linux, macOS) or an elevated
	// administrator or SYSTEM (Windows).
	identityRefreshPrivileged = identityRefreshPlatformPrivileged
	// identityRefreshResolveUser resolves --user to the uid or SID the
	// gateway takes, and the account name the OS cache flush needs.
	identityRefreshResolveUser = identityRefreshPlatformResolveUser
	// identityRefreshFlushOSCache flushes the OS directory cache: of the
	// named account only when name is set, else all of it.
	identityRefreshFlushOSCache = identityRefreshPlatformFlushOSCache
	identityRefreshPost         = enterpriseGatewayPost
	identityRefreshSecureClient = func() bool { return secureClientHost() }
)

type identityRefreshOptions struct {
	user         string
	flushOSCache bool
	maxUsers     int
	json         bool
}

// identityRefreshFlush is what the OS cache flush did.
type identityRefreshFlush struct {
	Requested bool `json:"requested"`
	// Flushed is none, user or all.
	Flushed string `json:"flushed"`
	// Method is the command that ran: sss_cache or dscacheutil.
	Method string `json:"method,omitempty"`
	// Reason says why nothing was flushed: not_sssd, no_per_user_flush,
	// windows_token_groups or failed.
	Reason string `json:"reason,omitempty"`
}

type identityRefreshAccountView struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name,omitempty"`
}

type identityRefreshChangeView struct {
	UserID          string `json:"user_id"`
	UserName        string `json:"user_name,omitempty"`
	Connector       string `json:"connector,omitempty"`
	PreviousProfile string `json:"previous_profile"`
	PreviousMatch   string `json:"previous_match"`
	Profile         string `json:"profile"`
	Match           string `json:"match"`
	Refused         bool   `json:"refused,omitempty"`
}

type identityRefreshFailureView struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name,omitempty"`
	Code     string `json:"code"`
}

// identityRefreshAnswer is the gateway answer (internal/gateway/identity_refresh.go).
type identityRefreshAnswer struct {
	Scope                     string                       `json:"scope"`
	ProfilesConfigured        bool                         `json:"profiles_configured"`
	Refreshed                 int                          `json:"refreshed"`
	Changed                   int                          `json:"changed"`
	Failed                    int                          `json:"failed"`
	Skipped                   int                          `json:"skipped"`
	Changes                   []identityRefreshChangeView  `json:"changes"`
	Failures                  []identityRefreshFailureView `json:"failures"`
	WindowsTokenGroupsPending []identityRefreshAccountView `json:"windows_token_groups_pending,omitempty"`
	DurationMS                int64                        `json:"duration_ms"`
}

// identityRefreshResult is the --json document (identity-refresh.schema.json).
type identityRefreshResult struct {
	SchemaVersion int  `json:"schema_version"`
	OK            bool `json:"ok"`
	*identityRefreshAnswer
	OSCacheFlush *identityRefreshFlush      `json:"os_cache_flush,omitempty"`
	Warnings     []enterprisestatus.Message `json:"warnings"`
	Errors       []enterprisestatus.Message `json:"errors"`
	ExitCode     int                        `json:"exit_code"`
}

func init() {
	enterpriseCmd.AddCommand(newEnterpriseIdentityCommand())
}

func newEnterpriseIdentityCommand() *cobra.Command {
	group := &cobra.Command{
		Use:   "identity",
		Short: "Re-read the directory facts of a standalone managed deployment",
		// Secure Client computers keep the command tree of main.
		Annotations:       map[string]string{secureClientAbsentAnnotation: "true"},
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	}
	group.AddCommand(newEnterpriseIdentityRefreshCommand())
	return group
}

func newEnterpriseIdentityRefreshCommand() *cobra.Command {
	opts := &identityRefreshOptions{}
	cmd := &cobra.Command{
		Use:   "refresh",
		Short: "Re-read directory facts now and report the accounts whose guardrail profile changed",
		Long: `Re-read directory facts (groups, UPN) now, for one account (--user) or for
every account the managed gateway has cached (at most --max-users), and
report the accounts whose guardrail profile changed. Hook calls use the new
facts from their next call.

--flush-os-cache first drops the operating system cache: on Linux with SSSD
sss_cache -u for --user, or sss_cache -E without it; on macOS
dscacheutil -flushcache and dsmemberutil flushcache, without --user only
(macOS has no per-account flush). Windows takes groups from the sign-in
token: a signed-in account gets a directory group change at its next
sign-in, and the result lists such accounts in windows_token_groups_pending.

Run as root on Linux and macOS, or from an elevated administrator prompt or
as SYSTEM on Windows; any other account is refused with not_admin. Account
names appear only in this output; telemetry gets counts.

Exit codes: 0 done, 1 failure (1603 on Windows), 2 invalid arguments (1639),
75 another refresh is running (1618).`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseIdentityRefresh(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.user, "user", "", "only this account (name, uid or SID)")
	cmd.Flags().BoolVar(&opts.flushOSCache, "flush-os-cache", false, "flush the OS directory cache first (only the --user account when given)")
	cmd.Flags().IntVar(&opts.maxUsers, "max-users", identityRefreshDefaultMaxUsers, fmt.Sprintf("re-read at most this many cached accounts (1 to %d)", identityRefreshMaxUsersCap))
	cmd.Flags().BoolVar(&opts.json, "json", false, "print the result as JSON")
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	return cmd
}

func identityRefreshFailureExit() int {
	if runtime.GOOS == "windows" {
		return enterprisestatus.WindowsExitFailure
	}
	return enterprisestatus.UnixExitFailure
}

func runEnterpriseIdentityRefresh(cmd *cobra.Command, opts *identityRefreshOptions) error {
	res := &identityRefreshResult{SchemaVersion: identityRefreshSchemaVersion,
		Warnings: []enterprisestatus.Message{}, Errors: []enterprisestatus.Message{}}
	fail := func(code, message string, exit int) error {
		res.Errors = append(res.Errors, enterprisestatus.Message{Code: code, Message: message})
		res.ExitCode = exit
		return printIdentityRefresh(cmd, opts, res, withExitCode(errors.New(code+": "+message), exit))
	}
	// Refuse first: a standard user learns nothing about any account.
	if !identityRefreshPrivileged() {
		message := "run this command as root"
		if runtime.GOOS == "windows" {
			message = "run this command from an elevated administrator prompt or as SYSTEM"
		}
		return fail("not_admin", message, identityRefreshFailureExit())
	}
	if identityRefreshSecureClient() {
		return fail("not_supported_secure_client", "identity refresh is not available with the Secure Client integration", identityRefreshFailureExit())
	}
	if opts.maxUsers < 1 || opts.maxUsers > identityRefreshMaxUsersCap {
		return fail("invalid_arguments", fmt.Sprintf("--max-users must be from 1 to %d", identityRefreshMaxUsersCap), enterprisestatus.InvalidArgsExitCode(runtime.GOOS))
	}
	key, name := "", ""
	if opts.user != "" {
		var err error
		if key, name, err = identityRefreshResolveUser(opts.user); err != nil {
			return fail("account_unresolved", err.Error(), enterprisestatus.InvalidArgsExitCode(runtime.GOOS))
		}
	}
	flushed := "none"
	if opts.flushOSCache {
		flush, warning := identityRefreshFlushOSCache(name)
		flush.Requested = true
		res.OSCacheFlush = &flush
		flushed = flush.Flushed
		if warning != nil {
			res.Warnings = append(res.Warnings, *warning)
		}
	}
	body, err := json.Marshal(map[string]any{"user": key, "max_users": opts.maxUsers, "os_cache_flushed": flushed})
	if err != nil {
		return fail("internal_error", err.Error(), identityRefreshFailureExit())
	}
	runtimeCommand = cmd
	answer := &identityRefreshAnswer{}
	if _, err := identityRefreshPost(identityRefreshGatewayPath, body, answer); err != nil {
		var refusal *enterpriseGatewayRefusal
		switch {
		case errors.As(err, &refusal) && refusal.code == "refresh_busy":
			return fail("refresh_busy", refusal.Error(), enterprisestatus.BusyExitCode(runtime.GOOS))
		case errors.As(err, &refusal) && refusal.code == "invalid_arguments":
			return fail("invalid_arguments", refusal.Error(), enterprisestatus.InvalidArgsExitCode(runtime.GOOS))
		case errors.As(err, &refusal) && refusal.code == "not_managed",
			errors.As(err, &refusal) && refusal.status == http.StatusNotFound:
			return fail("not_managed", "identity refresh runs on a standalone managed deployment only", identityRefreshFailureExit())
		default:
			return fail("gateway_unavailable", err.Error(), identityRefreshFailureExit())
		}
	}
	res.identityRefreshAnswer = answer
	if answer.Changes == nil {
		answer.Changes = []identityRefreshChangeView{}
	}
	if answer.Failures == nil {
		answer.Failures = []identityRefreshFailureView{}
	}
	if len(answer.WindowsTokenGroupsPending) > 0 {
		res.Warnings = append(res.Warnings, enterprisestatus.Message{Code: "windows_token_groups_pending",
			Message: fmt.Sprintf("%d account(s) take groups from their sign-in token: a directory group change reaches them at their next sign-in", len(answer.WindowsTokenGroupsPending))})
	}
	if answer.Skipped > 0 {
		res.Warnings = append(res.Warnings, enterprisestatus.Message{Code: "accounts_skipped",
			Message: fmt.Sprintf("%d cached account(s) were not re-read (--max-users %d)", answer.Skipped, opts.maxUsers)})
	}
	if answer.Failed > 0 {
		if answer.Scope == "user" {
			return fail("lookup_failed", "the directory lookup of the account failed; its hook calls keep the facts cached before", identityRefreshFailureExit())
		}
		res.Warnings = append(res.Warnings, enterprisestatus.Message{Code: "accounts_failed",
			Message: fmt.Sprintf("the directory lookup of %d account(s) failed; their hook calls keep the facts cached before", answer.Failed)})
	}
	res.OK, res.ExitCode = true, enterprisestatus.ExitOK
	return printIdentityRefresh(cmd, opts, res, nil)
}

func printIdentityRefresh(cmd *cobra.Command, opts *identityRefreshOptions, res *identityRefreshResult, failure error) error {
	if opts.json {
		if err := newEnterpriseJSONEncoder(cmd.OutOrStdout()).Encode(res); err != nil {
			return err
		}
		silenceJSONReportedError(cmd, true, failure)
		return failure
	}
	if failure != nil {
		return failure
	}
	writeIdentityRefreshText(cmd.OutOrStdout(), res)
	return nil
}

func writeIdentityRefreshText(w io.Writer, res *identityRefreshResult) {
	answer := res.identityRefreshAnswer
	if flush := res.OSCacheFlush; flush != nil {
		if flush.Flushed == "none" {
			fmt.Fprintf(w, "OS directory cache: not flushed (%s)\n", flush.Reason)
		} else {
			fmt.Fprintf(w, "OS directory cache: flushed (%s, %s)\n", flush.Flushed, flush.Method)
		}
	}
	fmt.Fprintf(w, "Re-read %d account(s): %d changed, %d failed, %d skipped (%d ms)\n",
		answer.Refreshed, answer.Changed, answer.Failed, answer.Skipped, answer.DurationMS)
	for _, change := range answer.Changes {
		account := change.UserName
		if account == "" {
			account = change.UserID
		}
		scope := ""
		if change.Connector != "" {
			scope = " (" + change.Connector + ")"
		}
		fmt.Fprintf(w, "  %s%s: %s -> %s (%s)\n", account, scope, identityRefreshProfileName(change.PreviousProfile), identityRefreshProfileName(change.Profile), change.Match)
	}
	for _, failure := range answer.Failures {
		fmt.Fprintf(w, "  %s: %s\n", failure.UserID, failure.Code)
	}
	for _, warning := range res.Warnings {
		fmt.Fprintf(w, "Warning: %s\n", warning.Message)
	}
}

func identityRefreshProfileName(name string) string {
	if name == "" {
		return "(none)"
	}
	return name
}
