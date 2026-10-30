// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// secretCheckTimeout bounds the one request of `secret check`.
const secretCheckTimeout = 20 * time.Second

// checkAIDefense is the check itself, and loadInstalledConfig reads the
// config it needs; tests replace both.
var (
	checkAIDefense      = gateway.CheckStandaloneAIDefense
	loadInstalledConfig = func(env *enterpriseunix.Env) (*config.Config, error) { return env.InstalledConfig() }
)

// secretCheckResult is the `enterprise secret check --json` document
// (packaging/mdm/contract/secret-check.schema.json).
type secretCheckResult struct {
	SchemaVersion int                        `json:"schema_version"`
	OK            bool                       `json:"ok"`
	Action        string                     `json:"action"`
	Name          string                     `json:"name"`
	AIDefense     string                     `json:"ai_defense"`
	Errors        []enterprisestatus.Message `json:"errors"`
	ExitCode      int                        `json:"exit_code"`
}

func newEnterpriseSecretCheckCommand() *cobra.Command {
	opts := &enterpriseSecretOptions{}
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Prove the Cisco AI Defense key with one request that carries no content (root, Linux and macOS)",
		Long: `Make one authenticated request to Cisco AI Defense with the stored credential,
through the administrator's egress proxy, and report what inspection.ai_defense
reports once a prompt has been inspected: ok, or unavailable:<code> (auth_failed,
credential_unavailable, unreachable, proxy_auth_required, proxy_config, error).
Today a device reports unknown until the first prompt is inspected. The request
carries a single full stop, no prompt or file text, and the command changes and
stores nothing. --name must be the credential that
enterprise.inspection.ai_defense.credential names. Exit codes: 0 when AI Defense
accepted the key, 1 when it did not (errors[0].code names why), 2 invalid arguments.`,
		Example:      `  sudo defenseclaw-gateway enterprise secret check --name ai-defense-api-key --json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseSecretCheck(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.name, "name", "", "the AI Defense credential (the name enterprise.inspection.ai_defense.credential gives)")
	_ = cmd.MarkFlagRequired("name")
	cmd.Flags().BoolVar(&opts.json, "json", false, "print JSON")
	flagError := func(c *cobra.Command, err error) error {
		return reportSecretFailure(c, "check", opts, lifecycleFlagError(c, err), opts.json || secretArgsRequestJSON(secretRawArgs()),
			enterprisestatus.UnixExitFailure, enterprisestatus.UnixExitInvalidArgs)
	}
	cmd.SetFlagErrorFunc(flagError)
	cmd.Args = func(c *cobra.Command, args []string) error {
		if err := strayArgumentError(c, args); err != nil {
			return flagError(c, err)
		}
		return nil
	}
	cmd.PreRunE = func(c *cobra.Command, _ []string) error {
		if err := c.ValidateRequiredFlags(); err != nil {
			return flagError(c, err)
		}
		return nil
	}
	return cmd
}

func runEnterpriseSecretCheck(cmd *cobra.Command, opts *enterpriseSecretOptions) error {
	fail := func(err error) error {
		return reportSecretFailure(cmd, "check", opts, err, opts.json, enterprisestatus.UnixExitFailure, enterprisestatus.UnixExitInvalidArgs)
	}
	env, err := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
	if err != nil {
		return fail(withExitCode(err, enterprisestatus.UnixExitFailure))
	}
	if env.Geteuid() != 0 {
		return fail(secretFailed("not_root", enterprisestatus.UnixExitFailure,
			fmt.Errorf("the credential is root-only; run: sudo %s enterprise secret check --name %s", filepath.Join(env.Layout.BinDir, "defenseclaw-gateway"), opts.name)))
	}
	if !managed.ValidCredentialName(opts.name) {
		return fail(lifecycleFlagError(cmd, fmt.Errorf("--name takes 1 to 63 lowercase letters, digits and dashes, starting with a letter or digit; not %q", opts.name)))
	}
	cfg, err := loadInstalledConfig(env)
	if errors.Is(err, fs.ErrNotExist) {
		return fail(secretFailed("not_installed", enterprisestatus.UnixExitFailure, errors.New("DefenseClaw enterprise is not installed")))
	}
	if err != nil {
		return fail(secretFailed(codeStateInvalid, enterprisestatus.UnixExitFailure, fmt.Errorf("cannot read the installed config: %w", err)))
	}
	if want := cfg.Enterprise.Inspection.AIDefense.Credential; want != opts.name {
		return fail(lifecycleFlagError(cmd, fmt.Errorf("--name %s is not the Cisco AI Defense credential; enterprise.inspection.ai_defense.credential names %q", opts.name, want)))
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), secretCheckTimeout)
	defer cancel()
	posture, err := checkAIDefense(ctx, cfg)
	if err != nil {
		return fail(secretFailed(codeStateInvalid, enterprisestatus.UnixExitFailure, err))
	}
	return printSecretCheck(cmd, opts, posture)
}

// codeStateInvalid is the code of a check that could not read the installed
// state, as the other secret verbs name it.
const codeStateInvalid = "state_invalid"

func printSecretCheck(cmd *cobra.Command, opts *enterpriseSecretOptions, posture string) error {
	res := secretCheckResult{SchemaVersion: 1, OK: posture == "ok", Action: "check", Name: opts.name, AIDefense: posture, Errors: []enterprisestatus.Message{}}
	var failure error
	switch {
	case posture == "disabled":
		res.Errors = append(res.Errors, enterprisestatus.Message{Code: "ai_defense_disabled",
			Message: "enterprise.inspection.ai_defense is off, so nothing uses this credential"})
	case posture != "ok":
		res.Errors = append(res.Errors, enterprisestatus.Message{Code: "ai_defense_unavailable",
			Message: "Cisco AI Defense did not accept the stored key (" + posture + "); the local policy engine keeps deciding"})
	}
	if !res.OK {
		res.ExitCode = enterprisestatus.UnixExitFailure
		failure = withExitCode(errors.New(res.Errors[0].Message), res.ExitCode)
	}
	if opts.json {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(res); err != nil {
			return err
		}
		silenceJSONReportedError(cmd, false, failure)
		return failure
	}
	if res.OK {
		fmt.Fprintf(cmd.OutOrStdout(), "Cisco AI Defense accepted the stored key %s.\n", opts.name)
		return nil
	}
	return failure
}
