// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func checkAIDefenseForPlatform(ctx context.Context, cfg *config.Config) (string, error) {
	return gateway.CheckStandaloneAIDefenseAs(ctx, cfg, windowsSecretGatewayAccount)
}

// loadSecretCheckConfig reads the installed config the check needs; tests
// replace it.
var (
	loadSecretCheckConfig = func() (*config.Config, error) {
		if err := requireWindowsSecretDeployment(); err != nil {
			return nil, err
		}
		cfg, err := loadWindowsEnterpriseStandaloneConfig("")
		if err != nil {
			return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, fmt.Errorf("cannot read the installed config: %w", err))
		}
		return cfg, nil
	}
)

func newEnterpriseSecretCheckCommand() *cobra.Command {
	opts := &enterpriseSecretOptions{}
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Prove the Cisco AI Defense key with one request that carries no content (elevated administrator or SYSTEM)",
		Long: `Make one authenticated request to Cisco AI Defense with the stored credential,
through the administrator's egress proxy, and report ok when the key is accepted,
rejected for HTTP 401 or 403, or unavailable:<code> when the credential or
request cannot be checked (credential_unavailable, unreachable,
proxy_auth_required, proxy_config, error). On Windows, enterprise windows status
reports inspection.ai_defense ok from gateway readiness alone; this proves the key.
The request carries a single full stop, no prompt or file text, and the
command changes and stores nothing. --name must be the credential that
enterprise.inspection.ai_defense.credential names. Exit codes: 0 when AI
Defense accepted the key, 1603 when it did not (errors[0].code names why),
1639 invalid arguments, 5 not elevated on a managed computer.`,
		Example:      `  & 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe' enterprise secret check --name ai-defense-api-key --json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseSecretCheck(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.name, "name", "", "the AI Defense credential (the name enterprise.inspection.ai_defense.credential gives)")
	_ = cmd.MarkFlagRequired("name")
	cmd.Flags().BoolVar(&opts.json, "json", false, "print JSON")
	flagError := func(c *cobra.Command, err error) error {
		return reportWindowsSecretFailure(c, "check", opts, lifecycleFlagError(c, err), opts.json || secretArgsRequestJSON(secretRawArgs()))
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
		return reportWindowsSecretFailure(cmd, "check", opts, err, opts.json)
	}
	if err := windowsSecretElevation("check", opts); err != nil {
		return fail(err)
	}
	if !managed.ValidCredentialName(opts.name) {
		return fail(lifecycleFlagError(cmd, fmt.Errorf("--name takes 1 to 63 lowercase letters, digits and dashes, starting with a letter or digit; not %q", opts.name)))
	}
	cfg, err := loadSecretCheckConfig()
	if err != nil {
		return fail(err)
	}
	if want := cfg.Enterprise.Inspection.AIDefense.Credential; want != opts.name {
		return fail(lifecycleFlagError(cmd, fmt.Errorf("--name %s is not the Cisco AI Defense credential; enterprise.inspection.ai_defense.credential names %q", opts.name, want)))
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), secretCheckTimeout)
	defer cancel()
	posture, err := checkAIDefense(ctx, cfg)
	if err != nil {
		return fail(secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err))
	}
	return printSecretCheck(cmd, opts, posture, windowsSecretExitFailure, true)
}
