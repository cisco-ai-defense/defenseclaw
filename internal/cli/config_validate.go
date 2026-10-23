// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

var (
	configValidatePath    string
	configValidateDataDir string
	configValidateJSON    bool
)

// configValidateCmd checks a candidate config.yaml with the compiler and the
// runtime loader the gateway runs at start, so an administrator learns before
// applying it whether a guardrail profile, a sandbox floor or any other
// setting would be refused. It is read-only: it starts nothing, opens no
// database and contacts no destination (GAP-0252).
var configValidateCmd = &cobra.Command{
	Use:   "validate [config.yaml]",
	Short: "Check a config.yaml the way the gateway loads it, without changing anything",
	Long: "Compiles the file with the strict compiler and the runtime loader the gateway runs at start: the schema, " +
		"guardrail profiles and assignments, every profile's sandbox floor combined with openshell.admin, " +
		"the rule packs and the observability destinations. Exits 0 when the gateway could load it. " +
		"A refusal names the setting and the profile. It changes nothing.",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := strings.TrimSpace(configValidatePath)
		if len(args) == 1 {
			path = strings.TrimSpace(args[0])
		}
		dataDir := strings.TrimSpace(configValidateDataDir)
		loaded, err := checkConfigV8Candidate(path, dataDir)
		var derivationErr error
		if err == nil {
			// The gateway derives every profile's policy and sandbox floor
			// (pack digests included) at load and on every reload.
			_, derivationErr = loaded.runtime.DeriveGuardrailProfiles()
		}
		out := cmd.OutOrStdout()
		if err != nil || derivationErr != nil {
			failure := configV8ValidationFailure(err)
			if derivationErr != nil {
				failure.Path = "$.guardrail.profiles"
				failure.Reason = configV8DiagnosticReason("config_semantic_invalid",
					configV8SettingRule(derivationErr.Error()), "", "")
				failure.ConfigVersion = loaded.runtime.ConfigVersion
			}
			refusal := err
			if derivationErr != nil {
				refusal = derivationErr
			}
			plain, managedHost := configValidatePlainRefusal(refusal, failure, configValidateShownPath(path), path)
			if managedHost {
				failure.Message = plain
			}
			if configValidateJSON {
				_ = json.NewEncoder(out).Encode(failure)
			}
			if managedHost {
				return errors.New(plain)
			}
			return fmt.Errorf("%s is not valid at %s: %s", configValidateShownPath(path), failure.Path, failure.Reason)
		}
		warnings := append(gateway.ConfigHILTWarnings(loaded.runtime), loaded.runtime.SandboxDefaultProfileWarnings()...)
		warnings = append(warnings, configV8InstalledAdvisories(loaded)...)
		if configValidateJSON {
			valid := true
			encoder := json.NewEncoder(out)
			encoder.SetEscapeHTML(false)
			return encoder.Encode(configV8WireResponse{
				WireVersion: configV8WireVersion, Kind: "validation", ConfigVersion: loaded.runtime.ConfigVersion,
				Source: loaded.source, DataDir: loaded.compiled.DataDir, GatewayAPIPort: loaded.gatewayAPIPort,
				PlanDigest: loaded.compiled.Plan.Digest(), NetworkValidation: "offline_syntax_and_literal_policy_only",
				Valid: &valid, Warnings: warnings,
			})
		}
		fmt.Fprintf(out, "%s: valid (config_version %d)\n", loaded.source, loaded.runtime.ConfigVersion)
		for _, warning := range warnings {
			fmt.Fprintf(out, "warning: %s\n", warning)
		}
		return nil
	},
}

func configValidateShownPath(path string) string {
	if path == "" {
		return config.ConfigPath()
	}
	return path
}

func init() {
	configValidateCmd.Flags().StringVar(&configValidatePath, "config", "", "config.yaml (default: the installed config)")
	configValidateCmd.Flags().StringVar(&configValidateDataDir, "data-dir", "", "default data directory when data_dir is omitted from the source")
	configValidateCmd.Flags().BoolVar(&configValidateJSON, "json", false, "print the result as JSON")
	configCmd.AddCommand(configValidateCmd)
}
