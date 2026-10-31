// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// secretCheckTimeout bounds the one request of `secret check`.
const secretCheckTimeout = 20 * time.Second

// checkAIDefense is the check itself (the same probe and client the gateway
// builds); tests replace it. On Windows the lifecycle status reports
// inspection.ai_defense ok from gateway readiness alone, so this is the one
// way to prove the key there (rel-1-0-6:GAP-0036).
var checkAIDefense = gateway.CheckStandaloneAIDefense

// secretCheckResult is the `enterprise secret check --json` document
// (packaging/mdm/contract/secret-result.schema.json, check result branch).
type secretCheckResult struct {
	SchemaVersion int                        `json:"schema_version"`
	OK            bool                       `json:"ok"`
	Action        string                     `json:"action"`
	Name          string                     `json:"name"`
	AIDefense     string                     `json:"ai_defense"`
	Errors        []enterprisestatus.Message `json:"errors"`
	ExitCode      int                        `json:"exit_code"`
}

// printSecretCheck reports the outcome of the request. failureExit is the
// exit of a key AI Defense did not accept: 1 on Linux and macOS, 1603 on
// Windows. quietJSON keeps the error line off stderr after a --json
// document, as every other Windows secret failure does; Linux and macOS
// keep it (their MDM wrapper quotes it).
func printSecretCheck(cmd *cobra.Command, opts *enterpriseSecretOptions, posture string, failureExit int, quietJSON bool) error {
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
		res.ExitCode = failureExit
		failure = withExitCode(errors.New(res.Errors[0].Message), res.ExitCode)
	}
	if opts.json {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(res); err != nil {
			return err
		}
		silenceJSONReportedError(cmd, quietJSON, failure)
		return failure
	}
	if res.OK {
		fmt.Fprintf(cmd.OutOrStdout(), "Cisco AI Defense accepted the stored key %s.\n", opts.name)
		return nil
	}
	return failure
}
