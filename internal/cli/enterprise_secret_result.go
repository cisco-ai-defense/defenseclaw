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
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// secretFailureResult is what `enterprise secret set|remove|status --json`
// prints when it fails without a lifecycle result: every Windows failure,
// and a Linux or macOS failure before the lifecycle ran (an argument, flag,
// privilege or value error). It is the failure branch of
// secret-result.schema.json; the value never appears in it.
type secretFailureResult struct {
	SchemaVersion    int                        `json:"schema_version"`
	OK               bool                       `json:"ok"`
	Action           string                     `json:"action"`
	Name             string                     `json:"name,omitempty"`
	GatewayRestarted bool                       `json:"gateway_restarted"`
	Errors           []enterprisestatus.Message `json:"errors"`
	ExitCode         int                        `json:"exit_code"`
}

// codeSecretChangeFailed is the code of a write or removal that did not
// happen, as the lifecycle reports a failed protected-state change.
const codeSecretChangeFailed = "change_failed"

// secretRefusal names the errors[].code of a secret failure.
type secretRefusal struct {
	code string
	err  error
}

func (r *secretRefusal) Error() string { return r.err.Error() }
func (r *secretRefusal) Unwrap() error { return r.err }

func secretFailed(code string, exit int, err error) error {
	return withExitCode(&secretRefusal{code: code, err: err}, exit)
}

// secretRawArgs is the command line a flag error is read from: cobra stops
// parsing at the bad flag, so a later --json is not in opts.
var secretRawArgs = func() []string { return os.Args[1:] }

// reportSecretFailure prints the failure document of err when asJSON and
// returns err, labelled failureExit when nothing chose an exit code. An
// error without a code is invalid_arguments when it carries invalidExit and
// state_invalid otherwise. The error line still goes to stderr (the Linux
// and macOS MDM wrapper quotes it); Windows silences it.
func reportSecretFailure(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error, asJSON bool, failureExit, invalidExit int) error {
	err = withExitCode(err, failureExit)
	if !asJSON {
		return err
	}
	exit := commandExitCode(err)
	code := secretFailureCode(err, invalidExit)
	result := secretFailureResult{SchemaVersion: 1, Action: action, Name: opts.name,
		Errors: []enterprisestatus.Message{{Code: code, Message: err.Error()}}, ExitCode: exit}
	if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(result); encodeErr != nil {
		return encodeErr
	}
	return err
}

// secretArgsRequestJSON reports whether a command line passes --json
// before any "--".
func secretArgsRequestJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--json" {
			return true
		}
		if value, ok := strings.CutPrefix(arg, "--json="); ok {
			on, err := strconv.ParseBool(value)
			return err == nil && on
		}
	}
	return false
}
