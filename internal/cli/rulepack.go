// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const rulePackWireVersion = 1

var safeRulePackWireCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type rulePackWireDiagnostic struct {
	Path   string `json:"path"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

type rulePackWireResponse struct {
	WireVersion int                        `json:"wire_version"`
	Kind        string                     `json:"kind"`
	Valid       bool                       `json:"valid"`
	Summary     *guardrail.RulePackSummary `json:"summary,omitempty"`
	Error       *rulePackWireDiagnostic    `json:"error,omitempty"`
}

var rulePackCmd = &cobra.Command{
	Use:    "rulepack",
	Short:  "Inspect a guardrail rule pack without starting the gateway",
	Hidden: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
}

var rulePackValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a guardrail rule pack",
	Args:  cobra.NoArgs,
	RunE:  runRulePackValidate,
}

var (
	rulePackValidateDir  string
	rulePackValidateJSON bool
)

func init() {
	rulePackValidateCmd.Flags().StringVar(
		&rulePackValidateDir,
		"dir",
		"",
		"rule-pack directory (empty validates embedded defaults)",
	)
	rulePackValidateCmd.Flags().BoolVar(
		&rulePackValidateJSON,
		"json",
		false,
		"emit a versioned machine-readable result",
	)
	rulePackCmd.AddCommand(rulePackValidateCmd)
	rootCmd.AddCommand(rulePackCmd)
}

func runRulePackValidate(cmd *cobra.Command, _ []string) error {
	rp, err := guardrail.LoadRulePack(rulePackValidateDir)
	if err != nil {
		diagnostic := rulePackDiagnostic(err)
		response := rulePackWireResponse{
			WireVersion: rulePackWireVersion,
			Kind:        "validation_error",
			Valid:       false,
			Error:       &diagnostic,
		}
		if writeErr := writeRulePackValidation(cmd.OutOrStdout(), response, rulePackValidateJSON); writeErr != nil {
			return errors.New("rule-pack validation failed and its safe diagnostic could not be written")
		}
		return fmt.Errorf("rule-pack validation failed [%s]", diagnostic.Code)
	}

	summary := rp.Summary()
	response := rulePackWireResponse{
		WireVersion: rulePackWireVersion,
		Kind:        "validation",
		Valid:       true,
		Summary:     &summary,
	}
	return writeRulePackValidation(cmd.OutOrStdout(), response, rulePackValidateJSON)
}

func writeRulePackValidation(w io.Writer, response rulePackWireResponse, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(response)
	}
	if response.Valid && response.Summary != nil {
		_, err := fmt.Fprintf(
			w,
			"valid rule pack: %d files, %d rules, digest %s\n",
			response.Summary.RuleFileCount,
			response.Summary.RuleCount,
			response.Summary.Digest,
		)
		return err
	}
	if response.Error == nil {
		return errors.New("rule-pack validator produced an incomplete response")
	}
	_, err := fmt.Fprintf(
		w,
		"invalid rule pack [%s] at %s: %s\n",
		response.Error.Code,
		response.Error.Path,
		response.Error.Reason,
	)
	return err
}

func rulePackDiagnostic(err error) rulePackWireDiagnostic {
	diagnostic := rulePackWireDiagnostic{
		Path:   "$",
		Code:   "rulepack_invalid",
		Reason: "rule pack could not be validated safely",
	}
	var packError *guardrail.RulePackError
	if errors.As(err, &packError) {
		diagnostic.Path = safeRulePackWireText(packError.Path, 512, "$")
		if safeRulePackWireCode.MatchString(packError.Code) {
			diagnostic.Code = packError.Code
		}
		diagnostic.Reason = safeRulePackWireText(
			packError.Reason,
			1_000,
			"rule pack could not be validated safely",
		)
	}
	return diagnostic
}

func safeRulePackWireText(value string, limit int, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if !utf8.ValidString(value) {
		return fallback
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fallback
		}
	}
	if len(value) > limit {
		value = value[:limit]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}
