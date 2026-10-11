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
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

const rulePackWireVersion = 1

const rulePackLongIntro = `Inspect a guardrail rule pack without starting the gateway or reading its
config. Administrators validate a custom pack with this command before`

var safeRulePackWireCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// These IDs use the shipped regex fallback without a semantic expression.
// List IDs here so a copied pack can distinguish its own new rules from them.
var shippedToolCallRegexIDs = map[string]bool{
	"CMD-REVSHELL-POWERSHELL-TCP":                     true,
	"SEC-ENV-DUMP-REQUEST":                            true,
	"credential.windows_lsass_memory_dump":            true,
	"tamper.posix_log_and_shell_history_destruction":  true,
	"credential.kubernetes_named_secret_content_read": true,
	"credential.kubernetes_batch_secret_collection":   true,
	"tamper.pam_permit_authentication_bypass":         true,
	"tamper.docker_insecure_http_registry":            true,
	"exfil.credential_archive_external_upload":        true,
	"persistence.global_ld_preload_install":           true,
	"privilege.host_namespace_entry":                  true,
	"lateral.workload_exec":                           true,
	"impact.fork_bomb":                                true,
	"impact.unbounded_cpu_fanout":                     true,
}

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
	Use:   "rulepack",
	Short: "Inspect a guardrail rule pack without starting the gateway",
	Long: rulePackLongIntro + `
registering it as guardrail.custom_packs.<name> (its path and the digest this
command prints) and selecting it with guardrail.rule_pack.`,
	// A Secure Client config stays on config_version 8, where rule_pack_dir
	// names the pack, so it keeps the help of main (issue #1092, GAP-0270).
	Annotations: map[string]string{secureClientLongAnnotation: rulePackLongIntro + `
pointing guardrail.rule_pack_dir at it.`},
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
}

var rulePackValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a guardrail rule pack",
	Long: `Validate a rule-pack directory the same way the gateway does when it loads
one, including every regular and semantic expression, and print a summary or
the first problem. Without --dir the embedded default pack is validated.
Exit status 0 means the pack is valid. On a host with a defenseclaw service
account the text output also exits 1 when that account cannot read the pack
(the gateway would refuse it); with --json the exit status reports validity
only and that problem is printed on stderr.

Example:
  defenseclaw-gateway rulepack validate --dir /etc/defenseclaw/policies/guardrail/custom`,
	Args: cobra.NoArgs,
	RunE: runRulePackValidate,
}

var (
	rulePackValidateDir  string
	rulePackValidateJSON bool

	// rulePackServiceReadProblemFn is replaced by tests.
	rulePackServiceReadProblemFn = rulePackServiceReadProblem
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
		// A directory-level problem is reported at the pack root ("."); the
		// text output names the directory the operator passed instead
		// (GAP-1405). The JSON wire format keeps its path-free contract.
		dirLevel := rulePackValidateDir != "" && diagnostic.Path == "." &&
			(strings.HasPrefix(diagnostic.Code, "directory_") || diagnostic.Code == "not_directory")
		if dirLevel && !rulePackValidateJSON {
			textDiag := diagnostic
			textDiag.Path = rulePackValidateDir
			response.Error = &textDiag
		}
		if writeErr := writeRulePackValidation(cmd.OutOrStdout(), response, rulePackValidateJSON); writeErr != nil {
			return errors.New("rule-pack validation failed and its safe diagnostic could not be written")
		}
		if dirLevel {
			return fmt.Errorf("rule-pack validation failed [%s]: check --dir %s (omit --dir to validate the embedded default pack)", diagnostic.Code, rulePackValidateDir)
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
	problem := ""
	if rulePackValidateDir != "" {
		problem = rulePackServiceReadProblemFn(cmd.Context(), rulePackValidateDir)
	}
	if problem != "" && !rulePackValidateJSON {
		// A script that checks only the exit status must not pass a pack the
		// gateway will refuse (GAP-1274).
		fmt.Fprintf(cmd.OutOrStdout(), "rule pack syntax is valid: %d files, %d rules, digest %s\n",
			summary.RuleFileCount, summary.RuleCount, summary.Digest)
		return fmt.Errorf("the gateway cannot load this pack: %s", problem)
	}
	if err := writeRulePackValidation(cmd.OutOrStdout(), response, rulePackValidateJSON); err != nil {
		return err
	}
	if problem != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: the gateway cannot load this pack: %s\n", problem)
	}
	if !rulePackValidateJSON {
		var customerIDs, shippedIDs []string
		for _, ruleFile := range rp.RuleFiles {
			if ruleFile == nil {
				continue
			}
			for _, rule := range ruleFile.Rules {
				if rule.Enabled != nil && !*rule.Enabled || !rule.ToolCallOnly || rule.Expression != "" {
					continue
				}
				id := safeRulePackWireText(rule.ID, 64, "(unsafe rule id)")
				if shippedToolCallRegexIDs[rule.ID] {
					shippedIDs = append(shippedIDs, id)
				} else {
					customerIDs = append(customerIDs, id)
				}
			}
		}
		sort.Strings(customerIDs)
		for _, id := range customerIDs {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: customer rule %s uses tool_call_only without an expression; its tool-call pattern matches use the regex fallback, which is detection-only and cannot block\n", id)
		}
		if len(customerIDs) > 0 && len(shippedIDs) > 0 {
			sort.Strings(shippedIDs)
			fmt.Fprintf(cmd.ErrOrStderr(), "note: known shipped rule IDs using the same fallback: %s\n", strings.Join(shippedIDs, ", "))
		}
	}
	return nil
}

func writeRulePackValidation(w io.Writer, response rulePackWireResponse, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(response)
	}
	if response.Valid && response.Summary != nil {
		if rulePackSecureClient() {
			_, err := fmt.Fprintf(w, "valid rule pack: %d files, %d rules, digest %s\n",
				response.Summary.RuleFileCount, response.Summary.RuleCount, response.Summary.Digest)
			return err
		}
		_, err := fmt.Fprintf(
			w,
			"valid rule pack: %d files, %d rules, digest %s\ncustom_packs pin: sha256:%s\n",
			response.Summary.RuleFileCount,
			response.Summary.RuleCount,
			response.Summary.Digest,
			response.Summary.FilesDigest,
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

// rulePackSecureClient checks the config source without starting the gateway.
// An unreadable config keeps the ordinary standalone validation output.
func rulePackSecureClient() bool {
	raw, err := os.ReadFile(config.ConfigPath())
	return err == nil && config.SecureClientSource(raw)
}
