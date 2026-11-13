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
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

var (
	policyCascadeConnector string
	policyCascadeProfile   string
	policyCascadeInput     string
	policyCascadeJSON      bool
)

func init() {
	policyCmd.AddCommand(policyCascadeCmd)
	policyCascadeCmd.Flags().StringVar(&policyCascadeConnector, "connector", "", "Agent connector (claudecode, codex, ...); empty for the global scope")
	policyCascadeCmd.Flags().StringVar(&policyCascadeProfile, "profile", "", "Guardrail profile to resolve for")
	policyCascadeCmd.Flags().StringVar(&policyCascadeInput, "input", "", "Replay one decision: a cascade policy input (JSON file) through the policy and the limits")
	policyCascadeCmd.Flags().BoolVar(&policyCascadeJSON, "json", false, "Print JSON")
}

var policyCascadeCmd = &cobra.Command{
	Use:               "cascade",
	Short:             "Show the effective guardrail cascade (rules, System One, judge, unknown tier, lanes, Rego policy, locks) for a connector",
	Args:              cobra.NoArgs,
	PersistentPreRunE: policyConfigOnlyPreRunE,
	PersistentPostRun: policyConfigOnlyPostRun,
	RunE: func(cmd *cobra.Command, _ []string) error {
		explanation, err := gateway.ExplainCascade(cfg, policyCascadeConnector, policyCascadeProfile)
		if err != nil {
			return err
		}
		var sim *gateway.CascadeSimulation
		if policyCascadeInput != "" {
			raw, err := os.ReadFile(policyCascadeInput)
			if err != nil {
				return fmt.Errorf("cascade: read %s: %w", policyCascadeInput, err)
			}
			var input map[string]any
			if err := json.Unmarshal(raw, &input); err != nil {
				return fmt.Errorf("cascade: %s is not a JSON object: %w", policyCascadeInput, err)
			}
			replayed, err := gateway.SimulateCascade(cmd.Context(), cfg, policyCascadeConnector, input)
			if err != nil {
				return err
			}
			sim = &replayed
		}
		if policyCascadeJSON {
			view := map[string]any{"cascade": explanation}
			if sim != nil {
				view["replay"] = sim
			}
			out, err := json.MarshalIndent(view, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		}
		printCascadeExplanation(cmd.OutOrStdout(), explanation, sim)
		return nil
	},
}

func printCascadeExplanation(w io.Writer, e gateway.CascadeExplanation, sim *gateway.CascadeSimulation) {
	scope := e.Connector
	if scope == "" {
		scope = "global scope"
	}
	if e.Profile != "" {
		scope += ", profile " + e.Profile
	}
	fmt.Fprintf(w, "Guardrail cascade for %s\n", scope)
	if e.Invalid != nil {
		fmt.Fprintf(w, "\n  INVALID: %s\n", e.Invalid.Message())
	}
	fmt.Fprintf(w, "\n1. Rules (always on): mode %s, pack %s (%s tier), block at %s, alert at %s (%s)", e.Rules.Mode, e.Rules.Pack, e.Rules.Tier, e.Rules.BlockAt, e.Rules.AlertAt, e.Rules.Source)
	if e.Rules.HILT {
		fmt.Fprintf(w, ", ask at %s", e.Rules.HILTMinimum)
	}
	fmt.Fprintln(w)
	s := e.SystemOne
	fmt.Fprintf(w, "2. System One: %s", s.Runs)
	if s.Runs != "off" {
		fmt.Fprintf(w, " (%s): confident allow at risk <= %.2f; confident block at risk >= %.2f and risk score >= %.2f", s.Protocol, s.AllowThreshold, s.BlockThreshold, s.BlockRiskScore)
		if s.EscalateRuleFlagged {
			fmt.Fprint(w, ", never on a call the rules flagged")
		}
		if s.Runs == "with_judge" {
			fmt.Fprint(w, "; a confident block goes to the judge (never final)")
		} else {
			fmt.Fprintf(w, "; a confident block blocks; unsure: %s", s.OnUnsure)
		}
	}
	fmt.Fprintln(w)
	j := e.Judge
	fmt.Fprintf(w, "3. LLM judge: %s", j.Runs)
	if j.Runs != "off" {
		fmt.Fprintf(w, "; at most %s", j.MaxAction)
		if j.BlockNeedsSystemOne {
			fmt.Fprint(w, "; blocks only when System One agrees (else asks)")
		}
		fmt.Fprintf(w, "; no verdict: %s", j.NoVerdict)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Unknown / truncated input: %s (%s)\n", e.Unknown.Action, e.Unknown.Setting)
	for _, lane := range e.Lanes {
		note := ""
		if lane.ShadowOnly != "" {
			note = " (shadow-only in this release: " + lane.ShadowOnly + ")"
		}
		fmt.Fprintf(w, "Lane %s: %s%s\n", lane.Name, lane.Mode, note)
	}
	if e.Policy.Active {
		fmt.Fprintf(w, "Rego policy: %s (%s); may set %s..%s on a flagged call; %d ms budget\n", e.Policy.Module, e.Policy.Digest, e.Policy.Lowest, e.Policy.Highest, e.Policy.TimeoutMs)
	} else {
		fmt.Fprintln(w, "Rego policy: off")
	}
	fmt.Fprintf(w, "A proven CRITICAL finding ends at least at: %s\n", e.CriticalFloor)
	if len(e.Locked) > 0 {
		fmt.Fprintf(w, "Locked by the administrator: %s\n", strings.Join(e.Locked, ", "))
	}
	fmt.Fprintf(w, "Gateway down: hooks fail %s\n", e.HookFailMode)
	if len(e.Sources) > 0 {
		keys := make([]string, 0, len(e.Sources))
		for k := range e.Sources {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintln(w, "\nSet by:")
		for _, k := range keys {
			fmt.Fprintf(w, "  %s <- %s\n", k, e.Sources[k])
		}
	}
	if sim != nil {
		o := sim.Outcome
		fmt.Fprintf(w, "\nReplay: before the policy %s; final %s, decided by %s", o.Before, o.Final, o.DecidedBy)
		if o.PolicyRule != "" {
			fmt.Fprintf(w, " (rule %s)", o.PolicyRule)
		}
		if o.Clamped {
			fmt.Fprint(w, "; the limits moved the policy's action")
		}
		if o.Error != "" {
			fmt.Fprintf(w, "; policy error: %s", o.Error)
		}
		fmt.Fprintln(w)
	}
}
