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
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func init() {
	rootCmd.AddCommand(guardrailCmd)
	guardrailCmd.AddCommand(guardrailRulesCmd)
	guardrailCmd.AddCommand(guardrailSuppressionsCmd)
	guardrailCmd.AddCommand(guardrailJudgeCmd)
	guardrailCmd.AddCommand(guardrailValidateCmd)

	guardrailRulesCmd.AddCommand(guardrailRulesListCmd)
	guardrailSuppressionsCmd.AddCommand(guardrailSuppressionsShowCmd)
	guardrailJudgeCmd.AddCommand(guardrailJudgeShowCmd)
}

var guardrailCmd = &cobra.Command{
	Use:   "guardrail",
	Short: "Inspect and manage guardrail rule packs",
	Long:  "View loaded rules, suppressions, judge configs, and validate rule pack integrity.",
}

var guardrailRulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage guardrail pattern rules",
}

var guardrailSuppressionsCmd = &cobra.Command{
	Use:   "suppressions",
	Short: "Manage finding suppressions",
}

var guardrailJudgeCmd = &cobra.Command{
	Use:   "judge",
	Short: "Inspect LLM judge configuration",
}

// ---------------------------------------------------------------------------
// guardrail rules list
// ---------------------------------------------------------------------------

var guardrailRulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all loaded pattern rules from the active rule pack",
	RunE: func(_ *cobra.Command, _ []string) error {
		rp := loadCLIRulePack()

		cats := rp.GetRuleCategories()
		if len(cats) == 0 {
			fmt.Println("No pattern rules loaded.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "CATEGORY\tID\tSEVERITY\tCONFIDENCE\tTITLE")
		for _, cat := range cats {
			for _, r := range cat.Rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%.2f\t%s\n", cat.Name, r.ID, r.Severity, r.Confidence, r.Title)
			}
		}
		w.Flush()

		total := 0
		for _, c := range cats {
			total += len(c.Rules)
		}
		fmt.Fprintf(os.Stderr, "\n%d rules across %d categories\n", total, len(cats))
		return nil
	},
}

// ---------------------------------------------------------------------------
// guardrail suppressions show
// ---------------------------------------------------------------------------

var guardrailSuppressionsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show loaded suppression rules",
	RunE: func(_ *cobra.Command, _ []string) error {
		rp := loadCLIRulePack()

		supp := rp.GetSuppressions()
		if supp == nil {
			fmt.Println("No suppressions loaded.")
			return nil
		}

		fmt.Println("Pre-judge strips:")
		if len(supp.PreJudgeStrips) == 0 {
			fmt.Println("  (none)")
		}
		for _, s := range supp.PreJudgeStrips {
			fmt.Printf("  - %s  applies_to=%v\n", s.ID, s.AppliesTo)
		}

		fmt.Println("\nFinding suppressions:")
		if len(supp.FindingSuppressions) == 0 {
			fmt.Println("  (none)")
		}
		for _, s := range supp.FindingSuppressions {
			cond := ""
			if s.Condition != "" {
				cond = fmt.Sprintf(" [condition=%s]", s.Condition)
			}
			fmt.Printf("  - %s  finding=%s  reason=%q%s\n", s.ID, s.FindingPattern, s.Reason, cond)
		}

		fmt.Println("\nTool suppressions:")
		if len(supp.ToolSuppressions) == 0 {
			fmt.Println("  (none)")
		}
		for _, s := range supp.ToolSuppressions {
			fmt.Printf("  - tool=%s  suppress=%v  reason=%q\n", s.ToolPattern.String(), s.SuppressFindings, s.Reason)
		}

		return nil
	},
}

// ---------------------------------------------------------------------------
// guardrail judge show
// ---------------------------------------------------------------------------

var guardrailJudgeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show loaded LLM judge configurations",
	RunE: func(_ *cobra.Command, _ []string) error {
		rp := loadCLIRulePack()

		for _, name := range []string{"injection", "pii"} {
			jc := rp.GetJudgeConfig(name)
			if jc == nil {
				fmt.Printf("[%s] not loaded\n\n", name)
				continue
			}
			fmt.Printf("[%s] enabled=%v  min_categories_for_high=%d\n", name, jc.Enabled, jc.MinCategoriesForHigh)
			fmt.Printf("  system_prompt: %d chars\n", len(jc.SystemPrompt))
			fmt.Printf("  categories:\n")
			for catName, cat := range jc.Categories {
				sev := cat.SeverityDefault
				if sev == "" {
					sev = "unset"
				}
				fmt.Printf("    - %s  finding_id=%s  severity=%s  enabled=%v\n", catName, cat.FindingID, sev, cat.Enabled)
			}
			fmt.Println()
		}
		return nil
	},
}

// ---------------------------------------------------------------------------
// guardrail validate
// ---------------------------------------------------------------------------

var guardrailValidateCmd = &cobra.Command{
	Use:   "validate [dir]",
	Short: "Validate a guardrail rule pack directory",
	Long:  "Load and validate all YAML files in a rule pack directory. Reports regex errors, missing files, and schema issues.",
	RunE: func(_ *cobra.Command, args []string) error {
		dir := ""
		if len(args) > 0 {
			dir = args[0]
		} else if cfg != nil {
			dir = cfg.Guardrail.RulePackDir
		}

		rp := gateway.LoadRulePack(dir)
		errs := rp.LoadErrors()

		cats := rp.GetRuleCategories()
		totalRules := 0
		for _, c := range cats {
			totalRules += len(c.Rules)
		}

		lp := rp.GetLocalPatterns()
		localCount := 0
		if lp != nil {
			localCount = len(lp.Injection) + len(lp.InjectionRegexes) + len(lp.PIIRequests) + len(lp.PIIDataRegexes) + len(lp.Secrets) + len(lp.Exfiltration)
		}

		supp := rp.GetSuppressions()
		suppCount := 0
		if supp != nil {
			suppCount = len(supp.PreJudgeStrips) + len(supp.FindingSuppressions) + len(supp.ToolSuppressions)
		}

		src := "embedded defaults"
		if dir != "" {
			src = dir
		}
		fmt.Printf("Rule pack source: %s\n", src)
		fmt.Printf("Pattern rules:    %d across %d categories\n", totalRules, len(cats))
		fmt.Printf("Local patterns:   %d\n", localCount)
		fmt.Printf("Suppressions:     %d\n", suppCount)

		for _, name := range []string{"injection", "pii"} {
			jc := rp.GetJudgeConfig(name)
			if jc != nil {
				fmt.Printf("Judge [%s]:       enabled=%v  categories=%d\n", name, jc.Enabled, len(jc.Categories))
			}
		}

		if len(errs) > 0 {
			fmt.Printf("\n%d validation errors:\n", len(errs))
			for _, e := range errs {
				fmt.Printf("  - %s\n", e)
			}
			return fmt.Errorf("rule pack has %d validation errors", len(errs))
		}

		fmt.Println("\nValidation: OK")
		return nil
	},
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func loadCLIRulePack() *gateway.RulePack {
	dir := ""
	if cfg != nil {
		dir = cfg.Guardrail.RulePackDir
	}
	rp := gateway.LoadRulePack(dir)
	if errs := rp.LoadErrors(); len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d rule pack load errors (run 'guardrail validate' for details)\n", len(errs))
	}

	return rp
}
