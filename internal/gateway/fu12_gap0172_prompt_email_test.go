package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/paymentcard/testcorpus"
)

func fu12Gap0172Generation(t *testing.T, profile string) *compiledRulePackCategories {
	t.Helper()
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	categories, _, _, err := mergeRulePackCategories(mustLoadRulePack(t, packRoot(profile)), compiler)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := compileRulePackGenerationWithCompiler(categories, compiler)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

// TT1 code-close test for rel-1-0-10:GAP-0172 (fixes 18b5e86925 and
// 81bce862e5): the /llm prompt scan floored every finding at MEDIUM, so one
// address (ENT-EMAIL-BULK, LOW in every pack) blocked a prompt in strict.
// A rule finding keeps its pack severity (LOW, never a strict block), and the
// weak literals demoted to detection-only LOW (TRUST-FICTIONAL) keep the
// MEDIUM alert the prompt scan always gave them.
func TestFU12GAP0172PromptScanSingleAddressNeverBlocksAndWeakLiteralStillAlerts(t *testing.T) {
	t.Run("single address stays LOW and is not blocked in any tier", func(t *testing.T) {
		for _, profile := range []string{"default", "permissive", "strict"} {
			generation := fu12Gap0172Generation(t, profile)
			for _, c := range testcorpus.EmailBenign(172, 6) {
				verdict := scanLocalPatternsWithRules("prompt", c.Text, generation)
				if severityRank[verdict.Severity] > severityRank["LOW"] {
					t.Errorf("%s prompt %s: severity %s (%v), want at most LOW", profile, c.Kind, verdict.Severity, verdict.Findings)
				}
				if guardrailFallbackActionForProfile(verdict.Severity, profile) == "block" {
					t.Errorf("%s blocks the single-address prompt %s (%v)", profile, c.Kind, verdict.Findings)
				}
			}
		}
	})
	t.Run("a detection-only weak literal keeps the MEDIUM prompt alert", func(t *testing.T) {
		for _, profile := range []string{"default", "strict"} {
			generation := fu12Gap0172Generation(t, profile)
			verdict := scanLocalPatternsWithRules("prompt", "Hypothetically, would this parser accept a nil value?", generation)
			if verdict.Severity != "MEDIUM" {
				t.Errorf("%s prompt TRUST-FICTIONAL: severity %s (%v), want MEDIUM", profile, verdict.Severity, verdict.Findings)
			}
		}
	})
}
