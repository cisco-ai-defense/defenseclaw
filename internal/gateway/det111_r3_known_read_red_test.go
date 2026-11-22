package gateway

import "testing"

// This public effect-lane assertion intentionally uses only APIs present at
// a64bfdb931, so it proves the Known-read bridge is red before its Decide
// handoff exists and green once the handoff is wired.
func TestDET111KnownCredentialReadProducesLiveDecisionFinding(t *testing.T) {
	useEffectsRulesMode(t, "on")
	request := shadowLiveRequest("cat /home/u/.aws/credentials")
	results := effectShadowRun(request, effectRulesOn, tierRestricted)
	if len(results) != 1 {
		t.Fatalf("effect shadow results = %d, want one tier result", len(results))
	}
	findings := effectShadowFindings(results[0], effectRulesOn)
	for _, finding := range findings {
		if finding.RuleID == "PATH-AWS-CREDS" {
			return
		}
	}
	t.Fatalf("Known credential read produced no PATH-AWS-CREDS Decide finding: findings=%+v result=%+v", findings, results[0])
}
