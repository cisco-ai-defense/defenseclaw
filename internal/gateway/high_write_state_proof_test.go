package gateway

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2268, GAP-2298, GAP-2378 (managed observe): the high-write pass
// matched a DefenseClaw state target and replaced the finding's proven
// state mutation with its exact target-match proof, so
// provenActiveStateMutation no longer saw the mutation and managed observe
// mode allowed ./build.sh > ~/.defenseclaw/hooks/f. An authorized proof
// the finding already has must stay.
func TestHighWriteKeepsAProvenStateMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	// The client resolved the target as the user; the gateway behind
	// ProtectHome reads nothing of the home itself.
	home := "/home/eng1@dclab.test"
	cwd := home + "/project"
	const ruleID = "tamper.detector_state_write"
	target := home + "/.defenseclaw/hooks/k04.sh"
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		proven := RuleFinding{RuleID: ruleID, enforcement: findingEnforcementAllowed}
		proven = proven.withTrustedActionProof(newFindingProof(findingProofActiveStateMutation, ruleID, true))
		request := trustedActionRequest{
			Input: actionfacts.Input{Tool: "Bash", Command: "./build.sh > " + target, CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX},
			Connector: connectorName, EnforcementCapable: true,
			ResolvedWriteTargets: map[string]string{target: target},
		}
		got := provedHighWriteFindings(t.Context(), request, []RuleFinding{proven})
		if len(got) == 0 {
			t.Fatalf("%s: finding dropped", connectorName)
		}
		for _, finding := range got {
			if finding.RuleID == ruleID && finding.proof.kind != findingProofActiveStateMutation {
				t.Errorf("%s: state mutation proof replaced by kind %d", connectorName, finding.proof.kind)
			}
		}
	}
}
