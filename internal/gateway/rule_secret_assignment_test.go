package gateway

import "testing"

// SEC-HEX-SECRET required the value to be quoted, so it missed secrets in the
// three places they actually live: .env files, shell `export` lines, and YAML.
// Found by live-probing the running gateway — reading DefenseClaw's own
// ~/.defenseclaw/.env printed a live 64-hex gateway token and raised nothing.
func TestSecretAssignmentDetectedWithoutQuotes(t *testing.T) {
	const hex64 = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"
	detected := []struct{ name, text string }{
		{"env unquoted gateway token", "DEFENSECLAW_GATEWAY_TOKEN=" + hex64},
		{"env unquoted api token", "API_TOKEN=" + hex64},
		{"env unquoted secret key", "SECRET_KEY=" + hex64},
		{"shell export", "export SERVICE_TOKEN=" + hex64},
		{"yaml scalar", "auth_token: " + hex64},
		{"quoted form still works", `secret_key="` + hex64 + `"`},
	}
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			rule := alertFatigueRule(t, profile, "SEC-HEX-SECRET")
			for _, tc := range detected {
				if firstAcceptedRuleMatch(rule, tc.text) == nil {
					t.Errorf("SEC-HEX-SECRET missed %s: %q", tc.name, tc.text)
				}
			}
		})
	}
}

// Guard the widened key-name alternation. A long hex value is ordinary in
// version control and content addressing; only a secret-shaped NAME should
// promote it to a finding.
func TestSecretAssignmentIgnoresOrdinaryHex(t *testing.T) {
	benign := []struct{ name, text string }{
		{"git commit sha", "commit=1a2b3c4d5e6f7890abcdef1234567890abcdef12"},
		{"content digest", "sha256=1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"},
		{"blob identifier", "blob_id: 1a2b3c4d5e6f7890abcdef1234567890abcdef12"},
		{"variable indirection", "API_TOKEN=${SERVICE_TOKEN}"},
		{"already redacted", "auth_token: <redacted len=64 sha=abc12345>"},
		{"short numeric", "TOKEN_COUNT=42"},
	}
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			rule := alertFatigueRule(t, profile, "SEC-HEX-SECRET")
			for _, tc := range benign {
				if firstAcceptedRuleMatch(rule, tc.text) != nil {
					t.Errorf("SEC-HEX-SECRET false positive on %s: %q", tc.name, tc.text)
				}
			}
		})
	}
}
