package gateway

import "testing"

// The credential validators reject only values the product can prove are not
// secrets: documented public examples and canonical filler words. They do not
// guess from shape.
func TestAcceptedCredentialMatch_RejectsOnlyProvableNonSecrets(t *testing.T) {
	rejected := []struct{ name, rule, candidate string }{
		{"documented AWS example", "SEC-AWS-KEY", "AKIAIOSFODNN7EXAMPLE"},
		{"canonical filler word", "SEC-OPENAI", "sk-proj-placeholder"},
		{"repeated short unit", "SEC-BEARER", "Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxx"},
		// A pure repetition of one short unit is caught by the pre-existing
		// repeatedShortCredentialUnit check from #693, which is narrower than
		// a general variety measure and does not touch the corpus token.
		{"all-zero filler tail", "SEC-AWS-KEY", "AKIA0000000000000000000000"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if acceptedCredentialMatch(tc.rule, tc.candidate) {
				t.Errorf("acceptedCredentialMatch(%q, %q) = true, want false", tc.rule, tc.candidate)
			}
		})
	}
}

// Regression guard for a heuristic that was tried and removed. A padded
// synthetic token and a leaked credential are indistinguishable by character
// variety or entropy, and the security corpus requires the padded form to be
// reported: eval-tool/005 asserts ghp_abc123ffff… (36 f's) reaches HIGH.
// Rejecting "low variety" candidates silently broke that case.
func TestAcceptedCredentialMatch_PaddedSyntheticTokensStillReport(t *testing.T) {
	accepted := []struct{ name, rule, candidate string }{
		{"corpus github token", "SEC-GITHUB-TOKEN", "ghp_abc123ffffffffffffffffffffffffffffffffffff"},
		{"random AWS key id", "SEC-AWS-KEY", "AKIA3FKJ2M5NQ7XZ8BWV"},
		{"random openai key", "SEC-OPENAI", "sk-proj-9Xk2mQ7vTz4RbN8pLwGh3JdY6CfA5sEu"},
		{"real token containing the word example", "SEC-BEARER", "Authorization: Bearer live-example-q7Vx2M9p4Rk8T3n6"},
		{"weak but real password", "SEC-CONNSTR", "postgres://user:changeme123@host.example/db"},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if !acceptedCredentialMatch(tc.rule, tc.candidate) {
				t.Errorf("acceptedCredentialMatch(%q, %q) = false, want true (credential suppressed)", tc.rule, tc.candidate)
			}
		})
	}
}

// A connection string whose password is a variable slot carries no password.
func TestConnectionStringWithAVariablePasswordIsNotACredential(t *testing.T) {
	for _, match := range []string{
		"postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/db",
		"postgres://app:$DB_PASSWORD@db.internal/app",
		"mysql://app:{{ db_password }}@db.internal/app",
		"redis://:<password>@cache.internal/0",
	} {
		if acceptedCredentialMatch("SEC-CONNSTR", match) {
			t.Errorf("acceptedCredentialMatch(SEC-CONNSTR, %q) = true, want false", match)
		}
	}
	if !acceptedCredentialMatch("SEC-CONNSTR", "postgres://app:changeme123@db.internal/app") {
		t.Error("a literal weak password must still be a credential")
	}
}
