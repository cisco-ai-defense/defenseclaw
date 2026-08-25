package gateway

import "testing"

// Provider-prefixed credential rules match on the prefix alone, so a
// hand-written filler tail satisfies them. These cases came from a real
// session where a synthetic token in a test file raised CRITICAL findings.
func TestAcceptedCredentialMatch_RejectsEmbeddedPlaceholders(t *testing.T) {
	rejected := []struct{ name, rule, candidate string }{
		{"filler tail dominated by one character", "SEC-AWS-KEY", "AKIAEXAMPLEFAKETOKEN0000000000000000000000000000000000000000000"},
		{"zero filler tail", "SEC-AWS-KEY", "AKIA0000000000000000000000"},
		{"documented AWS example", "SEC-AWS-KEY", "AKIAIOSFODNN7EXAMPLE"},
		{"single repeated char", "SEC-OPENAI", "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if acceptedCredentialMatch(tc.rule, tc.candidate) {
				t.Errorf("acceptedCredentialMatch(%q, %q) = true, want false", tc.rule, tc.candidate)
			}
		})
	}
}

// Regression guard: tightening placeholder handling must not silence real
// credentials. These are randomly-shaped values of provider length.
func TestAcceptedCredentialMatch_StillDetectsRealShapedCredentials(t *testing.T) {
	accepted := []struct{ name, rule, candidate string }{
		{"random AWS key id", "SEC-AWS-KEY", "AKIA3FKJ2M5NQ7XZ8BWV"},
		{"random AWS key id 2", "SEC-AWS-KEY", "AKIAQZ7T4YN2WVKD9RJH"},
		{"random openai key", "SEC-OPENAI", "sk-proj-9Xk2mQ7vTz4RbN8pLwGh3JdY6CfA5sEu"},
		// Regression guard: a real credential may contain a filler word. This
		// codebase never rejects on spelling, only on structure.
		{"real token containing the word example", "SEC-BEARER", "live-example-q7Vx2M9p4Rk8T3n6"},
		{"weak but real password", "SEC-CONNSTR", "postgres://user:changeme123@host.example/db"},
		{"high-entropy bearer", "SEC-BEARER", "fe58289546a78110469da64533f35d1064603756"},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if !acceptedCredentialMatch(tc.rule, tc.candidate) {
				t.Errorf("acceptedCredentialMatch(%q, %q) = false, want true (real credential suppressed)", tc.rule, tc.candidate)
			}
		})
	}
}

func TestCredentialLowVariety(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"short strings exempt", "aaaa", false},
		{"one char dominates", "akia000000000000000000", true},
		{"too few distinct", "abababababababababab", true},
		{"varied credential", "akia3fkj2m5nq7xz8bwv", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialLowVariety(tc.value); got != tc.want {
				t.Errorf("credentialLowVariety(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
