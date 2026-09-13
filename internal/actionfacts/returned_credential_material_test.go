// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

func TestClassifyReturnedCredentialMaterial(t *testing.T) {
	tgs := "$krb5tgs$23$*sql_svc$EXAMPLE.TEST$example.test/sql_svc*$" +
		strings.Repeat("a", 32) + "$" + strings.Repeat("b", 128)
	asrep := "$krb5asrep$23$user@EXAMPLE.TEST:" +
		strings.Repeat("c", 32) + "$" + strings.Repeat("d", 128)
	ntds := `EXAMPLE\\administrator:500:` + strings.Repeat("e", 32) +
		":" + strings.Repeat("f", 32) + ":::"
	ntlm := "NT hash: " + strings.Repeat("1", 32)

	tests := []struct {
		name string
		line string
		want ReturnedCredentialMaterial
	}{
		{"kerberos-tgs", tgs, ReturnedCredentialKerberosTGS},
		{"kerberos-asrep", asrep, ReturnedCredentialKerberosASREP},
		{"ntds", ntds, ReturnedCredentialNTDSRecord},
		{"labeled-ntlm", ntlm, ReturnedCredentialLabeledNTLM},
		{"mixed", tgs + "\n" + ntds, ReturnedCredentialKerberosTGS | ReturnedCredentialNTDSRecord},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyReturnedCredentialMaterial([]byte(test.line)); got != test.want || !got.Valid() {
				t.Fatalf("classification=%d valid=%t, want %d", got, got.Valid(), test.want)
			}
		})
	}
}

func TestClassifyReturnedCredentialMaterialRejectsHardNegatives(t *testing.T) {
	hash := strings.Repeat("a", 32)
	tests := []string{
		"",
		"const fixture = `NT hash: " + hash + "`",
		"echo 'NT hash: " + hash + "'",
		"grep -E '^\\$krb5asrep\\$23\\$' output.txt",
		"$krb5asrep$23$user@EXAMPLE.TEST:" + hash + "$truncated",
		"$krb5tgs$23$*user$EXAMPLE.TEST$spn*$placeholder$" + strings.Repeat("b", 128),
		"user:RID:LMHASH:NTHASH:::",
		"NT hash: REDACTED_SECRET",
		"prefix " + strings.Repeat("c", maxReturnedCredentialLineBytes),
		"NT hash: " + hash + "\x00suffix",
		strings.Repeat("x", MaxReturnedCredentialResultBytes+1) + "$krb5asrep$23$truncated",
	}
	for _, input := range tests {
		if got := ClassifyReturnedCredentialMaterial([]byte(input)); got != ReturnedCredentialMaterialNone || got.Valid() {
			t.Fatalf("hard negative classified as %d: %.80q", got, input)
		}
	}
}

func TestReturnedCredentialTelemetrySensitiveFailsClosed(t *testing.T) {
	hash := strings.Repeat("a", 32)
	for _, input := range []string{
		"prefix\x00\nNT hash: " + hash,
		strings.Repeat("padding", 3000) + "$krb5tgs$23$truncated",
		strings.Repeat("x", MaxReturnedCredentialResultBytes+1) + "$krb5asrep$23$truncated",
		"example:500:" + hash + ":" + strings.Repeat("b", 32) + ":::",
	} {
		if !ReturnedCredentialTelemetrySensitive([]byte(input)) {
			t.Fatalf("sensitive telemetry was not redacted: %.80q", input)
		}
	}
	for _, input := range []string{
		"",
		"build completed",
		"document says NT hash without a value",
		strings.Repeat("x", MaxReturnedCredentialResultBytes+1),
	} {
		if ReturnedCredentialTelemetrySensitive([]byte(input)) {
			t.Fatalf("ordinary telemetry was redacted: %q", input)
		}
	}
}

func TestExactReturnedCredentialSource(t *testing.T) {
	tests := []struct {
		name  string
		input Input
		want  ReturnedCredentialSource
	}{
		{"kerberoast", Input{Tool: "execute_command", Command: "impacket-GetUserSPNs -dc-ip 192.0.2.12 -request EXAMPLE.TEST/user:secret", DialectHint: DialectPOSIX}, ReturnedCredentialSourceKerberoast},
		{"asrep", Input{Tool: "execute_command", Command: "impacket-GetNPUsers EXAMPLE.TEST/user -dc-ip 192.0.2.12 -no-pass -request -format hashcat", DialectHint: DialectPOSIX}, ReturnedCredentialSourceASREPRoast},
		{"structured-secretsdump", Input{Tool: "secretsdump", Args: []byte(`{"method":"dcsync","target":"dc.example.test","username":"svc"}`)}, ReturnedCredentialSourceSecretsDump},
		{"literal-file-read", Input{Tool: "execute_command", Command: "cat /tmp/kerberoast.txt", DialectHint: DialectPOSIX}, ReturnedCredentialSourceFileRead},
		{"offline-crack-abstains", Input{Tool: "execute_command", Command: "hashcat -m 18200 asrep.txt words.txt", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"shell-wrapper-abstains", Input{Tool: "execute_command", Command: `bash -lc 'impacket-GetNPUsers EXAMPLE.TEST/user -no-pass -request'`, DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"pipeline-abstains", Input{Tool: "execute_command", Command: "impacket-GetNPUsers EXAMPLE.TEST/user -no-pass -request | tee /tmp/out", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"redirect-abstains", Input{Tool: "execute_command", Command: "impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret > /tmp/out", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"compound-abstains", Input{Tool: "execute_command", Command: "impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret; cat /tmp/out", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"multi-file-read-abstains", Input{Tool: "execute_command", Command: "cat /tmp/one /tmp/two", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"redirected-file-read-abstains", Input{Tool: "execute_command", Command: "cat /tmp/out 2>/dev/null", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"pipelined-file-read-abstains", Input{Tool: "execute_command", Command: "cat /tmp/out | head -1", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
		{"file-read-preview-abstains", Input{Tool: "execute_command", Command: "echo cat /tmp/out", DialectHint: DialectPOSIX}, ReturnedCredentialSourceNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if got := ExactReturnedCredentialSource(facts); got != test.want {
				t.Fatalf("source=%d want=%d facts=%+v", got, test.want, facts)
			}
		})
	}
}

func TestBashLoginCommandProjectsCredentialAcquisitionDetectionOnly(t *testing.T) {
	facts := Analyze(Input{
		Tool: "execute_command", DialectHint: DialectPOSIX,
		Command: `bash -lc 'mkdir -p /tmp/enum && impacket-GetUserSPNs -dc-ip 192.0.2.12 EXAMPLE.TEST/user:secret -request; cat /tmp/enum/out'`,
	})
	if facts.Parse.Status != StatusPartial || facts.Authoritative() ||
		facts.EnforcementEligible() || !ExactDirectoryCredentialAcquisition(facts) ||
		ExactReturnedCredentialSource(facts) != ReturnedCredentialSourceNone {
		t.Fatalf("login-shell facts escaped detection-only boundary: %+v", facts)
	}
}

func TestBashLoginCommandCredentialAcquisitionHardNegatives(t *testing.T) {
	for _, command := range []string{
		`bash -lc 'echo impacket-GetUserSPNs -request EXAMPLE.TEST/user'`,
		`bash -lc 'impacket-GetUserSPNs EXAMPLE.TEST/user'`,
		`bash -lc "$DYNAMIC"`,
		`env bash -lc 'impacket-GetNPUsers EXAMPLE.TEST/user -no-pass -request'`,
	} {
		facts := Analyze(Input{Tool: "execute_command", Command: command, DialectHint: DialectPOSIX})
		if ExactDirectoryCredentialAcquisition(facts) {
			t.Fatalf("hard negative projected acquisition: %q: %+v", command, facts)
		}
	}
}

func TestMatchesReturnedCredentialMaterial(t *testing.T) {
	if !MatchesReturnedCredentialMaterial(ReturnedCredentialSourceKerberoast, ReturnedCredentialKerberosTGS) ||
		!MatchesReturnedCredentialMaterial(ReturnedCredentialSourceASREPRoast, ReturnedCredentialKerberosASREP) ||
		!MatchesReturnedCredentialMaterial(ReturnedCredentialSourceSecretsDump, ReturnedCredentialNTDSRecord|ReturnedCredentialKerberosASREP) ||
		!MatchesReturnedCredentialMaterial(ReturnedCredentialSourceFileRead, ReturnedCredentialKerberosTGS|ReturnedCredentialLabeledNTLM) {
		t.Fatal("expected source/result correspondence did not match")
	}
	for _, mismatch := range []struct {
		source   ReturnedCredentialSource
		material ReturnedCredentialMaterial
	}{
		{ReturnedCredentialSourceNone, ReturnedCredentialKerberosTGS},
		{ReturnedCredentialSourceKerberoast, ReturnedCredentialKerberosASREP},
		{ReturnedCredentialSourceASREPRoast, ReturnedCredentialKerberosTGS},
		{ReturnedCredentialSourceSecretsDump, ReturnedCredentialKerberosTGS},
		{ReturnedCredentialSourceSecretsDump, ReturnedCredentialMaterialNone},
	} {
		if MatchesReturnedCredentialMaterial(mismatch.source, mismatch.material) {
			t.Fatalf("mismatch accepted: %+v", mismatch)
		}
	}
}
