// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"strings"
	"testing"
)

func TestExactKerberosTicketForgerySourceObservedForms(t *testing.T) {
	ntHash := strings.Repeat("a1", 16)
	aesKey := strings.Repeat("b2", 32)
	tests := []struct {
		name    string
		command string
	}{
		{
			name: "minimal nthash",
			command: "impacket-ticketer -nthash " + ntHash +
				" -domain-sid S-1-5-21-1001-1002-1003" +
				" -domain lab.example Administrator",
		},
		{
			name: "observed optional fields",
			command: "impacket-ticketer -domain LAB.EXAMPLE" +
				" -domain-sid S-1-5-21-1001-1002-1003" +
				" -aesKey " + aesKey +
				" -extra-sid S-1-5-21-2001-2002-2003-519" +
				" -spn krbtgt/parent.example -user-id 500" +
				" -groups 513,512,520,518,519 -user ticket-user forged_admin",
		},
		{
			name: "script spelling and 128 bit aes key",
			command: "ticketer.py -aesKey " + strings.Repeat("c3", 16) +
				" -domain-sid S-1-5-21-4001-4002-4003" +
				" -domain singlelabel user.name",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "execute_command", Command: test.command})
			fact, ok := ExactKerberosTicketForgerySource(facts)
			if !ok || facts.Parse.Status != StatusComplete || !facts.Authoritative() ||
				fact.CommandID == 0 ||
				!validPrivateDigest(fact.ExpectedArtifactIdentityDigest) {
				t.Fatalf("fact=%+v ok=%t parse=%+v commands=%+v",
					fact, ok, facts.Parse, facts.Commands)
			}
			principal := strings.Fields(test.command)[len(strings.Fields(test.command))-1]
			want := KerberosTicketArtifactIdentity(principal + ".ccache")
			if fact.ExpectedArtifactIdentityDigest != want {
				t.Fatalf("artifact digest=%q, want %q",
					fact.ExpectedArtifactIdentityDigest, want)
			}
			projection := fmt.Sprintf("%+v", fact)
			if strings.Contains(projection, ntHash) || strings.Contains(projection, aesKey) ||
				strings.Contains(projection, "lab.example") ||
				strings.Contains(projection, "Administrator") {
				t.Fatalf("sensitive invocation value escaped projection: %q", projection)
			}
		})
	}
}

func TestExactKerberosTicketForgerySourceStructuredArgv(t *testing.T) {
	principal := "structured-user"
	facts := Analyze(Input{
		Tool: "execute_command",
		Argv: []string{
			"impacket-ticketer", "-nthash", strings.Repeat("d4", 16),
			"-domain-sid", "S-1-5-21-5001-5002-5003",
			"-domain", "structured.example", principal,
		},
	})
	fact, ok := ExactKerberosTicketForgerySource(facts)
	if !ok || fact.ExpectedArtifactIdentityDigest !=
		KerberosTicketArtifactIdentity(principal+".ccache") {
		t.Fatalf("fact=%+v ok=%t parse=%+v commands=%+v",
			fact, ok, facts.Parse, facts.Commands)
	}

	dynamic := append([]string(nil), facts.Commands[0].Argv...)
	dynamic[len(dynamic)-1] = "$USER"
	if fact, ok := ExactKerberosTicketForgerySource(Analyze(Input{
		Tool: "execute_command", Argv: dynamic,
	})); ok {
		t.Fatalf("structured dynamic principal projected %+v", fact)
	}
}

func TestExactKerberosTicketForgerySourceHardNegatives(t *testing.T) {
	key := strings.Repeat("e5", 16)
	aes := strings.Repeat("f6", 32)
	base := "impacket-ticketer -nthash " + key +
		" -domain-sid S-1-5-21-6001-6002-6003" +
		" -domain lab.example Administrator"
	tests := []struct {
		name    string
		command string
	}{
		{name: "missing key", command: "impacket-ticketer -domain-sid S-1-5-21-6001-6002-6003 -domain lab.example Administrator"},
		{name: "both key modes", command: "impacket-ticketer -nthash " + key + " -aesKey " + aes + " -domain-sid S-1-5-21-6001-6002-6003 -domain lab.example Administrator"},
		{name: "duplicate key", command: "impacket-ticketer -nthash " + key + " -nthash " + key + " -domain-sid S-1-5-21-6001-6002-6003 -domain lab.example Administrator"},
		{name: "short nthash", command: strings.Replace(base, key, strings.Repeat("a", 31), 1)},
		{name: "non hex nthash", command: strings.Replace(base, key, strings.Repeat("z", 32), 1)},
		{name: "wrong aes length", command: strings.Replace(base, "-nthash "+key, "-aesKey "+strings.Repeat("a", 48), 1)},
		{name: "missing domain sid", command: "impacket-ticketer -nthash " + key + " -domain lab.example Administrator"},
		{name: "duplicate domain sid", command: strings.Replace(base, " -domain lab.example", " -domain-sid S-1-5-21-7001-7002-7003 -domain lab.example", 1)},
		{name: "non domain sid", command: strings.Replace(base, "S-1-5-21-6001-6002-6003", "S-1-5-32-544", 1)},
		{name: "placeholder sid", command: strings.Replace(base, "S-1-5-21-6001-6002-6003", "<DOMAIN_SID>", 1)},
		{name: "missing domain", command: "impacket-ticketer -nthash " + key + " -domain-sid S-1-5-21-6001-6002-6003 Administrator"},
		{name: "duplicate domain", command: strings.Replace(base, " Administrator", " -domain other.example Administrator", 1)},
		{name: "malformed domain", command: strings.Replace(base, "lab.example", "lab..example", 1)},
		{name: "dynamic domain", command: strings.Replace(base, "lab.example", "${DOMAIN}", 1)},
		{name: "missing principal", command: strings.TrimSuffix(base, " Administrator")},
		{name: "second positional", command: base + " OtherUser"},
		{name: "option after principal", command: base + " -user-id 500"},
		{name: "dynamic principal", command: strings.Replace(base, "Administrator", "${USER}", 1)},
		{name: "principal path", command: strings.Replace(base, "Administrator", "dir/Administrator", 1)},
		{name: "duplicate extra sid", command: strings.Replace(base, " Administrator", " -extra-sid S-1-5-21-7001-7002-7003-519 -extra-sid S-1-5-21-7001-7002-7003-519 Administrator", 1)},
		{name: "malformed extra sid", command: strings.Replace(base, " Administrator", " -extra-sid S-1-5-32-544 Administrator", 1)},
		{name: "duplicate group", command: strings.Replace(base, " Administrator", " -groups 512,512 Administrator", 1)},
		{name: "invalid spn", command: strings.Replace(base, " Administrator", " -spn krbtgt//parent.example Administrator", 1)},
		{name: "zero user id", command: strings.Replace(base, " Administrator", " -user-id 0 Administrator", 1)},
		{name: "unknown flag", command: strings.Replace(base, " Administrator", " -duration 24 Administrator", 1)},
		{name: "keytab instead of key", command: strings.Replace(base, "-nthash "+key, "-keytab ticket.keys", 1)},
		{name: "help", command: "impacket-ticketer -h"},
		{name: "sudo wrapper", command: "sudo " + base},
		{name: "env wrapper", command: "env MODE=test " + base},
		{name: "python wrapper", command: strings.Replace(base, "impacket-ticketer", "python3 ticketer.py", 1)},
		{name: "pipeline", command: base + " | tee ticket.log"},
		{name: "redirect", command: base + " 2>&1"},
		{name: "compound", command: base + " && echo done"},
		{name: "conditional", command: "if true; then " + base + "; fi"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "execute_command", Command: test.command})
			if fact, ok := ExactKerberosTicketForgerySource(facts); ok {
				t.Fatalf("hard negative projected %+v; parse=%+v commands=%+v",
					fact, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestKerberosTicketArtifactIdentityIsExactAndValueFree(t *testing.T) {
	first := KerberosTicketArtifactIdentity("Administrator.ccache")
	if !validPrivateDigest(first) || first ==
		KerberosTicketArtifactIdentity("administrator.ccache") {
		t.Fatalf("artifact identities must be valid and case-sensitive: %q", first)
	}
	invalid := []string{
		"", ".ccache", "Administrator", "Administrator.kirbi",
		"../Administrator.ccache", "/tmp/Administrator.ccache",
		`folder\Administrator.ccache`, "${USER}.ccache",
		"Administrator.ccache extra", "Administrator.ccache\n",
		"machine$account.ccache",
	}
	for _, value := range invalid {
		if digest := KerberosTicketArtifactIdentity(value); digest != "" {
			t.Fatalf("invalid artifact %q produced digest %q", value, digest)
		}
	}
}

func TestExactKerberosTicketForgerySourceRejectsNonAuthoritativeFacts(t *testing.T) {
	facts := Facts{
		Parse: ParseResult{Status: StatusPartial},
		Commands: []CommandFact{{
			ID: 1, Kind: CommandKindProcess, Effect: EffectExecute,
			Program: "impacket-ticketer", ArgvComplete: true,
			Argv: []string{
				"impacket-ticketer", "-nthash", strings.Repeat("a7", 16),
				"-domain-sid", "S-1-5-21-8001-8002-8003",
				"-domain", "lab.example", "Administrator",
			},
		}},
	}
	if fact, ok := ExactKerberosTicketForgerySource(facts); ok {
		t.Fatalf("non-authoritative facts projected %+v", fact)
	}
}
