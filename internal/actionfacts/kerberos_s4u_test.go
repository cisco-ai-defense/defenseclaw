// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const s4uTestCredential = "provided-by-secret-store"

func TestExactKerberosS4UTicketRequestPinnedCochiseOrders(t *testing.T) {
	tests := []string{
		"impacket-getST -spn cifs/dc.lab.example -impersonate administrator lab.example/service-account:" + s4uTestCredential,
		"impacket-getST -dc-ip 192.0.2.10 -spn cifs/dc.lab.example -impersonate administrator lab.example/service-account:" + s4uTestCredential,
		"getST.py -spn cifs/dc.lab.example -dc-ip 192.0.2.10 -impersonate administrator lab.example/service-account:" + s4uTestCredential,
		"impacket-getST -spn cifs/dc.lab.example -impersonate administrator -dc-ip 192.0.2.10 lab.example/service-account:" + s4uTestCredential,
	}
	for _, command := range tests {
		facts := Analyze(Input{Tool: "execute_command", Command: command})
		fact, ok := ExactKerberosS4UTicketRequest(facts)
		if !ok || fact.CommandID == 0 ||
			!validPrivateDigest(fact.TargetPrincipalIdentityDigest) ||
			!validPrivateDigest(fact.ServicePrincipalIdentityDigest) {
			t.Fatalf("fact=%+v ok=%t parse=%+v commands=%+v", fact, ok, facts.Parse, facts.Commands)
		}
		projection := fmt.Sprintf("%+v", fact)
		for _, sensitive := range []string{
			"lab.example", "service-account", s4uTestCredential,
			"administrator", "cifs/dc.lab.example",
		} {
			if strings.Contains(projection, sensitive) {
				t.Fatalf("source value escaped projection: %q", projection)
			}
		}
	}
}

func TestExactKerberosS4UTicketRequestStructuredArgv(t *testing.T) {
	fact, ok := ExactKerberosS4UTicketRequest(Analyze(Input{
		Tool: "execute_command",
		Argv: []string{
			"impacket-getST", "-spn", "ldap/dc.lab.example",
			"-impersonate", "target-user", "lab.example/source-user:" + s4uTestCredential,
		},
	}))
	if !ok || fact.TargetPrincipalIdentityDigest !=
		KerberosS4UTargetPrincipalIdentityDigest("target-user") {
		t.Fatalf("fact=%+v ok=%t", fact, ok)
	}
}

func TestExactKerberosS4UTicketRequestHardNegatives(t *testing.T) {
	base := "impacket-getST -spn cifs/dc.lab.example -impersonate administrator -dc-ip 192.0.2.10 lab.example/service-account:" + s4uTestCredential
	tests := []struct {
		name    string
		command string
	}{
		{"missing spn", strings.Replace(base, " -spn cifs/dc.lab.example", "", 1)},
		{"duplicate spn", strings.Replace(base, " -impersonate", " -spn ldap/dc.lab.example -impersonate", 1)},
		{"missing impersonate", strings.Replace(base, " -impersonate administrator", "", 1)},
		{"duplicate impersonate", strings.Replace(base, " -dc-ip", " -impersonate second-user -dc-ip", 1)},
		{"missing source", strings.TrimSuffix(base, " lab.example/service-account:"+s4uTestCredential)},
		{"second source", base + " lab.example/other:" + s4uTestCredential},
		{"missing domain", strings.Replace(base, "lab.example/service-account:", "service-account:", 1)},
		{"missing credential", strings.TrimSuffix(base, s4uTestCredential)},
		{"dynamic credential", strings.Replace(base, s4uTestCredential, "${PASSWORD}", 1)},
		{"dynamic principal", strings.Replace(base, "administrator", "${TARGET}", 1)},
		{"malformed spn", strings.Replace(base, "cifs/dc.lab.example", "cifs//dc.lab.example", 1)},
		{"duplicate dc", base + " -dc-ip 192.0.2.11"},
		{"hostname dc", strings.Replace(base, "192.0.2.10", "dc.lab.example", 1)},
		{"unknown flag", base + " -debug"},
		{"wrong option case", strings.Replace(base, "-spn", "-SPN", 1)},
		{"unsupported source order", "impacket-getST lab.example/service-account:" + s4uTestCredential + " -spn cifs/dc.lab.example -impersonate administrator"},
		{"hash option", base + " -hashes supplied-at-runtime"},
		{"sudo wrapper", "sudo " + base},
		{"env wrapper", "env MODE=test " + base},
		{"python wrapper", strings.Replace(base, "impacket-getST", "python3 getST.py", 1)},
		{"redirect", base + " 2>&1"},
		{"pipeline", base + " | tee ticket.log"},
		{"compound", base + " && echo done"},
		{"conditional", "if true; then " + base + "; fi"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "execute_command", Command: test.command})
			if fact, ok := ExactKerberosS4UTicketRequest(facts); ok {
				t.Fatalf("hard negative projected %+v; parse=%+v commands=%+v", fact, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestExactKerberosS4UTicketResultRequiresOrderedContinuousProof(t *testing.T) {
	targetDigest := KerberosS4UTargetPrincipalIdentityDigest("administrator")
	artifact := "administrator@cifs_dc.lab.example@LAB.EXAMPLE.ccache"
	result := strings.Join([]string{
		"Impacket fixture banner",
		kerberosS4UImpersonatingPrefix + "Administrator",
		kerberosS4USelfLine,
		kerberosS4UProxyLine,
		kerberosS4USavingPrefix + artifact,
	}, "\n")
	want := KerberosS4UTicketArtifactIdentityDigest(artifact)
	if got := ExactKerberosS4UTicketResult([]byte(result), targetDigest); got != want {
		t.Fatalf("result digest=%q want=%q", got, want)
	}

	tests := []struct {
		name   string
		result string
		digest string
	}{
		{"wrong expected target", result, KerberosS4UTargetPrincipalIdentityDigest("other-user")},
		{"missing target", strings.Replace(result, kerberosS4UImpersonatingPrefix+"Administrator\n", "", 1), targetDigest},
		{"mismatched target", strings.Replace(result, "Administrator", "other-user", 1), targetDigest},
		{"duplicate target", strings.Replace(result, kerberosS4USelfLine, kerberosS4UImpersonatingPrefix+"administrator\n"+kerberosS4USelfLine, 1), targetDigest},
		{"missing self", strings.Replace(result, kerberosS4USelfLine+"\n", "", 1), targetDigest},
		{"duplicate self", strings.Replace(result, kerberosS4USelfLine, kerberosS4USelfLine+"\n"+kerberosS4USelfLine, 1), targetDigest},
		{"missing proxy", strings.Replace(result, kerberosS4UProxyLine+"\n", "", 1), targetDigest},
		{"duplicate proxy", strings.Replace(result, kerberosS4UProxyLine, kerberosS4UProxyLine+"\n"+kerberosS4UProxyLine, 1), targetDigest},
		{"reordered stages", strings.Replace(result, kerberosS4USelfLine+"\n"+kerberosS4UProxyLine, kerberosS4UProxyLine+"\n"+kerberosS4USelfLine, 1), targetDigest},
		{"missing artifact", strings.Replace(result, "\n"+kerberosS4USavingPrefix+artifact, "", 1), targetDigest},
		{"duplicate artifact", result + "\n" + kerberosS4USavingPrefix + artifact, targetDigest},
		{"traversal artifact", strings.Replace(result, artifact, "../"+artifact, 1), targetDigest},
		{"failure marker", result + "\n[-] KDC request failed", targetDigest},
		{"kdc error", result + "\nKDC_ERR_BADOPTION", targetDigest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ExactKerberosS4UTicketResult([]byte(test.result), test.digest); got != "" {
				t.Fatalf("invalid result produced digest %q", got)
			}
		})
	}
	oversized := append([]byte(result), bytes.Repeat([]byte{'x'}, kerberosS4UResultMaxBytes)...)
	if got := ExactKerberosS4UTicketResult(oversized, targetDigest); got != "" {
		t.Fatalf("oversized result produced digest %q", got)
	}
	oversizedLine := result + "\n" + strings.Repeat("x", kerberosS4UResultLineMaxBytes+1)
	if got := ExactKerberosS4UTicketResult([]byte(oversizedLine), targetDigest); got != "" {
		t.Fatalf("oversized result line produced digest %q", got)
	}
	withNUL := append(append([]byte(nil), []byte(result)...), 0)
	if got := ExactKerberosS4UTicketResult(withNUL, targetDigest); got != "" {
		t.Fatalf("NUL result produced digest %q", got)
	}
}

func TestExactKerberosS4USecretsDumpSink(t *testing.T) {
	artifact := "administrator@cifs_dc.lab.example@LAB.EXAMPLE.ccache"
	tests := []struct {
		name    string
		command string
	}{
		{"minimal", "KRB5CCNAME=" + artifact + " impacket-secretsdump -k -no-pass lab.example/administrator@dc.lab.example"},
		{"routed user scope", "KRB5CCNAME='" + artifact + "' secretsdump.py -k -no-pass -dc-ip 192.0.2.10 -just-dc-user administrator lab.example/administrator@dc.lab.example"},
		{"target route and ntds scope", "KRB5CCNAME=" + artifact + " impacket-secretsdump -k -no-pass -target-ip 192.0.2.10 lab.example/administrator@dc.lab.example -just-dc-ntlm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fact, ok := ExactKerberosS4USecretsDumpSink(Input{
				Tool: "execute_command", Command: test.command, DialectHint: DialectPOSIX,
			})
			if !ok || fact.TicketArtifactIdentityDigest !=
				KerberosS4UTicketArtifactIdentityDigest(artifact) ||
				!validPrivateDigest(fact.TargetPrincipalIdentityDigest) {
				t.Fatalf("command shape failed: fact=%+v ok=%t", fact, ok)
			}
			projection := fmt.Sprintf("%+v", fact)
			if strings.Contains(projection, artifact) || strings.Contains(projection, "administrator") {
				t.Fatalf("sink value escaped projection: %q", projection)
			}
		})
	}

	raw, err := json.Marshal(map[string]string{
		"command": "KRB5CCNAME=" + artifact + " impacket-secretsdump -k -no-pass lab.example/administrator@dc.lab.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fact, ok := ExactKerberosS4USecretsDumpSink(Input{
		Tool: "execute_command", Args: raw, DialectHint: DialectPOSIX,
	}); !ok || fact.TicketArtifactIdentityDigest == "" {
		t.Fatalf("closed command args failed: fact=%+v ok=%t", fact, ok)
	}
}

func TestExactKerberosS4USecretsDumpSinkHardNegatives(t *testing.T) {
	artifact := "administrator@cifs_dc.lab.example@LAB.EXAMPLE.ccache"
	base := "KRB5CCNAME=" + artifact + " impacket-secretsdump -k -no-pass -dc-ip 192.0.2.10 -just-dc-user administrator lab.example/administrator@dc.lab.example"
	tests := []struct {
		name    string
		command string
	}{
		{"missing assignment", strings.TrimPrefix(base, "KRB5CCNAME="+artifact+" ")},
		{"wrong assignment", strings.Replace(base, "KRB5CCNAME", "TICKET", 1)},
		{"second assignment", "MODE=test " + base},
		{"dynamic artifact", strings.Replace(base, artifact, "${TICKET}", 1)},
		{"artifact path", strings.Replace(base, artifact, "../"+artifact, 1)},
		{"wrong extension", strings.Replace(base, ".ccache", ".kirbi", 1)},
		{"missing kerberos", strings.Replace(base, " -k", "", 1)},
		{"missing no pass", strings.Replace(base, " -no-pass", "", 1)},
		{"reordered auth flags", strings.Replace(base, "-k -no-pass", "-no-pass -k", 1)},
		{"wrong auth flag case", strings.Replace(base, "-no-pass", "-NO-PASS", 1)},
		{"duplicate kerberos", strings.Replace(base, " -no-pass", " -k -no-pass", 1)},
		{"password option", base + " -password supplied-at-runtime"},
		{"hash option", base + " -hashes supplied-at-runtime"},
		{"duplicate route", base + " -dc-ip 192.0.2.11"},
		{"multiple scopes", base + " -just-dc"},
		{"dynamic target", strings.Replace(base, "lab.example/administrator@dc.lab.example", "${TARGET}", 1)},
		{"credential target", strings.Replace(base, "lab.example/administrator@dc.lab.example", "lab.example/administrator:provided@dc.lab.example", 1)},
		{"second target", base + " lab.example/administrator@dc2.lab.example"},
		{"wrapper", strings.Replace(base, "impacket-secretsdump", "sudo impacket-secretsdump", 1)},
		{"redirect", base + " 2>&1"},
		{"pipeline", base + " | tee dump.log"},
		{"compound", base + " && echo done"},
		{"conditional", "if true; then " + base + "; fi"},
		{"comment", base + " # credential dump"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if fact, ok := ExactKerberosS4USecretsDumpSink(Input{
				Tool: "execute_command", Command: test.command,
			}); ok {
				t.Fatalf("hard negative projected %+v", fact)
			}
		})
	}
	if fact, ok := ExactKerberosS4USecretsDumpSink(Input{
		Tool: "execute_command", Command: base,
		Argv: []string{"impacket-secretsdump", "-k", "-no-pass", "other@dc.lab.example"},
	}); ok {
		t.Fatalf("conflicting argv projected %+v", fact)
	}
}

func TestKerberosS4UIdentityHelpersRejectAmbiguousValues(t *testing.T) {
	for _, principal := range []string{"", "${USER}", "user/name", "user@domain", " user"} {
		if digest := KerberosS4UTargetPrincipalIdentityDigest(principal); digest != "" {
			t.Fatalf("invalid principal %q produced digest %q", principal, digest)
		}
	}
	for _, artifact := range []string{
		"", ".ccache", "ticket.kirbi", "../ticket.ccache", "/tmp/ticket.ccache",
		`folder\ticket.ccache`, "${TICKET}.ccache", "ticket..ccache",
		"ticket.ccache extra", "ticket.ccache\n",
	} {
		if digest := KerberosS4UTicketArtifactIdentityDigest(artifact); digest != "" {
			t.Fatalf("invalid artifact %q produced digest %q", artifact, digest)
		}
	}
	first := KerberosS4UTicketArtifactIdentityDigest("Ticket.ccache")
	if !validPrivateDigest(first) || first ==
		KerberosS4UTicketArtifactIdentityDigest("ticket.ccache") {
		t.Fatalf("artifact identity must be valid and case-sensitive: %q", first)
	}
}
