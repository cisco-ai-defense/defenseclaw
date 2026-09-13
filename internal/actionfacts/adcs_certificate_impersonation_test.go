// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"strings"
	"testing"
)

const adcsTestPassword = "provided-by-secret-store"

func TestExactADCSCertificateImpersonationRequestObservedOrders(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{
			name: "routing before certificate options",
			command: "certipy-ad req -u missandei@essos.local -p " + adcsTestPassword +
				" -dc-ip 192.0.2.12 -target ca.essos.local -ca ESSOS-CA" +
				" -template ESC1 -upn administrator@essos.local",
		},
		{
			name: "routing between required options",
			command: "certipy-ad req -u robb.stark@north.example -p " + adcsTestPassword +
				" -ca EXAMPLE-CA -target 192.0.2.10 -template Administrator" +
				" -upn administrator@example.local",
		},
		{
			name: "certipy spelling without routing",
			command: "certipy req -template SubCA -upn Administrator@example.local" +
				" -ca EXAMPLE-CA -p " + adcsTestPassword + " -u user@example.local",
		},
		{
			name: "target after requested principal",
			command: "certipy-ad req -u user@example.local -p " + adcsTestPassword +
				" -ca EXAMPLE-CA -template ESC1 -upn admin@example.local" +
				" -target ca.example.local -dc-ip 2001:db8::10",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fact, ok := ExactADCSCertificateImpersonationRequest(Analyze(Input{
				Tool: "execute_command", Command: test.command,
			}))
			if !ok || fact.CommandID == 0 ||
				!validPrivateDigest(fact.SourcePrincipalIdentityDigest) ||
				!validPrivateDigest(fact.TargetPrincipalIdentityDigest) ||
				fact.SourcePrincipalIdentityDigest == fact.TargetPrincipalIdentityDigest {
				t.Fatalf("fact=%+v ok=%t", fact, ok)
			}
		})
	}
}

func TestExactADCSCertificateImpersonationRequestStructuredArgv(t *testing.T) {
	fact, ok := ExactADCSCertificateImpersonationRequest(Analyze(Input{
		Tool: "execute_command",
		Argv: []string{
			"certipy-ad", "req", "-u", "operator@example.local",
			"-p", adcsTestPassword, "-ca", "EXAMPLE-CA", "-template", "ESC1",
			"-upn", "administrator@example.local", "-target", "ca.example.local",
		},
	}))
	if !ok || fact.CommandID == 0 {
		t.Fatalf("fact=%+v ok=%t", fact, ok)
	}
}

func TestExactADCSCertificateImpersonationRequestHardNegatives(t *testing.T) {
	base := "certipy-ad req -u operator@example.local -p " + adcsTestPassword +
		" -ca EXAMPLE-CA -template ESC1 -upn administrator@example.local" +
		" -target ca.example.local -dc-ip 192.0.2.10"
	tests := []struct {
		name    string
		command string
	}{
		{name: "same principal", command: strings.Replace(base, "operator@example.local", "ADMINISTRATOR@EXAMPLE.LOCAL", 1)},
		{name: "ambiguous unqualified same local", command: strings.Replace(base, "operator@example.local", "administrator", 1)},
		{name: "missing source", command: strings.Replace(base, " -u operator@example.local", "", 1)},
		{name: "missing password", command: strings.Replace(base, " -p "+adcsTestPassword, "", 1)},
		{name: "hash credential", command: strings.Replace(base, "-p "+adcsTestPassword, "-hashes supplied-at-runtime", 1)},
		{name: "missing ca", command: strings.Replace(base, " -ca EXAMPLE-CA", "", 1)},
		{name: "missing template", command: strings.Replace(base, " -template ESC1", "", 1)},
		{name: "missing target principal", command: strings.Replace(base, " -upn administrator@example.local", "", 1)},
		{name: "duplicate source", command: strings.Replace(base, " -p ", " -u second@example.local -p ", 1)},
		{name: "duplicate optional", command: base + " -target other.example.local"},
		{name: "unknown option", command: base + " -debug yes"},
		{name: "flag as value", command: strings.Replace(base, "-ca EXAMPLE-CA", "-ca -template", 1)},
		{name: "dynamic source", command: strings.Replace(base, "operator@example.local", "${USER}@example.local", 1)},
		{name: "dynamic password", command: strings.Replace(base, adcsTestPassword, "$(credential-helper)", 1)},
		{name: "malformed target principal", command: strings.Replace(base, "administrator@example.local", "admin@@example.local", 1)},
		{name: "malformed ca", command: strings.Replace(base, "EXAMPLE-CA", "Example CA", 1)},
		{name: "invalid dc", command: strings.Replace(base, "192.0.2.10", "dc.example.local", 1)},
		{name: "unspecified dc", command: strings.Replace(base, "192.0.2.10", "0.0.0.0", 1)},
		{name: "sudo wrapper", command: "sudo " + base},
		{name: "env wrapper", command: "env MODE=test " + base},
		{name: "pipeline", command: base + " | tee request.log"},
		{name: "redirect", command: base + " 2>&1"},
		{name: "compound", command: base + " && echo done"},
		{name: "conditional", command: "if true; then " + base + "; fi"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "execute_command", Command: test.command})
			if fact, ok := ExactADCSCertificateImpersonationRequest(facts); ok {
				t.Fatalf("hard negative projected %+v; parse=%+v commands=%+v",
					fact, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestExactADCSCertificateImpersonationAuthObservedOrders(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantTarget bool
	}{
		{
			name: "minimal certipy-ad",
			command: "certipy-ad auth -pfx administrator.pfx" +
				" -dc-ip 192.0.2.10",
		},
		{
			name: "resolved target identity",
			command: "certipy auth -dc-ip 192.0.2.10 -username Administrator" +
				" -domain example.local -pfx /tmp/administrator.pfx",
			wantTarget: true,
		},
		{
			name: "upn target before artifact",
			command: "certipy-ad auth -username administrator@example.local" +
				" -pfx ./administrator.pfx -dc-ip 2001:db8::10",
			wantTarget: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fact, ok := ExactADCSCertificateImpersonationAuth(Analyze(Input{
				Tool: "execute_command", Command: test.command,
			}))
			if !ok || fact.CommandID == 0 ||
				!validPrivateDigest(fact.PFXArtifactIdentityDigest) {
				t.Fatalf("fact=%+v ok=%t", fact, ok)
			}
			if test.wantTarget != validPrivateDigest(fact.TargetPrincipalIdentityDigest) {
				t.Fatalf("target digest=%q wantTarget=%t", fact.TargetPrincipalIdentityDigest, test.wantTarget)
			}
		})
	}
}

func TestExactADCSCertificateImpersonationAuthHardNegatives(t *testing.T) {
	base := "certipy-ad auth -pfx administrator.pfx -dc-ip 192.0.2.10"
	tests := []struct {
		name    string
		command string
	}{
		{name: "missing pfx", command: "certipy-ad auth -dc-ip 192.0.2.10"},
		{name: "missing dc", command: "certipy-ad auth -pfx administrator.pfx"},
		{name: "wrong extension", command: strings.Replace(base, ".pfx", ".pem", 1)},
		{name: "dynamic artifact", command: strings.Replace(base, "administrator.pfx", "${CERT}.pfx", 1)},
		{name: "parent traversal", command: strings.Replace(base, "administrator.pfx", "../administrator.pfx", 1)},
		{name: "tilde artifact", command: strings.Replace(base, "administrator.pfx", "~/administrator.pfx", 1)},
		{name: "duplicate pfx", command: base + " -pfx second.pfx"},
		{name: "unknown option", command: base + " -no-save value"},
		{name: "domain without username", command: base + " -domain example.local"},
		{name: "conflicting username domain", command: base + " -username admin@other.local -domain example.local"},
		{name: "malformed username", command: base + " -username admin@@example.local"},
		{name: "invalid dc", command: strings.Replace(base, "192.0.2.10", "dc.example.local", 1)},
		{name: "sudo wrapper", command: "sudo " + base},
		{name: "pipeline", command: base + " | tee auth.log"},
		{name: "redirect", command: base + " 2>&1"},
		{name: "compound", command: base + " && echo done"},
		{name: "conditional", command: "if true; then " + base + "; fi"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "execute_command", Command: test.command})
			if fact, ok := ExactADCSCertificateImpersonationAuth(facts); ok {
				t.Fatalf("hard negative projected %+v; parse=%+v commands=%+v",
					fact, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestADCSCertificateIdentityDigestsAreCanonicalAndValueFree(t *testing.T) {
	const (
		source = "Operator@Example.Local"
		target = "Administrator@example.local"
		pfx    = "/tmp/administrator.pfx"
	)
	request, ok := ExactADCSCertificateImpersonationRequest(Analyze(Input{
		Tool: "execute_command",
		Command: "certipy-ad req -u " + source + " -p " + adcsTestPassword +
			" -ca EXAMPLE-CA -template ESC1 -upn " + target,
	}))
	if !ok {
		t.Fatal("expected exact request fact")
	}
	auth, ok := ExactADCSCertificateImpersonationAuth(Analyze(Input{
		Tool: "execute_command",
		Command: "certipy-ad auth -pfx " + pfx + " -dc-ip 192.0.2.10" +
			" -username Administrator -domain EXAMPLE.LOCAL",
	}))
	if !ok {
		t.Fatal("expected exact auth fact")
	}
	if request.SourcePrincipalIdentityDigest !=
		ADCSCertificatePrincipalIdentityDigest("operator", "example.local") ||
		request.TargetPrincipalIdentityDigest != auth.TargetPrincipalIdentityDigest ||
		auth.PFXArtifactIdentityDigest != ADCSCertificatePFXArtifactIdentityDigest(pfx) ||
		ADCSCertificatePFXArtifactIdentityDigest("./administrator.pfx") !=
			ADCSCertificatePFXArtifactIdentityDigest("administrator.pfx") {
		t.Fatalf("canonical identity mismatch: request=%+v auth=%+v", request, auth)
	}
	if ADCSCertificatePrincipalIdentityDigest("administrator", "example.local") ==
		ADCSCertificatePFXArtifactIdentityDigest("administrator.pfx") {
		t.Fatal("principal and artifact digest domains must differ")
	}
	projection := fmt.Sprintf("%+v %+v", request, auth)
	for _, raw := range []string{source, target, pfx, adcsTestPassword} {
		if strings.Contains(projection, raw) {
			t.Fatalf("raw value %q escaped projection %q", raw, projection)
		}
	}
}

func TestADCSCertificateIdentityDigestRejectsUnsafeValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		digest string
	}{
		{name: "empty principal", digest: ADCSCertificatePrincipalIdentityDigest("", "")},
		{name: "dynamic principal", digest: ADCSCertificatePrincipalIdentityDigest("${USER}", "example.local")},
		{name: "malformed domain", digest: ADCSCertificatePrincipalIdentityDigest("user", "example..local")},
		{name: "empty artifact", digest: ADCSCertificatePFXArtifactIdentityDigest("")},
		{name: "wrong artifact extension", digest: ADCSCertificatePFXArtifactIdentityDigest("ticket.pem")},
		{name: "artifact traversal", digest: ADCSCertificatePFXArtifactIdentityDigest("a/../../ticket.pfx")},
		{name: "artifact expansion", digest: ADCSCertificatePFXArtifactIdentityDigest("$(pwd)/ticket.pfx")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.digest != "" {
				t.Fatalf("unsafe value produced digest %q", test.digest)
			}
		})
	}
}

func TestExactADCSCertificateHelpersRejectNonAuthoritativeFacts(t *testing.T) {
	request := Facts{
		Parse: ParseResult{Status: StatusPartial},
		Commands: []CommandFact{{
			ID: 1, Kind: CommandKindProcess, Effect: EffectExecute,
			Program: "certipy-ad", ArgvComplete: true,
			Argv: []string{
				"certipy-ad", "req", "-u", "operator@example.local",
				"-p", adcsTestPassword, "-ca", "EXAMPLE-CA", "-template", "ESC1",
				"-upn", "administrator@example.local",
			},
		}},
	}
	if fact, ok := ExactADCSCertificateImpersonationRequest(request); ok {
		t.Fatalf("non-authoritative request projected %+v", fact)
	}
	request.Parse.Issues = []IssueCode{IssueUnknownOperandGrammar}
	request.Commands[0].ID = 0
	if fact, ok := ExactADCSCertificateImpersonationRequest(request); ok {
		t.Fatalf("zero-ID request projected %+v", fact)
	}
}
