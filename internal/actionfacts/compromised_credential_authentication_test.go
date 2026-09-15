// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompromisedCredentialAuthenticationProjectsExactOpaqueLineage(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	record := Analyze(Input{
		Tool:                     "add_compromised_account",
		Args:                     json.RawMessage(`{"username":"fixture.example\\operator","password":"fixture-secret-alpha"}`),
		CredentialLineageHMACKey: key,
	})
	used := Analyze(Input{
		Tool:                     "execute_command",
		Args:                     json.RawMessage(`{"command":"nxc smb host.fixture -u operator -p fixture-secret-alpha -d fixture.example --shares"}`),
		CredentialLineageHMACKey: key,
	})
	recorded, recordedOK := ExactCompromisedCredentialAuthentication(record)
	authenticated, authenticatedOK := ExactCompromisedCredentialAuthentication(used)
	if !recordedOK || !authenticatedOK ||
		recorded.Operation != CompromisedCredentialRecorded ||
		authenticated.Operation != CompromisedCredentialUsed ||
		recorded.AccountIdentityHMAC != authenticated.AccountIdentityHMAC ||
		recorded.CredentialValueHMAC != authenticated.CredentialValueHMAC {
		t.Fatalf("recorded=%+v/%t authenticated=%+v/%t parse=%+v commands=%+v",
			recorded, recordedOK, authenticated, authenticatedOK, used.Parse, used.Commands)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{"fixture.example", "operator", "fixture-secret-alpha"} {
		if strings.Contains(string(encoded), plaintext) {
			t.Fatalf("plaintext %q crossed Facts boundary: %s", plaintext, encoded)
		}
	}
}

func TestCompromisedCredentialAuthenticationAcceptsClosedMultipleTargetGrammar(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	facts := Analyze(Input{
		Tool: "execute_command",
		Args: json.RawMessage(
			`{"command":"nxc smb host-one.fixture host-two.fixture -u operator -p fixture-secret-alpha -d fixture.example --shares"}`,
		),
		CredentialLineageHMACKey: key,
	})
	fact, ok := ExactCompromisedCredentialAuthentication(facts)
	if !ok || fact.Operation != CompromisedCredentialUsed {
		t.Fatalf("multiple-target authentication fact=%+v/%t parse=%+v commands=%+v",
			fact, ok, facts.Parse, facts.Commands)
	}
}

func TestCompromisedCredentialAuthenticationRejectsNormalizedCrossDomainShape(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	recorded := Analyze(Input{
		Tool: "add_compromised_account",
		Args: json.RawMessage(
			`{"username":"sevenkingdoms.local\\Administrator","password":"REDACTED_SECRET_0001"}`,
		),
		CredentialLineageHMACKey: key,
	})
	used := Analyze(Input{
		Tool: "execute_command",
		Args: json.RawMessage(
			`{"command":"nxc smb 192.168.122.10 192.168.122.11 192.168.122.12 -u Administrator -H REDACTED_SECRET_0001 -d NORTH.SEVENKINGDOMS.LOCAL"}`,
		),
		CredentialLineageHMACKey: key,
	})
	left, leftOK := ExactCompromisedCredentialAuthentication(recorded)
	right, rightOK := ExactCompromisedCredentialAuthentication(used)
	if !leftOK || !rightOK || left.AccountIdentityHMAC == right.AccountIdentityHMAC ||
		left.CredentialValueHMAC != right.CredentialValueHMAC {
		t.Fatalf("cross-domain identities were not separated: recorded=%+v/%t used=%+v/%t",
			left, leftOK, right, rightOK)
	}
}

func TestCompromisedCredentialAuthenticationJoinsNormalizedMultipleTargetShape(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	recorded := Analyze(Input{
		Tool: "add_compromised_account",
		Args: json.RawMessage(
			`{"username":"brandon.stark@north.sevenkingdoms.local","password":"REDACTED_SECRET_0001"}`,
		),
		CredentialLineageHMACKey: key,
	})
	used := Analyze(Input{
		Tool: "execute_command",
		Args: json.RawMessage(
			`{"command":"nxc smb 192.168.122.10 192.168.122.11 192.168.122.12 -u brandon.stark -p REDACTED_SECRET_0001 -d north.sevenkingdoms.local"}`,
		),
		CredentialLineageHMACKey: key,
	})
	left, leftOK := ExactCompromisedCredentialAuthentication(recorded)
	right, rightOK := ExactCompromisedCredentialAuthentication(used)
	if !leftOK || !rightOK || left.AccountIdentityHMAC != right.AccountIdentityHMAC ||
		left.CredentialValueHMAC != right.CredentialValueHMAC {
		t.Fatalf("recorded=%+v/%t used=%+v/%t parse=%+v commands=%+v",
			left, leftOK, right, rightOK, used.Parse, used.Commands)
	}
}

func TestCompromisedCredentialAuthenticationRejectsAmbiguousAndUnresolvedInputs(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	for name, input := range map[string]Input{
		"missing key": {
			Tool: "add_compromised_account",
			Args: json.RawMessage(`{"username":"operator","password":"fixture-secret-alpha"}`),
		},
		"dynamic record": {
			Tool:                     "add_compromised_account",
			Args:                     json.RawMessage(`{"username":"operator","password":"${FIXTURE_PASSWORD}"}`),
			CredentialLineageHMACKey: key,
		},
		"extra record field": {
			Tool:                     "add_compromised_account",
			Args:                     json.RawMessage(`{"username":"operator","password":"fixture-secret-alpha","note":"x"}`),
			CredentialLineageHMACKey: key,
		},
		"dynamic authentication": {
			Tool:                     "execute_command",
			Args:                     json.RawMessage(`{"command":"nxc smb host.fixture -u operator -p ${FIXTURE_PASSWORD} --shares"}`),
			CredentialLineageHMACKey: key,
		},
		"multiple authentication commands": {
			Tool:                     "execute_command",
			Args:                     json.RawMessage(`{"command":"nxc smb one.fixture -u operator -p fixture-secret-alpha --shares && nxc smb two.fixture -u operator -p fixture-secret-alpha --shares"}`),
			CredentialLineageHMACKey: key,
		},
		"lowercase help is not hash": {
			Tool:                     "execute_command",
			Args:                     json.RawMessage(`{"command":"nxc smb host.fixture -u operator -h fixture-secret-alpha"}`),
			CredentialLineageHMACKey: key,
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := Analyze(input)
			if _, ok := ExactCompromisedCredentialAuthentication(facts); ok {
				t.Fatalf("unexpected lineage fact: %+v", facts.CompromisedCredentialAuthentications)
			}
		})
	}
}

func TestCompromisedCredentialAuthenticationSeparatesAccountCredentialAndProcessKey(t *testing.T) {
	project := func(username, credential string, key [32]byte) CompromisedCredentialAuthenticationFact {
		t.Helper()
		raw, err := json.Marshal(map[string]string{
			"username": username, "password": credential,
		})
		if err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{
			Tool: "add_compromised_account", Args: raw,
			CredentialLineageHMACKey: key,
		})
		fact, ok := ExactCompromisedCredentialAuthentication(facts)
		if !ok {
			t.Fatalf("missing fact for %q", username)
		}
		return fact
	}
	keyA, keyB := [32]byte{1}, [32]byte{2}
	base := project("operator", "fixture-secret-alpha", keyA)
	otherAccount := project("auditor", "fixture-secret-alpha", keyA)
	otherCredential := project("operator", "fixture-secret-beta", keyA)
	otherProcess := project("operator", "fixture-secret-alpha", keyB)
	if base.AccountIdentityHMAC == otherAccount.AccountIdentityHMAC ||
		base.CredentialValueHMAC != otherAccount.CredentialValueHMAC ||
		base.AccountIdentityHMAC != otherCredential.AccountIdentityHMAC ||
		base.CredentialValueHMAC == otherCredential.CredentialValueHMAC ||
		base.AccountIdentityHMAC == otherProcess.AccountIdentityHMAC ||
		base.CredentialValueHMAC == otherProcess.CredentialValueHMAC {
		t.Fatalf("lineage HMAC domains did not separate inputs")
	}
}
