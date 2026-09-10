// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func credentialRemoteArgs(t *testing.T, value map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCredentialRemoteExecutionFactsUseExactOpaqueTuple(t *testing.T) {
	secretsdump := Analyze(Input{Tool: "secretsdump", Args: credentialRemoteArgs(t, map[string]any{
		"method": "dcsync", "target": "DC01.INTERNAL.EXAMPLE.COM.",
		"username": "INTERNAL.EXAMPLE.COM\\svc_backup",
	})})
	psexec := Analyze(Input{Tool: "psexec", Args: credentialRemoteArgs(t, map[string]any{
		"command": "whoami /all", "target": "dc01.internal.example.com",
		"username": "svc_backup@INTERNAL.EXAMPLE.COM",
	})})
	firstOperation, firstDigest, firstOK := ExactCredentialRemoteExecutionOperation(secretsdump)
	secondOperation, secondDigest, secondOK := ExactCredentialRemoteExecutionOperation(psexec)
	if !firstOK || !secondOK || firstOperation != CredentialExtractionSecretsdump ||
		secondOperation != CredentialRemoteExecutionPsExec || firstDigest == "" ||
		firstDigest != secondDigest {
		t.Fatalf("operations=%q/%q digests=%q/%q ok=%t/%t",
			firstOperation, secondOperation, firstDigest, secondDigest, firstOK, secondOK)
	}
	for _, raw := range []string{"dc01", "internal", "svc_backup", "whoami"} {
		if strings.Contains(firstDigest, raw) {
			t.Fatalf("raw identity escaped opaque projection: %q", firstDigest)
		}
	}
}

func TestCredentialRemoteExecutionAcceptsObservedClosedSchemas(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		args      map[string]any
		operation CredentialRemoteExecutionOperation
	}{
		{name: "dcsync minimal", tool: "secretsdump", operation: CredentialExtractionSecretsdump,
			args: map[string]any{"method": "dcsync", "target": "zeta-dc01.zeta.example.com", "username": "administrator"}},
		{name: "sam minimal", tool: "secretsdump", operation: CredentialExtractionSecretsdump,
			args: map[string]any{"method": "sam", "target": "192.168.1.50", "username": "ACME\\svc_backup"}},
		{name: "lsa with authentication fields", tool: "secretsdump", operation: CredentialExtractionSecretsdump,
			args: map[string]any{"domain": "INTERNAL.EXAMPLE.COM", "method": "lsa", "password": "Summer2024!", "target": "DC01.INTERNAL.EXAMPLE.COM", "username": "svc_backup"}},
		{name: "psexec minimal", tool: "psexec", operation: CredentialRemoteExecutionPsExec,
			args: map[string]any{"command": "whoami /all", "target": "10.0.0.1", "username": "svc_sql"}},
		{name: "psexec password", tool: "psexec", operation: CredentialRemoteExecutionPsExec,
			args: map[string]any{"command": "hostname", "password": "Summer2024!", "target": "DC01.INTERNAL.EXAMPLE.COM", "username": "svc_backup"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: credentialRemoteArgs(t, test.args)})
			operation, digest, ok := ExactCredentialRemoteExecutionOperation(facts)
			if !ok || operation != test.operation || digest == "" {
				t.Fatalf("operation=%q digest=%q ok=%t facts=%+v", operation, digest, ok, facts)
			}
		})
	}
}

func TestCredentialRemoteExecutionClosedGrammarHardNegatives(t *testing.T) {
	validSecretsdump := map[string]any{
		"method": "dcsync", "target": "dc01.example.test", "username": "CORP\\svc_backup",
	}
	validPsExec := map[string]any{
		"command": "whoami", "target": "dc01.example.test", "username": "CORP\\svc_backup",
	}
	tests := []struct {
		name    string
		input   Input
		rawArgs json.RawMessage
	}{
		{name: "tool name only", input: Input{Tool: "secretsdump"}},
		{name: "documentation shell", input: Input{Tool: "execute_command", Command: "secretsdump CORP/user@example && psexec CORP/user@example whoami"}},
		{name: "lookalike secretsdump", input: Input{Tool: "impacket-secretsdump", Args: credentialRemoteArgs(t, validSecretsdump)}},
		{name: "lookalike psexec", input: Input{Tool: "execute_command", Args: credentialRemoteArgs(t, validPsExec)}},
		{name: "dynamic target", input: Input{Tool: "secretsdump", Args: credentialRemoteArgs(t, map[string]any{"method": "sam", "target": "${TARGET}", "username": "svc"})}},
		{name: "dynamic principal", input: Input{Tool: "psexec", Args: credentialRemoteArgs(t, map[string]any{"command": "whoami", "target": "dc01.example.test", "username": "{{ username }}"})}},
		{name: "unsupported method", input: Input{Tool: "secretsdump", Args: credentialRemoteArgs(t, map[string]any{"method": "all", "target": "dc01.example.test", "username": "svc"})}},
		{name: "extra extraction key", input: Input{Tool: "secretsdump", Args: credentialRemoteArgs(t, map[string]any{"method": "sam", "target": "dc01.example.test", "username": "svc", "output": "dump.txt"})}},
		{name: "extra remote key", input: Input{Tool: "psexec", Args: credentialRemoteArgs(t, map[string]any{"command": "whoami", "target": "dc01.example.test", "username": "svc", "usersfile_content": "inert"})}},
		{name: "command source conflict", input: Input{Tool: "psexec", Args: credentialRemoteArgs(t, validPsExec), Command: "whoami"}},
		{name: "localhost target", input: Input{Tool: "psexec", Args: credentialRemoteArgs(t, map[string]any{"command": "whoami", "target": "localhost", "username": "svc"})}},
		{name: "multicast target", input: Input{Tool: "psexec", Args: credentialRemoteArgs(t, map[string]any{"command": "whoami", "target": "224.0.0.1", "username": "svc"})}},
		{name: "duplicate key", input: Input{Tool: "secretsdump"}, rawArgs: json.RawMessage(`{"method":"sam","target":"dc01.example.test","target":"dc02.example.test","username":"svc"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := test.input
			if test.rawArgs != nil {
				input.Args = test.rawArgs
			}
			facts := Analyze(input)
			if operation, digest, ok := ExactCredentialRemoteExecutionOperation(facts); ok {
				t.Fatalf("unexpected operation=%q digest=%q", operation, digest)
			}
		})
	}
}

func TestCredentialRemoteExecutionTupleMismatchesStayDistinct(t *testing.T) {
	digest := func(target, principal string) string {
		facts := Analyze(Input{Tool: "psexec", Args: credentialRemoteArgs(t, map[string]any{
			"command": "whoami", "target": target, "username": principal,
		})})
		_, result, ok := ExactCredentialRemoteExecutionOperation(facts)
		if !ok {
			t.Fatalf("no digest for %q/%q", target, principal)
		}
		return result
	}
	baseline := digest("dc01.example.test", "CORP\\svc_backup")
	if baseline == digest("dc02.example.test", "CORP\\svc_backup") ||
		baseline == digest("dc01.example.test", "CORP\\svc_other") ||
		baseline == digest("dc01.example.test", "svc_backup") {
		t.Fatal("target or principal mismatch collided")
	}
}

func TestCredentialRemoteExecutionDomainIsPartOfPrincipalIdentity(t *testing.T) {
	digest := func(tool string, args map[string]any) string {
		facts := Analyze(Input{Tool: tool, Args: credentialRemoteArgs(t, args)})
		_, result, ok := ExactCredentialRemoteExecutionOperation(facts)
		if !ok {
			t.Fatalf("no digest for %s %+v", tool, args)
		}
		return result
	}
	explicit := digest("secretsdump", map[string]any{
		"domain": "CORP", "method": "dcsync", "password": "FixtureOnly!",
		"target": "dc01.example.test", "username": "svc_backup",
	})
	downlevel := digest("psexec", map[string]any{
		"command": "whoami", "target": "dc01.example.test", "username": "corp\\SVC_BACKUP",
	})
	upn := digest("psexec", map[string]any{
		"command": "whoami", "target": "dc01.example.test", "username": "svc_backup@CORP",
	})
	unqualified := digest("psexec", map[string]any{
		"command": "whoami", "target": "dc01.example.test", "username": "svc_backup",
	})
	otherDomain := digest("psexec", map[string]any{
		"command": "whoami", "target": "dc01.example.test", "username": "OTHER\\svc_backup",
	})
	if explicit != downlevel || explicit != upn {
		t.Fatalf("exact qualified equivalence failed: explicit=%s downlevel=%s upn=%s",
			explicit, downlevel, upn)
	}
	if explicit == unqualified || explicit == otherDomain {
		t.Fatal("domain-qualified principal joined an unqualified or different-domain principal")
	}

	for _, username := range []string{"OTHER\\svc_backup", "svc_backup@OTHER"} {
		facts := Analyze(Input{Tool: "secretsdump", Args: credentialRemoteArgs(t, map[string]any{
			"domain": "CORP", "method": "dcsync", "password": "FixtureOnly!",
			"target": "dc01.example.test", "username": username,
		})})
		if _, _, ok := ExactCredentialRemoteExecutionOperation(facts); ok {
			t.Fatalf("conflicting explicit and qualified domains accepted: %q", username)
		}
	}
}
