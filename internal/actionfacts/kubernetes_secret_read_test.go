// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExactKubernetesSecretContentRead(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{
			name: "singular json argv",
			input: Input{Tool: "execute_command", Argv: []string{
				"kubectl", "get", "secret", "database-login", "-o", "json",
			}},
		},
		{
			name: "plural yaml namespace before verb",
			input: Input{Tool: "execute_command", Argv: []string{
				"kubectl", "--namespace", "payments", "get", "secrets",
				"database-login", "--output=yaml",
			}},
		},
		{
			name: "closed jsonpath data key",
			input: Input{Tool: "execute_command", Argv: []string{
				"kubectl", "get", "secret", "database-login", "-n=payments",
				"--context", "development-cluster",
				"-o=jsonpath={.data.password}",
			}},
		},
		{
			name: "closed go template string data",
			input: Input{Tool: "execute_command", Argv: []string{
				"kubectl", "get", "secrets", "database-login",
				"--output", "go-template={{ .stringData.token_key }}",
			}},
		},
		{
			name: "structured kubectl schema namespace",
			input: Input{Tool: "kubectl", Args: json.RawMessage(
				`{"command":"get secret database-login --output json","namespace":"payments"}`,
			)},
		},
		{
			name: "matching schema and command namespace",
			input: Input{Tool: "kubectl", Args: json.RawMessage(
				`{"command":"get secret database-login -n payments -o yaml","namespace":"payments"}`,
			)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			fact, ok := ExactKubernetesSecretContentRead(test.input, facts)
			if !ok || !validPrivateDigest(fact.SecretIdentityDigest) {
				t.Fatalf("fact=%+v ok=%t parse=%+v", fact, ok, facts.Parse)
			}
			encoded, err := json.Marshal(fact)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != "{}" {
				t.Fatalf("private fact serialized as %s", encoded)
			}
		})
	}
}

func TestKubernetesSecretContentReadIdentityJoins(t *testing.T) {
	inputs := []Input{
		{Tool: "execute_command", Argv: []string{
			"kubectl", "get", "secret", "database-login", "-n", "payments", "-o", "json",
		}},
		{Tool: "execute_command", Argv: []string{
			"kubectl", "get", "secrets", "database-login", "--output=yaml",
			"--namespace=payments",
		}},
	}
	first, firstOK := ExactKubernetesSecretContentRead(inputs[0], Analyze(inputs[0]))
	second, secondOK := ExactKubernetesSecretContentRead(inputs[1], Analyze(inputs[1]))
	if !firstOK || !secondOK || first.SecretIdentityDigest != second.SecretIdentityDigest {
		t.Fatalf("equivalent identity mismatch: %+v/%t %+v/%t", first, firstOK, second, secondOK)
	}

	for _, different := range []Input{
		{Tool: "execute_command", Argv: []string{
			"kubectl", "get", "secret", "other-login", "-n", "payments", "-o", "json",
		}},
		{Tool: "execute_command", Argv: []string{
			"kubectl", "get", "secret", "database-login", "-n", "staging", "-o", "json",
		}},
		{Tool: "execute_command", Argv: []string{
			"kubectl", "get", "secret", "database-login", "-n", "payments",
			"--context", "other-cluster", "-o", "json",
		}},
	} {
		fact, ok := ExactKubernetesSecretContentRead(different, Analyze(different))
		if !ok || fact.SecretIdentityDigest == first.SecretIdentityDigest {
			t.Fatalf("different identity did not separate: %+v ok=%t", fact, ok)
		}
	}
}

func TestExactKubernetesSecretContentReadHardNegatives(t *testing.T) {
	commands := []string{
		"kubectl get secrets -A -o json",
		"kubectl get secrets --all-namespaces -o yaml",
		"kubectl get secret -o json",
		"kubectl get secret database-login",
		"kubectl get secret database-login -o name",
		"kubectl get secret database-login -o wide",
		"kubectl get secret database-login -o custom-columns=DATA:.data",
		"kubectl get secret database-login -o json -o json",
		"kubectl get secret database-login -o json --output yaml",
		"kubectl get secret database-login -n payments -n payments -o json",
		"kubectl get secret database-login -n payments --namespace staging -o json",
		"kubectl get secret database-login -l app=fixture -o json",
		"kubectl get secret database-login --selector app=fixture -o json",
		"kubectl get secret database-login --field-selector metadata.name=database-login -o json",
		"kubectl get secret database-login --raw /api/v1/secrets -o json",
		"kubectl get secret database-login --watch -o json",
		"kubectl get secret database-login -w -o json",
		"kubectl get secret database-login --context $CONTEXT -o json",
		"kubectl get secret database-login --context '{{context}}' -o json",
		"kubectl get secret database-login --context 'team context' -o json",
		"kubectl get secret $SECRET -o json",
		"kubectl get secret '$(hostname)' -o json",
		"kubectl get secret database-login -n '{{namespace}}' -o json",
		"kubectl get secret database-login other-login -o json",
		"kubectl get secret/database-login -o json",
		"kubectl get configmap database-login -o json",
		"kubectl describe secret database-login -o json",
		"kubectl get secret database-login --request-timeout=5s -o json",
		"kubectl get secret database-login -o 'jsonpath={.metadata.name}'",
		"kubectl get secret database-login -o 'jsonpath={range .data}{.}{end}'",
		"kubectl get secret database-login -o 'jsonpath={.data.*}'",
		"kubectl get secret database-login -o 'jsonpath={.data.password}{\"\\n\"}'",
		"kubectl get secret database-login -o 'go-template={{printf \"%s\" .data}}'",
		"kubectl get secret database-login -o 'go-template={{.metadata.name}}'",
		"sudo kubectl get secret database-login -o json",
		"sh -c 'kubectl get secret database-login -o json'",
		"kubectl get secret database-login -o json | jq .data",
		"kubectl get secret database-login -o json > /tmp/output",
		"echo $(kubectl get secret database-login -o json)",
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			input := Input{
				Tool: "execute_command", Command: command, DialectHint: DialectPOSIX,
			}
			if fact, ok := ExactKubernetesSecretContentRead(input, Analyze(input)); ok {
				t.Fatalf("hard negative produced fact %+v", fact)
			}
		})
	}
}

func TestExactKubernetesSecretContentReadRejectsAmbiguityAndIncompleteArgv(t *testing.T) {
	conflicting := Input{
		Tool:    "execute_command",
		Command: "kubectl get secret database-login -o json",
		Argv:    []string{"kubectl", "get", "secret", "other-login", "-o", "json"},
	}
	if fact, ok := ExactKubernetesSecretContentRead(conflicting, Analyze(conflicting)); ok {
		t.Fatalf("conflicting sources produced fact %+v", fact)
	}

	structuredConflict := Input{Tool: "kubectl", Args: json.RawMessage(
		`{"command":"get secret database-login -n staging -o json","namespace":"payments"}`,
	)}
	if fact, ok := ExactKubernetesSecretContentRead(
		structuredConflict,
		Analyze(structuredConflict),
	); ok {
		t.Fatalf("conflicting namespace produced fact %+v", fact)
	}

	incomplete := Facts{
		Parse: ParseResult{Status: StatusComplete, Dialect: DialectArgv},
		Commands: []CommandFact{{
			Effect: EffectExecute, Program: "kubectl", Executable: "kubectl",
			Argv: []string{"kubectl", "get", "secret", "database-login", "-o", "json"},
		}},
	}
	input := Input{Tool: "execute_command"}
	if fact, ok := ExactKubernetesSecretContentRead(input, incomplete); ok {
		t.Fatalf("incomplete argv produced fact %+v", fact)
	}

	nonAuthoritativeInput := Input{Tool: "execute_command", Argv: []string{
		"kubectl", "get", "secret", "database-login", "-o", "json",
	}}
	nonAuthoritative := Analyze(nonAuthoritativeInput)
	nonAuthoritative.Parse.Status = StatusPartial
	if fact, ok := ExactKubernetesSecretContentRead(
		nonAuthoritativeInput,
		nonAuthoritative,
	); ok {
		t.Fatalf("non-authoritative facts produced fact %+v", fact)
	}
}

func FuzzExactKubernetesSecretContentRead(f *testing.F) {
	for _, seed := range []string{
		"kubectl get secret database-login -o json",
		"kubectl get secrets -A -o yaml",
		"kubectl get secret database-login -o 'jsonpath={.data.password}'",
		"sudo kubectl get secret database-login -o json",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, command string) {
		if len(command) > maxCommandBytes {
			t.Skip()
		}
		input := Input{
			Tool: "execute_command", Command: command, DialectHint: DialectPOSIX,
		}
		facts := Analyze(input)
		fact, ok := ExactKubernetesSecretContentRead(input, facts)
		if !ok {
			return
		}
		if !facts.Authoritative() || !validPrivateDigest(fact.SecretIdentityDigest) {
			t.Fatalf("invalid exact result fact=%+v parse=%+v", fact, facts.Parse)
		}
		encoded, err := json.Marshal(fact)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), command) || string(encoded) != "{}" {
			t.Fatalf("private input escaped fact: %s", encoded)
		}
	})
}
