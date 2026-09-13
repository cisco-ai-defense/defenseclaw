// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

// projectStructuredCredentialReads recognizes the exact one-field schema
// observed in the public agentic red-team corpus. It retains only a reviewed
// credential-store class and never any extracted credential value.
func projectStructuredCredentialReads(input Input) []StructuredCredentialReadFact {
	if input.Tool != "credential_extract" || input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	source, ok := exactStructuredCredentialReadInput(input.Args)
	if !ok {
		return nil
	}
	return []StructuredCredentialReadFact{{Source: source}}
}

func exactStructuredCredentialReadInput(raw []byte) (string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 1 {
		return "", false
	}
	source, ok := object["source"].(string)
	if !ok || !knownStructuredCredentialSource(source) {
		return "", false
	}
	return source, true
}

func knownStructuredCredentialSource(source string) bool {
	switch source {
	case "browser", "config_files", "credential_manager", "env_vars",
		"kerberos_tickets", "keychain", "lsass", "sam", "ssh_keys":
		return true
	default:
		return false
	}
}

// ExactStructuredCredentialRead returns the reviewed source class only for a
// complete closed-schema projection.
func ExactStructuredCredentialRead(facts Facts) (string, bool) {
	if facts.Parse.Status != StatusComplete || len(facts.StructuredCredentialReads) != 1 {
		return "", false
	}
	source := facts.StructuredCredentialReads[0].Source
	return source, knownStructuredCredentialSource(source)
}
