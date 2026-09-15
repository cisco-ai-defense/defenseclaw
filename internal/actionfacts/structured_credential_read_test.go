// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestStructuredCredentialReadClosedSchema(t *testing.T) {
	for _, source := range []string{"browser", "config_files", "credential_manager", "env_vars", "kerberos_tickets", "keychain", "lsass", "sam", "ssh_keys"} {
		raw, err := json.Marshal(map[string]string{"source": source})
		if err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{Tool: "credential_extract", Args: raw})
		got, ok := ExactStructuredCredentialRead(facts)
		if !ok || got != source || !facts.Authoritative() || len(facts.Commands) != 0 {
			t.Fatalf("source=%q facts=%+v", source, facts)
		}
	}
}

func TestStructuredCredentialReadHardNegatives(t *testing.T) {
	for _, object := range []map[string]any{
		{"source": "documents"},
		{"source": "SSH_KEYS"},
		{"source": "ssh_keys", "target": "external.invalid"},
		{"source": 7},
	} {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{Tool: "credential_extract", Args: raw})
		if source, ok := ExactStructuredCredentialRead(facts); ok || source != "" || len(facts.StructuredCredentialReads) != 0 {
			t.Fatalf("object=%v projected=%+v", object, facts.StructuredCredentialReads)
		}
	}
}
