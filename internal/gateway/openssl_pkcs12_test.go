// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const openSSLPKCS12PrivateKeyRuleID = "credential.pkcs12_private_key_extract"

func TestOpenSSLPKCS12PrivateKeyExtractionDetectionOnly(t *testing.T) {
	t.Parallel()
	command := "openssl pkcs12 -in /tmp/account.pfx -nodes -passin pass:"
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	findings := scanTrustedToolArgs(t, "execute_command", string(raw))
	matched := findingWithID(findings, openSSLPKCS12PrivateKeyRuleID)
	if matched == nil || matched.Severity != "HIGH" || matched.Evidence != "" ||
		matched.contributesToEnforcement() {
		t.Fatalf("finding=%+v all=%v", matched, FindingStrings(findings))
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		evaluation := EvaluateDeterministicAction(
			context.Background(),
			actionfacts.Input{Tool: "execute_command", Command: command},
			command,
			"benchmark-"+profile,
			profile,
		)
		if evaluation.Action == guardrailActionBlock ||
			evaluation.Action == guardrailActionConfirm {
			t.Fatalf("profile=%s action=%s", profile, evaluation.Action)
		}
	}
}

func TestOpenSSLPKCS12PrivateKeyExtractionSafeNegatives(t *testing.T) {
	t.Parallel()
	for _, command := range []string{
		"openssl pkcs12 -in /tmp/account.pfx -nokeys",
		"openssl pkcs12 -in /tmp/account.pfx -noout -info",
		"openssl pkcs12 -in /tmp/account.pem -nodes",
		"openssl pkcs12 -in $BUNDLE -nodes",
		"echo 'openssl pkcs12 -in /tmp/account.pfx -nodes'",
	} {
		raw, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		findings := scanTrustedToolArgs(t, "execute_command", string(raw))
		if findingWithID(findings, openSSLPKCS12PrivateKeyRuleID) != nil {
			t.Fatalf("safe negative %q findings=%v", command, FindingStrings(findings))
		}
	}
}
