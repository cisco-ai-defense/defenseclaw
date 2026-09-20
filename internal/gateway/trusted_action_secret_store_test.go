// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestTrustedSecretStoreRotateValueIsNotDisclosure(t *testing.T) {
	const connector = "trusted-secret-store-value-test"
	installDefaultProfileConnector(t, connector)
	githubToken := runtimeDetectorSignature("gh", "p_", "A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5")
	stripeToken := runtimeDetectorSignature("sk", "_live_", "A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1")

	for _, test := range []struct {
		name string
		args map[string]any
	}{
		{
			name: "key destination",
			args: map[string]any{
				"account": "fixture-user", "sender": "fixture-user",
				"key": "services/evaluation/github-token", "value": githubToken,
			},
		},
		{
			name: "name destination",
			args: map[string]any{
				"account": "fixture-user", "sender": "fixture-user",
				"name": "services/evaluation/payment-key", "value": stripeToken,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := mustTrustedSecretStoreJSON(t, test.args)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "secrets_store.rotate", Args: raw},
				LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
			})
			if findingWithID(findings, "SEC-GITHUB-TOKEN") != nil ||
				findingWithID(findings, "SEC-STRIPE") != nil {
				t.Fatalf("secret destination value became disclosure: %+v", findings)
			}
		})
	}
}

func TestTrustedSecretStoreRotateBenchmarkEnvelopeUsesOnlyExactValue(t *testing.T) {
	const connector = "trusted-secret-store-envelope-test"
	installDefaultProfileConnector(t, connector)
	token := runtimeDetectorSignature("gh", "p_", "C7b9A2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5")
	arguments := map[string]any{
		"account": "fixture-user", "sender": "fixture-user",
		"key": "kv/fixture-user/github-token", "value": token,
	}
	raw := mustTrustedSecretStoreJSON(t, map[string]any{
		"_mole_evidence": map[string]any{
			"service": "secrets_store", "action": "rotate",
			"account": "fixture-user", "args_sha256": strings.Repeat("0", 64),
		},
		"_mole_arguments": arguments,
	})
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: "secrets_store.rotate", Args: raw},
		LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
	})
	if findingWithID(findings, "SEC-GITHUB-TOKEN") != nil {
		t.Fatalf("exact wrapped secret destination value became disclosure: %+v", findings)
	}
}

func TestTrustedSecretStoreRotateValueBoundaryHardNegatives(t *testing.T) {
	const connector = "trusted-secret-store-hard-negative-test"
	installDefaultProfileConnector(t, connector)
	token := runtimeDetectorSignature("gh", "p_", "D7b9A2c4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5")
	valid := func() map[string]any {
		return map[string]any{
			"account": "fixture-user", "sender": "fixture-user",
			"key": "kv/fixture-user/github-token", "value": token,
		}
	}

	for _, test := range []struct {
		name       string
		tool       string
		args       func() json.RawMessage
		legacyText func(json.RawMessage) string
	}{
		{
			name: "wrong tool", tool: "chat.send",
			args: func() json.RawMessage { return mustTrustedSecretStoreJSON(t, valid()) },
		},
		{
			name: "extra field", tool: "secrets_store.rotate",
			args: func() json.RawMessage {
				value := valid()
				value["command"] = "publish"
				return mustTrustedSecretStoreJSON(t, value)
			},
		},
		{
			name: "identity mismatch", tool: "secrets_store.rotate",
			args: func() json.RawMessage {
				value := valid()
				value["sender"] = "other-user"
				return mustTrustedSecretStoreJSON(t, value)
			},
		},
		{
			name: "both destination aliases", tool: "secrets_store.rotate",
			args: func() json.RawMessage {
				value := valid()
				value["name"] = "other-destination"
				return mustTrustedSecretStoreJSON(t, value)
			},
		},
		{
			name: "duplicate value", tool: "secrets_store.rotate",
			args: func() json.RawMessage {
				return json.RawMessage(`{"account":"fixture-user","sender":"fixture-user","key":"safe","value":"` + token + `","value":"replacement"}`)
			},
		},
		{
			name: "legacy mismatch", tool: "secrets_store.rotate",
			args: func() json.RawMessage { return mustTrustedSecretStoreJSON(t, valid()) },
			legacyText: func(raw json.RawMessage) string {
				return string(raw) + ` {"note":"` + token + `"}`
			},
		},
		{
			name: "wrong envelope action", tool: "secrets_store.rotate",
			args: func() json.RawMessage {
				return mustTrustedSecretStoreJSON(t, map[string]any{
					"_mole_evidence": map[string]any{
						"service": "secrets_store", "action": "read",
					},
					"_mole_arguments": valid(),
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := test.args()
			legacyText := string(raw)
			if test.legacyText != nil {
				legacyText = test.legacyText(raw)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: test.tool, Args: raw},
				LegacyText: legacyText, Connector: connector, EnforcementCapable: true,
			})
			if findingWithID(findings, "SEC-GITHUB-TOKEN") == nil {
				t.Fatalf("hard negative suppressed secret finding: %+v", findings)
			}
		})
	}

	t.Run("destination remains scanned", func(t *testing.T) {
		raw := mustTrustedSecretStoreJSON(t, map[string]any{
			"account": "fixture-user", "sender": "fixture-user",
			"key": token, "value": "provided by secret store",
		})
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "secrets_store.rotate", Args: raw},
			LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
		})
		if findingWithID(findings, "SEC-GITHUB-TOKEN") == nil {
			t.Fatalf("destination field escaped secret scan: %+v", findings)
		}
	})
}

func mustTrustedSecretStoreJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
