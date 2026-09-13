// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestStructuredPortForwardExactCapabilities(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		kind string
	}{
		{name: "local", raw: `{"type":"local","listen_port":13306,"target_host":"10.0.2.30","target_port":1433}`, kind: "local"},
		{name: "dynamic", raw: `{"type":"dynamic","listen_port":1080}`, kind: "dynamic"},
		{name: "socks source zero values", raw: `{"type":"socks","listen_port":1080,"target_host":"","target_port":0}`, kind: "socks"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "port_forward", Args: json.RawMessage(test.raw)})
			fact, ok := ExactStructuredPortForward(facts)
			if !ok || fact.Kind != test.kind || !facts.Authoritative() {
				t.Fatalf("fact=%+v ok=%t parse=%+v", fact, ok, facts.Parse)
			}
			if test.kind == "local" && (!validPrivateDigest(fact.TargetIdentityDigest) || fact.TargetPort != 1433) {
				t.Fatalf("local identity=%+v", fact)
			}
		})
	}
}

func TestStructuredPortForwardHardNegatives(t *testing.T) {
	for _, raw := range []string{
		`{"type":"remote","listen_port":1080,"target_host":"10.0.0.1","target_port":22}`,
		`{"type":"local","listen_port":0,"target_host":"10.0.0.1","target_port":22}`,
		`{"type":"local","listen_port":1080,"target_host":"$HOST","target_port":22}`,
		`{"type":"local","listen_port":1080,"target_host":"10.0.0.1"}`,
		`{"type":"dynamic","listen_port":1080,"target_host":"10.0.0.1","target_port":22}`,
		`{"type":"socks","listen_port":1080,"target_port":1}`,
		`{"type":"local","listen_port":1080,"target_host":"10.0.0.1","target_port":22,"bind":"0.0.0.0"}`,
	} {
		facts := Analyze(Input{Tool: "port_forward", Args: json.RawMessage(raw)})
		if fact, ok := ExactStructuredPortForward(facts); ok || facts.Authoritative() {
			t.Fatalf("hard negative escaped: fact=%+v ok=%t parse=%+v raw=%s", fact, ok, facts.Parse, raw)
		}
	}
}

func TestStructuredPortForwardTargetIdentityIsOpaqueAndStable(t *testing.T) {
	fact := func(host string, port int) StructuredPortForwardFact {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"type": "local", "listen_port": 8080, "target_host": host, "target_port": port,
		})
		if err != nil {
			t.Fatal(err)
		}
		result, ok := ExactStructuredPortForward(Analyze(Input{Tool: "port_forward", Args: raw}))
		if !ok {
			t.Fatalf("no fact for %s:%d", host, port)
		}
		return result
	}
	first := fact("db.internal", 5432)
	same := fact("DB.INTERNAL", 5432)
	other := fact("db.internal", 3306)
	if first.TargetIdentityDigest != same.TargetIdentityDigest ||
		first.TargetIdentityDigest == other.TargetIdentityDigest ||
		first.TargetIdentityDigest == "db.internal" {
		t.Fatalf("digests=%+v/%+v/%+v", first, same, other)
	}
}
