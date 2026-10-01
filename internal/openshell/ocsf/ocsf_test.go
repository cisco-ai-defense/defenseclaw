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

//go:build !windows

package ocsf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func intPtr(n int) *int { return &n }

// kv builds a Context map from key, value pairs.
func kv(pairs ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return m
}

// TestParseUpstreamShapes covers every class with the exact strings the
// upstream formatter's own tests pin (crates/openshell-ocsf shorthand.rs at
// v0.1.1), plus the live shapes captured on the host.
func TestParseUpstreamShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Record
	}{
		{"net allowed", "NET:OPEN [INFO] ALLOWED python3(42) -> api.example.com:443 [policy:default-egress engine:mechanistic]",
			Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityInfo, Action: ActionAllowed, Binary: "python3", PID: 42, HasPID: true,
				Host: "api.example.com", Port: 443, Policy: "default-egress", Engine: "mechanistic", Context: kv("policy", "default-egress", "engine", "mechanistic")}},
		{"net bypass with protocol", "NET:REFUSE [MED] DENIED node(1234) -> 93.184.216.34:443/tcp [policy:bypass-detect engine:nftables]",
			Record{Class: ClassNetwork, Activity: "REFUSE", Severity: SeverityMedium, Action: ActionDenied, Binary: "node", PID: 1234, HasPID: true,
				Host: "93.184.216.34", Port: 443, Protocol: "tcp", Policy: "bypass-detect", Engine: "nftables", Context: kv("policy", "bypass-detect", "engine", "nftables")}},
		{"net message only", "NET:OPEN [INFO] [msg:relay open (channel_id=ch-42)]",
			Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityInfo, Message: "relay open (channel_id=ch-42)", Context: kv("msg", "relay open (channel_id=ch-42)")}},
		{"net denied reason with nested brackets",
			"NET:OPEN [MED] DENIED curl(1618) -> 169.254.169.254:80 [policy:- engine:ssrf] [reason:169.254.169.254 resolves to always-blocked address [metadata], connection rejected]",
			Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityMedium, Action: ActionDenied, Binary: "curl", PID: 1618, HasPID: true,
				Host: "169.254.169.254", Port: 80, Policy: "-", Engine: "ssrf", Reason: "169.254.169.254 resolves to always-blocked address [metadata], connection rejected",
				Context: kv("policy", "-", "engine", "ssrf", "reason", "169.254.169.254 resolves to always-blocked address [metadata], connection rejected")}},
		// The formatter prints the binary path unescaped, and the sandboxed
		// process names its binary: only the last " -> " separates actor
		// and destination, so a name cannot pick the reported host or pid.
		{"net actor path containing the separator", "NET:OPEN [MED] DENIED /sandbox/x(1) -> good.example:443(4242) -> blocked.example:443 [policy:- engine:opa]",
			Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityMedium, Action: ActionDenied, Binary: "/sandbox/x(1) -> good.example:443", PID: 4242, HasPID: true,
				Host: "blocked.example", Port: 443, Policy: "-", Engine: "opa", Context: kv("policy", "-", "engine", "opa")}},
		{"http actor path containing the separator",
			"HTTP:GET [MED] DENIED /sandbox/a(1) -> GET https://api.github.com/x(4242) -> GET https://blocked.example/upload [policy:- engine:opa]",
			Record{Class: ClassHTTP, Activity: "GET", Severity: SeverityMedium, Action: ActionDenied, Binary: "/sandbox/a(1) -> GET https://api.github.com/x", PID: 4242, HasPID: true,
				Method: "GET", URL: "https://blocked.example/upload", Host: "blocked.example", Port: 443, Path: "/upload", Policy: "-", Engine: "opa", Context: kv("policy", "-", "engine", "opa")}},
		{"http allowed with actor", "HTTP:GET [INFO] ALLOWED curl(88) -> GET https://api.example.com/v1/data [policy:default-egress engine:mechanistic]",
			Record{Class: ClassHTTP, Activity: "GET", Severity: SeverityInfo, Action: ActionAllowed, Binary: "curl", PID: 88, HasPID: true, Method: "GET",
				URL: "https://api.example.com/v1/data", Host: "api.example.com", Port: 443, Path: "/v1/data", Policy: "default-egress", Engine: "mechanistic",
				Context: kv("policy", "default-egress", "engine", "mechanistic")}},
		{"http unmapped attributes", "HTTP:POST [INFO] ALLOWED POST http://httpbin.org:443/anything [policy:httpbin engine:extension] [attempt:2 cached:true]",
			Record{Class: ClassHTTP, Activity: "POST", Severity: SeverityInfo, Action: ActionAllowed, Method: "POST", URL: "http://httpbin.org:443/anything",
				Host: "httpbin.org", Port: 443, Path: "/anything", Policy: "httpbin", Engine: "extension",
				Context: kv("policy", "httpbin", "engine", "extension", "attempt", "2", "cached", "true")}},
		{"http denied mcp reason inside the unmapped group",
			"HTTP:POST [MED] DENIED POST http://host.openshell.internal:8766/mcp [policy:reachy-mcp engine:l7-mcp] [attempt:1 reason:JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=move_head]",
			Record{Class: ClassHTTP, Activity: "POST", Severity: SeverityMedium, Action: ActionDenied, Method: "POST", URL: "http://host.openshell.internal:8766/mcp",
				Host: "host.openshell.internal", Port: 8766, Path: "/mcp", Policy: "reachy-mcp", Engine: "l7-mcp",
				Reason:  "JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=move_head",
				Context: kv("policy", "reachy-mcp", "engine", "l7-mcp", "attempt", "1", "reason", "JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=move_head")}},
		{"http default port from scheme", "HTTP:GET [INFO] ALLOWED curl(68) -> GET http://172.20.0.1/test?a=1 [policy:allow engine:mechanistic]",
			Record{Class: ClassHTTP, Activity: "GET", Severity: SeverityInfo, Action: ActionAllowed, Binary: "curl", PID: 68, HasPID: true, Method: "GET",
				URL: "http://172.20.0.1/test?a=1", Host: "172.20.0.1", Port: 80, Path: "/test?a=1", Policy: "allow", Engine: "mechanistic", Context: kv("policy", "allow", "engine", "mechanistic")}},
		{"ssh with peer and auth", "SSH:OPEN [INFO] ALLOWED 10.42.0.1:48201 [auth:NSSH1]",
			Record{Class: ClassSSH, Activity: "OPEN", Severity: SeverityInfo, Action: ActionAllowed, Host: "10.42.0.1", Port: 48201, Auth: "NSSH1", Context: kv("auth", "NSSH1")}},
		{"process launch", "PROC:LAUNCH [INFO] python3(42) [cmd:python3 /app/main.py]",
			Record{Class: ClassProcess, Activity: "LAUNCH", Severity: SeverityInfo, Binary: "python3", PID: 42, HasPID: true, CmdLine: "python3 /app/main.py", Context: kv("cmd", "python3 /app/main.py")}},
		{"process terminate", "PROC:TERMINATE [INFO] python3(42) [exit:0]",
			Record{Class: ClassProcess, Activity: "TERMINATE", Severity: SeverityInfo, Binary: "python3", PID: 42, HasPID: true, ExitCode: intPtr(0), Context: kv("exit", "0")}},
		{"finding blocked", `FINDING:BLOCKED [HIGH] "NSSH1 Nonce Replay Attack" [type:nssh1-replay-abc confidence:high]`,
			Record{Class: ClassFinding, Activity: "BLOCKED", Severity: SeverityHigh, Title: "NSSH1 Nonce Replay Attack", FindingType: "nssh1-replay-abc", Confidence: "high",
				Context: kv("type", "nssh1-replay-abc", "confidence", "high")}},
		{"finding with multi-word disposition", `FINDING:NO ACTION [LOW] "configured content matched" [type:content_guard.match count:1 source:content_guard]`,
			Record{Class: ClassFinding, Activity: "NO ACTION", Severity: SeverityLow, Title: "configured content matched", FindingType: "content_guard.match",
				Context: kv("type", "content_guard.match", "count", "1", "source", "content_guard")}},
		{"finding escapes cannot forge a second line",
			`FINDING:CREATE [INFO] "matched \"value\"\nFINDING:FORGED" [type:content_guard\u{a}forged source\u{a}forged:guard\]\u{a}FINDING:FORGED]`,
			Record{Class: ClassFinding, Activity: "CREATE", Severity: SeverityInfo, Title: "matched \"value\"\nFINDING:FORGED", FindingType: "content_guard\nforged",
				Context: kv("type", "content_guard\nforged", "source\nforged", "guard]\nFINDING:FORGED")}},
		{"lifecycle", "LIFECYCLE:START [INFO] openshell-sandbox success",
			Record{Class: ClassLifecycle, Activity: "START", Severity: SeverityInfo, App: "openshell-sandbox", Status: "success"}},
		{"config loaded", "CONFIG:LOADED [INFO] policy reloaded [version:v3 hash:sha256:abc123def456]",
			Record{Class: ClassConfig, Activity: "LOADED", Severity: SeverityInfo, Message: "policy reloaded", Context: kv("version", "v3", "hash", "sha256:abc123def456")}},
		{"config auto approval provenance",
			"CONFIG:APPROVED [INFO] auto-approved: no new prover findings (source=agent_authored) [auto:true source:agent_authored prover_delta:empty resolved_from:sandbox version:v4 hash:sha256:cafe]",
			Record{Class: ClassConfig, Activity: "APPROVED", Severity: SeverityInfo, Message: "auto-approved: no new prover findings (source=agent_authored)",
				Context: kv("auto", "true", "source", "agent_authored", "prover_delta", "empty", "resolved_from", "sandbox", "version", "v4", "hash", "sha256:cafe")}},
		{"base event", "EVENT [INFO] Network namespace created [ns:openshell-sandbox-abc123]",
			Record{Class: ClassEvent, Severity: SeverityInfo, Message: "Network namespace created", Context: kv("ns", "openshell-sandbox-abc123")}},
		{"api inference", "API:INFERENCE [INFO] Success claude-haiku via anthropic 812ms [messages:create]",
			Record{Class: ClassAPI, Activity: "INFERENCE", Severity: SeverityInfo, Status: "Success", Model: "claude-haiku", Provider: "anthropic", LatencyMS: 812, Operation: "messages:create"}},
		{"leading timestamp is tolerated", "14:00:00.000 NET:LISTEN [INFO] 127.0.0.1:3128",
			Record{Class: ClassNetwork, Activity: "LISTEN", Severity: SeverityInfo, Host: "127.0.0.1", Port: 3128}},
		{"ipv6 destination", "NET:OPEN [INFO] ALLOWED curl(7) -> 2001:db8::1:443",
			Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityInfo, Action: ActionAllowed, Binary: "curl", PID: 7, HasPID: true, Host: "2001:db8::1", Port: 443}},
		{"unknown class keeps text", "AUDIT:NEW [CRIT] something new [k:v]",
			Record{Class: "AUDIT", Activity: "NEW", Severity: SeverityCritical, Message: "something new", Context: kv("k", "v")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if tc.want.Raw = tc.in; err != nil || !reflect.DeepEqual(got, tc.want) {
				gj, _ := json.MarshalIndent(got, "", "  ")
				wj, _ := json.MarshalIndent(tc.want, "", "  ")
				t.Fatalf("Parse = %v, got\n%s\nwant\n%s", err, gj, wj)
			}
		})
	}
}

func TestParseRejectsNonShorthand(t *testing.T) {
	for _, in := range []string{
		"",
		"plain supervisor log line",
		"net:open [INFO] lower-case class",
		"NET:OPEN [DEBUG] unknown severity",
		"[INFO] no class",
	} {
		if rec, err := Parse(in); !errors.Is(err, ErrNotShorthand) || rec.Raw != in || rec.Class != "" {
			t.Fatalf("Parse(%q) = %+v, %v; want ErrNotShorthand", in, rec, err)
		}
	}
}

func TestClassAndSeverityIDs(t *testing.T) {
	for class, uid := range map[Class]int{ClassNetwork: 4001, ClassHTTP: 4002, ClassSSH: 4007, ClassProcess: 1007,
		ClassFinding: 2004, ClassLifecycle: 6002, ClassConfig: 5019, ClassAPI: 6003, ClassEvent: 0, "NEW": 0} {
		if class.UID() != uid {
			t.Fatalf("%s.UID() = %d, want %d", class, class.UID(), uid)
		}
	}
	for sev, id := range map[Severity]int{SeverityInfo: 1, SeverityLow: 2, SeverityMedium: 3, SeverityHigh: 4,
		SeverityCritical: 5, SeverityFatal: 6, "": 0} {
		if sev.ID() != id {
			t.Fatalf("%q.ID() = %d, want %d", sev, sev.ID(), id)
		}
	}
	if !IsShorthand("OCSF", "") || !IsShorthand("INFO", "ocsf") || IsShorthand("INFO", "openshell_sandbox") {
		t.Fatal("IsShorthand misclassifies")
	}
}

type corpusLine struct {
	Cursor string            `json:"cursor"`
	Fields map[string]string `json:"fields"`
	Level  string            `json:"level"`
	Msg    string            `json:"msg"`
	Target string            `json:"target"`
}

// TestCorpusGolden parses every OCSF line captured from a live OpenShell
// 0.1.1 sandbox (spike 3) and compares the records with a reviewed golden
// file. Run with -update to regenerate after an intentional parser change.
func TestCorpusGolden(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "ocsf-corpus-spike3.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var records []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Bytes()
		if !bytes.HasPrefix(raw, []byte("{")) {
			continue // watch driver annotations, not stream events
		}
		var line corpusLine
		if err := json.Unmarshal(raw, &line); err != nil {
			t.Fatalf("corpus line %q: %v", raw, err)
		}
		if !IsShorthand(line.Level, line.Target) {
			t.Fatalf("corpus line is not OCSF: %q", raw)
		}
		if len(line.Fields) != 0 {
			t.Fatalf("0.1.1 was expected to leave fields empty: %q", raw)
		}
		rec, err := Parse(line.Msg)
		if err != nil {
			t.Fatalf("Parse(%q): %v", line.Msg, err)
		}
		records = append(records, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 27 {
		t.Fatalf("parsed %d corpus records, want 27", len(records))
	}

	got, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "ocsf-corpus-spike3.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test -run TestCorpusGolden -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("corpus records differ from %s; rerun with -update and review the diff", golden)
	}

	// Semantic spot checks independent of the golden bytes.
	var denied []string
	for _, r := range records {
		if r.Denied() {
			denied = append(denied, r.Host)
		}
	}
	if strings.Join(denied, ",") != "api.github.com,evil.example.net,evil.example.net,169.254.169.254" {
		t.Fatalf("denied destinations = %v", denied)
	}
	for _, r := range records {
		if r.Class == ClassNetwork && r.Action == ActionAllowed && r.Engine == "opa" && r.Binary != "/usr/bin/curl" {
			t.Fatalf("allowed opa decision lost its binary: %+v", r)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"NET:OPEN [INFO] ALLOWED python3(42) -> api.example.com:443 [policy:default-egress engine:mechanistic]",
		`FINDING:BLOCKED [HIGH] "x\"" [type:a\]]`,
		"HTTP:POST [MED] DENIED POST http://h:1/p [reason:a [b]] c]",
		"API:INFERENCE [INFO] [",
		"PROC:LAUNCH [INFO] ((((1)) [exit:x]",
		"CONFIG:X [INFO] ]]]] [[[[ [a:b",
		`EVENT [INFO] \u{zz \u{110000}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		rec, err := Parse(in)
		if rec.Raw != in {
			t.Fatalf("Raw not preserved")
		}
		if err == nil && rec.Class == "" {
			t.Fatalf("accepted line without a class: %q", in)
		}
	})
}
