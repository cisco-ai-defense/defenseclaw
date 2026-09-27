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

// TestParseUpstreamShapes covers every class with the exact strings the
// upstream formatter's own tests pin (crates/openshell-ocsf shorthand.rs at
// v0.1.1), plus the live shapes captured on the host.
func TestParseUpstreamShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Record
	}{
		{
			name: "net allowed",
			in:   "NET:OPEN [INFO] ALLOWED python3(42) -> api.example.com:443 [policy:default-egress engine:mechanistic]",
			want: Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityInfo, Action: ActionAllowed,
				Binary: "python3", PID: 42, HasPID: true, Host: "api.example.com", Port: 443,
				Policy: "default-egress", Engine: "mechanistic",
				Context: map[string]string{"policy": "default-egress", "engine": "mechanistic"}},
		},
		{
			name: "net bypass with protocol",
			in:   "NET:REFUSE [MED] DENIED node(1234) -> 93.184.216.34:443/tcp [policy:bypass-detect engine:nftables]",
			want: Record{Class: ClassNetwork, Activity: "REFUSE", Severity: SeverityMedium, Action: ActionDenied,
				Binary: "node", PID: 1234, HasPID: true, Host: "93.184.216.34", Port: 443, Protocol: "tcp",
				Policy: "bypass-detect", Engine: "nftables",
				Context: map[string]string{"policy": "bypass-detect", "engine": "nftables"}},
		},
		{
			name: "net message only",
			in:   "NET:OPEN [INFO] [msg:relay open (channel_id=ch-42)]",
			want: Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityInfo,
				Message: "relay open (channel_id=ch-42)", Context: map[string]string{"msg": "relay open (channel_id=ch-42)"}},
		},
		{
			name: "net denied reason with nested brackets",
			in:   "NET:OPEN [MED] DENIED curl(1618) -> 169.254.169.254:80 [policy:- engine:ssrf] [reason:169.254.169.254 resolves to always-blocked address [metadata], connection rejected]",
			want: Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityMedium, Action: ActionDenied,
				Binary: "curl", PID: 1618, HasPID: true, Host: "169.254.169.254", Port: 80,
				Policy: "-", Engine: "ssrf",
				Reason: "169.254.169.254 resolves to always-blocked address [metadata], connection rejected",
				Context: map[string]string{"policy": "-", "engine": "ssrf",
					"reason": "169.254.169.254 resolves to always-blocked address [metadata], connection rejected"}},
		},
		{
			// The formatter prints the binary path unescaped, and the
			// sandboxed process names its binary: only the last " -> "
			// separates actor and destination, so a name cannot pick the
			// reported host or pid.
			name: "net actor path containing the separator",
			in:   "NET:OPEN [MED] DENIED /sandbox/x(1) -> good.example:443(4242) -> blocked.example:443 [policy:- engine:opa]",
			want: Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityMedium, Action: ActionDenied,
				Binary: "/sandbox/x(1) -> good.example:443", PID: 4242, HasPID: true, Host: "blocked.example", Port: 443,
				Policy: "-", Engine: "opa", Context: map[string]string{"policy": "-", "engine": "opa"}},
		},
		{
			name: "http actor path containing the separator",
			in:   "HTTP:GET [MED] DENIED /sandbox/a(1) -> GET https://api.github.com/x(4242) -> GET https://blocked.example/upload [policy:- engine:opa]",
			want: Record{Class: ClassHTTP, Activity: "GET", Severity: SeverityMedium, Action: ActionDenied,
				Binary: "/sandbox/a(1) -> GET https://api.github.com/x", PID: 4242, HasPID: true, Method: "GET",
				URL: "https://blocked.example/upload", Host: "blocked.example", Port: 443, Path: "/upload",
				Policy: "-", Engine: "opa", Context: map[string]string{"policy": "-", "engine": "opa"}},
		},
		{
			name: "http allowed with actor",
			in:   "HTTP:GET [INFO] ALLOWED curl(88) -> GET https://api.example.com/v1/data [policy:default-egress engine:mechanistic]",
			want: Record{Class: ClassHTTP, Activity: "GET", Severity: SeverityInfo, Action: ActionAllowed,
				Binary: "curl", PID: 88, HasPID: true, Method: "GET", URL: "https://api.example.com/v1/data",
				Host: "api.example.com", Port: 443, Path: "/v1/data", Policy: "default-egress", Engine: "mechanistic",
				Context: map[string]string{"policy": "default-egress", "engine": "mechanistic"}},
		},
		{
			name: "http unmapped attributes",
			in:   "HTTP:POST [INFO] ALLOWED POST http://httpbin.org:443/anything [policy:httpbin engine:extension] [attempt:2 cached:true]",
			want: Record{Class: ClassHTTP, Activity: "POST", Severity: SeverityInfo, Action: ActionAllowed,
				Method: "POST", URL: "http://httpbin.org:443/anything", Host: "httpbin.org", Port: 443, Path: "/anything",
				Policy: "httpbin", Engine: "extension",
				Context: map[string]string{"policy": "httpbin", "engine": "extension", "attempt": "2", "cached": "true"}},
		},
		{
			name: "http denied mcp reason inside the unmapped group",
			in:   "HTTP:POST [MED] DENIED POST http://host.openshell.internal:8766/mcp [policy:reachy-mcp engine:l7-mcp] [attempt:1 reason:JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=move_head]",
			want: Record{Class: ClassHTTP, Activity: "POST", Severity: SeverityMedium, Action: ActionDenied,
				Method: "POST", URL: "http://host.openshell.internal:8766/mcp", Host: "host.openshell.internal", Port: 8766,
				Path: "/mcp", Policy: "reachy-mcp", Engine: "l7-mcp",
				Reason: "JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=move_head",
				Context: map[string]string{"policy": "reachy-mcp", "engine": "l7-mcp", "attempt": "1",
					"reason": "JSONRPC_L7_REQUEST decision=deny rule_methods=tools/call tools=move_head"}},
		},
		{
			name: "http default port from scheme",
			in:   "HTTP:GET [INFO] ALLOWED curl(68) -> GET http://172.20.0.1/test?a=1 [policy:allow engine:mechanistic]",
			want: Record{Class: ClassHTTP, Activity: "GET", Severity: SeverityInfo, Action: ActionAllowed,
				Binary: "curl", PID: 68, HasPID: true, Method: "GET", URL: "http://172.20.0.1/test?a=1",
				Host: "172.20.0.1", Port: 80, Path: "/test?a=1", Policy: "allow", Engine: "mechanistic",
				Context: map[string]string{"policy": "allow", "engine": "mechanistic"}},
		},
		{
			name: "ssh with peer and auth",
			in:   "SSH:OPEN [INFO] ALLOWED 10.42.0.1:48201 [auth:NSSH1]",
			want: Record{Class: ClassSSH, Activity: "OPEN", Severity: SeverityInfo, Action: ActionAllowed,
				Host: "10.42.0.1", Port: 48201, Auth: "NSSH1", Context: map[string]string{"auth": "NSSH1"}},
		},
		{
			name: "process launch",
			in:   "PROC:LAUNCH [INFO] python3(42) [cmd:python3 /app/main.py]",
			want: Record{Class: ClassProcess, Activity: "LAUNCH", Severity: SeverityInfo, Binary: "python3", PID: 42,
				HasPID: true, CmdLine: "python3 /app/main.py", Context: map[string]string{"cmd": "python3 /app/main.py"}},
		},
		{
			name: "process terminate",
			in:   "PROC:TERMINATE [INFO] python3(42) [exit:0]",
			want: Record{Class: ClassProcess, Activity: "TERMINATE", Severity: SeverityInfo, Binary: "python3", PID: 42,
				HasPID: true, ExitCode: intPtr(0), Context: map[string]string{"exit": "0"}},
		},
		{
			name: "finding blocked",
			in:   `FINDING:BLOCKED [HIGH] "NSSH1 Nonce Replay Attack" [type:nssh1-replay-abc confidence:high]`,
			want: Record{Class: ClassFinding, Activity: "BLOCKED", Severity: SeverityHigh, Title: "NSSH1 Nonce Replay Attack",
				FindingType: "nssh1-replay-abc", Confidence: "high",
				Context: map[string]string{"type": "nssh1-replay-abc", "confidence": "high"}},
		},
		{
			name: "finding with multi-word disposition",
			in:   `FINDING:NO ACTION [LOW] "configured content matched" [type:content_guard.match count:1 source:content_guard]`,
			want: Record{Class: ClassFinding, Activity: "NO ACTION", Severity: SeverityLow, Title: "configured content matched",
				FindingType: "content_guard.match",
				Context:     map[string]string{"type": "content_guard.match", "count": "1", "source": "content_guard"}},
		},
		{
			name: "finding escapes cannot forge a second line",
			in:   `FINDING:CREATE [INFO] "matched \"value\"\nFINDING:FORGED" [type:content_guard\u{a}forged source\u{a}forged:guard\]\u{a}FINDING:FORGED]`,
			want: Record{Class: ClassFinding, Activity: "CREATE", Severity: SeverityInfo,
				Title: "matched \"value\"\nFINDING:FORGED", FindingType: "content_guard\nforged",
				Context: map[string]string{"type": "content_guard\nforged", "source\nforged": "guard]\nFINDING:FORGED"}},
		},
		{
			name: "lifecycle",
			in:   "LIFECYCLE:START [INFO] openshell-sandbox success",
			want: Record{Class: ClassLifecycle, Activity: "START", Severity: SeverityInfo, App: "openshell-sandbox", Status: "success"},
		},
		{
			name: "config loaded",
			in:   "CONFIG:LOADED [INFO] policy reloaded [version:v3 hash:sha256:abc123def456]",
			want: Record{Class: ClassConfig, Activity: "LOADED", Severity: SeverityInfo, Message: "policy reloaded",
				Context: map[string]string{"version": "v3", "hash": "sha256:abc123def456"}},
		},
		{
			name: "config auto approval provenance",
			in:   "CONFIG:APPROVED [INFO] auto-approved: no new prover findings (source=agent_authored) [auto:true source:agent_authored prover_delta:empty resolved_from:sandbox version:v4 hash:sha256:cafe]",
			want: Record{Class: ClassConfig, Activity: "APPROVED", Severity: SeverityInfo,
				Message: "auto-approved: no new prover findings (source=agent_authored)",
				Context: map[string]string{"auto": "true", "source": "agent_authored", "prover_delta": "empty",
					"resolved_from": "sandbox", "version": "v4", "hash": "sha256:cafe"}},
		},
		{
			name: "base event",
			in:   "EVENT [INFO] Network namespace created [ns:openshell-sandbox-abc123]",
			want: Record{Class: ClassEvent, Severity: SeverityInfo, Message: "Network namespace created",
				Context: map[string]string{"ns": "openshell-sandbox-abc123"}},
		},
		{
			name: "api inference",
			in:   "API:INFERENCE [INFO] Success claude-haiku via anthropic 812ms [messages:create]",
			want: Record{Class: ClassAPI, Activity: "INFERENCE", Severity: SeverityInfo, Status: "Success",
				Model: "claude-haiku", Provider: "anthropic", LatencyMS: 812, Operation: "messages:create"},
		},
		{
			name: "leading timestamp is tolerated",
			in:   "14:00:00.000 NET:LISTEN [INFO] 127.0.0.1:3128",
			want: Record{Class: ClassNetwork, Activity: "LISTEN", Severity: SeverityInfo, Host: "127.0.0.1", Port: 3128},
		},
		{
			name: "ipv6 destination",
			in:   "NET:OPEN [INFO] ALLOWED curl(7) -> 2001:db8::1:443",
			want: Record{Class: ClassNetwork, Activity: "OPEN", Severity: SeverityInfo, Action: ActionAllowed,
				Binary: "curl", PID: 7, HasPID: true, Host: "2001:db8::1", Port: 443},
		},
		{
			name: "unknown class keeps text",
			in:   "AUDIT:NEW [CRIT] something new [k:v]",
			want: Record{Class: "AUDIT", Activity: "NEW", Severity: SeverityCritical, Message: "something new",
				Context: map[string]string{"k": "v"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			tc.want.Raw = tc.in
			if !reflect.DeepEqual(got, tc.want) {
				gj, _ := json.MarshalIndent(got, "", "  ")
				wj, _ := json.MarshalIndent(tc.want, "", "  ")
				t.Fatalf("got\n%s\nwant\n%s", gj, wj)
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
		rec, err := Parse(in)
		if !errors.Is(err, ErrNotShorthand) {
			t.Fatalf("Parse(%q) err = %v, want ErrNotShorthand", in, err)
		}
		if rec.Raw != in || rec.Class != "" {
			t.Fatalf("Parse(%q) = %+v", in, rec)
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
