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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const installPolicyTestToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// installPolicyGateway is a fake DefenseClaw gateway: it proves the
// listener with the plugin credential (unless badProof) and answers the
// scan routes with status and body.
func installPolicyGateway(t *testing.T, status int, body string, badProof bool) (string, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.URL.Path == connector.UserScopedListenerProofPath {
			nonce := r.Header.Get(connector.UserScopedListenerNonceHeader)
			proof, err := connector.UserScopedListenerProof(installPolicyTestToken, "openclaw", nonce)
			if err != nil || r.Header.Get(connector.UserScopedListenerKeyIDHeader) != connector.UserScopedCredentialKeyID(installPolicyTestToken) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if badProof {
				proof = strings.Repeat("0", 64)
			}
			w.Header().Set(connector.UserScopedListenerProofHeader, proof)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+installPolicyTestToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), &calls
}

// installPolicySourceJSON is the staged folder OpenClaw names, as a JSON
// string in the host's absolute form (the command refuses a relative one).
var installPolicySourceJSON = func() string {
	source := "/tmp/openclaw-stage/root"
	if runtime.GOOS == "windows" {
		source = `C:\openclaw-stage\root`
	}
	b, _ := json.Marshal(source)
	return string(b)
}()

func installPolicyRequest(targetType string) string {
	return `{"protocolVersion":1,"openclawVersion":"2026.11.3","targetType":"` + targetType +
		`","targetName":"weather","sourcePath":` + installPolicySourceJSON + `,"sourcePathKind":"directory","origin":{"type":"clawhub"},"request":{"kind":"skill-install","mode":"install"}}`
}

func runInstallPolicy(t *testing.T, ep openClawInstallPolicyEndpoint, stdin string) openClawInstallPolicyAnswer {
	t.Helper()
	if ep.deadline == 0 {
		ep.deadline = 5 * time.Second
	}
	prev := resolveOpenClawInstallPolicyEndpoint
	resolveOpenClawInstallPolicyEndpoint = func(func(string) string) openClawInstallPolicyEndpoint { return ep }
	t.Cleanup(func() { resolveOpenClawInstallPolicyEndpoint = prev })
	var out, errOut bytes.Buffer
	cmd := connectorOpenClawInstallPolicyCmd
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetContext(context.Background())
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("install-policy returned an error, OpenClaw would get no answer: %v", err)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout is not exactly one JSON line: %q", out.String())
	}
	var answer openClawInstallPolicyAnswer
	if err := json.Unmarshal(out.Bytes(), &answer); err != nil {
		t.Fatalf("stdout is not JSON: %v %q", err, out.String())
	}
	if answer.ProtocolVersion != 1 || (answer.Decision != "allow" && answer.Decision != "block") {
		t.Fatalf("answer %+v is not allow or block with protocolVersion 1", answer)
	}
	if answer.Decision == "block" && strings.TrimSpace(answer.Reason) == "" {
		t.Fatalf("a block without a reason fails closed in OpenClaw with no DefenseClaw reason")
	}
	answer.Note = errOut.String()
	return answer
}

func TestConnectorOpenClawInstallPolicyAllowsAnAdmittedSkill(t *testing.T) {
	addr, calls := installPolicyGateway(t, http.StatusOK,
		`{"verdict":"clean","admission":{"verdict":"clean","reason":""},"result":{"findings":[]}}`, false)
	answer := runInstallPolicy(t, openClawInstallPolicyEndpoint{addr: addr, token: installPolicyTestToken, failsClosed: true}, installPolicyRequest("skill"))
	if answer.Decision != "allow" || len(answer.Findings) != 0 {
		t.Fatalf("answer = %+v, want allow", answer)
	}
	if strings.Join(*calls, ",") != "GET "+connector.UserScopedListenerProofPath+",POST /v1/skill/scan" {
		t.Fatalf("gateway calls = %v", *calls)
	}
}

func TestConnectorOpenClawInstallPolicyBlocksWithFindings(t *testing.T) {
	addr, calls := installPolicyGateway(t, http.StatusOK, `{"admission":{"verdict":"blocked","reason":"HIGH finding"},`+
		`"result":{"findings":[{"severity":"HIGH","title":"curl piped to sh","rule_id":"CMD-001","location":"SKILL.md:3","scanner":"skill-scanner"},`+
		`{"severity":"INFO","title":"note","scanner":"skill-scanner"},{"severity":"MEDIUM","title":""}]}}`, false)
	answer := runInstallPolicy(t, openClawInstallPolicyEndpoint{addr: addr, token: installPolicyTestToken}, installPolicyRequest("plugin"))
	if answer.Decision != "block" || !strings.Contains(answer.Reason, "HIGH finding") {
		t.Fatalf("answer = %+v, want block with the admission reason", answer)
	}
	want := []openClawInstallPolicyFinding{
		{RuleID: "CMD-001", Message: "curl piped to sh", Severity: "critical", File: "SKILL.md:3"},
		{RuleID: "skill-scanner", Message: "note", Severity: "info"},
	}
	if len(answer.Findings) != len(want) || answer.Findings[0] != want[0] || answer.Findings[1] != want[1] {
		t.Fatalf("findings = %+v, want %+v", answer.Findings, want)
	}
	if (*calls)[len(*calls)-1] != "POST /v1/plugin/scan" {
		t.Fatalf("a plugin went to %v", *calls)
	}
}

func TestConnectorOpenClawInstallPolicyBadRequests(t *testing.T) {
	ep := openClawInstallPolicyEndpoint{addr: "127.0.0.1:1", token: installPolicyTestToken, failsClosed: false}
	for name, stdin := range map[string]string{
		"not json":         "install weather",
		"empty":            "",
		"two values":       installPolicyRequest("skill") + installPolicyRequest("skill"),
		"protocol 2":       strings.Replace(installPolicyRequest("skill"), `"protocolVersion":1`, `"protocolVersion":2`, 1),
		"no protocol":      strings.Replace(installPolicyRequest("skill"), `"protocolVersion":1,`, "", 1),
		"oversize":         `{"protocolVersion":1,"pad":"` + strings.Repeat("x", openClawInstallPolicyMaxInput) + `"}`,
		"unknown target":   installPolicyRequest("hook"),
		"relative source":  strings.Replace(installPolicyRequest("skill"), installPolicySourceJSON, `"stage/root"`, 1),
		"credential issue": "",
	} {
		t.Run(name, func(t *testing.T) {
			e := ep
			if name == "credential issue" {
				stdin = installPolicyRequest("skill")
				e.problem = "DefenseClaw has no OpenClaw plugin credential; run defenseclaw setup openclaw"
			}
			if answer := runInstallPolicy(t, e, stdin); answer.Decision != "block" {
				t.Fatalf("answer = %+v, want block", answer)
			}
		})
	}
	// The npm metadata check before the download names a file: allowed,
	// OpenClaw asks again with the staged folder.
	file := strings.Replace(installPolicyRequest("plugin"), `"sourcePathKind":"directory"`, `"sourcePathKind":"file"`, 1)
	if answer := runInstallPolicy(t, ep, file); answer.Decision != "allow" {
		t.Fatalf("npm metadata check = %+v, want allow", answer)
	}
}

// A gateway that does not answer: strict and managed block, the OSS
// default and permissive allow (with a stderr warning and no findings).
func TestConnectorOpenClawInstallPolicyGatewayDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	for _, closed := range []bool{true, false} {
		answer := runInstallPolicy(t, openClawInstallPolicyEndpoint{addr: addr, token: installPolicyTestToken, failsClosed: closed}, installPolicyRequest("skill"))
		switch {
		case closed && (answer.Decision != "block" || !strings.Contains(answer.Reason, "did not answer")):
			t.Fatalf("strict/managed outage = %+v, want block", answer)
		case !closed && (answer.Decision != "allow" || len(answer.Findings) != 0 || !strings.Contains(answer.Note, "WARNING")):
			t.Fatalf("OSS outage = %+v, want allow with a warning", answer)
		}
	}
	// A gateway that does not answer within the deadline is an outage too.
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(2 * time.Second) }))
	defer slow.Close()
	start := time.Now()
	answer := runInstallPolicy(t, openClawInstallPolicyEndpoint{addr: slow.Listener.Addr().String(), token: installPolicyTestToken,
		deadline: 300 * time.Millisecond}, installPolicyRequest("skill"))
	if answer.Decision != "allow" || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("a slow gateway in OSS = %+v after %v, want allow within the deadline", answer, time.Since(start))
	}
}

// Not an outage: a listener that does not prove itself, a refused
// credential, an error answer or no admission blocks in every tier.
func TestConnectorOpenClawInstallPolicyClosedFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		body     string
		badProof bool
	}{
		"bad proof":    {http.StatusOK, `{"admission":{"verdict":"clean"}}`, true},
		"server error": {http.StatusInternalServerError, `{"error":"judge failed"}`, false},
		"no admission": {http.StatusOK, `{"verdict":"clean","result":{"findings":[]}}`, false},
		"not json":     {http.StatusOK, `<html>`, false},
	} {
		t.Run(name, func(t *testing.T) {
			addr, calls := installPolicyGateway(t, tc.status, tc.body, tc.badProof)
			answer := runInstallPolicy(t, openClawInstallPolicyEndpoint{addr: addr, token: installPolicyTestToken, failsClosed: false}, installPolicyRequest("skill"))
			if answer.Decision != "block" {
				t.Fatalf("answer = %+v, want block", answer)
			}
			if tc.badProof && len(*calls) != 1 {
				t.Fatalf("the scan was sent to a listener that did not prove itself: %v", *calls)
			}
		})
	}
	addr, _ := installPolicyGateway(t, http.StatusOK, `{}`, false)
	answer := runInstallPolicy(t, openClawInstallPolicyEndpoint{addr: addr, token: strings.Repeat("f", 64)}, installPolicyRequest("skill"))
	if answer.Decision != "block" {
		t.Fatalf("a refused credential = %+v, want block", answer)
	}
	if answer := runInstallPolicy(t, openClawInstallPolicyEndpoint{addr: "192.0.2.1:18970", token: installPolicyTestToken}, installPolicyRequest("skill")); answer.Decision != "block" {
		t.Fatalf("a non-loopback gateway = %+v, want block", answer)
	}
}

func TestConnectorOpenClawInstallPolicyDeadline(t *testing.T) {
	for raw, want := range map[string]time.Duration{"": 7500 * time.Millisecond, "30000": 25 * time.Second, "4000": 3 * time.Second, "junk": 7500 * time.Millisecond} {
		if got := openClawInstallPolicyDeadline(raw); got != want {
			t.Errorf("deadline(%q) = %v, want %v", raw, got, want)
		}
	}
}
