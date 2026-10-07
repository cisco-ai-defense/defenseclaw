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

package manager

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// fakeLineage is a ProcessLookup that knows one process.
type fakeLineage struct{}

func (fakeLineage) Lineage(sandbox string, pid int) []ProcessRef {
	if pid != 77 {
		return nil
	}
	return []ProcessRef{{PID: 77, PPID: 1, Exe: "/usr/bin/curl", Comm: "curl"}, {PID: 1, Exe: "/bin/sh", Comm: "sh"}}
}

func destinationKinds(t *testing.T, e *harnessEnv, name string) map[string]sandboxapi.DestinationRow {
	t.Helper()
	d, err := e.m.Destinations(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]sandboxapi.DestinationRow{}
	for _, r := range d.Destinations {
		out[r.Host] = r
	}
	return out
}

// Both boundaries' observations become one destination per host, told apart
// in order: model provider, the harness's vendor, shadow AI (catalogued or
// inference-shaped), the proxy's category, blocked, other. Shadow AI is a
// finding once per provider and session, LOW while refused and MEDIUM once
// reached.
func TestDestinationsAreClassified(t *testing.T) {
	e := liveEnv(t, "destbox", nil)
	e.m.procs = fakeLineage{}
	ctx, now := context.Background(), time.Now()
	id := e.binding("destbox").ID
	proxy := func(kind egress.EventKind, host string, category egress.Category) {
		e.m.egressEvent(ctx, egress.Event{Kind: kind, Time: now, BindingID: id, SandboxName: "destbox", Method: "CONNECT",
			Host: host, Port: 443, Category: category}, 0)
	}
	e.ocsf("destbox", "NET:OPEN [INFO] ALLOWED "+testClaudeBin+"(7) -> api.anthropic.com:443/tcp [policy:_provider_anthropic engine:opa]", now)
	e.ocsf("destbox", "HTTP:POST [INFO] ALLOWED POST https://api.anthropic.com/v1/messages [policy:_provider_anthropic engine:opa]", now)
	e.ocsf("destbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(77) -> claude.ai:443/tcp [policy:allow_claude engine:opa]", now)
	e.ocsf("destbox", "NET:OPEN [MED] DENIED /usr/bin/python3(42) -> evil.example.com:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]", now)
	proxy(egress.EventBlocked, "api.openai.com", egress.CategoryNotAllowlisted)
	proxy(egress.EventAllowed, "api.openai.com", "")
	proxy(egress.EventAllowed, "api.openai.com", "")
	proxy(egress.EventBlocked, "inference.example-llm.net", egress.CategoryNotAllowlisted)
	proxy(egress.EventAllowed, "registry.npmjs.org", egress.CategoryPackageRegistry)
	proxy(egress.EventAllowed, "api.mailgun.net", "")

	rows := destinationKinds(t, e, "destbox")
	for host, kind := range map[string]string{
		"api.anthropic.com": sandboxapi.DestinationModelProvider, "claude.ai": sandboxapi.DestinationHarnessVendor,
		"api.openai.com": sandboxapi.DestinationOtherAI, "inference.example-llm.net": sandboxapi.DestinationUnknownAI,
		"registry.npmjs.org": string(egress.CategoryPackageRegistry), "evil.example.com": sandboxapi.DestinationBlocked,
		// An ordinary REST API whose name happens to hold the letters "ai".
		"api.mailgun.net": sandboxapi.DestinationOther,
	} {
		if rows[host].Kind != kind {
			t.Errorf("%s: kind %q, want %q (%+v)", host, rows[host].Kind, kind, rows[host])
		}
	}
	if r := rows["api.anthropic.com"]; r.Connections != 2 || r.ModelTurns != 1 || r.Rule != "_provider_anthropic" || r.Binaries[0] != testClaudeBin {
		t.Errorf("model provider = %+v", r)
	}
	if r := rows["claude.ai"]; r.PID != 77 || len(r.Lineage) != 2 || r.Lineage[1].Exe != "/bin/sh" {
		t.Errorf("lineage = %+v", r)
	}
	if r := rows["evil.example.com"]; r.Refused != 1 || r.Connections != 0 {
		t.Errorf("refused = %+v", r)
	}

	shadow := e.tel.findingsOf(audit.SandboxFindingShadowAI)
	if len(shadow) != 3 {
		t.Fatalf("shadow AI findings = %+v", shadow)
	}
	if f := shadow[0]; f.Severity != "LOW" || f.TargetRef != "api.openai.com" || strings.Contains(f.Remediation, "policy block") {
		t.Errorf("refused shadow AI = %+v", f)
	}
	// A connector's host is named by its vendor, not the connector.
	if f := shadow[1]; f.Severity != "MEDIUM" || f.TargetRef != "api.openai.com" || f.Sandbox.BindingID != id || f.UserName != "dev" ||
		f.Title != "Shadow AI: the sandbox reached OpenAI" || !strings.Contains(f.Remediation, "policy block api.openai.com") {
		t.Errorf("reached shadow AI = %+v", f)
	}
	if r := rows["api.openai.com"]; r.Provider != "OpenAI" || r.Vendor != "OpenAI" {
		t.Errorf("shadow AI row = %+v", r)
	}
	if r := rows["claude.ai"]; r.Provider != "Claude Code" {
		t.Errorf("harness vendor row = %+v", r)
	}
	if f := shadow[2]; f.Severity != "LOW" || f.TargetRef != "inference.example-llm.net" {
		t.Errorf("unknown AI = %+v", f)
	}
	if feed := e.events("destbox", sandboxapi.ActivityFinding, sandboxapi.ReasonShadowAI); len(feed) != 3 {
		t.Errorf("shadow AI feed = %+v", feed)
	}
	if v := e.get("destbox"); v.Egress.ModelAPIs != 2 || v.Egress.ShadowAI != 2 {
		t.Errorf("egress summary = %+v", v.Egress)
	}

	// A new session reports a provider again.
	e.stopBox("destbox")
	e.startBox("destbox", sandboxapi.StartRequest{})
	proxy(egress.EventAllowed, "api.openai.com", "")
	if n := len(e.tel.findingsOf(audit.SandboxFindingShadowAI)); n != 4 {
		t.Fatalf("shadow AI findings after a restart = %d", n)
	}
}

// The host of a shadow AI finding comes from the sandbox, so it goes into
// the block command a user copies only as a host name or an IP address;
// any other spelling is shown made safe, and the command is left out.
func TestShadowRemediationPastesOnlyAHost(t *testing.T) {
	for _, c := range []struct {
		host    string
		command bool
	}{
		{"api.openai.com", true}, {"192.0.2.7", true}, {"2001:db8::7", true},
		{"llm.example.net;dccert-block-marker", false}, {"llm.example.net dccert-block-marker", false},
		{"*.example-llm.net", false}, {"10.0.0.0/8", false}, {"[2001:db8::7]", false}, {"llm.example.net\x1b[0m", false},
	} {
		got := shadowRemediation("destbox", c.host, true)
		if strings.Contains(got, "policy block "+c.host+".") != c.command || !c.command && strings.Contains(got, "policy block") ||
			strings.ContainsRune(got, 0x1b) || !strings.Contains(got, "`defenseclaw sandbox destinations destbox`") {
			t.Errorf("%q: %q", c.host, got)
		}
	}
	if got := shadowRemediation("destbox", "api.openai.com", false); strings.Contains(got, "policy block") {
		t.Errorf("refused: %q", got)
	}
}

// The host and binary of a shadow AI finding come from the sandbox too, so
// the finding's title, description and evidence, and its feed line, show
// them made safe: no line separator, bidirectional control or C1 control
// the sandbox sent reaches telemetry or an alert view.
func TestShadowAIFindingShowsTheHostMadeSafe(t *testing.T) {
	e := liveEnv(t, "destbox", nil)
	ls, rlo, csi := "\u2028", "\u202e", "\u009b"
	e.m.observeDestination(context.Background(), e.boxOf("destbox"), destinationSighting{
		host: "inference.example-llm.net" + ls + "x" + rlo + "y" + csi, port: 443, at: time.Now(), binary: "/usr/bin/py" + rlo + "thon" + ls})
	shadow := e.tel.findingsOf(audit.SandboxFindingShadowAI)
	if len(shadow) != 1 {
		t.Fatalf("shadow AI findings = %+v", shadow)
	}
	f := shadow[0]
	fields := map[string]string{"title": f.Title, "description": f.Description, "evidence": f.Evidence, "remediation": f.Remediation}
	for _, ev := range e.events("destbox", sandboxapi.ActivityFinding, sandboxapi.ReasonShadowAI) {
		fields["feed message"] = ev.Message
	}
	for field, text := range fields {
		if strings.ContainsAny(text, ls+rlo+csi) {
			t.Errorf("%s holds a control the sandbox sent: %q", field, text)
		}
	}
	if !strings.Contains(f.Title, "the sandbox reached inference.example-llm.net x") || !strings.Contains(f.Evidence, "binary=/usr/bin/py") ||
		fields["feed message"] == "" {
		t.Errorf("finding = %+v, feed %q", f, fields["feed message"])
	}
}

// A --credential binding's endpoint, which a provider rule opens as it does
// the model endpoint, is a credential destination: no model provider (the
// status counts one model API) and no shadow AI.
func TestDestinationsTellCredentialEndpointsFromTheModelProvider(t *testing.T) {
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "credbox",
		LLM:         &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-dccert"}},
		Credentials: []sandboxapi.CredentialBinding{{Name: "STRIPE_API_KEY", Value: "dccert-block-marker", Host: "api.stripe.com"}}})
	now := time.Now()
	e.ocsf("credbox", "NET:OPEN [INFO] ALLOWED "+testClaudeBin+"(7) -> api.anthropic.com:443/tcp [policy:_provider_credbox-llm engine:opa]", now)
	e.ocsf("credbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(8) -> api.stripe.com:443/tcp [policy:_provider_credbox-cred-0 engine:opa]", now)
	rows := destinationKinds(t, e, "credbox")
	if rows["api.anthropic.com"].Kind != sandboxapi.DestinationModelProvider || rows["api.stripe.com"].Kind != sandboxapi.DestinationCredential {
		t.Fatalf("rows = %+v", rows)
	}
	if v := e.get("credbox"); v.Egress.ModelAPIs != 1 || v.Egress.ShadowAI != 0 {
		t.Fatalf("egress summary = %+v", v.Egress)
	}
}

// The model provider row is named by the sandbox's --llm provider, not by
// OpenShell's provider rule (named after the sandbox), and shows the binary
// whose model calls got through, not one only refused the host (GAP-0079).
func TestDestinationsNameTheModelProviderAndItsBinary(t *testing.T) {
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "brbox",
		LLM: &sandboxapi.LLMCredential{Profile: profiles.ClaudeBedrockMantleID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "dccert-block-marker"}}})
	now, host := time.Now(), "bedrock-mantle.us-east-1.api.aws"
	e.ocsf("brbox", "NET:OPEN [INFO] ALLOWED "+testClaudeBin+"(7) -> "+host+":443/tcp [policy:_provider_brbox_llm engine:opa]", now)
	e.ocsf("brbox", "NET:OPEN [MED] DENIED /usr/bin/curl(9) -> "+host+":443/tcp [policy:- engine:opa] [reason:unsupported_rule]", now)
	r := destinationKinds(t, e, "brbox")[host]
	if r.Kind != sandboxapi.DestinationModelProvider || r.Provider != "Amazon Bedrock" || len(r.Binaries) != 2 || r.Binaries[1] != testClaudeBin {
		t.Fatalf("model provider row = %+v", r)
	}
	for _, id := range profiles.IDs() {
		if id != profiles.IngressID && llmProviderName(id) == "" {
			t.Errorf("profile %s has no provider name", id)
		}
	}
}

// The destinations are kept across daemon restarts; a delete removes them.
func TestDestinationsAreKeptAndForgotten(t *testing.T) {
	e := liveEnv(t, "keepbox", nil)
	e.ocsf("keepbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> files.example.org:443/tcp [policy:allow_files engine:opa]", time.Now())
	e.ocsf("keepbox", "NET:OPEN [MED] DENIED /usr/bin/curl(9) -> paste.example.net:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]", time.Now())
	e.stopBox("keepbox")
	path := filepath.Join(e.dataDir, "sandboxes", "keepbox", destinationsFile)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("kept destinations: %v %v", info, err)
	}
	e.restartDaemon()
	e.startBox("keepbox", sandboxapi.StartRequest{})
	if rows := destinationKinds(t, e, "keepbox"); rows["files.example.org"].Connections != 1 {
		t.Fatalf("after a restart = %+v", rows)
	}
	// The status Egress line sums up the kept destinations, so a restart
	// does not zero it next to its AI summary (GAP-0100).
	if eg := e.get("keepbox").Egress; eg.Blocked != 1 || eg.BlockedRequests != 1 {
		t.Fatalf("egress after a restart = %+v", eg)
	}
	// A delete drops them before it forgets the sandbox: a sighting that
	// arrives in between (a refusal the egress sink still held) and a
	// flush neither bring the table back nor write the file again.
	must(t, e.m.dropDestinations("keepbox", e.binding("keepbox").ID))
	e.ocsf("keepbox", "NET:OPEN [MED] DENIED /usr/bin/curl(9) -> late.example.org:443/tcp [policy:- engine:opa]", time.Now())
	e.m.flushDestinations("")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destinations after a late sighting: %v", err)
	}
	if rows := destinationKinds(t, e, "keepbox"); len(rows) != 0 {
		t.Fatalf("the dropped table came back: %+v", rows)
	}
	e.deleteBox("keepbox", sandboxapi.DeleteRequest{})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destinations after delete: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("sandbox dir after delete: %v", err)
	}
	// A new sandbox of the name starts with none.
	e.live(sandboxapi.CreateRequest{Name: "keepbox"})
	if rows := destinationKinds(t, e, "keepbox"); len(rows) != 0 {
		t.Fatalf("a new sandbox of the name has %+v", rows)
	}
}

// The egress proxy's counts are a destination's: the counter's rows merge
// into the view and are kept across daemon restarts, and a delete forgets
// what the counter counted for the binding. The counter starts over with
// the daemon, so a host the sandbox reached before a restart is first-seen
// again: the large-upload block cuts an upload to it again.
func TestDestinationsCountTheProxysTraffic(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Egress.LargeUploadMB = 1
		c.OpenShell.Egress.BlockLargeUploads = true
	})
	e.run()
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "upbox"})
	upload := func(proxy *liveProxy) {
		t.Helper()
		conn, br := proxy.open(t, "upbox", "example.org:80")
		const size = 2 << 20
		_, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: example.org\r\nContent-Length: %d\r\n\r\n", size)
		must(t, err)
		chunk := bytes.Repeat([]byte("u"), 32<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				break // the proxy cut the tunnel
			}
		}
		_, _ = io.Copy(io.Discard, br)
	}
	cuts := func() int { return len(e.tel.findingsOf(audit.SandboxFindingLargeUpload)) }
	upload(proxy)
	eventually(t, "the cut", func() bool { return cuts() == 1 })
	var row sandboxapi.DestinationRow
	eventually(t, "the counter's counts in the view", func() bool {
		row = destinationKinds(t, e, "upbox")["example.org"]
		return row.Tunnels == 1 && row.BytesUp > 0
	})
	if !slices.Contains(row.Sources, sandboxapi.SourceProxy) || row.BytesUp > 1<<20 {
		t.Fatalf("row = %+v", row)
	}

	e.stopBox("upbox")
	e.restartDaemon()
	proxy = startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.startBox("upbox", sandboxapi.StartRequest{})
	if kept := destinationKinds(t, e, "upbox")["example.org"]; kept.Tunnels != row.Tunnels || kept.BytesUp != row.BytesUp {
		t.Fatalf("kept %+v, want the counts of %+v", kept, row)
	}
	if eg := e.get("upbox").Egress; eg.Destinations != 1 || eg.BytesUp != row.BytesUp {
		t.Fatalf("egress after a restart = %+v, want the counts of %+v", eg, row)
	}
	upload(proxy)
	eventually(t, "the cut in the new session", func() bool { return cuts() == 2 })
	eventually(t, "both runs' counts", func() bool { return destinationKinds(t, e, "upbox")["example.org"].Tunnels == 2 })

	binding := e.binding("upbox").ID
	e.deleteBox("upbox", sandboxapi.DeleteRequest{})
	e.m.mu.Lock()
	counter := e.m.proxy.Counter()
	e.m.mu.Unlock()
	if left := counter.DestinationsFor(binding); len(left) != 0 {
		t.Fatalf("the counter kept %+v for the deleted sandbox", left)
	}
}

// The view keeps at most sandboxapi.MaxDestinations hosts: the oldest that
// are no AI destinations make room, and the drop is counted.
func TestDestinationsAreBounded(t *testing.T) {
	e := liveEnv(t, "capbox", nil)
	at := time.Now()
	e.ocsf("capbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> api.openai.com:443/tcp [policy:allow_x engine:opa]", at)
	for i := range sandboxapi.MaxDestinations + 5 {
		at = at.Add(time.Second)
		e.ocsf("capbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> h"+strconv.Itoa(i)+".example.org:443/tcp [policy:allow_x engine:opa]", at)
	}
	d, _ := e.m.Destinations(context.Background(), "capbox")
	rows := destinationKinds(t, e, "capbox")
	if len(d.Destinations) != sandboxapi.MaxDestinations || d.Dropped != 6 || rows["api.openai.com"].Kind != sandboxapi.DestinationOtherAI ||
		rows["h0.example.org"].Host != "" || rows["h516.example.org"].Host == "" {
		t.Fatalf("rows %d dropped %d", len(d.Destinations), d.Dropped)
	}
}

// A table full of made-up inference-shaped names still records a catalogued
// AI provider, in place of the oldest of them, and reports it.
func TestDestinationsFullOfUnknownAIStillReportAProvider(t *testing.T) {
	e := liveEnv(t, "fullbox", nil)
	at := time.Now()
	for i := range sandboxapi.MaxDestinations {
		at = at.Add(time.Second)
		e.ocsf("fullbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> n"+strconv.Itoa(i)+"-llm.example:443/tcp [policy:allow_x engine:opa]", at)
	}
	before := len(e.tel.findingsOf(audit.SandboxFindingShadowAI))
	e.ocsf("fullbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> n9999-llm.example:443/tcp [policy:allow_x engine:opa]", at.Add(time.Second))
	e.ocsf("fullbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> api.openai.com:443/tcp [policy:allow_x engine:opa]", at.Add(2*time.Second))
	rows := destinationKinds(t, e, "fullbox")
	if len(rows) != sandboxapi.MaxDestinations || rows["api.openai.com"].Kind != sandboxapi.DestinationOtherAI ||
		rows["n0-llm.example"].Host != "" || rows["n9999-llm.example"].Host != "" {
		t.Fatalf("%d rows, api.openai.com %+v", len(rows), rows["api.openai.com"])
	}
	shadow := e.tel.findingsOf(audit.SandboxFindingShadowAI)
	if len(shadow) != before+1 || shadow[len(shadow)-1].TargetRef != "api.openai.com" {
		t.Fatalf("findings before %d, after %+v", before, shadow[before:])
	}
}

// TestProxiedDestinationsNameTheirProgram (GAP-0084, GAP-0088): every host
// reached through the egress proxy showed BINARY "-" (the proxy sees no
// program, and OpenShell's record of the connection names the proxy, not
// the host), so a shadow AI row could not say what called it. A proxied
// request takes the program of the one connection to the proxy OpenShell
// recorded around it, whichever came first; two programs then leave it
// unnamed rather than guessed.
func TestProxiedDestinationsNameTheirProgram(t *testing.T) {
	e := newEnv(t, nil)
	now, advance := e.fakeClock(time.Now())
	e.live(sandboxapi.CreateRequest{Name: "pbox"})
	b := e.boxOf("pbox")
	opened := func(bin string, pid int) {
		e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: bin, PID: pid, HasPID: true, Host: openshellHostAlias,
			Port: testEgressPort, Action: ocsf.ActionAllowed, Policy: "defenseclaw_egress"}, now())
	}
	request := func(host string) {
		e.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventAllowed, SandboxName: "pbox", Host: host, Port: 443, Method: "CONNECT",
			Time: now(), FirstSeen: true}, 0)
	}
	request("pypi.org")
	opened("/usr/bin/curl", 77)
	advance(time.Minute)
	request("api.openai.com")
	opened("/usr/bin/curl", 78)
	opened("/usr/bin/python3", 79)
	advance(time.Minute)
	d, err := e.m.Destinations(t.Context(), "pbox")
	must(t, err)
	got := map[string]sandboxapi.DestinationRow{}
	for _, r := range d.Destinations {
		got[r.Host] = r
	}
	if r := got["pypi.org"]; !slices.Equal(r.Binaries, []string{"/usr/bin/curl"}) || r.PID != 77 {
		t.Fatalf("pypi.org = %+v", r)
	}
	if r := got["api.openai.com"]; len(r.Binaries) != 0 || r.PID != 0 {
		t.Fatalf("api.openai.com, two programs at once = %+v", r)
	}
}

// TestAProxiedRefusalKeepsTheBinaryThatGotThrough: a proxied request is
// paired with its program only after a window, and a refusal paired then
// still does not move its program ahead of the one whose traffic got
// through (the row's view shows the last binary).
func TestAProxiedRefusalKeepsTheBinaryThatGotThrough(t *testing.T) {
	e := newEnv(t, nil)
	now, advance := e.fakeClock(time.Now())
	e.live(sandboxapi.CreateRequest{Name: "rbox"})
	b := e.boxOf("rbox")
	request := func(bin string, pid int, kind egress.EventKind) {
		e.m.egressEvent(t.Context(), egress.Event{Kind: kind, SandboxName: "rbox", Host: "example.org", Port: 443, Method: "CONNECT",
			Time: now(), FirstSeen: true, Category: egress.CategoryNotAllowlisted}, 0)
		e.m.ocsfEvent(t.Context(), b, ocsf.Record{Class: ocsf.ClassNetwork, Binary: bin, PID: pid, HasPID: true, Host: openshellHostAlias,
			Port: testEgressPort, Action: ocsf.ActionAllowed, Policy: "defenseclaw_egress"}, now())
		advance(time.Minute)
		_, err := e.m.Destinations(t.Context(), "rbox")
		must(t, err)
	}
	request("/usr/bin/curl", 77, egress.EventAllowed)
	request("/usr/bin/wget", 78, egress.EventBlocked)
	d, err := e.m.Destinations(t.Context(), "rbox")
	must(t, err)
	if len(d.Destinations) != 1 || !slices.Equal(d.Destinations[0].Binaries, []string{"/usr/bin/wget", "/usr/bin/curl"}) {
		t.Fatalf("destinations = %+v, want curl last (its traffic got through)", d.Destinations)
	}
}
