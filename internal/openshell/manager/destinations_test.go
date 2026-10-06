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

package manager

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
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

	rows := destinationKinds(t, e, "destbox")
	for host, kind := range map[string]string{
		"api.anthropic.com": sandboxapi.DestinationModelProvider, "claude.ai": sandboxapi.DestinationHarnessVendor,
		"api.openai.com": sandboxapi.DestinationOtherAI, "inference.example-llm.net": sandboxapi.DestinationUnknownAI,
		"registry.npmjs.org": string(egress.CategoryPackageRegistry), "evil.example.com": sandboxapi.DestinationBlocked,
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
	if f := shadow[0]; f.Severity != "LOW" || f.TargetRef != "api.openai.com" {
		t.Errorf("refused shadow AI = %+v", f)
	}
	if f := shadow[1]; f.Severity != "MEDIUM" || f.TargetRef != "api.openai.com" || f.Sandbox.BindingID != id || f.UserName != "dev" {
		t.Errorf("reached shadow AI = %+v", f)
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

// The destinations are kept across daemon restarts; a host reached in an
// earlier session is no first-seen destination for the proxy counter; a
// delete removes them.
func TestDestinationsAreKeptAndForgotten(t *testing.T) {
	e := liveEnv(t, "keepbox", nil)
	e.ocsf("keepbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> files.example.org:443/tcp [policy:allow_files engine:opa]", time.Now())
	b := e.binding("keepbox")
	p := egress.Principal{BindingID: b.ID, SandboxName: "keepbox"}
	if e.m.KnownDestination(p, "files.example.org") {
		t.Fatal("a host first reached in this session is known")
	}
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
	if !e.m.KnownDestination(p, "FILES.example.org.") || e.m.KnownDestination(p, "other.example") ||
		e.m.KnownDestination(egress.Principal{BindingID: "sb_other", SandboxName: "keepbox"}, "files.example.org") {
		t.Fatal("KnownDestination does not follow the kept destinations")
	}
	e.deleteBox("keepbox", sandboxapi.DeleteRequest{})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destinations after delete: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("sandbox dir after delete: %v", err)
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
