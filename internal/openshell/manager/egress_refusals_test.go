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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// #954: a CONNECT the sandbox's egress proxy refuses is kept for the
// sandbox binding whose credential made it, and EgressRefusals hands it out
// once, with the unblock command for that sandbox: not to another binding,
// not after the window, and not once the user unblocked the host.
func TestEgressRefusalsReachTheBindingsAgentOnce(t *testing.T) {
	e := newEnv(t, nil)
	_, advance := e.fakeClock(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.create(sandboxapi.CreateRequest{Name: "egbox"})
	e.create(sandboxapi.CreateRequest{Name: "otherbox", Project: e.otherProject("other")})
	eg, other := e.binding("egbox"), e.binding("otherbox")
	refusals := func(b sandboxauth.Binding) []EgressRefusal {
		t.Helper()
		return e.m.EgressRefusals(b.ID, b.SandboxName)
	}
	connect := func(sandbox, target string) {
		t.Helper()
		if status, _ := proxy.connect(t, sandbox, target); status != http.StatusForbidden {
			t.Fatalf("%s CONNECT %s = %d, want the proxy's refusal", sandbox, target, status)
		}
	}

	connect("egbox", "webhook.site:443")
	got := refusals(eg)
	if len(got) != 1 || got[0].Host != "webhook.site" || got[0].Port != 443 || got[0].Category != string(egress.CategoryWebhookCatcher) ||
		got[0].What != "webhook catcher" ||
		got[0].Remedy != "the user can allow it for this sandbox with `defenseclaw sandbox unblock webhook.site --sandbox egbox`" {
		t.Fatalf("refusals = %+v", got)
	}
	// Told once: neither the same answer again nor a repeat of the refusal
	// within the window.
	if got := refusals(eg); len(got) != 0 {
		t.Fatalf("told again: %+v", got)
	}
	connect("egbox", "webhook.site:443")
	if got := refusals(eg); len(got) != 0 {
		t.Fatalf("a repeat was told again: %+v", got)
	}
	// Only the binding whose credential made the request, under its own
	// sandbox name.
	connect("egbox", "pastebin.com:443")
	if got := refusals(other); len(got) != 0 {
		t.Fatalf("another sandbox was told: %+v", got)
	}
	if got := e.m.EgressRefusals(eg.ID, "otherbox"); len(got) != 0 {
		t.Fatalf("another name was told: %+v", got)
	}
	if got := e.m.EgressRefusals(other.ID, "egbox"); len(got) != 0 {
		t.Fatalf("another binding was told: %+v", got)
	}
	// A destination the user unblocked since is left out (the unblock
	// scoping of Manager.EgressUnblock).
	_, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "pastebin.com", Sandbox: "egbox"})
	must(t, err)
	if got := refusals(eg); len(got) != 0 {
		t.Fatalf("an unblocked destination was told: %+v", got)
	}
	// Past the window a refusal is not the call's any more, and a new one
	// is told again.
	connect("egbox", "93.184.216.34:443")
	advance(egressRefusalWindow + time.Second)
	if got := refusals(eg); len(got) != 0 {
		t.Fatalf("an expired refusal was told: %+v", got)
	}
	connect("egbox", "webhook.site:443")
	if got := refusals(eg); len(got) != 1 || got[0].Host != "webhook.site" {
		t.Fatalf("after the window = %+v", got)
	}
	// A deleted sandbox's refusals go with it.
	connect("egbox", "webhook.site:8443")
	if _, err := e.m.Delete(t.Context(), "egbox", sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := refusals(eg); len(got) != 0 {
		t.Fatalf("a deleted sandbox's refusals = %+v", got)
	}
}

// RT U3: when the large-upload block cut an upload on a tunnel it had let
// through, the agent saw only "curl: (56) Failure when receiving data from
// the peer" and replied "Uploaded the file."; the #954 note covered refused
// CONNECTs only. The cut is kept like a refusal: told once, within the
// window, with what went up and the unblock command, and a refusal of the
// host after it is the same news.
func TestEgressRefusalsTellOfALargeUploadCut(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Egress.LargeUploadMB = 1
		c.OpenShell.Egress.BlockLargeUploads = true
	})
	_, advance := e.fakeClock(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	e.run()
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "upbox"})
	b := e.binding("upbox")
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
	var got []EgressRefusal
	eventually(t, "the cut among the refusals", func() bool {
		got = append(got, e.m.EgressRefusals(b.ID, b.SandboxName)...)
		return len(got) > 0
	})
	if len(got) != 1 || got[0].Host != "example.org" || got[0].Category != string(egress.CategoryLargeUpload) || !got[0].Cut ||
		got[0].Sent <= 0 || got[0].Sent > 1<<20 ||
		got[0].Remedy != "the user can allow it for this sandbox with `defenseclaw sandbox unblock example.org --sandbox upbox`" {
		t.Fatalf("refusals = %+v", got)
	}
	// A refusal of the host after the cut is not told again.
	if status, _ := proxy.connect(t, "upbox", "example.org:80"); status != http.StatusForbidden {
		t.Fatalf("CONNECT after the cut = %d", status)
	}
	if got := e.m.EgressRefusals(b.ID, b.SandboxName); len(got) != 0 {
		t.Fatalf("told again: %+v", got)
	}
	// Past the window it is an ordinary refusal of the blocked host.
	advance(egressRefusalWindow + time.Second)
	if status, _ := proxy.connect(t, "upbox", "example.org:80"); status != http.StatusForbidden {
		t.Fatalf("CONNECT after the window = %d", status)
	}
	if got := e.m.EgressRefusals(b.ID, b.SandboxName); len(got) != 1 || got[0].Cut || got[0].Category != string(egress.CategoryLargeUpload) {
		t.Fatalf("after the window = %+v", got)
	}
}

// A refusal belongs to the session whose agent made the request: a stop and
// a start keep the sandbox's binding, and the new session's agent is not
// told of what the proxy refused the one before.
func TestEgressRefusalsEndWithTheSession(t *testing.T) {
	e := newEnv(t, nil)
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "egbox"})
	before := e.binding("egbox")
	if status, _ := proxy.connect(t, "egbox", "webhook.site:443"); status != http.StatusForbidden {
		t.Fatalf("CONNECT webhook.site = %d, want the proxy's refusal", status)
	}
	e.stopBox("egbox")
	e.startBox("egbox", sandboxapi.StartRequest{})
	after := e.binding("egbox")
	if after.ID != before.ID {
		t.Fatalf("the start made a new binding %s (was %s)", after.ID, before.ID)
	}
	if got := e.m.EgressRefusals(after.ID, after.SandboxName); len(got) != 0 {
		t.Fatalf("the new session was told of the last one's refusals: %+v", got)
	}
}

// The agent is told who can allow a destination: the unblock command only
// while an unblock lifts the refusal, and otherwise who can, never a way
// around it.
func TestEgressRefusalRemedies(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Admin.EgressBlock = []string{"corp-banned.example"}
		c.OpenShell.Egress.Block = []string{"drop.example.org"}
	})
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.create(sandboxapi.CreateRequest{Name: "rembox"})
	b := e.binding("rembox")
	for _, tc := range []struct {
		target, what, remedy string
	}{
		{"x.corp-banned.example:443", "blocked by the organization's policy", "only the user's administrator can allow it"},
		{"drop.example.org:443", "on the sandbox's block list", "only removing it from the block list allows it"},
		{"10.1.2.3:443", "private network", "only the user's DefenseClaw operator can open it (openshell.egress.allow)"},
		{"169.254.169.254:443", "this machine or a metadata address", "sandboxes never reach it"},
		{"example.org:22", "port the proxy does not relay", "only the user's DefenseClaw operator can add the port (openshell.egress.ports)"},
		{"93.184.216.34:443", "an IP address instead of a host name",
			"the user can allow it for this sandbox with `defenseclaw sandbox unblock 93.184.216.34 --sandbox rembox`"},
	} {
		if status, body := proxy.connect(t, "rembox", tc.target); status != http.StatusForbidden {
			t.Fatalf("CONNECT %s = %d %+v", tc.target, status, body)
		}
		got := e.m.EgressRefusals(b.ID, b.SandboxName)
		if len(got) != 1 || got[0].What != tc.what || got[0].Remedy != tc.remedy {
			t.Errorf("CONNECT %s: refusals = %+v, want %q / %q", tc.target, got, tc.what, tc.remedy)
		}
	}
	// A refusal an unblock would have lifted offers no unblock once the
	// organization turns unblocking off.
	if status, _ := proxy.connect(t, "rembox", "webhook.site:443"); status != http.StatusForbidden {
		t.Fatal("webhook.site was not refused")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	e.m.refreshEgress()
	if got := e.m.EgressRefusals(b.ID, b.SandboxName); len(got) != 1 || got[0].Remedy != "only the user's administrator can allow it" {
		t.Fatalf("under allow_unblock: false = %+v", got)
	}
}

// The memory keeps only what the agent cannot read, only host names, and a
// bounded number per binding and of bindings.
func TestRefusalMemoryBounds(t *testing.T) {
	r := newRefusalMemory()
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	blocked := func(binding, host string) egress.Event {
		return egress.Event{Kind: egress.EventBlocked, Method: http.MethodConnect, BindingID: binding, SandboxName: "sb-" + binding,
			Host: host, Port: 443, Category: egress.CategoryWebhookCatcher, Source: egress.SourceFeed, Unblockable: true}
	}
	// Not kept: a plain-HTTP refusal (its 403 body reaches the client), a
	// rate limit, an invalid target, a sanitized name, another event.
	plain := blocked("b1", "webhook.site")
	plain.Method = http.MethodGet
	limited := blocked("b1", "example.org")
	limited.Category = egress.CategoryRateLimited
	invalid := blocked("b1", "bad?host")
	invalid.Category = egress.CategoryInvalidDestination
	allowed := blocked("b1", "example.org")
	allowed.Kind = egress.EventAllowed
	for _, ev := range []egress.Event{plain, limited, invalid, blocked("b1", "evil`host`.example"), blocked("b1", "a b"), allowed,
		blocked("", "webhook.site")} {
		r.note(ev, at)
	}
	if got := r.take("b1", "sb-b1", at); len(got) != 0 {
		t.Fatalf("kept %+v", got)
	}
	// The latest maxRefusedHosts per binding, oldest first; a repeat moves
	// to the end.
	for i := range maxRefusedHosts + 3 {
		r.note(blocked("b1", "h"+strconv.Itoa(i)+".example"), at.Add(time.Duration(i)*time.Second))
	}
	r.note(blocked("b1", "H4.Example."), at.Add(time.Minute))
	got := r.take("b1", "sb-b1", at.Add(time.Minute))
	var hosts []string
	for _, h := range got {
		hosts = append(hosts, h.host)
	}
	if want := "h3.example h5.example h6.example h7.example h8.example h9.example h10.example h4.example"; strings.Join(hosts, " ") != want {
		t.Fatalf("kept %q, want %q", hosts, want)
	}
	// A bounded number of bindings: the stalest goes.
	for i := range maxRefusalBindings + 1 {
		r.note(blocked("x"+strconv.Itoa(i), "webhook.site"), at.Add(time.Duration(i)*time.Millisecond))
	}
	r.mu.Lock()
	n, _, oldest := len(r.byBinding), r.byBinding["b1"], r.byBinding["x0"]
	r.mu.Unlock()
	if n > maxRefusalBindings || oldest != nil {
		t.Fatalf("%d bindings kept (x0 kept: %t)", n, oldest != nil)
	}
}
