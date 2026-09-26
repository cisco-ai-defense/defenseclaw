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

package egress

import (
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// Public-looking addresses used across the tests. They are never contacted:
// the proxy tests' fake dialer routes every dial to a local listener.
const (
	publicV4    = "8.8.8.8"
	publicV4Alt = "8.8.4.4"
	publicV6    = "2001:4860:4860::8888"
)

func mustDecider(t *testing.T, opts DeciderOptions) *Decider {
	t.Helper()
	d, err := NewDecider(opts)
	if err != nil {
		t.Fatalf("NewDecider: %v", err)
	}
	return d
}

var testPrincipal = Principal{BindingID: "b-1", SandboxID: "sb-1", SandboxName: "sb-one"}

type decisionWant struct {
	allowed     bool
	category    Category
	source      Source
	rule        string
	unblockable bool
}

func checkDecision(t *testing.T, d *Decider, p Principal, host string, port int, want decisionWant) Decision {
	t.Helper()
	got := d.Decide(p, host, port)
	if got.Allowed != want.allowed || got.Category != want.category || got.Source != want.source ||
		(want.rule != "" && got.Rule != want.rule) || got.Unblockable != want.unblockable {
		t.Errorf("Decide(%q, %d) = %+v; want %+v", host, port, got, want)
	}
	if !got.Allowed && got.Reason == "" {
		t.Errorf("Decide(%q, %d) blocked without a reason", host, port)
	}
	return got
}

func TestDecideOpenMode(t *testing.T) {
	d := mustDecider(t, DeciderOptions{})
	allow := decisionWant{allowed: true, source: SourceDefault}
	private := decisionWant{category: CategoryPrivateNetwork, source: SourceGuard}
	invalid := decisionWant{category: CategoryInvalidDestination, source: SourceGuard}
	literal := decisionWant{category: CategoryIPLiteral, source: SourceDefault, unblockable: true}

	tests := []struct {
		host string
		port int
		want decisionWant
	}{
		{"example.com", 443, allow},
		{"EXAMPLE.com.", 80, allow},
		{publicV4, 443, literal},
		{"[" + publicV6 + "]", 443, literal},
		{publicV6, 80, literal},
		{"::ffff:" + publicV4, 443, literal},
		{"webhook.site", 443, decisionWant{category: CategoryWebhookCatcher, source: SourceFeed, rule: "webhook.site", unblockable: true}},
		{"abc.ngrok-free.app", 443, decisionWant{category: CategoryTunnel, source: SourceFeed, rule: "*.ngrok-free.app", unblockable: true}},
		{"pastebin.com", 80, decisionWant{category: CategoryPasteSite, source: SourceFeed, unblockable: true}},
		{"example.com", 22, decisionWant{category: CategoryPortNotAllowed, source: SourceGuard}},
		{"example.com", 8443, decisionWant{category: CategoryPortNotAllowed, source: SourceGuard}},
		{"example.com", 0, invalid},
		{"example.com", 70000, invalid},
		{"", 443, invalid},
		{"exa mple.com", 443, invalid},
		{"127.1", 443, invalid},
		{"0x7f.1", 443, invalid},

		// IPv4 literals the guard refuses.
		{"127.0.0.1", 443, private},
		{"127.8.9.10", 443, private},
		{"10.0.0.1", 443, private},
		{"172.16.5.4", 443, private},
		{"192.168.1.1", 80, private},
		{"169.254.169.254", 80, private},
		{"169.254.170.2", 80, private},
		{"100.64.0.1", 443, private},
		{"100.100.100.200", 80, private},
		{"0.0.0.0", 443, private},
		{"0.1.2.3", 443, private},
		{"198.18.0.2", 443, private},
		{"192.0.2.10", 443, private},
		{"224.0.0.1", 443, private},
		{"240.0.0.1", 443, private},
		{"255.255.255.255", 443, private},

		// IPv6 literals the guard refuses, bracketed or not.
		{"[::1]", 443, private},
		{"::", 443, private},
		{"[fe80::1]", 443, private},
		{"fe80::1%eth0", 443, private},
		{"[fc00::1]", 443, private},
		{"[fd00::1]", 443, private},
		{"[fd00:ec2::254]", 80, private},
		{"[::ffff:127.0.0.1]", 443, private},
		{"[::ffff:169.254.169.254]", 80, private},
		{"[::127.0.0.1]", 443, private},
		{"[64:ff9b::7f00:1]", 443, private},
		{"[2002:7f00:1::1]", 443, private},
		{"[2001:db8::1]", 443, private},
		{"[ff02::1]", 443, private},

		// Names that are host-internal by definition.
		{"localhost", 443, private},
		{"LOCALHOST.", 443, private},
		{"api.localhost", 443, private},
		{"host.openshell.internal", 443, private},
		{"host.docker.internal", 443, private},
		{"metadata.google.internal", 80, private},
		{"printer.local", 80, private},
		{"router.home.arpa", 80, private},
		{"nas.lan", 80, private},
		{"metadata", 80, private},
		{"intranet", 443, private},
	}
	for _, tt := range tests {
		checkDecision(t, d, testPrincipal, tt.host, tt.port, tt.want)
	}

	got := d.Decide(testPrincipal, "webhook.site", 443)
	if got.Feed != "defenseclaw-blocklist" || got.FeedVersion == "" || got.Entry != "Webhook.site" || got.Mode != ModeOpen {
		t.Errorf("feed provenance = %+v", got)
	}
	if got := d.Decide(testPrincipal, "example.com", 22); !strings.Contains(got.Reason, "80, 443") {
		t.Errorf("port reason %q does not list the allowed ports", got.Reason)
	}
	if got := d.Decide(testPrincipal, "bad\r\nhost", 443); strings.ContainsAny(got.Host, "\r\n") {
		t.Errorf("invalid host echoed unsanitized: %q", got.Host)
	}
}

// The operator's private-upstream allowlist exists for the daemon's own
// upstreams and must never widen what a sandbox can reach.
func TestDecideIgnoresDaemonPrivateAllowlist(t *testing.T) {
	netguard.SetAllowedPrivateIPs([]net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("100.64.0.9")})
	t.Cleanup(func() { netguard.SetAllowedPrivateIPs(nil) })
	d := mustDecider(t, DeciderOptions{})
	for _, host := range []string{"10.0.0.5", "100.64.0.9"} {
		checkDecision(t, d, testPrincipal, host, 443, decisionWant{category: CategoryPrivateNetwork, source: SourceGuard})
	}
}

// In open mode a public IP literal needs an operator allow or an unblock: a
// literal sidesteps the name-based blocklist (CONNECT to a CDN address, then
// any blocked site's server name).
func TestDecideIPLiterals(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(
		Unblock{Pattern: publicV4, SandboxID: "sb-1"},
		Unblock{Pattern: "2001:4860::/32"},
	)
	if err != nil {
		t.Fatal(err)
	}
	team, err := ParseFeed([]byte("schema_version: 1\nkind: blocklist\nname: team\nfeed_version: \"1\"\nentries:\n" +
		"  - {name: Drop net, category: file_drop, hosts: [\"8.8.4.0/24\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := BuiltinBlocklist()
	if err != nil {
		t.Fatal(err)
	}
	d := mustDecider(t, DeciderOptions{Unblocks: unblocks, Allow: []string{"1.1.1.0/24"}, Blocklists: []*Feed{builtin, team}})
	other := Principal{BindingID: "b-2", SandboxID: "sb-2"}
	literal := decisionWant{category: CategoryIPLiteral, source: SourceDefault, unblockable: true}

	got := checkDecision(t, d, other, publicV4, 443, literal)
	if got.Host != publicV4 || !strings.Contains(got.Reason, "blocklist") {
		t.Errorf("ip_literal decision = %+v", got)
	}
	checkDecision(t, d, testPrincipal, publicV4, 443, decisionWant{allowed: true, source: SourceUnblock, rule: publicV4})
	checkDecision(t, d, other, publicV6, 443, decisionWant{allowed: true, source: SourceUnblock, rule: "2001:4860::/32"})
	checkDecision(t, d, other, "1.1.1.1", 443, decisionWant{allowed: true, source: SourceOperator, rule: "1.1.1.0/24"})
	// A feed's CIDR entry keeps its own category.
	checkDecision(t, d, other, publicV4Alt, 443, decisionWant{category: CategoryFileDrop, source: SourceFeed, rule: "8.8.4.0/24", unblockable: true})
	// Names are unaffected.
	checkDecision(t, d, other, "example.com", 443, decisionWant{allowed: true, source: SourceDefault})

	// Allowlist mode already refuses literals as not allowlisted; a
	// principal in open mode on an allowlist decider gets ip_literal.
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist})
	checkDecision(t, a, other, publicV4, 443, decisionWant{category: CategoryNotAllowlisted, source: SourceDefault, unblockable: true})
	open := other
	open.Mode = ModeOpen
	checkDecision(t, a, open, publicV4, 443, literal)
}

// This machine's own public addresses are refused by the guard, which
// neither operator allows nor unblocks can lift.
func TestDecideOwnAddresses(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: ownV4}, Unblock{Pattern: ownV6})
	if err != nil {
		t.Fatal(err)
	}
	d := mustDecider(t, DeciderOptions{Allow: []string{ownV4, publicV4}, Unblocks: unblocks})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	private := decisionWant{category: CategoryPrivateNetwork, source: SourceGuard}
	for _, host := range []string{ownV4, "::ffff:" + ownV4, ownV6, "[" + ownV6 + "]"} {
		for _, port := range []int{80, 443} {
			got := checkDecision(t, d, testPrincipal, host, port, private)
			if !strings.Contains(got.Reason, "belongs to this machine") {
				t.Errorf("Decide(%s) reason = %q", host, got.Reason)
			}
		}
	}
	checkDecision(t, d, testPrincipal, publicV4, 443, decisionWant{allowed: true, source: SourceOperator})
	// Names are checked against their answers at dial time, not here.
	checkDecision(t, d, testPrincipal, "example.com", 443, decisionWant{allowed: true, source: SourceDefault})
}

func TestDecideAllowlistMode(t *testing.T) {
	d := mustDecider(t, DeciderOptions{Mode: ModeAllowlist})
	got := checkDecision(t, d, testPrincipal, "registry.npmjs.org", 443, decisionWant{allowed: true, category: CategoryPackageRegistry, source: SourceFeed})
	if got.Feed != "defenseclaw-allowlist" || got.Entry == "" || got.Mode != ModeAllowlist {
		t.Errorf("allowlist provenance = %+v", got)
	}
	checkDecision(t, d, testPrincipal, "objects.githubusercontent.com", 443, decisionWant{allowed: true, category: CategorySourceHosting, source: SourceFeed})
	checkDecision(t, d, testPrincipal, "example.com", 443, decisionWant{category: CategoryNotAllowlisted, source: SourceDefault, unblockable: true})
	checkDecision(t, d, testPrincipal, publicV4, 443, decisionWant{category: CategoryNotAllowlisted, source: SourceDefault, unblockable: true})
	checkDecision(t, d, testPrincipal, "webhook.site", 443, decisionWant{category: CategoryWebhookCatcher, source: SourceFeed, unblockable: true})
	checkDecision(t, d, testPrincipal, "localhost", 443, decisionWant{category: CategoryPrivateNetwork, source: SourceGuard})

	// A principal's own mode wins over the decider default.
	open := testPrincipal
	open.Mode = ModeOpen
	checkDecision(t, d, open, "example.com", 443, decisionWant{allowed: true, source: SourceDefault})
	strict := mustDecider(t, DeciderOptions{})
	balanced := testPrincipal
	balanced.Mode = ModeAllowlist
	checkDecision(t, strict, balanced, "example.com", 443, decisionWant{category: CategoryNotAllowlisted, source: SourceDefault, unblockable: true})
}

func TestDecideOperatorLists(t *testing.T) {
	d := mustDecider(t, DeciderOptions{
		Block: []string{"example.com", "*.corp-exfil.net", "8.8.4.0/24", "both.example.org"},
		Allow: []string{"webhook.site", "both.example.org", "127.0.0.1", "*.partner.example.net"},
	})
	opBlock := decisionWant{category: CategoryOperatorBlock, source: SourceOperator}
	checkDecision(t, d, testPrincipal, "example.com", 443, withRule(opBlock, "example.com"))
	checkDecision(t, d, testPrincipal, "a.b.corp-exfil.net", 443, withRule(opBlock, "*.corp-exfil.net"))
	checkDecision(t, d, testPrincipal, publicV4Alt, 443, withRule(opBlock, "8.8.4.0/24"))
	checkDecision(t, d, testPrincipal, "both.example.org", 443, withRule(opBlock, "both.example.org"))
	// Operator allow overrides the feed ...
	checkDecision(t, d, testPrincipal, "webhook.site", 443, decisionWant{allowed: true, source: SourceOperator, rule: "webhook.site"})
	// ... but never the guard.
	checkDecision(t, d, testPrincipal, "127.0.0.1", 443, decisionWant{category: CategoryPrivateNetwork, source: SourceGuard})
	checkDecision(t, d, testPrincipal, "webhook.site", 22, decisionWant{category: CategoryPortNotAllowed, source: SourceGuard})

	// Operator allow admits destinations in allowlist mode.
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, Allow: []string{"*.partner.example.net"}})
	checkDecision(t, a, testPrincipal, "api.partner.example.net", 443, decisionWant{allowed: true, source: SourceOperator})
	checkDecision(t, a, testPrincipal, "partner.example.net", 443, decisionWant{category: CategoryNotAllowlisted, source: SourceDefault, unblockable: true})
}

func withRule(w decisionWant, rule string) decisionWant {
	w.rule = rule
	return w
}

func TestDecideUnblocks(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(
		Unblock{Pattern: "webhook.site", SandboxID: "sb-1"},
		Unblock{Pattern: "*.NGROK-FREE.app"},
		Unblock{Pattern: "example.com"},
		Unblock{Pattern: "localhost"},
		Unblock{Pattern: "10.0.0.0/8"},
	)
	if err != nil {
		t.Fatal(err)
	}
	other := Principal{BindingID: "b-2", SandboxID: "sb-2"}
	anonymous := Principal{BindingID: "b-3"}

	d := mustDecider(t, DeciderOptions{Unblocks: unblocks, Block: []string{"example.com"}})
	unblocked := decisionWant{allowed: true, source: SourceUnblock}
	checkDecision(t, d, testPrincipal, "webhook.site", 443, withRule(unblocked, "webhook.site"))
	checkDecision(t, d, other, "webhook.site", 443, decisionWant{category: CategoryWebhookCatcher, source: SourceFeed, unblockable: true})
	checkDecision(t, d, anonymous, "webhook.site", 443, decisionWant{category: CategoryWebhookCatcher, source: SourceFeed, unblockable: true})
	checkDecision(t, d, other, "x.ngrok-free.app", 443, withRule(unblocked, "*.ngrok-free.app"))
	// Unblocks never lift operator or guard blocks.
	checkDecision(t, d, testPrincipal, "example.com", 443, decisionWant{category: CategoryOperatorBlock, source: SourceOperator})
	checkDecision(t, d, testPrincipal, "localhost", 443, decisionWant{category: CategoryPrivateNetwork, source: SourceGuard})
	checkDecision(t, d, testPrincipal, "10.1.2.3", 443, decisionWant{category: CategoryPrivateNetwork, source: SourceGuard})

	// In allowlist mode an unblock admits a not-allowlisted destination.
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, Unblocks: unblocks})
	checkDecision(t, a, testPrincipal, "example.com", 443, withRule(unblocked, "example.com"))
}

func TestMemoryUnblocks(t *testing.T) {
	m, err := NewMemoryUnblocks()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Add(Unblock{Pattern: "bad host"}); !errors.Is(err, ErrInvalidPattern) {
		t.Fatalf("Add(bad) = %v", err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.Add(Unblock{Pattern: "Webhook.Site", SandboxID: "sb-1"}))
	must(m.Add(Unblock{Pattern: "webhook.site", SandboxID: "sb-1"})) // replaces
	must(m.Add(Unblock{Pattern: "webhook.site"}))
	must(m.Add(Unblock{Pattern: "paste.ee", SandboxID: "sb-1"}))
	must(m.Add(Unblock{Pattern: "paste.ee", SandboxID: "sb-2"}))
	if n := len(m.List()); n != 4 {
		t.Fatalf("List() has %d entries, want 4: %+v", n, m.List())
	}
	if u, ok := m.Unblocked(testPrincipal, "WEBHOOK.site."); !ok || u.SandboxID != "sb-1" {
		t.Errorf("sandbox-scoped unblock not preferred: %+v %v", u, ok)
	}
	if !m.Remove("sb-1", "WEBHOOK.SITE") || m.Remove("sb-1", "webhook.site") {
		t.Error("Remove did not remove exactly once")
	}
	if u, ok := m.Unblocked(testPrincipal, "webhook.site"); !ok || u.SandboxID != "" {
		t.Errorf("persistent unblock not used: %+v %v", u, ok)
	}
	if n := m.RemoveSandbox("sb-1"); n != 1 {
		t.Errorf("RemoveSandbox = %d, want 1", n)
	}
	if m.RemoveSandbox("") != 0 {
		t.Error("RemoveSandbox(\"\") removed persistent unblocks")
	}
	before := m.List()
	if err := m.Replace([]Unblock{{Pattern: "ok.example"}, {Pattern: "*"}}); err == nil {
		t.Fatal("Replace accepted an invalid pattern")
	}
	if !slices.Equal(before, m.List()) {
		t.Error("a failed Replace changed the set")
	}
	must(m.Replace(nil))
	if _, ok := m.Unblocked(testPrincipal, "webhook.site"); ok {
		t.Error("Replace(nil) kept unblocks")
	}
	if _, ok := m.Unblocked(testPrincipal, "bad host"); ok {
		t.Error("invalid host matched")
	}
}

func TestNewDeciderValidation(t *testing.T) {
	block, _ := BuiltinBlocklist()
	allow, _ := BuiltinAllowlist()
	bad := map[string]DeciderOptions{
		"mode":           {Mode: "deny"},
		"port zero":      {Ports: []int{0}},
		"port range":     {Ports: []int{443, 65536}},
		"block pattern":  {Block: []string{"*"}},
		"allow pattern":  {Allow: []string{"a.*.com"}},
		"blocklist kind": {Blocklists: []*Feed{allow}},
		"allowlist kind": {Allowlists: []*Feed{block}},
		"nil feed":       {Blocklists: []*Feed{nil}},
		"unparsed feed":  {Blocklists: []*Feed{{Kind: FeedKindBlocklist}}},
	}
	for name, opts := range bad {
		if _, err := NewDecider(opts); err == nil {
			t.Errorf("%s: NewDecider accepted %+v", name, opts)
		}
	}

	d := mustDecider(t, DeciderOptions{Ports: []int{8443, 443, 443}})
	if got := d.Ports(); !slices.Equal(got, []int{443, 8443}) {
		t.Errorf("Ports() = %v", got)
	}
	checkDecision(t, d, testPrincipal, "example.com", 8443, decisionWant{allowed: true, source: SourceDefault})
	checkDecision(t, d, testPrincipal, "example.com", 80, decisionWant{category: CategoryPortNotAllowed, source: SourceGuard})
	if d.Mode() != ModeOpen {
		t.Errorf("Mode() = %q", d.Mode())
	}
	infos := d.Feeds()
	if len(infos) != 2 || infos[0].Kind != FeedKindBlocklist || infos[1].Kind != FeedKindAllowlist || infos[0].Digest == "" {
		t.Errorf("Feeds() = %+v", infos)
	}

	// An empty feed list disables the built-in feed.
	none := mustDecider(t, DeciderOptions{Blocklists: []*Feed{}})
	checkDecision(t, none, testPrincipal, "webhook.site", 443, decisionWant{allowed: true, source: SourceDefault})

	// Extra feeds apply in order after the first.
	team, err := ParseFeed([]byte("schema_version: 1\nkind: blocklist\nname: team\nfeed_version: \"7\"\nentries:\n" +
		"  - {name: Team drop, category: file_drop, hosts: [drop.example.org, webhook.site]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	both := mustDecider(t, DeciderOptions{Blocklists: []*Feed{block, team}})
	if got := both.Decide(testPrincipal, "drop.example.org", 443); got.Feed != "team" || got.FeedVersion != "7" {
		t.Errorf("team feed decision = %+v", got)
	}
	if got := both.Decide(testPrincipal, "webhook.site", 443); got.Feed != "defenseclaw-blocklist" {
		t.Errorf("first feed did not win: %+v", got)
	}
}

func TestModes(t *testing.T) {
	for in, want := range map[string]Mode{"open": ModeOpen, " Allowlist ": ModeAllowlist} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("balanced"); err == nil {
		t.Error("ParseMode accepted a profile name")
	}
	profiles := []struct {
		profile string
		mode    Mode
		enabled bool
		bad     bool
	}{
		{"", ModeOpen, true, false},
		{"open", ModeOpen, true, false},
		{"Balanced", ModeAllowlist, true, false},
		{"strict", "", false, false},
		{"yolo", "", false, true},
	}
	for _, p := range profiles {
		mode, enabled, err := ModeForProfile(p.profile)
		if (err != nil) != p.bad || mode != p.mode || enabled != p.enabled {
			t.Errorf("ModeForProfile(%q) = %q, %v, %v", p.profile, mode, enabled, err)
		}
	}
}
