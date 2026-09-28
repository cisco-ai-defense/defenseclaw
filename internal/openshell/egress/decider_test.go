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
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	host := decisionWant{category: CategoryHostInternal, source: SourceGuard}
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

		// IPv4 literals the guard refuses: this machine and what only it
		// reaches, and private networks.
		{"127.0.0.1", 443, host},
		{"127.8.9.10", 443, host},
		{"10.0.0.1", 443, private},
		{"172.16.5.4", 443, private},
		{"192.168.1.1", 80, private},
		{"169.254.169.254", 80, host},
		{"169.254.170.2", 80, host},
		{"100.64.0.1", 443, private},
		{"100.100.100.200", 80, host},
		{"0.0.0.0", 443, host},
		{"0.1.2.3", 443, host},
		{"198.18.0.2", 443, host},
		{"192.0.2.10", 443, host},
		{"224.0.0.1", 443, host},
		{"240.0.0.1", 443, host},
		{"255.255.255.255", 443, host},
		// Host services on addresses netguard passes as public: the Azure
		// WireServer.
		{"168.63.129.16", 80, host},
		{"168.63.129.17", 443, literal},

		// IPv6 literals the guard refuses, bracketed or not.
		{"[::1]", 443, host},
		{"::", 443, host},
		{"[fe80::1]", 443, host},
		{"fe80::1%eth0", 443, host},
		{"[fc00::1]", 443, private},
		{"[fd00::1]", 443, private},
		{"[fd00:ec2::254]", 80, host},
		// IPv6 metadata servers in unique local space (Google Cloud, Oracle
		// Cloud) and the deprecated site-local range.
		{"[fd20:ce::254]", 80, host},
		{"[fd00:c1::a9fe:a9fe]", 80, host},
		{"[fd20:ce::253]", 80, private},
		{"[fec0::1]", 443, host},
		{"[feff:ffff::1]", 443, host},
		{"[::ffff:127.0.0.1]", 443, host},
		{"[::ffff:10.1.2.3]", 443, private},
		{"[::ffff:169.254.169.254]", 80, host},
		{"[::127.0.0.1]", 443, host},
		{"[64:ff9b::7f00:1]", 443, host},
		{"[2002:7f00:1::1]", 443, host},
		{"[2001:db8::1]", 443, host},
		{"[ff02::1]", 443, host},

		// Names that are host-internal by definition ...
		{"localhost", 443, host},
		{"LOCALHOST.", 443, host},
		{"api.localhost", 443, host},
		{"myhost.localdomain", 443, host},
		{"host.openshell.internal", 443, host},
		{"x.openshell.internal", 443, host},
		{"host.docker.internal", 443, host},
		{"host.containers.internal", 443, host},
		{"metadata.google.internal", 80, host},
		// ... intranet names ...
		{"artifactory.corp.internal", 443, private},
		{"printer.local", 80, private},
		{"router.home.arpa", 80, private},
		{"nas.lan", 80, private},
		{"build.corp", 443, private},
		// ... and single-label names, which only the host's DNS search
		// domains would resolve.
		{"metadata", 80, invalid},
		{"intranet", 443, invalid},
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
			got := checkDecision(t, d, testPrincipal, host, port, decisionWant{category: CategoryHostInternal, source: SourceGuard})
			if !strings.Contains(got.Reason, "belongs to this machine") {
				t.Errorf("Decide(%s) reason = %q", host, got.Reason)
			}
		}
	}
	checkDecision(t, d, testPrincipal, publicV4, 443, decisionWant{allowed: true, source: SourceOperator})
	// Names are checked against their answers at dial time, not here.
	checkDecision(t, d, testPrincipal, "example.com", 443, decisionWant{allowed: true, source: SourceDefault})

	// Other hosts on this machine's public subnets are its local network:
	// the /64 of a global IPv6 address and the prefix of a public IPv4 one.
	for _, host := range []string{"2620:fe::1", "[2620:fe::ffff:2]", "9.9.200.1", "::ffff:9.9.0.1"} {
		got := checkDecision(t, d, testPrincipal, host, 443, private)
		if !strings.Contains(got.Reason, "own subnets") {
			t.Errorf("Decide(%s) reason = %q", host, got.Reason)
		}
	}
	checkDecision(t, d, testPrincipal, "2620:fe:0:1::1", 443, decisionWant{category: CategoryIPLiteral, source: SourceDefault, unblockable: true})
}

// Private networks open only through the operator's allow list: a pattern
// for the name, or an IP or CIDR no wider than the private range or on-link
// subnet it covers. Unblocks never open them, operator blocks still win,
// and nothing opens this machine itself or what only it can reach.
func TestDecidePrivateNetworksOpenThroughOperatorAllow(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: "10.9.0.0/16"}, Unblock{Pattern: "db.lan"})
	if err != nil {
		t.Fatal(err)
	}
	d := mustDecider(t, DeciderOptions{
		Mode:     ModeAllowlist,
		Unblocks: unblocks,
		Allow: []string{
			"10.20.0.0/16", "192.168.1.50", "fd12:3456::/32", "2620:fe::/64", "100.64.0.0/10",
			"*.corp", "artifactory.example.internal", "0.0.0.0/0", "::/0", "172.0.0.0/8",
			"127.0.0.1", "localhost", "*.openshell.internal", "metadata.google.internal", "169.254.169.254", ownV4,
			"fd20:ce::/32", "fd20:ce::254", "168.63.129.16", "fec0::/10",
		},
		Block: []string{"10.20.9.9", "blocked.corp"},
	})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	operator := decisionWant{allowed: true, source: SourceOperator}
	private := decisionWant{category: CategoryPrivateNetwork, source: SourceGuard}
	host := decisionWant{category: CategoryHostInternal, source: SourceGuard}
	tests := []struct {
		host string
		want decisionWant
	}{
		{"10.20.3.4", withRule(operator, "10.20.0.0/16")},
		{"192.168.1.50", withRule(operator, "192.168.1.50")},
		{"[fd12:3456::1]", withRule(operator, "fd12:3456::/32")},
		{"2620:fe::1", withRule(operator, "2620:fe::/64")},
		{"100.100.1.1", withRule(operator, "100.64.0.0/10")},
		{"git.corp", withRule(operator, "*.corp")},
		{"artifactory.example.internal", withRule(operator, "artifactory.example.internal")},
		// Operator blocks still win over an opened private destination.
		{"10.20.9.9", withRule(decisionWant{category: CategoryOperatorBlock, source: SourceOperator}, "10.20.9.9")},
		{"blocked.corp", withRule(decisionWant{category: CategoryOperatorBlock, source: SourceOperator}, "blocked.corp")},
		// Wider than the private range: 0.0.0.0/0, ::/0 and 172.0.0.0/8
		// open public literals but no private network.
		{"10.1.2.3", private},
		{"172.16.0.1", private},
		{"[fd00::1]", private},
		{"192.168.1.51", private},
		{"9.9.200.1", private},
		{"8.8.8.8", withRule(operator, "0.0.0.0/0")},
		// An unblock is not an operator allow.
		{"10.9.1.1", private},
		{"db.lan", private},
		{"nas.lan", private},
		// This machine and what only it reaches stay closed.
		{"127.0.0.1", host},
		{"localhost", host},
		{"host.openshell.internal", host},
		{"metadata.google.internal", host},
		{"169.254.169.254", host},
		{ownV4, host},
		{"[fd20:ce::254]", host},
		{"168.63.129.16", host},
		{"[fec0::1]", host},
		{"[fd20:ce::1]", withRule(operator, "fd20:ce::/32")},
	}
	for _, tt := range tests {
		got := checkDecision(t, d, testPrincipal, tt.host, 443, tt.want)
		if got.Category == CategoryPrivateNetwork && !strings.Contains(DefaultUnblockHint(testPrincipal, got), "openshell.egress.allow") {
			t.Errorf("Decide(%s) hint = %q", tt.host, DefaultUnblockHint(testPrincipal, got))
		}
		if got.Category == CategoryHostInternal && !strings.Contains(DefaultUnblockHint(testPrincipal, got), "--host-port") {
			t.Errorf("Decide(%s) hint = %q", tt.host, DefaultUnblockHint(testPrincipal, got))
		}
	}
}

// The private-network hint names only entries openshell.egress.allow
// accepts, and each of them opens the destination it is meant for: the
// configuration takes names, "*." wildcards and single IP addresses, not
// CIDRs.
func TestPrivateNetworkHintMatchesConfig(t *testing.T) {
	hint := DefaultUnblockHint(testPrincipal, Decision{Host: "wiki.example.com", Port: 443, Category: CategoryPrivateNetwork})
	for _, want := range []string{"openshell.egress.allow", "exact host name", "IP address", "*.corp"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint %q does not mention %q", hint, want)
		}
	}
	if strings.Contains(hint, "CIDR") || strings.Contains(hint, "/8") {
		t.Errorf("hint %q suggests a CIDR, which openshell.egress.allow rejects", hint)
	}
	for _, entry := range []string{"wiki.example.com", "10.9.9.9", "fd00::9", "*.corp"} {
		if err := config.ValidateOpenShellEgressPattern(entry); err != nil {
			t.Errorf("config rejects the hinted entry %q: %v", entry, err)
		}
	}
	// Config also accepts CIDR prefixes (the proxy's pattern grammar); the
	// hint deliberately suggests the simplest entries that open one private
	// destination: the exact name, its address, or an intranet wildcard.
	g, r, _ := newTestGuard(t)
	r.set("wiki.example.com", []string{"10.9.9.9"})
	r.set("git.corp", []string{"10.9.9.10"})
	for _, tt := range []struct{ allow, host string }{
		{"wiki.example.com", "wiki.example.com"},
		{"10.9.9.9", "wiki.example.com"},
		{"10.9.9.9", "10.9.9.9"},
		{"*.corp", "git.corp"},
	} {
		d := mustDecider(t, DeciderOptions{Allow: []string{tt.allow}})
		d.local = g.local
		dec := d.Decide(testPrincipal, tt.host, 443)
		if !dec.Allowed {
			t.Errorf("allow %q: Decide(%s) = %+v", tt.allow, tt.host, dec)
			continue
		}
		conn, _, err := g.dial(context.Background(), dec.Host, dec.Port, d.dialRules(testPrincipal, dec))
		if err != nil {
			t.Errorf("allow %q: dial(%s) = %v", tt.allow, tt.host, err)
			continue
		}
		_ = conn.Close()
	}
}

// With openshell.admin.allow_unblock: false the sandbox policy drops the
// allow entries the user adds, so the private-network hint must not send
// them to openshell.egress.allow: only the administrator can open the
// destination.
func TestPrivateNetworkHintWithoutUnblocking(t *testing.T) {
	d := mustDecider(t, DeciderOptions{NoUnblock: true})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	for _, host := range []string{"10.9.9.9", "wiki.corp"} {
		dec := d.Decide(testPrincipal, host, 443)
		if dec.Category != CategoryPrivateNetwork || !dec.NoUnblock {
			t.Fatalf("Decide(%s) = %+v", host, dec)
		}
		hint := DefaultUnblockHint(testPrincipal, dec)
		if strings.Contains(hint, "openshell.egress.allow") || strings.Contains(hint, "sandbox unblock") ||
			!strings.Contains(hint, "administrator") || !strings.Contains(hint, "openshell.admin.egress_allow_only") {
			t.Errorf("Decide(%s) hint = %q", host, hint)
		}
	}
	open := mustDecider(t, DeciderOptions{})
	if dec := open.Decide(testPrincipal, "wiki.corp", 443); dec.NoUnblock ||
		!strings.Contains(DefaultUnblockHint(testPrincipal, dec), "openshell.egress.allow") {
		t.Errorf("hint with unblocking = %q", DefaultUnblockHint(testPrincipal, dec))
	}
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
	checkDecision(t, d, testPrincipal, "localhost", 443, decisionWant{category: CategoryHostInternal, source: SourceGuard})

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
	checkDecision(t, d, testPrincipal, "127.0.0.1", 443, decisionWant{category: CategoryHostInternal, source: SourceGuard})
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

// TestDecideAdminLists pins where the administrator's lists sit: after the
// guard and the ports, before the block list and every unblock, and never
// unblockable.
func TestDecideAdminLists(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(
		Unblock{Pattern: "a.ngrok.io"}, Unblock{Pattern: "pypi.org"}, Unblock{Pattern: "x.pastebin.com"},
	)
	if err != nil {
		t.Fatal(err)
	}
	d := mustDecider(t, DeciderOptions{
		AdminBlock: []string{"*.ngrok.io", "8.8.4.0/24"},
		AllowOnly:  []string{"*.ngrok.io", "*.pastebin.com", "git.corp", "8.8.8.8", "wiki.corp.example"},
		Block:      []string{"wiki.corp.example"},
		Allow:      []string{"a.ngrok.io"},
		Unblocks:   unblocks,
	})
	admin := decisionWant{category: CategoryAdminBlock, source: SourceAdmin}
	outside := decisionWant{category: CategoryAdminAllowOnly, source: SourceAdmin}
	checkDecision(t, d, testPrincipal, "a.ngrok.io", 443, withRule(admin, "*.ngrok.io"))
	checkDecision(t, d, testPrincipal, publicV4Alt, 443, withRule(admin, "8.8.4.0/24"))
	checkDecision(t, d, testPrincipal, "pypi.org", 443, outside)
	checkDecision(t, d, testPrincipal, "example.com", 443, outside)
	// Inside the allow-only list the block list, the feed and the guard
	// still apply; unblocks lift only the feed.
	checkDecision(t, d, testPrincipal, "wiki.corp.example", 443, decisionWant{category: CategoryOperatorBlock, source: SourceOperator})
	checkDecision(t, d, testPrincipal, "x.pastebin.com", 443, decisionWant{allowed: true, source: SourceUnblock})
	checkDecision(t, d, testPrincipal, "y.pastebin.com", 443, decisionWant{category: CategoryPasteSite, source: SourceFeed, unblockable: true})
	checkDecision(t, d, testPrincipal, "localhost", 443, decisionWant{category: CategoryHostInternal, source: SourceGuard})
	checkDecision(t, d, testPrincipal, "git.corp", 22, decisionWant{category: CategoryPortNotAllowed, source: SourceGuard})
	// An allow-only entry allows, opens the intranet name it names, and
	// admits an IP literal in either mode.
	checkDecision(t, d, testPrincipal, "git.corp", 443, decisionWant{allowed: true, source: SourceAdmin, rule: "git.corp"})
	checkDecision(t, d, testPrincipal, publicV4, 443, decisionWant{allowed: true, source: SourceAdmin, rule: "8.8.8.8"})
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, AllowOnly: []string{"*.example.org"}, Allowlists: []*Feed{}})
	checkDecision(t, a, testPrincipal, "docs.example.org", 443, decisionWant{allowed: true, source: SourceAdmin, rule: "*.example.org"})
	checkDecision(t, a, testPrincipal, "registry.npmjs.org", 443, outside)
	if got := d.Decide(testPrincipal, "a.ngrok.io", 443); !strings.Contains(got.Reason, "your organization's DefenseClaw policy") {
		t.Errorf("admin block reason = %q", got.Reason)
	}
	if hint := DefaultUnblockHint(testPrincipal, d.Decide(testPrincipal, "pypi.org", 443)); !strings.Contains(hint, "organization") ||
		strings.Contains(hint, "sandbox unblock") {
		t.Errorf("admin hint = %q", hint)
	}
}

// TestDecideNoUnblock pins openshell.admin.allow_unblock: false: unblocks
// are ignored, nothing is reported unblockable, and the feed wins over the
// allow list.
func TestDecideNoUnblock(t *testing.T) {
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: "webhook.site"}, Unblock{Pattern: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	d := mustDecider(t, DeciderOptions{NoUnblock: true, Unblocks: unblocks, Allow: []string{"x.pastebin.com", "docs.example.org"}})
	if d.UnblocksAllowed() {
		t.Fatal("UnblocksAllowed with NoUnblock")
	}
	checkDecision(t, d, testPrincipal, "webhook.site", 443, decisionWant{category: CategoryWebhookCatcher, source: SourceFeed})
	checkDecision(t, d, testPrincipal, "x.pastebin.com", 443, decisionWant{category: CategoryPasteSite, source: SourceFeed})
	checkDecision(t, d, testPrincipal, "docs.example.org", 443, decisionWant{allowed: true, source: SourceOperator})
	checkDecision(t, d, testPrincipal, publicV4, 443, decisionWant{category: CategoryIPLiteral, source: SourceDefault})
	a := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, NoUnblock: true, Unblocks: unblocks})
	checkDecision(t, a, testPrincipal, "example.com", 443, decisionWant{category: CategoryNotAllowlisted, source: SourceDefault})
	hint := DefaultUnblockHint(testPrincipal, d.Decide(testPrincipal, "webhook.site", 443))
	if strings.Contains(hint, "sandbox unblock") || !strings.Contains(hint, "organization") {
		t.Errorf("hint without unblocking = %q", hint)
	}
	if hint := DefaultUnblockHint(testPrincipal, d.Decide(testPrincipal, publicV4, 443)); strings.Contains(hint, "sandbox unblock") {
		t.Errorf("IP-literal hint without unblocking = %q", hint)
	}
	// Dial time: an allow entry no longer lifts a feed CIDR either.
	withCIDR := mustDecider(t, DeciderOptions{NoUnblock: true, Blocklists: []*Feed{testFeedCIDR(t)}, Allow: []string{"cdn.example", publicV4Alt}})
	dec := withCIDR.Decide(testPrincipal, "cdn.example", 443)
	if !dec.Allowed {
		t.Fatalf("cdn.example = %+v", dec)
	}
	if got := withCIDR.CheckAddrs(testPrincipal, dec, []netip.Addr{netip.MustParseAddr(publicV4Alt)}); got.Allowed || got.Unblockable {
		t.Fatalf("feed CIDR at dial time without unblocking = %+v", got)
	}
}

func TestDecideHostSkipsPorts(t *testing.T) {
	d := mustDecider(t, DeciderOptions{Ports: []int{443}})
	if got := d.DecideHost(testPrincipal, "example.com"); !got.Allowed || got.Port != 0 {
		t.Fatalf("DecideHost = %+v", got)
	}
	if got := d.Decide(testPrincipal, "example.com", 80); got.Allowed || got.Category != CategoryPortNotAllowed {
		t.Fatalf("Decide port 80 = %+v", got)
	}
	for host, want := range map[string]Category{
		"webhook.site": CategoryWebhookCatcher, "localhost": CategoryHostInternal, "10.0.0.1": CategoryPrivateNetwork,
		"intranet": CategoryInvalidDestination, publicV4: CategoryIPLiteral,
	} {
		if got := d.DecideHost(testPrincipal, host); got.Allowed || got.Category != want {
			t.Errorf("DecideHost(%s) = %+v, want %s", host, got, want)
		}
	}
}

// TestCheckAddrs pins the dial-time rules callers apply to what a name
// resolves to before they open a path the proxy does not guard.
func TestCheckAddrs(t *testing.T) {
	d := mustDecider(t, DeciderOptions{
		Blocklists: []*Feed{testFeedCIDR(t)},
		AdminBlock: []string{"8.8.8.0/29"},
		Block:      []string{"1.1.1.0/24"},
		Allow:      []string{"db.partner.example"},
	})
	addrs := func(list ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range list {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	for _, tc := range []struct {
		host   string
		addrs  []netip.Addr
		want   Category
		source Source
	}{
		{"ok.example", addrs("9.9.9.9", "2620:fe::fe"), "", ""},
		{"loop.example", addrs("9.9.9.9", "127.0.0.1"), CategoryHostInternal, SourceGuard},
		{"meta.example", addrs("169.254.169.254"), CategoryHostInternal, SourceGuard},
		{"zoned.example", []netip.Addr{netip.MustParseAddr("fe80::1").WithZone("eth0")}, CategoryHostInternal, SourceGuard},
		{"lan.example", addrs("10.0.0.5"), CategoryPrivateNetwork, SourceGuard},
		{"db.partner.example", addrs("10.0.0.6"), "", ""},
		{"admin.example", addrs("8.8.8.3"), CategoryAdminBlock, SourceAdmin},
		{"op.example", addrs("1.1.1.1"), CategoryOperatorBlock, SourceOperator},
		{"drop.example", addrs(publicV4Alt), CategoryFileDrop, SourceFeed},
	} {
		dec := d.Decide(testPrincipal, tc.host, 443)
		if !dec.Allowed {
			t.Fatalf("Decide(%s) = %+v", tc.host, dec)
		}
		got := d.CheckAddrs(testPrincipal, dec, tc.addrs)
		switch {
		case tc.want == "" && !got.Allowed:
			t.Errorf("CheckAddrs(%s) = %+v, want allowed", tc.host, got)
		case tc.want != "" && (got.Allowed || got.Category != tc.want || got.Source != tc.source || got.Reason == ""):
			t.Errorf("CheckAddrs(%s) = %+v, want %s from %s", tc.host, got, tc.want, tc.source)
		}
	}
	// A refusal is returned as is.
	refused := d.Decide(testPrincipal, "webhook.site", 443)
	if got := d.CheckAddrs(testPrincipal, refused, addrs("9.9.9.9")); got != refused {
		t.Fatalf("CheckAddrs of a refusal = %+v", got)
	}
}

func TestLookupHost(t *testing.T) {
	r := newFakeResolver()
	r.set("cdn.example", []string{"9.9.9.9", "::ffff:8.8.8.8", "2620:fe::fe"})
	r.fail("gone.example", errors.New("no such host"))
	got, err := LookupHost(context.Background(), r, "CDN.Example.")
	if err != nil || len(got) != 3 || got[1] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("LookupHost = %v, %v", got, err)
	}
	if names := r.names(); len(names) != 1 || names[0] != "cdn.example." {
		t.Fatalf("looked up %v, want the fully qualified name", names)
	}
	if got, err := LookupHost(context.Background(), r, "[2001:4860:4860::8888]"); err != nil || len(got) != 1 || got[0] != netip.MustParseAddr(publicV6) {
		t.Fatalf("LookupHost of a literal = %v, %v", got, err)
	}
	if _, err := LookupHost(context.Background(), r, "gone.example"); err == nil {
		t.Fatal("a failed lookup succeeded")
	}
	if _, err := LookupHost(context.Background(), r, "bad host"); err == nil {
		t.Fatal("an invalid host was looked up")
	}
	r.set("empty.example", nil)
	if _, err := LookupHost(context.Background(), r, "empty.example"); !errors.Is(err, ErrNoAddresses) {
		t.Fatalf("empty answer = %v", err)
	}
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
	checkDecision(t, d, testPrincipal, "localhost", 443, decisionWant{category: CategoryHostInternal, source: SourceGuard})
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
