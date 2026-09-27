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

package packs

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// testFeed stands in for the egress proxy's builtin exfiltration feed.
func testFeed(feeds []string, host string) (string, bool) {
	if containsString(feeds, FeedBuiltin) && (host == "webhook.site" || host == "raw.githubusercontent.com" ||
		strings.HasSuffix(host, ".pastebin.com")) {
		return "exfil:" + host, true
	}
	return "", false
}

func withHostname(t *testing.T, name string) {
	t.Helper()
	previous := osHostname
	osHostname = func() (string, error) { return name, nil }
	t.Cleanup(func() { osHostname = previous })
}

func TestAllowActions(t *testing.T) {
	withHostname(t, "DevBox.corp.example")
	// This machine's real addresses would turn some destinations below
	// into host-port requests.
	withInterfaceAddrs(t)
	type outcome struct {
		constraint string // "" allows; "error" is a plain (non-Violation) refusal
		fatal      bool
	}
	allowed := outcome{}
	invalid := outcome{constraint: "error"}
	for _, tc := range []struct {
		name   string
		edit   func(*config.OpenShellConfig)
		flags  Flags
		action Action
		want   outcome
	}{
		{"unblock by default", nil, Flags{}, Action{Kind: ActionUnblock, Host: "webhook.site"}, allowed},
		{"unblock off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionUnblock, Host: "webhook.site"}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"unblock admin-blocked host", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"*.ngrok.io"} }, Flags{},
			Action{Kind: ActionUnblock, Host: "Abc.NGROK.io."}, outcome{constraint: "openshell.admin.egress_block"}},
		{"unblock outside allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			Action{Kind: ActionUnblock, Host: "pypi.org"}, outcome{constraint: "openshell.admin.egress_allow_only"}},
		{"unblock inside allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			Action{Kind: ActionUnblock, Host: "git.corp.example"}, allowed},
		{"unblock under the strict profile", nil, Flags{Profile: "strict"},
			Action{Kind: ActionUnblock, Host: "pypi.org"}, outcome{constraint: "profile strict"}},
		{"unblock under an admin-forced strict profile", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "strict" }, Flags{},
			Action{Kind: ActionUnblock, Host: "pypi.org"}, outcome{constraint: "openshell.admin.min_profile"}},
		{"unblock a glob", nil, Flags{}, Action{Kind: ActionUnblock, Host: "*.example.com"}, invalid},
		{"unblock nothing", nil, Flags{}, Action{Kind: ActionUnblock}, invalid},
		{"unblock a URL", nil, Flags{}, Action{Kind: ActionUnblock, Host: "https://x.example"}, invalid},

		{"approve once", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443, Feed: testFeed}, allowed},
		{"approve once without a feed matcher", nil, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, allowed},
		{"approve once without a feed matcher when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, invalid},
		// Block entries are applied before unblocks, so an approval, which
		// bypasses the proxy, cannot lift them either.
		{"approve a blocklisted host", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"paste.example"} }, Flags{},
			Action{Kind: ActionApprove, Host: "paste.example", Port: 443, Feed: testFeed}, outcome{constraint: "openshell.egress.block"}},
		{"approve a blocklisted host when unblock is off", func(o *config.OpenShellConfig) {
			o.Egress.Block, o.Admin.AllowUnblock = []string{"paste.example"}, boolPtr(false)
		}, Flags{}, Action{Kind: ActionApprove, Host: "Paste.Example.", Port: 443, Feed: testFeed}, outcome{constraint: "openshell.egress.block"}},
		{"unblock a blocklisted host", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"*.paste.example"} }, Flags{},
			Action{Kind: ActionUnblock, Host: "a.paste.example"}, outcome{constraint: "openshell.egress.block"}},
		{"approve a blocklisted address spelled differently", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"93.184.215.14"} }, Flags{},
			Action{Kind: ActionApprove, Host: "[::ffff:5db8:d70e]", Port: 443}, outcome{constraint: "openshell.egress.block"}},

		// Every spelling of an address is that address.
		{"unblock an uncompressed spelling of an admin-blocked address", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock = []string{"2001:db8::7"}
		}, Flags{}, Action{Kind: ActionUnblock, Host: "2001:0DB8:0000:0000:0000:0000:0000:0007"}, outcome{constraint: "openshell.admin.egress_block"}},
		{"approve a mapped spelling of an admin-blocked address", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock = []string{"203.0.113.7"}
		}, Flags{}, Action{Kind: ActionApprove, Host: "::ffff:203.0.113.7", Port: 443}, outcome{constraint: "openshell.admin.egress_block"}},
		{"approve a bracketed spelling of an admin-blocked address", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock = []string{"[2001:db8::7]"}
		}, Flags{}, Action{Kind: ActionApprove, Host: "[2001:db8:0::7]", Port: 443}, outcome{constraint: "openshell.admin.egress_block"}},
		{"approve inside an admin-blocked range", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock = []string{"198.51.100.0/24"}
		}, Flags{}, Action{Kind: ActionApprove, Host: "198.51.100.9", Port: 443}, outcome{constraint: "openshell.admin.egress_block"}},
		{"unblock inside an admin-blocked IPv6 range", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock = []string{"2001:db8:1::/48"}
		}, Flags{}, Action{Kind: ActionUnblock, Host: "2001:db8:1:ffff::1"}, outcome{constraint: "openshell.admin.egress_block"}},
		{"approve outside an admin allow-only range", func(o *config.OpenShellConfig) {
			o.Admin.EgressAllowOnly = []string{"93.184.215.0/24"}
		}, Flags{}, Action{Kind: ActionApprove, Host: "93.184.216.34", Port: 443}, outcome{constraint: "openshell.admin.egress_allow_only"}},
		{"approve inside an admin allow-only range", func(o *config.OpenShellConfig) {
			o.Admin.EgressAllowOnly = []string{"93.184.215.0/24"}
		}, Flags{}, Action{Kind: ActionApprove, Host: "93.184.215.14", Port: 443}, allowed},
		{"approve a range", nil, Flags{}, Action{Kind: ActionApprove, Host: "198.51.100.0/24", Port: 443}, invalid},
		{"unblock a single-address range", nil, Flags{}, Action{Kind: ActionUnblock, Host: "198.51.100.7/32"}, invalid},
		{"approve the Podman host alias", nil, Flags{}, Action{Kind: ActionApprove, Host: "host.containers.internal", Port: OpenShellGatewayPort},
			outcome{constraint: "defenseclaw"}},
		{"approve a feed host", nil, Flags{}, Action{Kind: ActionApprove, Host: "webhook.site", Port: 443, Feed: testFeed}, allowed},
		{"approve a feed host when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "webhook.site", Port: 443, Feed: testFeed}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a feed host with the feed off", func(o *config.OpenShellConfig) { o.Egress.Feed = "none" }, Flags{},
			Action{Kind: ActionApprove, Host: "webhook.site", Port: 443}, allowed},
		{"approve a private address", nil, Flags{}, Action{Kind: ActionApprove, Host: "10.0.0.5", Port: 5432}, allowed},
		{"approve a private address when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "10.0.0.5", Port: 5432, Feed: testFeed}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a CGNAT address when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "100.64.1.2", Port: 443, Feed: testFeed}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve the metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "169.254.169.254", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve a mapped metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "[::ffff:169.254.169.254]", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve the IPv6 metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "fd00:ec2::254", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve the Alibaba metadata address", nil, Flags{}, Action{Kind: ActionApprove, Host: "100.100.100.200", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve a metadata name", nil, Flags{}, Action{Kind: ActionApprove, Host: "Metadata.Google.Internal", Port: 80}, outcome{constraint: "defenseclaw"}},
		{"approve a link-local address", nil, Flags{}, Action{Kind: ActionApprove, Host: "fe80::1", Port: 22}, outcome{constraint: "defenseclaw"}},
		{"approve multicast", nil, Flags{}, Action{Kind: ActionApprove, Host: "224.0.0.251", Port: 5353}, outcome{constraint: "defenseclaw"}},
		{"approve a short IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "127.1", Port: 18970}, invalid},
		{"approve a decimal IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "2130706433", Port: 18970}, invalid},
		{"approve a hex IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "0x7f000001", Port: 18970}, invalid},
		{"approve an octal IPv4 spelling", nil, Flags{}, Action{Kind: ActionApprove, Host: "0177.0.0.1", Port: 18970}, invalid},
		{"unblock a short IPv4 spelling", nil, Flags{}, Action{Kind: ActionUnblock, Host: "10.1"}, invalid},
		{"approve ip6-localhost", nil, Flags{}, Action{Kind: ActionApprove, Host: "ip6-localhost", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve localhost.localdomain", nil, Flags{}, Action{Kind: ActionApprove, Host: "localhost.localdomain", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve the Docker host alias", nil, Flags{}, Action{Kind: ActionApprove, Host: "host.docker.internal", Port: OpenShellGatewayPort}, outcome{constraint: "defenseclaw"}},
		{"approve this machine by name", nil, Flags{}, Action{Kind: ActionApprove, Host: "devbox", Port: 18971}, outcome{constraint: "defenseclaw"}},
		{"approve this machine by mDNS name", nil, Flags{}, Action{Kind: ActionApprove, Host: "devbox.local", Port: 18972}, outcome{constraint: "defenseclaw"}},
		{"approve this machine by full name", nil, Flags{}, Action{Kind: ActionApprove, Host: "devbox.corp.example.", Port: 18972}, outcome{constraint: "defenseclaw"}},
		{"approve a mapped loopback address", nil, Flags{}, Action{Kind: ActionApprove, Host: "::ffff:127.0.0.1", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve another loopback address with host ports off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "127.0.0.2", Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"approve ip6-loopback with host ports off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "ip6-loopback", Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"approve an admin-blocked host", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"api.example.com"} }, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, outcome{constraint: "openshell.admin.egress_block"}},
		{"approve always", nil, Flags{}, Action{Kind: ActionApproveAlways, Host: "api.example.com", Port: 443}, allowed},
		{"approve always off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApproveAlways, Host: "api.example.com"}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve the host alias", nil, Flags{}, Action{Kind: ActionApprove, Host: OpenShellHostAlias, Port: 5432}, allowed},
		{"approve the OpenShell gateway", nil, Flags{},
			Action{Kind: ActionApprove, Host: OpenShellHostAlias, Port: OpenShellGatewayPort}, outcome{constraint: "defenseclaw"}},
		{"approve loopback API", nil, Flags{},
			Action{Kind: ActionApproveAlways, Host: "127.0.0.1", Port: 18970}, outcome{constraint: "defenseclaw"}},
		{"approve localhost without port", nil, Flags{}, Action{Kind: ActionApprove, Host: "localhost"}, invalid},
		{"approve host with host ports off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "[::1]", Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"approve bad port", nil, Flags{}, Action{Kind: ActionApprove, Host: "api.example.com", Port: 70000}, invalid},

		{"host port", nil, Flags{}, Action{Kind: ActionHostPort, Port: 5432}, allowed},
		{"host port reserved", nil, Flags{}, Action{Kind: ActionHostPort, Port: 18972}, outcome{constraint: "defenseclaw"}},
		{"host port admin off", func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, Flags{},
			Action{Kind: ActionHostPort, Port: 5432}, outcome{constraint: "openshell.admin.allow_host_ports"}},
		{"host port strict pack", nil, Flags{Pack: "strict"}, Action{Kind: ActionHostPort, Port: 5432}, outcome{constraint: "pack strict"}},
		{"host port zero", nil, Flags{}, Action{Kind: ActionHostPort}, invalid},

		{"mount", nil, Flags{}, Action{Kind: ActionMount, Path: "/src/app"}, allowed},
		{"mount off", func(o *config.OpenShellConfig) { o.Admin.AllowMount = boolPtr(false) }, Flags{},
			Action{Kind: ActionMount, Path: "/src/app"}, outcome{constraint: "openshell.admin.allow_mount"}},
		{"mount a copy-only project", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-*"} }, Flags{},
			Action{Kind: ActionMount, Path: "/src/customer-a/lib"}, outcome{constraint: "openshell.admin.require_copy_for"}},
		{"mount a parent of a copy-only project", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-acme"} }, Flags{Copy: true},
			Action{Kind: ActionMount, Path: "/src"}, outcome{constraint: "openshell.admin.require_copy_for"}},
		{"mount a copy-only project spelled in another case", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-acme"} }, Flags{Copy: true},
			Action{Kind: ActionMount, Path: "/SRC/Customer-ACME/app"}, outcome{constraint: "openshell.admin.require_copy_for"}},
		{"mount a sibling of a copy-only project", func(o *config.OpenShellConfig) { o.Admin.RequireCopyFor = []string{"/src/customer-acme"} }, Flags{Copy: true},
			Action{Kind: ActionMount, Path: "/src/internal"}, allowed},
		{"mount relative", nil, Flags{}, Action{Kind: ActionMount, Path: "lib"}, invalid},

		{"mount under a required copy-mode pack", func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "strict" }, Flags{},
			Action{Kind: ActionMount, Path: "/src/app"}, outcome{constraint: "openshell.admin.required_pack"}},
		{"mount under a required mount-mode pack", func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "balanced" }, Flags{},
			Action{Kind: ActionMount, Path: "/src/app"}, allowed},
		// A chosen (not required) copy-mode pack is no floor.
		{"mount under a chosen copy-mode pack", nil, Flags{Pack: "strict"}, Action{Kind: ActionMount, Path: "/src/app"}, allowed},

		{"yolo", nil, Flags{}, Action{Kind: ActionYolo}, allowed},
		{"yolo off", func(o *config.OpenShellConfig) { o.Admin.AllowYolo = boolPtr(false) }, Flags{},
			Action{Kind: ActionYolo}, outcome{constraint: "openshell.admin.allow_yolo"}},
		{"yolo under a required pack that keeps the prompts", func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "strict" }, Flags{},
			Action{Kind: ActionYolo}, outcome{constraint: "openshell.admin.required_pack"}},
		{"yolo under a required pack that skips the prompts", func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "open" }, Flags{},
			Action{Kind: ActionYolo}, allowed},
		{"yolo under a chosen pack that keeps the prompts", nil, Flags{Pack: "strict"}, Action{Kind: ActionYolo}, allowed},
		{"learn", nil, Flags{}, Action{Kind: ActionLearnMode}, allowed},
		{"learn off", func(o *config.OpenShellConfig) { o.Admin.AllowLearnMode = boolPtr(false) }, Flags{},
			Action{Kind: ActionLearnMode}, outcome{constraint: "openshell.admin.allow_learn_mode"}},

		{"harness", nil, Flags{}, Action{Kind: ActionHarness, Harness: "codex"}, allowed},
		{"harness refused", func(o *config.OpenShellConfig) { o.Admin.AllowedHarnesses = []string{"codex"} }, Flags{},
			Action{Kind: ActionHarness, Harness: "Claude-Code"}, outcome{constraint: "openshell.admin.allowed_harnesses", fatal: true}},
		{"harness malformed", nil, Flags{}, Action{Kind: ActionHarness, Harness: "a b"}, invalid},

		{"unknown action", nil, Flags{}, Action{Kind: "teleport"}, invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, _ := mustResolve(t, testConfig(tc.edit), tc.flags)
			err := eff.Allow(tc.action)
			var v *Violation
			isViolation := errors.As(err, &v)
			switch {
			case tc.want == allowed:
				if err != nil {
					t.Fatalf("Allow(%+v) = %v, want nil", tc.action, err)
				}
			case tc.want == invalid:
				if err == nil || isViolation {
					t.Fatalf("Allow(%+v) = %v, want a plain error", tc.action, err)
				}
			default:
				if !isViolation || v.Constraint != tc.want.constraint || v.Fatal != tc.want.fatal || v.Source != SourceUser {
					t.Fatalf("Allow(%+v) = %#v, want constraint %q", tc.action, err, tc.want.constraint)
				}
				if v.Admin() && !strings.HasPrefix(v.Message, "blocked by your organization's DefenseClaw policy: ") {
					t.Fatalf("admin message = %q", v.Message)
				}
				if v.Message == "" || v.Detail == "" || v.Attempted == "" && tc.action.Kind != ActionYolo && tc.action.Kind != ActionLearnMode {
					t.Fatalf("violation lacks text: %+v", v)
				}
			}
		})
	}

	var nilEff *Effective
	if err := nilEff.Allow(Action{Kind: ActionYolo}); err == nil {
		t.Fatal("a nil Effective must refuse every action")
	}
}

func TestAllowMessages(t *testing.T) {
	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Admin.EgressBlock = []string{"*.ngrok.io"}
	}), Flags{})
	err := eff.Allow(Action{Kind: ActionUnblock, Host: "x.ngrok.io"})
	want := "blocked by your organization's DefenseClaw policy: egress.unblock (x.ngrok.io matches *.ngrok.io on your organization's blocklist)"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	err = eff.Allow(Action{Kind: ActionHostPort, Port: 17670})
	if err == nil || !strings.HasPrefix(err.Error(), "DefenseClaw never opens the OpenShell gateway (port 17670) to a sandbox") {
		t.Fatalf("error = %v", err)
	}
	strict, _ := mustResolve(t, testConfig(nil), Flags{Profile: "strict"})
	err = strict.Allow(Action{Kind: ActionUnblock, Host: "pypi.org"})
	if err == nil || !strings.HasPrefix(err.Error(), "not allowed by the strict sandbox profile: egress.unblock") {
		t.Fatalf("error = %v", err)
	}
}

func TestDecideEgress(t *testing.T) {
	feed := testFeed
	for _, tc := range []struct {
		name        string
		edit        func(*config.OpenShellConfig)
		flags       Flags
		host        string
		port        int
		allowed     bool
		rule        EgressRule
		match       string
		unblockable bool
	}{
		{"open web", nil, Flags{}, "example.org", 443, true, RuleNetworkOpen, "", false},
		{"feed hit", nil, Flags{}, "WEBHOOK.site.", 443, false, RuleFeed, "exfil:webhook.site", true},
		{"feed off", func(o *config.OpenShellConfig) { o.Egress.Feed = "none" }, Flags{}, "webhook.site", 443, true, RuleNetworkOpen, "", false},
		{"allow exempts from the feed", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"webhook.site"} }, Flags{},
			"webhook.site", 443, true, RuleAllow, "webhook.site", false},
		{"user block", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"*.example.org"} }, Flags{},
			"cdn.example.org", 443, false, RuleBlock, "*.example.org", false},
		{"block beats allow", func(o *config.OpenShellConfig) {
			o.Egress.Block, o.Egress.Allow = []string{"example.org"}, []string{"example.org"}
		}, Flags{}, "example.org", 443, false, RuleBlock, "example.org", false},
		{"apex is not a subdomain", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"*.example.org"} }, Flags{},
			"example.org", 443, true, RuleNetworkOpen, "", false},
		{"port outside the list", nil, Flags{}, "example.org", 22, false, RulePort, "22", false},
		{"port unchecked", nil, Flags{}, "example.org", 0, true, RuleNetworkOpen, "", false},
		{"user ports", func(o *config.OpenShellConfig) { o.Egress.Ports = []int{8443} }, Flags{}, "example.org", 443, false, RulePort, "443", false},
		{"allowlist hit", nil, Flags{Profile: "balanced"}, "example.org", 443, false, RuleNetworkAllowlist, "", true},
		{"allowlist pack entry", nil, Flags{Pack: "balanced"}, "pypi.org", 443, true, RuleAllow, "pypi.org", false},
		{"deny profile", nil, Flags{Profile: "strict"}, "pypi.org", 443, false, RuleNetworkDeny, "", false},
		{"admin block", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock, o.Egress.Allow = []string{"*.ngrok.io"}, []string{"a.ngrok.io"}
		}, Flags{}, "a.ngrok.io", 443, false, RuleAdminBlock, "*.ngrok.io", false},
		{"admin allow-only miss", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			"pypi.org", 443, false, RuleAdminAllowOnly, "", false},
		{"admin allow-only hit", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			"git.corp.example", 443, true, RuleAdminAllowOnly, "*.corp.example", false},
		{"feed inside allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.pastebin.com"} }, Flags{},
			"x.pastebin.com", 443, false, RuleFeed, "exfil:x.pastebin.com", true},
		{"unblock disabled", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			"webhook.site", 443, false, RuleFeed, "exfil:webhook.site", false},
		{"curated allow entry exempts from the feed", nil, Flags{Pack: "balanced"},
			"raw.githubusercontent.com", 443, true, RuleAllow, "*.githubusercontent.com", false},
		{"nothing exempts from the feed when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{Pack: "balanced"},
			"raw.githubusercontent.com", 443, false, RuleFeed, "exfil:raw.githubusercontent.com", false},
		{"raised profile uses the curated allowlist", nil, Flags{Profile: "balanced"},
			"registry.npmjs.org", 443, true, RuleAllow, "registry.npmjs.org", false},
		{"admin floor uses the curated allowlist", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" }, Flags{},
			"pypi.org", 443, true, RuleAllow, "pypi.org", false},
		{"user allow-everything is ignored", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"*", "*.com"} }, Flags{Profile: "balanced"},
			"example.com", 443, false, RuleNetworkAllowlist, "", true},
		// The reported bypass: an admin balanced floor, no unblocking, and a
		// user allow-everything entry.
		{"floor with a user allow-everything entry", func(o *config.OpenShellConfig) {
			o.Egress.Allow, o.Admin.MinProfile, o.Admin.AllowUnblock = []string{"*"}, "balanced", boolPtr(false)
		}, Flags{}, "webhook.site", 443, false, RuleFeed, "exfil:webhook.site", false},
		{"ip literal", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"2001:db8::1"} }, Flags{},
			"[2001:db8::1]", 443, false, RuleBlock, "2001:db8::1", false},
		{"admin block in another spelling", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"2001:db8::7"} }, Flags{},
			"[2001:DB8:0:0::7]", 443, false, RuleAdminBlock, "2001:db8::7", false},
		{"admin block of a mapped address", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"::ffff:203.0.113.7"} }, Flags{},
			"203.0.113.7", 443, false, RuleAdminBlock, "203.0.113.7", false},
		{"admin block range", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"198.51.100.0/24"} }, Flags{},
			"198.51.100.200", 443, false, RuleAdminBlock, "198.51.100.0/24", false},
		{"admin block range misses", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"198.51.100.0/24"} }, Flags{},
			"198.51.101.1", 443, true, RuleNetworkOpen, "", false},
		{"user block range", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"2001:db8:1::/48"} }, Flags{},
			"2001:db8:1::99", 443, false, RuleBlock, "2001:db8:1::/48", false},
		{"allow range", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"198.51.100.0/24"} }, Flags{Profile: "balanced"},
			"198.51.100.9", 443, true, RuleAllow, "198.51.100.0/24", false},
		{"range host", nil, Flags{}, "198.51.100.0/24", 443, false, RuleInvalid, "", false},
		{"empty host", nil, Flags{}, "", 443, false, RuleInvalid, "", false},
		{"wildcard host", nil, Flags{}, "*.example.org", 443, false, RuleInvalid, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, _ := mustResolve(t, testConfig(tc.edit), tc.flags)
			got := eff.DecideEgress(tc.host, tc.port, feed)
			want := EgressDecision{Allowed: tc.allowed, Rule: tc.rule, Match: tc.match, Unblockable: tc.unblockable}
			if got != want {
				t.Fatalf("DecideEgress(%q, %d) = %+v, want %+v", tc.host, tc.port, got, want)
			}
		})
	}

	eff, _ := mustResolve(t, testConfig(nil), Flags{})
	if got := eff.DecideEgress("webhook.site", 443, nil); !got.Allowed {
		t.Fatalf("without a feed matcher the feed step is skipped: %+v", got)
	}
	var nilEff *Effective
	if got := nilEff.DecideEgress("example.org", 443, feed); got.Allowed {
		t.Fatal("a nil Effective must refuse egress")
	}
}

func TestMatchHost(t *testing.T) {
	for _, tc := range []struct {
		glob, host string
		want       bool
	}{
		{"*", "anything.example", true},
		{"example.com", "example.com", true},
		{"example.com", "EXAMPLE.com.", true},
		{"example.com", "www.example.com", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"203.0.113.7", "203.0.113.7", true},
		{"", "example.com", false},
		{"example.com", "", false},
		// Addresses match by value, whatever their spelling.
		{"2001:db8::7", "2001:0DB8:0000:0000:0000:0000:0000:0007", true},
		{"2001:db8::7", "[2001:db8:0::7]", true},
		{"203.0.113.7", "::ffff:203.0.113.7", true},
		{"::ffff:203.0.113.7", "203.0.113.7", true},
		{"203.0.113.7", "[::ffff:cb00:7107]", true},
		{"198.51.100.0/24", "198.51.100.77", true},
		{"198.51.100.0/24", "::ffff:198.51.100.77", true},
		{"198.51.100.0/24", "198.51.101.77", false},
		{"2001:db8::/32", "2001:db8:ffff::1", true},
		// Names and addresses never match each other.
		{"198.51.100.0/24", "198.51.100.77.nip.example", false},
		{"*.example.com", "203.0.113.7", false},
		// "*" (no longer valid in lists) still matches everything; other
		// malformed patterns match nothing.
		{"*.203.0.113.7", "a.203.0.113.7", false},
		{"a.*.example", "a.b.example", false},
	} {
		if got := MatchHost(tc.glob, tc.host); got != tc.want {
			t.Errorf("MatchHost(%q, %q) = %v, want %v", tc.glob, tc.host, got, tc.want)
		}
	}
	if !MatchAnyHost([]string{"a.example", "*.b.example"}, "x.b.example") || MatchAnyHost(nil, "x") {
		t.Fatal("MatchAnyHost")
	}
}

func withInterfaceAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	var list []net.Addr
	for _, a := range addrs {
		ip, network, err := net.ParseCIDR(a)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, &net.IPNet{IP: ip, Mask: network.Mask})
	}
	previous := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) { return list, nil }
	t.Cleanup(func() { interfaceAddrs = previous })
}

// TestApproveThisMachinesAddresses: an approval for one of this machine's
// interface addresses is a host-port request, so DefenseClaw's own
// listeners stay closed and the host-port constraints apply.
func TestApproveThisMachinesAddresses(t *testing.T) {
	withInterfaceAddrs(t, "172.17.0.1/16", "192.168.1.20/24", "fd12:3456:789a::20/64", "93.184.215.14/24", "fe80::1/64")
	eff, _ := mustResolve(t, testConfig(nil), Flags{})
	for _, tc := range []struct {
		host       string
		port       int
		constraint string // "" allows
	}{
		{"172.17.0.1", 18970, "defenseclaw"},
		{"192.168.1.20", OpenShellGatewayPort, "defenseclaw"},
		{"::ffff:192.168.1.20", 18971, "defenseclaw"},
		{"93.184.215.14", 18972, "defenseclaw"},
		{"172.17.0.1", 5432, ""},
		// Other hosts on the same networks are not this machine.
		{"172.17.0.2", 18970, ""},
		{"192.168.1.21", 18970, ""},
		// A link-local interface address is never approved at all.
		{"fe80::1", 5432, "defenseclaw"},
	} {
		err := eff.Allow(Action{Kind: ActionApprove, Host: tc.host, Port: tc.port})
		var v *Violation
		switch {
		case tc.constraint == "" && err != nil:
			t.Errorf("approve %s:%d = %v, want nil", tc.host, tc.port, err)
		case tc.constraint != "" && (!errors.As(err, &v) || v.Constraint != tc.constraint):
			t.Errorf("approve %s:%d = %v, want constraint %q", tc.host, tc.port, err, tc.constraint)
		}
	}
	// The host-port switches apply to this machine's addresses too.
	off, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }), Flags{})
	var v *Violation
	if err := off.Allow(Action{Kind: ActionApprove, Host: "192.168.1.20", Port: 5432}); !errors.As(err, &v) ||
		v.Constraint != "openshell.admin.allow_host_ports" {
		t.Fatalf("approve with host ports off = %v", err)
	}
	strict, _ := mustResolve(t, testConfig(nil), Flags{Pack: "strict", Profile: "open"})
	if err := strict.Allow(Action{Kind: ActionApprove, Host: "fd12:3456:789a::20", Port: 5432}); !errors.As(err, &v) ||
		v.Constraint != "pack strict" {
		t.Fatalf("approve under a pack without host ports = %v", err)
	}
	if err := eff.Allow(Action{Kind: ActionApprove, Host: "172.17.0.1"}); err == nil || errors.As(err, &v) {
		t.Fatalf("approving this machine without a port = %v, want a plain error", err)
	}
}

// TestBlockListIsNotUnblockable: the pack's and the user's block entries are
// applied by the egress proxy before unblocks, so the policy reports them as
// not unblockable and refuses unblocks and approvals for them.
func TestBlockListIsNotUnblockable(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "team", strings.Replace(customPack("team"), "network: {mode: open}",
		"network: {mode: open}\negress: {block: ['*.paste.example']}", 1))
	eff, _ := mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.PackDir, o.Egress.Block = "team", root, []string{"drop.example"}
	}), Flags{})
	for _, tc := range []struct {
		host, constraint, message string
	}{
		{"a.paste.example", "pack team", "not allowed by the team sandbox pack: "},
		{"drop.example", "openshell.egress.block", "blocked by your own openshell.egress.block list: "},
	} {
		if d := eff.DecideEgress(tc.host, 443, testFeed); d.Allowed || d.Rule != RuleBlock || d.Unblockable {
			t.Fatalf("DecideEgress(%s) = %+v", tc.host, d)
		}
		for _, kind := range []ActionKind{ActionUnblock, ActionApprove, ActionApproveAlways} {
			err := eff.Allow(Action{Kind: kind, Host: tc.host, Port: 443})
			var v *Violation
			if !errors.As(err, &v) || v.Constraint != tc.constraint || !strings.HasPrefix(v.Message, tc.message) ||
				v.Admin() || !strings.Contains(v.Detail, tc.host) {
				t.Fatalf("Allow(%s %s) = %#v", kind, tc.host, err)
			}
		}
	}
	// Feed entries stay unblockable.
	if d := eff.DecideEgress("webhook.site", 443, testFeed); d.Rule != RuleFeed || !d.Unblockable {
		t.Fatalf("feed decision %+v", d)
	}
	if err := eff.Allow(Action{Kind: ActionUnblock, Host: "webhook.site"}); err != nil {
		t.Fatalf("unblocking a feed entry: %v", err)
	}
}
