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
	"net/netip"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

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
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, allowed},
		{"approve once with unblock on", nil, Flags{},
			Action{Kind: ActionApprove, Host: "api.example.com", Port: 443}, allowed},
		// The policy checks against the proxy's own feed; no matcher to pass.
		{"approve a feed subdomain when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "x.pastebin.com", Port: 443}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve an allowed feed host when unblock is off", func(o *config.OpenShellConfig) {
			o.Admin.AllowUnblock, o.Admin.EgressAllowOnly = boolPtr(false), []string{"webhook.site"}
		}, Flags{}, Action{Kind: ActionApprove, Host: "webhook.site", Port: 443}, outcome{constraint: "openshell.admin.allow_unblock"}},
		// The proxy's guard: other names of this machine, intranet names.
		{"approve a localdomain name", nil, Flags{}, Action{Kind: ActionApprove, Host: "build.localdomain", Port: 443},
			outcome{constraint: "defenseclaw"}},
		{"approve an OpenShell-internal name", nil, Flags{}, Action{Kind: ActionApprove, Host: "gateway.openshell.internal", Port: 443},
			outcome{constraint: "defenseclaw"}},
		{"approve an intranet name", nil, Flags{}, Action{Kind: ActionApprove, Host: "jira.corp", Port: 443}, allowed},
		{"approve an intranet name when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "jira.corp", Port: 443}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a single-label name", nil, Flags{}, Action{Kind: ActionApprove, Host: "intranet", Port: 443}, invalid},
		{"unblock a private address", nil, Flags{}, Action{Kind: ActionUnblock, Host: "10.1.2.3"}, outcome{constraint: "defenseclaw"}},
		{"unblock an intranet name", nil, Flags{}, Action{Kind: ActionUnblock, Host: "wiki.internal"}, outcome{constraint: "defenseclaw"}},
		{"unblock this machine", nil, Flags{}, Action{Kind: ActionUnblock, Host: "localhost"}, outcome{constraint: "defenseclaw"}},
		{"unblock the metadata address", nil, Flags{}, Action{Kind: ActionUnblock, Host: "169.254.169.254"}, outcome{constraint: "defenseclaw"}},
		{"unblock a single-label name", nil, Flags{}, Action{Kind: ActionUnblock, Host: "intranet"}, invalid},
		{"unblock a public IP literal", nil, Flags{}, Action{Kind: ActionUnblock, Host: "93.184.216.34"}, allowed},
		{"unblock a host the policy allows", nil, Flags{}, Action{Kind: ActionUnblock, Host: "example.org"}, allowed},
		// Block entries are applied before unblocks, so an approval, which
		// bypasses the proxy, cannot lift them either.
		{"approve a blocklisted host", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"paste.example"} }, Flags{},
			Action{Kind: ActionApprove, Host: "paste.example", Port: 443}, outcome{constraint: "openshell.egress.block"}},
		{"approve a blocklisted host when unblock is off", func(o *config.OpenShellConfig) {
			o.Egress.Block, o.Admin.AllowUnblock = []string{"paste.example"}, boolPtr(false)
		}, Flags{}, Action{Kind: ActionApprove, Host: "Paste.Example.", Port: 443}, outcome{constraint: "openshell.egress.block"}},
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
		{"approve a feed host", nil, Flags{}, Action{Kind: ActionApprove, Host: "webhook.site", Port: 443}, allowed},
		{"approve a feed host when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "webhook.site", Port: 443}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a feed host with the feed off", func(o *config.OpenShellConfig) { o.Egress.Feed = "none" }, Flags{},
			Action{Kind: ActionApprove, Host: "webhook.site", Port: 443}, allowed},
		{"approve a private address", nil, Flags{}, Action{Kind: ActionApprove, Host: "10.0.0.5", Port: 5432}, allowed},
		{"approve a private address when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "10.0.0.5", Port: 5432}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve a CGNAT address when unblock is off", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "100.64.1.2", Port: 443}, outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve public allowed_ips", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"93.184.216.0/24"}}, allowed},
		{"approve private allowed_ips", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"10.0.0.0/8"}}, allowed},
		{"approve private allowed_ips without unblock", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"8.0.0.0/5"}},
			outcome{constraint: "openshell.admin.allow_unblock"}},
		{"approve metadata allowed_ips", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"169.254.0.0/16"}}, outcome{constraint: "defenseclaw"}},
		{"approve loopback-holding allowed_ips", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"64.0.0.0/2"}}, outcome{constraint: "defenseclaw"}},
		{"approve malformed allowed_ips", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"10.0.0.0/33"}}, invalid},
		// allowed_ips are held to the proxy guard's view of this machine
		// (see hostaddrs_test.go): its own addresses are never opened, the
		// rest of its public subnets are its local network.
		{"approve allowed_ips of this machine", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{testOwnV4}}, outcome{constraint: "defenseclaw"}},
		{"approve allowed_ips holding this machine", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"185.199.0.0/16"}}, outcome{constraint: "defenseclaw"}},
		{"approve allowed_ips holding this machine's IPv6 address", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"2a00:1450::/32"}}, outcome{constraint: "defenseclaw"}},
		{"approve allowed_ips on this machine's subnet", nil, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"185.199.9.128/25"}}, allowed},
		{"approve allowed_ips on this machine's subnet without unblock", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			Action{Kind: ActionApprove, Host: "cdn.example.com", Port: 443, AllowedIPs: []string{"2a00:1450:9::1"}},
			outcome{constraint: "openshell.admin.allow_unblock"}},
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
		{"feed hit", nil, Flags{}, "WEBHOOK.site.", 443, false, RuleFeed, "Webhook.site", true},
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
		{"deny profile feed host", nil, Flags{Profile: "strict"}, "webhook.site", 443, false, RuleNetworkDeny, "", false},
		{"admin block", func(o *config.OpenShellConfig) {
			o.Admin.EgressBlock, o.Egress.Allow = []string{"*.ngrok.io"}, []string{"a.ngrok.io"}
		}, Flags{}, "a.ngrok.io", 443, false, RuleAdminBlock, "*.ngrok.io", false},
		{"admin allow-only miss", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			"pypi.org", 443, false, RuleAdminAllowOnly, "", false},
		{"admin allow-only hit", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} }, Flags{},
			"git.corp.example", 443, true, RuleAdminAllowOnly, "*.corp.example", false},
		{"feed inside allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.pastebin.com"} }, Flags{},
			"x.pastebin.com", 443, false, RuleFeed, "Pastebin", true},
		{"unblock disabled", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			"webhook.site", 443, false, RuleFeed, "Webhook.site", false},
		{"required pack allow entry exempts from the feed", func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "feedteam" }, Flags{},
			"x.pastebin.com", 443, true, RuleAllow, "x.pastebin.com", false},
		{"nothing exempts from the feed when unblock is off", func(o *config.OpenShellConfig) {
			o.Admin.RequiredPack, o.Admin.AllowUnblock = "feedteam", boolPtr(false)
		}, Flags{}, "x.pastebin.com", 443, false, RuleFeed, "Pastebin", false},
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
		}, Flags{}, "webhook.site", 443, false, RuleFeed, "Webhook.site", false},
		// The proxy's guard and IP-literal rule are part of the verdict.
		{"open mode IP literal", nil, Flags{}, "93.184.216.34", 443, false, RuleIPLiteral, "", true},
		{"open mode IP literal without unblocks", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, Flags{},
			"93.184.216.34", 443, false, RuleIPLiteral, "", false},
		{"private address", nil, Flags{}, "10.1.2.3", 443, false, RulePrivateNetwork, "", false},
		{"intranet name", nil, Flags{}, "wiki.corp", 443, false, RulePrivateNetwork, "", false},
		{"intranet name the user allowed", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"wiki.corp"} }, Flags{},
			"wiki.corp", 443, true, RuleAllow, "wiki.corp", false},
		{"this machine", nil, Flags{}, "localhost", 443, false, RuleHostInternal, "", false},
		{"metadata", nil, Flags{}, "169.254.169.254", 80, false, RuleHostInternal, "", false},
		{"documentation range is reserved", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"198.51.100.0/24"} }, Flags{},
			"198.51.100.9", 443, false, RuleHostInternal, "", false},
		{"ip literal block", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"2606:4700::1111"} }, Flags{},
			"[2606:4700::1111]", 443, false, RuleBlock, "2606:4700::1111", false},
		{"admin block in another spelling", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"2606:4700::7"} }, Flags{},
			"[2606:4700:0:0::7]", 443, false, RuleAdminBlock, "2606:4700::7", false},
		{"admin block of a mapped address", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"::ffff:93.184.216.34"} }, Flags{},
			"93.184.216.34", 443, false, RuleAdminBlock, "93.184.216.34", false},
		{"admin block range", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"93.184.216.0/24"} }, Flags{},
			"93.184.216.200", 443, false, RuleAdminBlock, "93.184.216.0/24", false},
		{"admin block range misses", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"93.184.216.0/24"} }, Flags{},
			"93.184.217.1", 443, false, RuleIPLiteral, "", true},
		{"user block range", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"2606:4700:1::/48"} }, Flags{},
			"2606:4700:1::99", 443, false, RuleBlock, "2606:4700:1::/48", false},
		{"allow range", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"93.184.216.0/24"} }, Flags{Profile: "balanced"},
			"93.184.216.9", 443, true, RuleAllow, "93.184.216.0/24", false},
		{"range host", nil, Flags{}, "93.184.216.0/24", 443, false, RuleInvalid, "", false},
		{"empty host", nil, Flags{}, "", 443, false, RuleInvalid, "", false},
		{"wildcard host", nil, Flags{}, "*.example.org", 443, false, RuleInvalid, "", false},
		{"single-label host", nil, Flags{}, "intranet", 443, false, RuleInvalid, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(tc.edit)
			if cfg.OpenShell.Admin.RequiredPack == "feedteam" {
				root := t.TempDir()
				writePack(t, root, "feedteam", strings.Replace(customPack("feedteam"), "network: {mode: open}",
					"network: {mode: open}\negress: {allow: [x.pastebin.com]}", 1))
				cfg.OpenShell.PackDir = root
			}
			eff, _ := mustResolve(t, cfg, tc.flags)
			got := eff.DecideEgress(tc.host, tc.port)
			if got.Allowed != tc.allowed || got.Rule != tc.rule || got.Match != tc.match || got.Unblockable != tc.unblockable {
				t.Fatalf("DecideEgress(%q, %d) = %+v, want allowed=%v rule=%s match=%q unblockable=%v",
					tc.host, tc.port, got, tc.allowed, tc.rule, tc.match, tc.unblockable)
			}
			if !got.Allowed && got.Reason == "" {
				t.Fatalf("DecideEgress(%q, %d) refused without a reason", tc.host, tc.port)
			}
		})
	}

	var nilEff *Effective
	if got := nilEff.DecideEgress("example.org", 443); got.Allowed {
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
		if d := eff.DecideEgress(tc.host, 443); d.Allowed || d.Rule != RuleBlock || d.Unblockable {
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
	if d := eff.DecideEgress("webhook.site", 443); d.Rule != RuleFeed || !d.Unblockable {
		t.Fatalf("feed decision %+v", d)
	}
	if err := eff.Allow(Action{Kind: ActionUnblock, Host: "webhook.site"}); err != nil {
		t.Fatalf("unblocking a feed entry: %v", err)
	}
}

func TestClassifyAllowedIP(t *testing.T) {
	for entry, want := range map[string]AllowedIPClass{
		"93.184.216.34":          AllowedIPPublic,
		"93.184.216.0/24":        AllowedIPPublic,
		"2606:2800:220:1::/64":   AllowedIPPublic,
		"10.0.5.20":              AllowedIPPrivate,
		"172.20.0.0/16":          AllowedIPPrivate,
		"8.0.0.0/5":              AllowedIPPrivate,
		"100.64.0.0/12":          AllowedIPPrivate,
		"fd12:3456::/32":         AllowedIPPrivate,
		"::ffff:10.1.0.0/112":    AllowedIPPrivate,
		"127.0.0.1":              AllowedIPNever,
		"169.254.169.254/32":     AllowedIPNever,
		"100.64.0.0/10":          AllowedIPNever,
		"0.0.0.0/0":              AllowedIPNever,
		"128.0.0.0/1":            AllowedIPNever,
		"::/0":                   AllowedIPNever,
		"::1":                    AllowedIPNever,
		"fe80::/10":              AllowedIPNever,
		"64:ff9b::a00:1":         AllowedIPNever,
		"2002::/16":              AllowedIPNever,
		"::ffff:0:0/95":          AllowedIPNever,
		"::ffff:169.254.0.0/112": AllowedIPNever,
		"168.63.129.16":          AllowedIPNever,
		"168.63.0.0/16":          AllowedIPNever,
		"fd20:ce::254":           AllowedIPNever,
		"fd20::/16":              AllowedIPNever,
		"fec0::/10":              AllowedIPNever,
	} {
		_, got, err := ClassifyAllowedIP(entry)
		if err != nil || got != want {
			t.Errorf("ClassifyAllowedIP(%q) = %v, %v; want %v", entry, got, err, want)
		}
	}
	for _, bad := range []string{"", "example.com", "10.0.0.0/33", "fe80::1%eth0"} {
		if _, _, err := ClassifyAllowedIP(bad); err == nil {
			t.Errorf("ClassifyAllowedIP(%q) accepted", bad)
		}
	}
}

// TestCuratedAllowlistOpensNoPrivateNetwork pins that DefenseClaw's curated
// allowlist admits its names without opening the private addresses they
// might resolve to, which only an operator's own allow entry for the name
// does: nobody wrote an entry for registry.npmjs.org, so a private answer for
// it is refused at dial time (and a direct rule for it asks).
func TestCuratedAllowlistOpensNoPrivateNetwork(t *testing.T) {
	withInterfaceAddrs(t)
	private := []netip.Addr{netip.MustParseAddr("10.0.0.9")}
	public := []netip.Addr{netip.MustParseAddr("104.16.0.1")}
	for _, tc := range []struct {
		name        string
		edit        func(*config.OpenShellConfig)
		flags       Flags
		host        string
		opens       bool
		wantAllowed bool
	}{
		{"balanced pack", nil, Flags{Pack: "balanced"}, "registry.npmjs.org", false, true},
		{"balanced profile over the open pack", nil, Flags{Profile: "balanced"}, "pypi.org", false, true},
		{"administrator's balanced floor", func(o *config.OpenShellConfig) { o.Admin.MinProfile = "balanced" }, Flags{}, "github.com", false, true},
		{"required balanced pack", func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "balanced" }, Flags{}, "crates.io", false, true},
		{"the user's own entry for a curated name", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"registry.npmjs.org"} },
			Flags{Pack: "balanced"}, "registry.npmjs.org", true, true},
		{"the user's own entry", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"db.corp-tools.example"} },
			Flags{Pack: "balanced"}, "db.corp-tools.example", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, _ := mustResolve(t, testConfig(tc.edit), tc.flags)
			d, err := eff.EgressDecider(nil)
			if err != nil {
				t.Fatal(err)
			}
			dec := d.Decide(policyProbe, tc.host, 443)
			if dec.Allowed != tc.wantAllowed {
				t.Fatalf("Decide(%s) = %+v", tc.host, dec)
			}
			if got := d.CheckAddrs(policyProbe, dec, public); !got.Allowed {
				t.Fatalf("a public answer for %s = %+v", tc.host, got)
			}
			got := d.CheckAddrs(policyProbe, dec, private)
			if got.Allowed != tc.opens || (!tc.opens && got.Category != egress.CategoryPrivateNetwork) {
				t.Fatalf("a private answer for %s = %+v, want opened %v", tc.host, got, tc.opens)
			}
			if !strings.Contains(listValue(eff.Egress.Allow), tc.host) {
				t.Fatalf("egress.allow = %v, want it to show %s", eff.Egress.Allow, tc.host)
			}
		})
	}
}

// TestNeverOpenPrefixesAreGuarded pins that what triage never approves in
// allowed_ips is what the egress proxy's guard refuses outright: the first
// and last address of every never-open range resolve to a host-internal
// refusal at dial time, and every range the guard alone adds to netguard's
// is never opened.
func TestNeverOpenPrefixesAreGuarded(t *testing.T) {
	withInterfaceAddrs(t)
	eff, _ := mustResolve(t, testConfig(nil), Flags{})
	d, err := eff.EgressDecider(nil)
	if err != nil {
		t.Fatal(err)
	}
	probe := egress.Decision{Allowed: true, Host: "probe.example.com", Source: egress.SourceDefault}
	for _, prefix := range neverOpenPrefixes {
		for _, addr := range []netip.Addr{prefix.Masked().Addr(), lastAddr(prefix)} {
			if got := d.CheckAddrs(policyProbe, probe, []netip.Addr{addr}); got.Category != egress.CategoryHostInternal {
				t.Errorf("%s (in never-open %s) at dial time = %+v, want a host-internal refusal", addr, prefix, got)
			}
		}
	}
	for _, prefix := range egress.NeverReachPrefixes() {
		if _, class, err := ClassifyAllowedIP(prefix.String()); err != nil || class != AllowedIPNever {
			t.Errorf("ClassifyAllowedIP(%s) = %v, %v; want never", prefix, class, err)
		}
	}
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Masked().Addr().AsSlice()
	for i := prefix.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}
