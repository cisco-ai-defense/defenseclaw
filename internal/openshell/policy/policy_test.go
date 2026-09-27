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

package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"gopkg.in/yaml.v3"
)

func baseInput(profile Profile, harness string) Input {
	return Input{
		Profile:     profile,
		Harness:     harness,
		Workdir:     "/work/myapp",
		WorkdirMode: WorkdirMount,
		RunAsUser:   "1000",
		RunAsGroup:  "1000",
		IngressPort: 18971,
		EgressPort:  18972,
	}
}

// goldenCases is the profile x harness matrix plus the copy-mode, context
// mount and extra-rule shapes.
func goldenCases() map[string]Input {
	cases := map[string]Input{}
	for _, profile := range []Profile{ProfileOpen, ProfileBalanced, ProfileStrict} {
		for _, harness := range []string{"claudecode", "codex"} {
			in := baseInput(profile, harness)
			if harness == "claudecode" {
				in.HarnessReadOnly = []string{"/opt/defenseclaw-harness/claudecode"}
			}
			cases[string(profile)+"-"+harness] = in
		}
	}
	copyMode := baseInput(ProfileOpen, "codex")
	copyMode.WorkdirMode = WorkdirCopy
	copyMode.Workdir = "/sandbox/work/myapp"
	copyMode.RunAsUser, copyMode.RunAsGroup = "sandbox", "sandbox"
	cases["open-codex-copy"] = copyMode

	context := baseInput(ProfileBalanced, "claudecode")
	context.Mounts = []Mount{
		{Target: "/work/myapp/.git/hooks", ReadOnly: true},
		{Target: "/work/myapp/.env", ReadOnly: true},
		{Target: "/context/lib", ReadOnly: true},
		{Target: "/context/scratch", ReadOnly: false},
	}
	cases["balanced-claudecode-context"] = context

	hostPort := baseInput(ProfileStrict, "codex")
	hostPort.HostPorts = []int{5432}
	hostPort.ExtraRules = map[string]v1.NetworkPolicyRule{
		"host_port_5432": {
			Endpoints: []v1.PolicyNetworkEndpoint{{Host: "host.openshell.internal", Port: 5432, Protocol: "tcp", TLS: v1.NetworkTLSModeSkip}},
			Binaries:  []v1.PolicyNetworkBinary{{Path: "/**"}},
		},
		"docs_python": {
			Endpoints: []v1.PolicyNetworkEndpoint{{Host: "docs.python.org", Port: 443, Protocol: "rest", Access: v1.NetworkAccessPresetReadOnly, Enforcement: v1.NetworkEnforcementModeEnforce}},
			Binaries:  []v1.PolicyNetworkBinary{{Path: "/usr/bin/curl"}},
		},
	}
	cases["strict-codex-extra-rules"] = hostPort
	return cases
}

func TestRenderGolden(t *testing.T) {
	update := os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1"
	for name, in := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			p, err := Render(in)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			out, err := MarshalYAML(p)
			if err != nil {
				t.Fatalf("MarshalYAML: %v", err)
			}
			golden := filepath.Join("testdata", name+".yaml")
			if update {
				if err := os.WriteFile(golden, out, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
			}
			if !bytes.Equal(want, out) {
				t.Fatalf("%s drifted:\n%s", golden, out)
			}
			// The YAML is unknown-field free: strict parsing restores the
			// exact typed policy.
			back, err := ParseYAML(out)
			if err != nil {
				t.Fatalf("ParseYAML: %v", err)
			}
			if !reflect.DeepEqual(back, p) {
				t.Fatalf("round trip changed the policy:\n got %#v\nwant %#v", back, p)
			}
		})
	}
}

// acceptedKeys are the policy-file keys OpenShell 0.1.1 loaded in the
// harness spike (hs-policy-*.yaml and spike4.yaml). The built-in profiles may
// only emit these.
var acceptedKeys = map[string]bool{
	"version": true, "filesystem_policy": true, "landlock": true, "process": true, "network_policies": true,
	"include_workdir": true, "read_only": true, "read_write": true, "compatibility": true,
	"run_as_user": true, "run_as_group": true, "endpoints": true, "binaries": true,
	"host": true, "port": true, "protocol": true, "tls": true, "access": true, "enforcement": true, "path": true,
}

func collectKeys(t *testing.T, node *yaml.Node, underRules bool, keys map[string]bool) {
	t.Helper()
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			collectKeys(t, child, false, keys)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if !underRules {
				keys[key] = true
			}
			collectKeys(t, node.Content[i+1], key == "network_policies", keys)
		}
	}
}

func TestBuiltInProfilesEmitOnlyAcceptedKeys(t *testing.T) {
	for name, in := range goldenCases() {
		if len(in.ExtraRules) > 0 {
			continue
		}
		p, err := Render(in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := MarshalYAML(p)
		if err != nil {
			t.Fatal(err)
		}
		var node yaml.Node
		if err := yaml.Unmarshal(out, &node); err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		collectKeys(t, &node, false, keys)
		for key := range keys {
			if !acceptedKeys[key] {
				t.Errorf("%s: key %q was never validated against OpenShell", name, key)
			}
		}
	}
}

func TestRenderProfileNetworkRules(t *testing.T) {
	for _, tc := range []struct {
		profile  Profile
		wantRule bool
		mode     EgressMode
	}{
		{ProfileOpen, true, EgressAllowByDefault},
		{ProfileBalanced, true, EgressAllowlist},
		{ProfileStrict, false, EgressOff},
	} {
		p, err := Render(baseInput(tc.profile, "claudecode"))
		if err != nil {
			t.Fatal(err)
		}
		rule, ok := p.NetworkPolicies[EgressRuleName]
		if ok != tc.wantRule {
			t.Fatalf("%s: egress rule present = %t", tc.profile, ok)
		}
		if ok {
			ep := rule.Endpoints[0]
			if ep.Host != EgressHost || ep.Port != 18972 || ep.Protocol != "tcp" || ep.TLS != v1.NetworkTLSModeSkip || rule.Binaries[0].Path != AnyBinary {
				t.Fatalf("%s: egress rule = %#v", tc.profile, rule)
			}
		}
		if len(p.NetworkPolicies) != map[bool]int{true: 1, false: 0}[tc.wantRule] {
			t.Fatalf("%s: unexpected rules %v", tc.profile, p.NetworkPolicies)
		}
		if EgressModeFor(tc.profile) != tc.mode {
			t.Fatalf("%s: egress mode = %s", tc.profile, EgressModeFor(tc.profile))
		}
	}
}

func TestRenderFilesystem(t *testing.T) {
	p, err := Render(goldenCases()["balanced-claudecode-context"])
	if err != nil {
		t.Fatal(err)
	}
	rw := p.Filesystem.ReadWrite
	ro := p.Filesystem.ReadOnly
	for _, want := range []string{"/work/myapp", "/tmp", "/dev/null", "/dev/ptmx", "/dev/pts", "/dev/tty", "/sandbox", "/context/scratch"} {
		if !contains(rw, want) {
			t.Errorf("read_write missing %s: %v", want, rw)
		}
	}
	for _, want := range []string{"/usr", "/etc", "/proc", "/opt", "/context/lib"} {
		if !contains(ro, want) {
			t.Errorf("read_only missing %s: %v", want, ro)
		}
	}
	// Nested grants collapse into their parent.
	harness := mustRender(t, goldenCases()["open-claudecode"])
	if contains(harness.Filesystem.ReadOnly, "/opt/defenseclaw-harness/claudecode") || !contains(harness.Filesystem.ReadOnly, "/opt") {
		t.Errorf("harness root under /opt did not collapse: %v", harness.Filesystem.ReadOnly)
	}
	outside := baseInput(ProfileOpen, "claudecode")
	outside.HarnessReadOnly = []string{"/nix/store/claude", "/nix/store/claude/bin"}
	if got := mustRender(t, outside).Filesystem.ReadOnly; !contains(got, "/nix/store/claude") || contains(got, "/nix/store/claude/bin") {
		t.Errorf("harness roots outside the base = %v", got)
	}
	for _, inside := range []string{"/work/myapp/.git/hooks", "/work/myapp/.env"} {
		if contains(ro, inside) || contains(rw, inside) {
			t.Errorf("%s is under the workdir and must be enforced by its mount only", inside)
		}
	}
	if !sort.StringsAreSorted(rw) || !sort.StringsAreSorted(ro) {
		t.Fatal("filesystem lists must be sorted")
	}
	if !p.Filesystem.IncludeWorkdir || p.Landlock.Compatibility != LandlockHardRequirement {
		t.Fatal("base filesystem/landlock settings changed")
	}
	if p.Process.RunAsUser != "1000" || p.Process.RunAsGroup != "1000" {
		t.Fatalf("process = %#v", p.Process)
	}
}

func TestRenderRejectsUnsafeInput(t *testing.T) {
	mutate := func(fn func(*Input)) Input {
		in := baseInput(ProfileOpen, "codex")
		fn(&in)
		return in
	}
	cases := map[string]Input{
		"unknown-profile":        mutate(func(in *Input) { in.Profile = "yolo" }),
		"bad-harness":            mutate(func(in *Input) { in.Harness = "Claude Code" }),
		"no-mode":                mutate(func(in *Input) { in.WorkdirMode = "" }),
		"relative-workdir":       mutate(func(in *Input) { in.Workdir = "work/myapp" }),
		"unclean-workdir":        mutate(func(in *Input) { in.Workdir = "/work/../etc" }),
		"root-workdir":           mutate(func(in *Input) { in.Workdir = "/" }),
		"system-workdir":         mutate(func(in *Input) { in.Workdir = "/usr/local/src" }),
		"mount-outside-work":     mutate(func(in *Input) { in.Workdir = "/srv/myapp" }),
		"workdir-is-home":        mutate(func(in *Input) { in.WorkdirMode = WorkdirCopy; in.Workdir = "/sandbox" }),
		"root-user":              mutate(func(in *Input) { in.RunAsUser = "0" }),
		"root-group-name":        mutate(func(in *Input) { in.RunAsGroup = "root" }),
		"named-user-mount":       mutate(func(in *Input) { in.RunAsUser = "sandbox" }),
		"shell-in-user":          mutate(func(in *Input) { in.RunAsUser = "1000;rm" }),
		"missing-egress":         mutate(func(in *Input) { in.EgressPort = 0 }),
		"port-collision":         mutate(func(in *Input) { in.EgressPort = in.IngressPort }),
		"missing-ingress":        mutate(func(in *Input) { in.IngressPort = 0 }),
		"mount-over-etc":         mutate(func(in *Input) { in.Mounts = []Mount{{Target: "/etc/ssh", ReadOnly: true}} }),
		"mount-parent-of-system": mutate(func(in *Input) { in.Mounts = []Mount{{Target: "/", ReadOnly: true}} }),
		"mount-parent-of-work":   mutate(func(in *Input) { in.Mounts = []Mount{{Target: "/work", ReadOnly: false}} }),
		"harness-root-slash":     mutate(func(in *Input) { in.HarnessReadOnly = []string{"/"} }),
		"reserved-rule": mutate(func(in *Input) {
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"defenseclaw_x": anyRule("example.org", 443)}
		}),
		"provider-rule": mutate(func(in *Input) {
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"_provider_x": anyRule("example.org", 443)}
		}),
		"rule-to-ingress": mutate(func(in *Input) {
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"x": anyRule("host.openshell.internal", 18971)}
		}),
		"rule-no-binaries": mutate(func(in *Input) {
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"x": {Endpoints: []v1.PolicyNetworkEndpoint{{Host: "example.org", Port: 443}}}}
		}),
		"rule-terminate-tls": mutate(func(in *Input) {
			r := anyRule("example.org", 443)
			r.Endpoints[0].TLS = v1.NetworkTLSModeTerminate
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"x": r}
		}),
		"rule-credential-binding": mutate(func(in *Input) {
			r := anyRule("example.org", 443)
			r.Endpoints[0].CredentialBinding = &types.NetworkCredentialBinding{Provider: "p"}
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"x": r}
		}),
		"rule-l7-on-tcp": mutate(func(in *Input) {
			r := anyRule("example.org", 443)
			r.Endpoints[0].Access = v1.NetworkAccessPresetFull
			in.ExtraRules = map[string]v1.NetworkPolicyRule{"x": r}
		}),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Render(in); err == nil {
				t.Fatal("unsafe input rendered")
			}
		})
	}
}

// TestRenderKeepsExtraRulesOffReservedEndpoints covers every spelling of a
// DefenseClaw or OpenShell listener an extra rule could use: other ports,
// the Ports list, host case, wildcards, loopback aliases, IP literals and
// allowed_ips ranges.
func TestRenderKeepsExtraRulesOffReservedEndpoints(t *testing.T) {
	endpoint := func(ep v1.PolicyNetworkEndpoint) map[string]v1.NetworkPolicyRule {
		if ep.Protocol == "" {
			ep.Protocol = "tcp"
		}
		return map[string]v1.NetworkPolicyRule{"x": {Endpoints: []v1.PolicyNetworkEndpoint{ep}, Binaries: []v1.PolicyNetworkBinary{{Path: "/**"}}}}
	}
	refused := map[string]struct {
		ep        v1.PolicyNetworkEndpoint
		hostPorts []int
		want      string
	}{
		"ingress-in-ports-list":  {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Ports: []uint32{18971}}, nil, "hook ingress"},
		"egress-in-ports-list":   {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Ports: []uint32{5432, 18972}}, []int{5432}, "egress proxy"},
		"upper-case-ingress":     {v1.PolicyNetworkEndpoint{Host: "HOST.OPENSHELL.INTERNAL", Port: 18971}, nil, "hook ingress"},
		"mixed-case-api":         {v1.PolicyNetworkEndpoint{Host: "Host.OpenShell.Internal", Port: 18970}, nil, "DefenseClaw API"},
		"main-api":               {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 18970}, nil, "DefenseClaw API"},
		"openshell-gateway":      {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 17670}, nil, "OpenShell gateway"},
		"unconsented-host-port":  {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 5433}, []int{5432}, "not a consented host port"},
		"wildcard-openshell":     {v1.PolicyNetworkEndpoint{Host: "*.openshell.internal", Port: 18972}, nil, "could match host.openshell.internal"},
		"double-wildcard-tld":    {v1.PolicyNetworkEndpoint{Host: "**.internal", Port: 443}, nil, "could match host.openshell.internal"},
		"wildcard-openshell-sub": {v1.PolicyNetworkEndpoint{Host: "*.x.openshell.internal", Port: 443}, nil, "could match host.openshell.internal"},
		"wildcard-docker-host":   {v1.PolicyNetworkEndpoint{Host: "*.docker.internal", Port: 443}, nil, "loopback name"},
		"wildcard-localhost":     {v1.PolicyNetworkEndpoint{Host: "*.localhost", Port: 443}, nil, "loopback name"},
		"openshell-name":         {v1.PolicyNetworkEndpoint{Host: "gateway.openshell.internal", Port: 443}, nil, "reserved by OpenShell"},
		"localhost":              {v1.PolicyNetworkEndpoint{Host: "localhost", Port: 18970}, nil, "loopback name"},
		"localhost-subdomain":    {v1.PolicyNetworkEndpoint{Host: "api.localhost", Port: 80}, nil, "loopback name"},
		"docker-desktop-host":    {v1.PolicyNetworkEndpoint{Host: "host.docker.internal", Port: 18970}, nil, "loopback name"},
		"loopback-literal":       {v1.PolicyNetworkEndpoint{Host: "127.0.0.1", Port: 18970}, nil, "loopback"},
		"short-loopback":         {v1.PolicyNetworkEndpoint{Host: "127.1", Port: 18970}, nil, "canonical"},
		"decimal-loopback":       {v1.PolicyNetworkEndpoint{Host: "2130706433", Port: 18970}, nil, "canonical"},
		"hex-loopback":           {v1.PolicyNetworkEndpoint{Host: "0x7f000001", Port: 18970}, nil, "canonical"},
		"zero-padded-loopback":   {v1.PolicyNetworkEndpoint{Host: "127.000.000.001", Port: 18970}, nil, "canonical"},
		"metadata-literal":       {v1.PolicyNetworkEndpoint{Host: "169.254.169.254", Port: 80}, nil, "link-local"},
		"synthetic-literal":      {v1.PolicyNetworkEndpoint{Host: "198.18.0.2", Port: 18971}, nil, "OpenShell synthetic"},
		"cgnat-literal":          {v1.PolicyNetworkEndpoint{Host: "100.100.100.200", Port: 80}, nil, "CGNAT"},
		"wildcard-ip":            {v1.PolicyNetworkEndpoint{Host: "*.0.0.1", Port: 80}, nil, "canonical"},
		"allowed-loopback":       {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 5432, AllowedIPs: []string{"127.0.0.0/8"}}, nil, "loopback"},
		"allowed-loopback-addr":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 5432, AllowedIPs: []string{"127.0.0.2"}}, nil, "loopback"},
		"allowed-metadata":       {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"169.254.169.254/32"}}, nil, "link-local"},
		"allowed-cgnat":          {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"100.64.0.0/10"}}, nil, "CGNAT"},
		"allowed-everything":     {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"0.0.0.0/0"}}, nil, "overlaps"},
		"allowed-synthetic":      {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"198.18.0.0/16"}}, nil, "OpenShell synthetic"},
		"allowed-v6-loopback":    {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::1/128"}}, nil, "loopback"},
		"allowed-v4-mapped":      {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::ffff:127.0.0.1"}}, nil, "loopback"},
		"allowed-v4-mapped-all":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::ffff:0:0/96"}}, nil, "overlaps"},
		"allowed-v6-link-local":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"fe80::/10"}}, nil, "link-local"},
		"allowed-v6-everything":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"::/0"}}, nil, "overlaps"},
		"allowed-not-canonical":  {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"10.0.0.1/8"}}, nil, "canonical CIDR"},
		"allowed-garbage":        {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 80, AllowedIPs: []string{"db.internal"}}, nil, "not an IP"},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			in := baseInput(ProfileOpen, "codex")
			in.HostPorts = tc.hostPorts
			in.ExtraRules = endpoint(tc.ep)
			_, err := Render(in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}

	// Consented host ports themselves may not name a reserved listener.
	for name, ports := range map[string][]int{
		"consent-ingress": {18971}, "consent-egress": {18972}, "consent-api": {18970},
		"consent-gateway": {17670}, "consent-out-of-range": {70000}, "consent-zero": {0},
	} {
		t.Run(name, func(t *testing.T) {
			in := baseInput(ProfileOpen, "codex")
			in.HostPorts = ports
			if _, err := Render(in); err == nil {
				t.Fatal("reserved or invalid host port consented")
			}
		})
	}
	// Custom API and gateway ports move the reservation with them.
	moved := baseInput(ProfileOpen, "codex")
	moved.APIPort, moved.GatewayPort = 28970, 27670
	moved.HostPorts = []int{18970, 17670}
	moved.ExtraRules = endpoint(v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Ports: []uint32{18970, 17670}})
	if _, err := Render(moved); err != nil {
		t.Fatalf("ports freed by a custom API and gateway port: %v", err)
	}
	moved.HostPorts = []int{28970}
	moved.ExtraRules = nil
	if _, err := Render(moved); err == nil || !strings.Contains(err.Error(), "DefenseClaw API") {
		t.Fatalf("custom API port consented: %v", err)
	}

	accepted := map[string]struct {
		ep        v1.PolicyNetworkEndpoint
		hostPorts []int
	}{
		"consented-host-port":  {v1.PolicyNetworkEndpoint{Host: "host.openshell.internal", Port: 5432}, []int{5432}},
		"consented-port-list":  {v1.PolicyNetworkEndpoint{Host: "HOST.openshell.internal", Ports: []uint32{5432, 8080}}, []int{8080, 5432}},
		"public-literal":       {v1.PolicyNetworkEndpoint{Host: "93.184.216.34", Port: 443}, nil},
		"public-wildcard":      {v1.PolicyNetworkEndpoint{Host: "**.example.org", Port: 443}, nil},
		"hex-looking-name":     {v1.PolicyNetworkEndpoint{Host: "0xproject.example.org", Port: 443}, nil},
		"lan-allowed-ips":      {v1.PolicyNetworkEndpoint{Host: "db.lan.example.org", Port: 5432, AllowedIPs: []string{"10.0.0.0/24", "192.168.1.20"}}, nil},
		"public-v6-allowed-ip": {v1.PolicyNetworkEndpoint{Host: "db.example.org", Port: 5432, AllowedIPs: []string{"2001:db8::/32"}}, nil},
	}
	for name, tc := range accepted {
		t.Run(name, func(t *testing.T) {
			in := baseInput(ProfileOpen, "codex")
			in.HostPorts = tc.hostPorts
			in.ExtraRules = endpoint(tc.ep)
			if _, err := Render(in); err != nil {
				t.Fatalf("Render: %v", err)
			}
		})
	}
}

func anyRule(host string, port uint32) v1.NetworkPolicyRule {
	return v1.NetworkPolicyRule{
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: host, Port: port, Protocol: "tcp"}},
		Binaries:  []v1.PolicyNetworkBinary{{Path: "/**"}},
	}
}

func TestMarshalYAMLRefusesUnrepresentableFields(t *testing.T) {
	p, err := Render(baseInput(ProfileStrict, "codex"))
	if err != nil {
		t.Fatal(err)
	}
	p.NetworkPolicies["x"] = v1.NetworkPolicyRule{
		Name:      "x",
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: "example.org", Port: 443, Protocol: "rest", AllowEncodedSlash: true}},
		Binaries:  []v1.PolicyNetworkBinary{{Path: "/**"}},
	}
	if _, err := MarshalYAML(p); err == nil || !strings.Contains(err.Error(), "does not carry") {
		t.Fatalf("MarshalYAML error = %v", err)
	}
}

func TestParseYAMLIsStrict(t *testing.T) {
	good, err := MarshalYAML(mustRender(t, baseInput(ProfileOpen, "codex")))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unknown-top-key":      string(good) + "extra_key: 1\n",
		"unknown-endpoint-key": strings.Replace(string(good), "tls: skip", "tls: skip\n                bogus: true", 1),
		"unknown-tls":          strings.Replace(string(good), "tls: skip", "tls: terminate", 1),
		"second-document":      string(good) + "---\nversion: 1\n",
		"root-user":            strings.Replace(string(good), `run_as_user: "1000"`, `run_as_user: "0"`, 1),
		"best-effort-landlock": strings.Replace(string(good), "hard_requirement", "best_effort", 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if doc == string(good) {
				t.Fatal("mutation did not apply")
			}
			if _, err := ParseYAML([]byte(doc)); err == nil {
				t.Fatal("invalid document parsed")
			}
		})
	}
}

// TestParseYAMLAcceptsSpikePolicy loads a policy OpenShell 0.1.1 accepted in
// the harness spike (network_policies empty, hand-written ordering).
func TestParseYAMLAcceptsSpikePolicy(t *testing.T) {
	spike := `version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /proc, /dev/urandom, /var/log, /opt]
  read_write: [/tmp, /dev/null, /dev/ptmx, /dev/pts, /dev/tty, /work/proj]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: "1000"
  run_as_group: "1000"
network_policies: {}
`
	p, err := ParseYAML([]byte(spike))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if len(p.NetworkPolicies) != 0 || p.Process.RunAsUser != "1000" {
		t.Fatalf("parsed %#v", p)
	}
}

func TestParseProfile(t *testing.T) {
	for in, want := range map[string]Profile{"": ProfileOpen, "OPEN": ProfileOpen, " balanced ": ProfileBalanced, "strict": ProfileStrict} {
		got, err := ParseProfile(in)
		if err != nil || got != want {
			t.Fatalf("ParseProfile(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseProfile("permissive"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestValidateRejectsExternalPolicies(t *testing.T) {
	p := mustRender(t, baseInput(ProfileOpen, "codex"))
	p.NetworkMiddlewares = map[string]types.NetworkMiddlewareConfig{"m": {Name: "m"}}
	if err := Validate(p); err == nil {
		t.Fatal("middleware accepted")
	}
	p = mustRender(t, baseInput(ProfileOpen, "codex"))
	p.Filesystem.ReadOnly = append(p.Filesystem.ReadOnly, "/work/myapp")
	if err := Validate(p); err == nil {
		t.Fatal("path listed read-only and read-write accepted")
	}
	p = mustRender(t, baseInput(ProfileOpen, "codex"))
	p.NetworkPolicies = nil
	if err := Validate(p); err == nil {
		t.Fatal("nil network policies accepted")
	}
	if err := Validate(nil); err == nil {
		t.Fatal("nil policy accepted")
	}
}

func mustRender(t *testing.T, in Input) *v1.SandboxPolicy {
	t.Helper()
	p, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
