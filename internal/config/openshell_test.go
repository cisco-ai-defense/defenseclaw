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

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeOpenShellConfig(t *testing.T, section string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	raw := "config_version: 8\ndata_dir: " + dir + "\n" + section
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenShellLoaderDefaults(t *testing.T) {
	path := writeOpenShellConfig(t, "")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	o := cfg.OpenShell
	if o.Enabled {
		t.Fatal("openshell.enabled must default to false")
	}
	if o.Binary != "openshell" || o.EffectiveBinary() != "openshell" {
		t.Fatalf("binary = %q", o.Binary)
	}
	if want := filepath.Join(cfg.DataDir, "policies", "sandbox"); o.PackDir != want {
		t.Fatalf("pack_dir = %q, want %q", o.PackDir, want)
	}
	if o.Workdir.GitDepth != 200 || o.Workdir.OnExit != "ask" {
		t.Fatalf("workdir defaults = %+v", o.Workdir)
	}
	if o.Approvals.DebounceMs != 3000 || !o.Approvals.AgentProposalsEnabled() {
		t.Fatalf("approvals defaults = %+v", o.Approvals)
	}
	if o.TokenDelivery != "provider" {
		t.Fatalf("token_delivery = %q", o.TokenDelivery)
	}
	// Pack-governed keys stay unset so the selected pack supplies them.
	if o.Pack != "" || o.Profile != "" || o.Yolo != nil || o.Workdir.Mode != "" ||
		o.Workdir.MaxUploadMB != 0 || len(o.Egress.Ports) != 0 || o.Egress.LargeUploadMB != 0 ||
		o.Egress.Feed != "" || o.MCP.Import != nil {
		t.Fatalf("pack-governed keys received loader defaults: %+v", o)
	}
	if !o.Admin.IsZero() {
		t.Fatalf("admin defaults = %+v", o.Admin)
	}
	if got, want := cfg.OpenShellIngressPort(), DefaultGatewayAPIPort+1; got != want {
		t.Fatalf("ingress port = %d, want %d", got, want)
	}
	if got, want := cfg.OpenShellEgressPort(), DefaultGatewayAPIPort+2; got != want {
		t.Fatalf("egress port = %d, want %d", got, want)
	}

	defaults := DefaultConfig().OpenShell
	defaults.PackDir = o.PackDir
	if !reflect.DeepEqual(defaults, o) {
		t.Fatalf("DefaultConfig().OpenShell diverges from loader defaults\ndefault: %+v\nloaded:  %+v", defaults, o)
	}
}

func TestOpenShellFullSectionLoads(t *testing.T) {
	path := writeOpenShellConfig(t, `gateway:
  api_port: 19000
openshell:
  enabled: true
  binary: /usr/bin/openshell
  gateway: {name: openshell, workspace: team}
  egress_port: 19500
  pack: balanced
  pack_dir: /etc/defenseclaw/packs
  profile: strict
  yolo: false
  workdir: {mode: copy, masks: ['.env*'], unmask: [.env.example], max_upload_mb: 100, git_depth: 50, on_exit: keep}
  egress: {block: [paste.example], allow: ['*.npmjs.org'], ports: [443, 8443], large_upload_mb: 10, feed: none}
  image: {base: 'registry.example/base@sha256:abc', harness_versions: {codex: 0.146.0}}
  approvals: {debounce_ms: 1500, agent_proposals: false}
  resources: {cpu: '2', memory: 4Gi}
  harnesses: [claude-code, codex]
  wrappers: [claudecode]
  mcp: {import: false, host_ports: [5432]}
  upstream_telemetry: true
  token_delivery: env
  middleware: {enabled: true}
  admin:
    required_pack: strict
    min_profile: balanced
    allow_yolo: false
    allow_mount: true
    allowed_harnesses: [codex]
    egress_block: ['*.ngrok.io']
    egress_allow_only: ['*.corp.example']
    require_copy_for: [/src/customer-*]
    max_resources: {cpu: 500m, memory: 8Gi}
    locked: [profile, yolo]
`)
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	o := cfg.OpenShell
	f := false
	tr := true
	want := OpenShellConfig{
		Enabled:           true,
		Binary:            "/usr/bin/openshell",
		Gateway:           OpenShellGatewayConfig{Name: "openshell", Workspace: "team"},
		EgressPort:        19500,
		Pack:              "balanced",
		PackDir:           "/etc/defenseclaw/packs",
		Profile:           "strict",
		Yolo:              &f,
		Workdir:           OpenShellWorkdirConfig{Mode: "copy", Masks: []string{".env*"}, Unmask: []string{".env.example"}, MaxUploadMB: 100, GitDepth: 50, OnExit: "keep"},
		Egress:            OpenShellEgressConfig{Block: []string{"paste.example"}, Allow: []string{"*.npmjs.org"}, Ports: []int{443, 8443}, LargeUploadMB: 10, Feed: "none"},
		Image:             OpenShellImageConfig{Base: "registry.example/base@sha256:abc", HarnessVersions: map[string]string{"codex": "0.146.0"}},
		Approvals:         OpenShellApprovalsConfig{DebounceMs: 1500, AgentProposals: &f},
		Resources:         OpenShellResourcesConfig{CPU: "2", Memory: "4Gi"},
		Harnesses:         []string{"claude-code", "codex"},
		Wrappers:          []string{"claudecode"},
		MCP:               OpenShellMCPConfig{Import: &f, HostPorts: []int{5432}},
		Middleware:        OpenShellMiddlewareConfig{Enabled: true},
		TokenDelivery:     "env",
		UpstreamTelemetry: true,
		Admin: OpenShellAdminConfig{
			RequiredPack:     "strict",
			MinProfile:       "balanced",
			AllowYolo:        &f,
			AllowMount:       &tr,
			AllowedHarnesses: []string{"codex"},
			EgressBlock:      []string{"*.ngrok.io"},
			EgressAllowOnly:  []string{"*.corp.example"},
			RequireCopyFor:   []string{"/src/customer-*"},
			MaxResources:     OpenShellResourcesConfig{CPU: "500m", Memory: "8Gi"},
			Locked:           []string{"profile", "yolo"},
		},
	}
	if !reflect.DeepEqual(o, want) {
		t.Fatalf("decoded openshell section\n got: %+v\nwant: %+v", o, want)
	}
	if o.Approvals.AgentProposalsEnabled() {
		t.Fatal("agent_proposals: false must disable agent proposals")
	}
	if got := cfg.OpenShellIngressPort(); got != 19001 {
		t.Fatalf("ingress port = %d, want api_port+1", got)
	}
	if got := cfg.OpenShellEgressPort(); got != 19500 {
		t.Fatalf("egress port = %d, want the explicit port", got)
	}
	if !o.Admin.IsLocked("yolo") || o.Admin.IsLocked("pack") {
		t.Fatalf("locked keys = %v", o.Admin.Locked)
	}
}

// Round trip: Config.Save writes the section with omitempty so a loaded
// default config does not grow an openshell block, and an explicit section
// survives unchanged.
func TestOpenShellYAMLRoundTrip(t *testing.T) {
	var empty OpenShellConfig
	data, err := yaml.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "{}" {
		t.Fatalf("zero section marshals to %q", data)
	}
	f := false
	in := OpenShellConfig{
		Enabled: true, Profile: "balanced", Yolo: &f,
		Workdir: OpenShellWorkdirConfig{Mode: "copy", Masks: []string{"*.pem"}},
		Egress:  OpenShellEgressConfig{Ports: []int{443}},
		MCP:     OpenShellMCPConfig{Import: &f},
		Admin:   OpenShellAdminConfig{AllowYolo: &f, Locked: []string{"yolo"}},
	}
	data, err = yaml.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out OpenShellConfig
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the section\n in: %+v\nout: %+v\nyaml:\n%s", in, out, data)
	}
}

func TestOpenShellValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*OpenShellConfig)
		want string
	}{
		{"same ports", func(o *OpenShellConfig) { o.IngressPort, o.EgressPort = 19001, 19001 }, "must differ"},
		{"port range", func(o *OpenShellConfig) { o.EgressPort = 70000 }, "egress_port"},
		{"profile", func(o *OpenShellConfig) { o.Profile = "wide" }, "profile"},
		{"workdir mode", func(o *OpenShellConfig) { o.Workdir.Mode = "overlay" }, "workdir.mode"},
		{"on exit", func(o *OpenShellConfig) { o.Workdir.OnExit = "delete" }, "workdir.on_exit"},
		{"feed", func(o *OpenShellConfig) { o.Egress.Feed = "custom" }, "egress.feed"},
		{"token delivery", func(o *OpenShellConfig) { o.TokenDelivery = "file" }, "token_delivery"},
		{"negative upload", func(o *OpenShellConfig) { o.Workdir.MaxUploadMB = -1 }, "max_upload_mb"},
		{"absolute mask", func(o *OpenShellConfig) { o.Workdir.Masks = []string{".env", "/srv/app/.env"} }, "workdir.masks[1]"},
		{"escaping unmask", func(o *OpenShellConfig) { o.Workdir.Unmask = []string{"../../secrets/app.key"} }, "workdir.unmask[0]"},
		{"home unmask", func(o *OpenShellConfig) { o.Workdir.Unmask = []string{"~/notes.txt"} }, "workdir.unmask[0]"},
		{"proxy port zero", func(o *OpenShellConfig) { o.Egress.Ports = []int{0} }, "egress.ports[0]"},
		{"host port", func(o *OpenShellConfig) { o.MCP.HostPorts = []int{65536} }, "mcp.host_ports[0]"},
		{"block glob", func(o *OpenShellConfig) { o.Egress.Block = []string{"https://x.example"} }, "egress.block[0]"},
		{"inner wildcard", func(o *OpenShellConfig) { o.Egress.Allow = []string{"a.*.example"} }, "egress.allow[0]"},
		{"double wildcard", func(o *OpenShellConfig) { o.Egress.Allow = []string{"**.example"} }, "egress.allow[0]"},
		{"harness", func(o *OpenShellConfig) { o.Harnesses = []string{"claude code"} }, "harnesses[0]"},
		{"image harness", func(o *OpenShellConfig) { o.Image.HarnessVersions = map[string]string{"bad name": "1"} }, "image.harness_versions"},
		{"cpu", func(o *OpenShellConfig) { o.Resources.CPU = "0" }, "resources.cpu"},
		{"memory", func(o *OpenShellConfig) { o.Resources.Memory = "4GB" }, "resources.memory"},
		{"admin profile", func(o *OpenShellConfig) { o.Admin.MinProfile = "none" }, "admin.min_profile"},
		{"admin locked", func(o *OpenShellConfig) { o.Admin.Locked = []string{"enabled"} }, "admin.locked[0]"},
		{"admin max", func(o *OpenShellConfig) { o.Admin.MaxResources.CPU = "lots" }, "admin.max_resources.cpu"},
		{"admin copy glob", func(o *OpenShellConfig) { o.Admin.RequireCopyFor = []string{" "} }, "admin.require_copy_for[0]"},
		{"relative copy glob", func(o *OpenShellConfig) {
			o.Admin.RequireCopyFor = []string{"/src/customer-*", "customer-*"}
		}, "admin.require_copy_for[1]"},
		{"every host blocked", func(o *OpenShellConfig) { o.Egress.Block = []string{"*"} }, "egress.block[0]"},
		{"admin allow-only everything", func(o *OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*"} }, "admin.egress_allow_only[0]"},
		{"admin block", func(o *OpenShellConfig) { o.Admin.EgressBlock = []string{"x.example/path"} }, "admin.egress_block[0]"},
		{"pack digest format", func(o *OpenShellConfig) {
			o.Admin.RequiredPack, o.Admin.RequiredPackDigest = "strict", "sha256:ABC"
		}, "admin.required_pack_digest"},
		{"pack digest without a pack", func(o *OpenShellConfig) {
			o.Admin.RequiredPackDigest = "sha256:" + strings.Repeat("a", 64)
		}, "needs admin.required_pack"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := DefaultConfig().OpenShell
			tc.edit(&o)
			err := o.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}

	valid := DefaultConfig().OpenShell
	valid.Workdir.Masks = []string{".env.*", "secrets/**", "**/*.pem"}
	valid.Workdir.Unmask = []string{".env.example", "./certs/dev.pem"}
	valid.Egress.Block = []string{"Paste.Example.", "*.ngrok.io", "203.0.113.9", "[2001:db8::1]", "198.51.100.0/24"}
	valid.Admin.RequireCopyFor = []string{"/src/customer-*", "~/clients/*", "**/customer-*"}
	valid.Resources = OpenShellResourcesConfig{CPU: "1.5", Memory: "512Mi"}
	valid.Admin.Locked = append([]string(nil), OpenShellLockableKeys...)
	valid.Admin.RequiredPack, valid.Admin.RequiredPackDigest = "strict", "sha256:"+strings.Repeat("0f", 32)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid section rejected: %v", err)
	}
	var nilSection *OpenShellConfig
	if err := nilSection.Validate(); err != nil {
		t.Fatalf("nil section: %v", err)
	}
}

func TestConfigValidateOpenShellListeners(t *testing.T) {
	config := func(edit func(*Config)) *Config {
		cfg := DefaultConfig()
		cfg.Gateway.APIPort = 18970
		cfg.Guardrail.Port = 4000
		cfg.OpenShell.Enabled = true
		if edit != nil {
			edit(cfg)
		}
		return cfg
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string // "" is valid
	}{
		{"derived ports", nil, ""},
		{"explicit distinct ports", func(c *Config) { c.OpenShell.IngressPort, c.OpenShell.EgressPort = 19001, 19002 }, ""},
		{"default api port", func(c *Config) { c.Gateway.APIPort = 0 }, ""},
		{"ingress on the derived egress port", func(c *Config) { c.OpenShell.IngressPort = 18972 }, "resolve to the same port 18972"},
		{"egress on the derived ingress port", func(c *Config) { c.OpenShell.EgressPort = 18971 }, "resolve to the same port 18971"},
		{"egress on the api port", func(c *Config) { c.OpenShell.EgressPort = 18970 }, "egress_port 18970 collides with gateway.api_port"},
		{"ingress on the guardrail port", func(c *Config) { c.OpenShell.IngressPort = 4000 }, "ingress_port 4000 collides with guardrail.port"},
		{"derived port on the guardrail port", func(c *Config) { c.Guardrail.Port = 18972 }, "egress_port 18972 collides with guardrail.port"},
		{"derived port out of range", func(c *Config) { c.Gateway.APIPort = 65535 }, "leaves no room"},
		{"explicit ports near the top", func(c *Config) {
			c.Gateway.APIPort, c.OpenShell.IngressPort, c.OpenShell.EgressPort = 65535, 65533, 65534
		}, ""},
		{"disabled integration binds nothing", func(c *Config) {
			c.OpenShell.Enabled = false
			c.Guardrail.Port, c.OpenShell.EgressPort = 18971, 18970
		}, ""},
		{"section errors come first", func(c *Config) {
			c.OpenShell.Enabled = false
			c.OpenShell.Profile = "wide"
		}, "profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := config(tc.edit).ValidateOpenShell()
			if tc.want == "" && err != nil {
				t.Fatalf("ValidateOpenShell() = %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("ValidateOpenShell() = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
	var nilConfig *Config
	if err := nilConfig.ValidateOpenShell(); err != nil {
		t.Fatalf("nil config: %v", err)
	}
}

func TestOpenShellInvalidSectionFailsLoad(t *testing.T) {
	path := writeOpenShellConfig(t, "openshell:\n  ingress_port: 19001\n  egress_port: 19001\n")
	_, err := LoadFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "config: openshell:") {
		t.Fatalf("LoadFromFile() = %v, want an openshell validation error", err)
	}
}

// The same cases as TestOpenShellValidation.test_project_globs in
// cli/tests/test_config_openshell.py.
func TestValidateOpenShellProjectGlob(t *testing.T) {
	for _, glob := range []string{
		".env", " .env.* ", "secrets/**", "**/*.pem", "a/b/c.key", "./certs/dev.pem", "a..b", "..env", "db:backup",
		strings.Repeat("a", MaxOpenShellProjectGlobBytes),
	} {
		if err := ValidateOpenShellProjectGlob(glob); err != nil {
			t.Errorf("ValidateOpenShellProjectGlob(%q) = %v", glob, err)
		}
	}
	for _, glob := range []string{
		"", "  ", "/srv/app/.env", "~/notes.txt", "~notes", `certs\dev.pem`, "../x", "a/../b", "a/..", "..",
		"C:/work/.env", "c:env", "a\x00b", strings.Repeat("a", MaxOpenShellProjectGlobBytes+1),
	} {
		if err := ValidateOpenShellProjectGlob(glob); err == nil {
			t.Errorf("ValidateOpenShellProjectGlob(%q) accepted", glob)
		}
	}
	if err := ValidateOpenShellProjectGlobs("workdir.unmask", []string{".env.example", "/x"}); err == nil ||
		!strings.HasPrefix(err.Error(), "workdir.unmask[1]: ") {
		t.Fatalf("list error = %v", err)
	}
}

func TestParseOpenShellEgressPattern(t *testing.T) {
	for in, want := range map[string]string{
		"Paste.Example.":       "paste.example",
		" *.NGROK.io ":         "*.ngrok.io",
		"_dmarc.example":       "_dmarc.example",
		"1.2.example":          "1.2.example",
		"203.0.113.9":          "203.0.113.9",
		"[2001:DB8::1]":        "2001:db8::1",
		"2001:0db8:0000::0001": "2001:db8::1",
		"::ffff:203.0.113.9":   "203.0.113.9",
		"[::ffff:cb00:7109]":   "203.0.113.9",
		"10.1.2.3/8":           "10.0.0.0/8",
		"2001:db8:1::/48":      "2001:db8:1::/48",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
		"0.0.0.0/0":            "0.0.0.0/0",
		"2001:db8::1/128":      "2001:db8::1",
		"198.51.100.7/32":      "198.51.100.7",
	} {
		got, err := ParseOpenShellEgressPattern(in)
		if err != nil || got.String() != want || NormalizeOpenShellEgressPattern(in) != want {
			t.Errorf("ParseOpenShellEgressPattern(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", " ", "*", "**.example", "a.*.example", "*.", "paste.example:443", "https://x.example", "x.example/path",
		"example.com..", "-bad.example", strings.Repeat("a", 64) + ".example", ":::1", "fe80::1%eth0",
		"01.2.3.4", "999.1.1.1", "127.1", "2130706433", "0x7f000001", "203.0.113.9.", "*.203.0.113.9", "*.[::1]",
		"10.0.0.0/33", "10.0.0.0/08", "10.0.0.0/", "10.0.0.0/-1", "::ffff:10.0.0.0/80", "[2001:db8::]/32",
		"fe80::%eth0/64", "example.com/24", "2001:db8::/129", "10.0.0.0/255.0.0.0",
	} {
		if err := ValidateOpenShellEgressPattern(bad); err == nil {
			t.Errorf("ValidateOpenShellEgressPattern(%q) accepted", bad)
		}
	}

	parse := func(s string) OpenShellEgressPattern {
		t.Helper()
		p, err := ParseOpenShellEgressPattern(s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "Example.COM.", true},
		{"example.com", "a.example.com", false},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"203.0.113.9", "::ffff:203.0.113.9", true},
		{"203.0.113.9", "[::ffff:cb00:7109]", true},
		{"2001:db8::1", "2001:0DB8:0:0::1", true},
		{"10.0.0.0/8", "10.200.3.4", true},
		{"10.0.0.0/8", "::ffff:10.200.3.4", true},
		{"10.0.0.0/8", "11.0.0.1", false},
		{"2001:db8::/32", "[2001:db8:ffff::1]", true},
		{"2001:db8::/32", "2001:db9::1", false},
		// Names never match addresses, and addresses never match names.
		{"10.0.0.0/8", "ten.example", false},
		{"203.0.113.9", "203.0.113.9.nip.example", false},
	} {
		host, addr := NormalizeOpenShellHost(tc.host)
		if got := parse(tc.pattern).Matches(host, addr); got != tc.want {
			t.Errorf("%q matches %q = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
	for _, tc := range []struct {
		outer, inner string
		want         bool
	}{
		{"*.example.com", "*.example.com", true},
		{"*.example.com", "*.a.example.com", true},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"a.example.com", "*.a.example.com", false},
		{"10.0.0.0/8", "10.1.0.0/16", true},
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.1.0.0/16", "10.0.0.0/8", false},
		{"10.0.0.0/8", "ten.example", false},
		{"::ffff:10.0.0.0/104", "10.9.0.0/16", true},
	} {
		if got := parse(tc.outer).Covers(parse(tc.inner)); got != tc.want {
			t.Errorf("%q covers %q = %v, want %v", tc.outer, tc.inner, got, tc.want)
		}
	}
}

func TestValidateOpenShellCopyPattern(t *testing.T) {
	for _, pattern := range []string{
		"/src/customer-*", " /src/customer-* ", "~", "~/clients/*", "**", "**/customer-*", "C:/src/*", `C:\src\*`,
		"/src/[a-c]*", `/srv/\*literal`, "/src/[^x]y", `/src/[\]a]x`,
	} {
		if err := ValidateOpenShellCopyPattern(pattern); err != nil {
			t.Errorf("ValidateOpenShellCopyPattern(%q) = %v", pattern, err)
		}
	}
	for _, pattern := range []string{
		"", "  ", "customer-*", "*/customer-acme", "src/client-*", "./src", "~clients", "C:src", "*",
		"/src/customer-[ab", "/src/[]x]", "/src/[a-]", "/src/[-a]", `/src/customer\`, "/src/a\x00b",
	} {
		if err := ValidateOpenShellCopyPattern(pattern); err == nil {
			t.Errorf("ValidateOpenShellCopyPattern(%q) accepted", pattern)
		}
	}
}

func TestParseOpenShellQuantities(t *testing.T) {
	for in, want := range map[string]int64{"2": 2000, "1.5": 1500, "0.25": 250, "500m": 500, " 3 ": 3000} {
		got, err := ParseOpenShellCPU(in)
		if err != nil || got != want {
			t.Fatalf("ParseOpenShellCPU(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "0m", "-1", "1.2345", "2cores", "1e3"} {
		if _, err := ParseOpenShellCPU(bad); err == nil {
			t.Fatalf("ParseOpenShellCPU(%q) accepted", bad)
		}
	}
	for in, want := range map[string]int64{
		"1024": 1024, "1k": 1000, "1Ki": 1024, "512Mi": 512 << 20, "4Gi": 4 << 30, "2G": 2_000_000_000, "1Ti": 1 << 40,
	} {
		got, err := ParseOpenShellMemory(in)
		if err != nil || got != want {
			t.Fatalf("ParseOpenShellMemory(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "4GB", "1.5Gi", "-1Mi", "999999999999999Ti"} {
		if _, err := ParseOpenShellMemory(bad); err == nil {
			t.Fatalf("ParseOpenShellMemory(%q) accepted", bad)
		}
	}
}

func TestPolicyConnectorsUnionsSandboxHarnesses(t *testing.T) {
	cfg := &Config{}
	if got := cfg.PolicyConnectors(); len(got) != 0 {
		t.Fatalf("unconfigured PolicyConnectors() = %v", got)
	}
	cfg.OpenShell.Harnesses = []string{"Codex", "claude-code", " "}
	if got, want := cfg.PolicyConnectors(), []string{"claudecode", "codex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("harness-only PolicyConnectors() = %v, want %v", got, want)
	}
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {}, "cursor": {}}
	if got, want := cfg.PolicyConnectors(), []string{"claudecode", "codex", "cursor"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("PolicyConnectors() = %v, want %v", got, want)
	}
	if got, want := cfg.ActiveConnectors(), []string{"codex", "cursor"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ActiveConnectors() must not include sandbox harnesses: %v", got)
	}
	var nilCfg *Config
	if got := nilCfg.PolicyConnectors(); got != nil {
		t.Fatalf("nil PolicyConnectors() = %v", got)
	}
}

func TestOpenShellProfileRank(t *testing.T) {
	if !(OpenShellProfileRank("open") < OpenShellProfileRank("balanced") &&
		OpenShellProfileRank("balanced") < OpenShellProfileRank("strict")) {
		t.Fatal("profile ranks must order open < balanced < strict")
	}
	if OpenShellProfileRank("") != -1 || OpenShellProfileRank("Strict") != -1 {
		t.Fatal("unknown profiles must rank -1")
	}
}
