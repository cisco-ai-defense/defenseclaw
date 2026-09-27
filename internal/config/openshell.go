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
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// OpenShell sandbox profiles, from loosest to strictest. They name the
// network posture the policy renderer produces: open (DefenseClaw egress proxy
// allow-by-default with the blocklist), balanced (proxy allowlist, triaged
// approvals) and strict (provider hosts only, manual approvals).
const (
	OpenShellProfileOpen     = "open"
	OpenShellProfileBalanced = "balanced"
	OpenShellProfileStrict   = "strict"
)

// Workspace modes: the live bind mount of the launch folder, or a sanitized
// copy that comes back as a patch or branch.
const (
	OpenShellWorkdirMount = "mount"
	OpenShellWorkdirCopy  = "copy"
)

// What `sandbox run` does with the agent's changes when the session ends.
const (
	OpenShellOnExitAsk  = "ask"
	OpenShellOnExitKeep = "keep"
	OpenShellOnExitUndo = "undo"
)

// Egress blocklist feed selectors for openshell.egress.feed.
const (
	OpenShellFeedBuiltin = "builtin"
	OpenShellFeedNone    = "none"
)

// How a sandbox receives its ingress binding token: as an OpenShell provider
// credential (the agent only ever sees a placeholder) or as a plain env var.
const (
	OpenShellTokenDeliveryProvider = "provider"
	OpenShellTokenDeliveryEnv      = "env"
)

// Loader defaults for the openshell section. Keys the sandbox policy pack
// governs (profile, yolo, workdir mode, upload caps, egress lists, MCP import)
// have no loader default: an unset key inherits the pack's value.
const (
	DefaultOpenShellBinary             = "openshell"
	DefaultOpenShellApprovalDebounceMs = 3000
	DefaultOpenShellGitDepth           = 200
	DefaultOpenShellOnExit             = OpenShellOnExitAsk
	DefaultOpenShellTokenDelivery      = OpenShellTokenDeliveryProvider
	// DefaultOpenShellPackDirName is the directory under <policy_dir> that
	// holds custom sandbox policy packs (<name>/pack.yaml), mirroring the
	// repository's policies/sandbox layout.
	DefaultOpenShellPackDirName = "sandbox"

	// DefaultSandboxHome is the legacy openshell-sandbox user's home.
	//
	// LEGACY(openshell-0.0.x): delete one release after cleanup.
	DefaultSandboxHome = "/home/sandbox"
)

// OpenShellLockableKeys are the openshell keys an administrator can list in
// openshell.admin.locked so `sandbox run` flags cannot override them.
var OpenShellLockableKeys = []string{
	"mcp.host_ports",
	"mcp.import",
	"pack",
	"profile",
	"resources",
	"workdir.mode",
	"workdir.unmask",
	"yolo",
}

// OpenShellConfig configures the NVIDIA OpenShell 0.1.x sandbox integration
// (`defenseclaw sandbox …`).
//
// The sandbox posture is layered: the selected policy pack supplies every
// default, the keys below override it, `sandbox run` flags override those, and
// Admin clamps the result (see internal/openshell/packs). Pack-governed keys
// therefore stay unset (empty, zero, or nil) unless the operator sets them.
//
// The legacy openshell-sandbox (0.0.x) sub-keys policy_dir, version, auto_pair
// and host_networking are still accepted by the v8 schema and ignored. Mode and
// SandboxHome are read only by the legacy shim (legacy_openshell.go) until
// `defenseclaw sandbox legacy-cleanup` resets them. No migration rewrites them.
type OpenShellConfig struct {
	// Enabled turns on the sandbox ingress and egress listeners and the
	// sandbox API. Off by default.
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// Binary is the upstream `openshell` CLI used for terminal attach, file
	// transfer, port forwarding and gateway registration.
	Binary  string                 `mapstructure:"binary"  yaml:"binary,omitempty"`
	Gateway OpenShellGatewayConfig `mapstructure:"gateway" yaml:"gateway,omitempty"`
	// IngressPort is the sandbox hook ingress listener; 0 means api_port+1.
	IngressPort int `mapstructure:"ingress_port" yaml:"ingress_port,omitempty"`
	// EgressPort is the DefenseClaw egress proxy; 0 means api_port+2.
	EgressPort int `mapstructure:"egress_port" yaml:"egress_port,omitempty"`
	// Pack selects the sandbox policy pack: a built-in name (open, balanced,
	// strict), a custom pack name under PackDir, or an absolute path to a
	// pack.yaml or its directory. Empty selects the default pack (open).
	Pack string `mapstructure:"pack" yaml:"pack,omitempty"`
	// PackDir holds custom packs as <name>/pack.yaml. Defaults to
	// <policy_dir>/sandbox.
	PackDir string `mapstructure:"pack_dir" yaml:"pack_dir,omitempty"`
	// Profile overrides the pack's network profile (open|balanced|strict).
	Profile string `mapstructure:"profile" yaml:"profile,omitempty"`
	// Yolo overrides the pack's skip-permissions default for the harness.
	Yolo              *bool                     `mapstructure:"yolo"               yaml:"yolo,omitempty"`
	Workdir           OpenShellWorkdirConfig    `mapstructure:"workdir"            yaml:"workdir,omitempty"`
	Egress            OpenShellEgressConfig     `mapstructure:"egress"             yaml:"egress,omitempty"`
	Image             OpenShellImageConfig      `mapstructure:"image"              yaml:"image,omitempty"`
	Approvals         OpenShellApprovalsConfig  `mapstructure:"approvals"          yaml:"approvals,omitempty"`
	Resources         OpenShellResourcesConfig  `mapstructure:"resources"          yaml:"resources,omitempty"`
	Harnesses         []string                  `mapstructure:"harnesses"          yaml:"harnesses,omitempty"`
	Wrappers          []string                  `mapstructure:"wrappers"           yaml:"wrappers,omitempty"`
	MCP               OpenShellMCPConfig        `mapstructure:"mcp"                yaml:"mcp,omitempty"`
	UpstreamTelemetry bool                      `mapstructure:"upstream_telemetry" yaml:"upstream_telemetry,omitempty"`
	TokenDelivery     string                    `mapstructure:"token_delivery"     yaml:"token_delivery,omitempty"`
	Middleware        OpenShellMiddlewareConfig `mapstructure:"middleware"         yaml:"middleware,omitempty"`
	// Admin holds the administrator's constraints. In managed_enterprise the
	// config file is administrator-owned and Admin is authoritative;
	// elsewhere it is still enforced, but the user owns the file.
	Admin OpenShellAdminConfig `mapstructure:"admin" yaml:"admin,omitempty"`

	// Mode is the legacy openshell-sandbox standalone marker.
	//
	// LEGACY(openshell-0.0.x): delete one release after cleanup.
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
	// SandboxHome is the legacy sandbox user's home directory.
	//
	// LEGACY(openshell-0.0.x): delete one release after cleanup.
	SandboxHome string `mapstructure:"sandbox_home" yaml:"sandbox_home,omitempty"`
}

// OpenShellGatewayConfig selects the local OpenShell gateway registration and
// workspace (tenant). Empty values mean the active registration and the
// "default" workspace.
type OpenShellGatewayConfig struct {
	Name      string `mapstructure:"name"      yaml:"name,omitempty"`
	Workspace string `mapstructure:"workspace" yaml:"workspace,omitempty"`
}

// OpenShellWorkdirConfig controls how the project folder reaches the sandbox.
type OpenShellWorkdirConfig struct {
	// Mode overrides the pack's workspace mode (mount|copy).
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
	// Masks adds secret-file globs to the pack's masks.
	Masks []string `mapstructure:"masks" yaml:"masks,omitempty"`
	// Unmask lists project paths that stay visible despite a mask.
	Unmask []string `mapstructure:"unmask" yaml:"unmask,omitempty"`
	// MaxUploadMB overrides the pack's copy-mode upload cap; 0 inherits.
	MaxUploadMB int    `mapstructure:"max_upload_mb" yaml:"max_upload_mb,omitempty"`
	GitDepth    int    `mapstructure:"git_depth"     yaml:"git_depth,omitempty"`
	OnExit      string `mapstructure:"on_exit"       yaml:"on_exit,omitempty"`
}

// OpenShellEgressConfig adds to the pack's egress posture.
type OpenShellEgressConfig struct {
	Block []string `mapstructure:"block" yaml:"block,omitempty"`
	Allow []string `mapstructure:"allow" yaml:"allow,omitempty"`
	// Ports replaces the pack's proxy port list when non-empty.
	Ports []int `mapstructure:"ports" yaml:"ports,omitempty"`
	// LargeUploadMB overrides the pack's first-seen-host upload alert
	// threshold; 0 inherits.
	LargeUploadMB int `mapstructure:"large_upload_mb" yaml:"large_upload_mb,omitempty"`
	// Feed is "" (the pack's feeds), "builtin", or "none".
	Feed string `mapstructure:"feed" yaml:"feed,omitempty"`
}

// OpenShellImageConfig pins the overlay image inputs. An empty Base selects the
// digest-pinned NVIDIA community base DefenseClaw ships with.
type OpenShellImageConfig struct {
	Base            string            `mapstructure:"base"             yaml:"base,omitempty"`
	HarnessVersions map[string]string `mapstructure:"harness_versions" yaml:"harness_versions,omitempty"`
}

// OpenShellApprovalsConfig tunes OpenShell draft-proposal handling.
type OpenShellApprovalsConfig struct {
	// DebounceMs batches approvals until hooks have been quiet this long,
	// because every OpenShell policy reload closes open connections.
	DebounceMs int `mapstructure:"debounce_ms" yaml:"debounce_ms,omitempty"`
	// AgentProposals lets the agent submit its own policy proposals; nil
	// means true.
	AgentProposals *bool `mapstructure:"agent_proposals" yaml:"agent_proposals,omitempty"`
}

// AgentProposalsEnabled reports whether agent-submitted proposals are
// accepted for triage (default true).
func (a OpenShellApprovalsConfig) AgentProposalsEnabled() bool {
	return a.AgentProposals == nil || *a.AgentProposals
}

// OpenShellResourcesConfig is a sandbox resource request (or, under Admin, a
// ceiling). CPU is cores or millicores ("2", "1.5", "500m"); Memory is bytes
// with an optional binary or decimal suffix ("512Mi", "4Gi", "2G"). Empty
// means unlimited.
type OpenShellResourcesConfig struct {
	CPU    string `mapstructure:"cpu"    yaml:"cpu,omitempty"`
	Memory string `mapstructure:"memory" yaml:"memory,omitempty"`
}

// OpenShellMCPConfig controls how the harness's MCP servers come along.
type OpenShellMCPConfig struct {
	// Import overrides the pack's MCP import default.
	Import *bool `mapstructure:"import" yaml:"import,omitempty"`
	// HostPorts are host localhost ports the user consented to open for
	// host-side MCP servers.
	HostPorts []int `mapstructure:"host_ports" yaml:"host_ports,omitempty"`
}

// OpenShellMiddlewareConfig is the experimental supervisor-middleware switch.
type OpenShellMiddlewareConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
}

// OpenShellAdminConfig is the administrator's sandbox policy. Every field is
// optional; an unset field imposes no constraint. The Allow* switches are
// tri-state so an absent key never reads as "false".
type OpenShellAdminConfig struct {
	// RequiredPack forces the pack (name or absolute path) and makes its
	// posture a floor: user keys and run flags may tighten its profile,
	// skip-permissions default, workspace mode, MCP import, blocklist feeds
	// and proxy ports, but not loosen them. In managed_enterprise a custom
	// required pack must be an administrator-owned file users cannot modify.
	RequiredPack string `mapstructure:"required_pack" yaml:"required_pack,omitempty"`
	// RequiredPackDigest pins RequiredPack's content ("sha256:<hex>", the
	// pack digest `defenseclaw sandbox pack show` reports); a pack with any
	// other content refuses to run.
	RequiredPackDigest string `mapstructure:"required_pack_digest" yaml:"required_pack_digest,omitempty"`
	// MinProfile is the loosest profile allowed (strict > balanced > open).
	MinProfile     string `mapstructure:"min_profile"      yaml:"min_profile,omitempty"`
	AllowYolo      *bool  `mapstructure:"allow_yolo"       yaml:"allow_yolo,omitempty"`
	AllowMount     *bool  `mapstructure:"allow_mount"      yaml:"allow_mount,omitempty"`
	AllowHostPorts *bool  `mapstructure:"allow_host_ports" yaml:"allow_host_ports,omitempty"`
	// AllowUnblock governs one-click unblocks, approve-always, user allow
	// entries and turning the blocklist feed off.
	AllowUnblock   *bool `mapstructure:"allow_unblock"    yaml:"allow_unblock,omitempty"`
	AllowLearnMode *bool `mapstructure:"allow_learn_mode" yaml:"allow_learn_mode,omitempty"`
	// AllowedHarnesses limits which harnesses may run; empty allows all.
	AllowedHarnesses []string `mapstructure:"allowed_harnesses" yaml:"allowed_harnesses,omitempty"`
	// EgressBlock is always merged into the blocklist and cannot be
	// unblocked.
	EgressBlock []string `mapstructure:"egress_block" yaml:"egress_block,omitempty"`
	// EgressAllowOnly forces allowlist mode: no destination outside these
	// host globs is reachable.
	EgressAllowOnly []string `mapstructure:"egress_allow_only" yaml:"egress_allow_only,omitempty"`
	// RequireCopyFor lists project path globs that must use copy mode.
	RequireCopyFor []string                 `mapstructure:"require_copy_for" yaml:"require_copy_for,omitempty"`
	MaxResources   OpenShellResourcesConfig `mapstructure:"max_resources"    yaml:"max_resources,omitempty"`
	// Locked lists openshell keys (OpenShellLockableKeys) that `sandbox run`
	// flags may not override.
	Locked []string `mapstructure:"locked" yaml:"locked,omitempty"`
}

// IsZero reports whether no administrator constraint is configured.
func (a OpenShellAdminConfig) IsZero() bool {
	return a.RequiredPack == "" && a.RequiredPackDigest == "" && a.MinProfile == "" && a.AllowYolo == nil &&
		a.AllowMount == nil && a.AllowHostPorts == nil && a.AllowUnblock == nil &&
		a.AllowLearnMode == nil && len(a.AllowedHarnesses) == 0 &&
		len(a.EgressBlock) == 0 && len(a.EgressAllowOnly) == 0 &&
		len(a.RequireCopyFor) == 0 && a.MaxResources == (OpenShellResourcesConfig{}) &&
		len(a.Locked) == 0
}

// IsLocked reports whether key is listed in Locked.
func (a OpenShellAdminConfig) IsLocked(key string) bool {
	for _, locked := range a.Locked {
		if strings.TrimSpace(locked) == key {
			return true
		}
	}
	return false
}

// IsStandalone reports whether the config still records the legacy
// openshell-sandbox standalone mode.
func (o *OpenShellConfig) IsStandalone() bool {
	return o.Mode == "standalone"
}

// EffectiveSandboxHome returns the recorded legacy sandbox home or the default.
func (o *OpenShellConfig) EffectiveSandboxHome() string {
	if o.SandboxHome != "" {
		return o.SandboxHome
	}
	return DefaultSandboxHome
}

// EffectiveBinary returns the openshell CLI to run.
func (o *OpenShellConfig) EffectiveBinary() string {
	if b := strings.TrimSpace(o.Binary); b != "" {
		return b
	}
	return DefaultOpenShellBinary
}

// EffectiveIngressPort returns the sandbox hook ingress port for a gateway
// API port (0 selects the default API port).
func (o *OpenShellConfig) EffectiveIngressPort(apiPort int) int {
	if o.IngressPort > 0 {
		return o.IngressPort
	}
	return effectiveAPIPort(apiPort) + 1
}

// EffectiveEgressPort returns the egress proxy port for a gateway API port.
func (o *OpenShellConfig) EffectiveEgressPort(apiPort int) int {
	if o.EgressPort > 0 {
		return o.EgressPort
	}
	return effectiveAPIPort(apiPort) + 2
}

// OpenShellIngressPort returns the sandbox hook ingress port of this config.
func (c *Config) OpenShellIngressPort() int {
	return c.OpenShell.EffectiveIngressPort(c.Gateway.APIPort)
}

// OpenShellEgressPort returns the egress proxy port of this config.
func (c *Config) OpenShellEgressPort() int {
	return c.OpenShell.EffectiveEgressPort(c.Gateway.APIPort)
}

func effectiveAPIPort(apiPort int) int {
	if apiPort > 0 {
		return apiPort
	}
	return DefaultGatewayAPIPort
}

// PolicyConnectors returns the connectors whose rule packs and hook
// configuration DefenseClaw serves: the active host connectors plus every
// harness enabled for OpenShell sandboxes (openshell.harnesses), which can run
// in a sandbox without being installed on the host. The result is normalized,
// deduplicated and sorted. Use it for rule packs and hook config only; roster,
// status and inventory surfaces keep using ActiveConnectors.
func (c *Config) PolicyConnectors() []string {
	if c == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var names []string
	add := func(raw string) {
		name := normalizeConnectorKey(raw)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	for _, name := range c.ActiveConnectors() {
		add(name)
	}
	for _, name := range c.OpenShell.Harnesses {
		add(name)
	}
	sort.Strings(names)
	return names
}

// NormalizeConnectorName canonicalizes a connector or harness name the way
// every connector-keyed config lookup does ("claude-code" → "claudecode").
func NormalizeConnectorName(name string) string {
	return normalizeConnectorKey(name)
}

// OpenShellProfileRank orders profiles from loosest (0) to strictest (2). An
// unknown profile returns -1.
func OpenShellProfileRank(profile string) int {
	switch profile {
	case OpenShellProfileOpen:
		return 0
	case OpenShellProfileBalanced:
		return 1
	case OpenShellProfileStrict:
		return 2
	default:
		return -1
	}
}

var (
	openShellNamePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	openShellHostLabel        = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
	openShellCPUPattern       = regexp.MustCompile(`^([0-9]{1,6})(\.[0-9]{1,3})?$|^([0-9]{1,9})m$`)
	openShellMemoryPattern    = regexp.MustCompile(`^([0-9]{1,15})(Ki|Mi|Gi|Ti|k|K|M|G|T)?$`)
	openShellPackDigest       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	openShellMemoryMultiplier = map[string]int64{
		"": 1, "k": 1000, "K": 1000, "M": 1000 * 1000, "G": 1000 * 1000 * 1000,
		"T": 1000 * 1000 * 1000 * 1000, "Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40,
	}
)

// ParseOpenShellCPU parses a CPU quantity ("2", "1.5", "500m") into
// millicores.
func ParseOpenShellCPU(value string) (int64, error) {
	value = strings.TrimSpace(value)
	match := openShellCPUPattern.FindStringSubmatch(value)
	if match == nil {
		return 0, fmt.Errorf("cpu %q must be cores (\"2\", \"1.5\") or millicores (\"500m\")", value)
	}
	if match[3] != "" {
		milli, err := strconv.ParseInt(match[3], 10, 64)
		if err != nil || milli <= 0 {
			return 0, fmt.Errorf("cpu %q must be positive", value)
		}
		return milli, nil
	}
	whole, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cpu %q is out of range", value)
	}
	milli := whole * 1000
	if frac := strings.TrimPrefix(match[2], "."); frac != "" {
		for len(frac) < 3 {
			frac += "0"
		}
		part, _ := strconv.ParseInt(frac, 10, 64)
		milli += part
	}
	if milli <= 0 {
		return 0, fmt.Errorf("cpu %q must be positive", value)
	}
	return milli, nil
}

// ParseOpenShellMemory parses a memory quantity ("512Mi", "4Gi", "2G",
// "1073741824") into bytes.
func ParseOpenShellMemory(value string) (int64, error) {
	value = strings.TrimSpace(value)
	match := openShellMemoryPattern.FindStringSubmatch(value)
	if match == nil {
		return 0, fmt.Errorf("memory %q must be bytes with an optional Ki/Mi/Gi/Ti or k/M/G/T suffix", value)
	}
	number, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || number <= 0 {
		return 0, fmt.Errorf("memory %q must be positive", value)
	}
	multiplier := openShellMemoryMultiplier[match[2]]
	if number > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("memory %q is out of range", value)
	}
	return number * multiplier, nil
}

// NormalizeOpenShellHostGlob lowercases a host glob and strips a trailing dot.
func NormalizeOpenShellHostGlob(glob string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(glob)), ".")
}

// ValidateOpenShellHostGlob accepts "*", an exact host name, "*.<host>"
// (every subdomain, not the apex), or an IP literal. Schemes, ports, paths and
// inner wildcards are rejected.
func ValidateOpenShellHostGlob(glob string) error {
	g := NormalizeOpenShellHostGlob(glob)
	switch {
	case g == "":
		return errors.New("host glob is empty")
	case g == "*":
		return nil
	case net.ParseIP(strings.Trim(g, "[]")) != nil:
		return nil
	case len(g) > 253:
		return fmt.Errorf("host glob %q is longer than 253 characters", glob)
	}
	name := strings.TrimPrefix(g, "*.")
	for _, label := range strings.Split(name, ".") {
		if !openShellHostLabel.MatchString(label) {
			return fmt.Errorf("host glob %q must be a host name, \"*.<host>\", \"*\" or an IP address", glob)
		}
	}
	return nil
}

// ValidateOpenShell checks the openshell section (OpenShellConfig.Validate)
// and, when the sandbox integration is enabled, that its effective listener
// ports are usable and collide neither with each other nor with DefenseClaw's
// API and guardrail proxy. A disabled integration binds nothing, so its derived
// ports are not checked.
func (c *Config) ValidateOpenShell() error {
	if c == nil {
		return nil
	}
	if err := c.OpenShell.Validate(); err != nil {
		return err
	}
	if !c.OpenShell.Enabled {
		return nil
	}
	return c.validateOpenShellListeners()
}

func (c *Config) validateOpenShellListeners() error {
	apiPort := effectiveAPIPort(c.Gateway.APIPort)
	listeners := []struct {
		key  string
		port int
	}{
		{"ingress_port", c.OpenShellIngressPort()},
		{"egress_port", c.OpenShellEgressPort()},
	}
	var errs []error
	for _, l := range listeners {
		if l.port > 65535 {
			errs = append(errs, fmt.Errorf("%s: gateway.api_port %d leaves no room for the derived port %d; set openshell.%s",
				l.key, apiPort, l.port, l.key))
			continue
		}
		if l.port == apiPort {
			errs = append(errs, fmt.Errorf("%s %d collides with gateway.api_port", l.key, l.port))
		}
		if c.Guardrail.Port > 0 && l.port == c.Guardrail.Port {
			errs = append(errs, fmt.Errorf("%s %d collides with guardrail.port", l.key, l.port))
		}
	}
	if in, eg := listeners[0].port, listeners[1].port; in == eg {
		errs = append(errs, fmt.Errorf("ingress_port and egress_port resolve to the same port %d", in))
	}
	return errors.Join(errs...)
}

// Validate checks the openshell section's values and relationships. The v8
// schema owns shape; this also protects programmatic configs and checks what
// the schema cannot express (quantities, distinct ports, known lockable keys).
// Config.ValidateOpenShell adds the checks that need the rest of the config.
func (o *OpenShellConfig) Validate() error {
	if o == nil {
		return nil
	}
	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	check(validateOpenShellPort("ingress_port", o.IngressPort, true))
	check(validateOpenShellPort("egress_port", o.EgressPort, true))
	if o.IngressPort != 0 && o.IngressPort == o.EgressPort {
		check(fmt.Errorf("ingress_port and egress_port must differ (both %d)", o.IngressPort))
	}
	check(validateOpenShellEnum("profile", o.Profile, true,
		OpenShellProfileOpen, OpenShellProfileBalanced, OpenShellProfileStrict))
	check(validateOpenShellEnum("workdir.mode", o.Workdir.Mode, true,
		OpenShellWorkdirMount, OpenShellWorkdirCopy))
	check(validateOpenShellEnum("workdir.on_exit", o.Workdir.OnExit, true,
		OpenShellOnExitAsk, OpenShellOnExitKeep, OpenShellOnExitUndo))
	check(validateOpenShellEnum("egress.feed", o.Egress.Feed, true,
		OpenShellFeedBuiltin, OpenShellFeedNone))
	check(validateOpenShellEnum("token_delivery", o.TokenDelivery, true,
		OpenShellTokenDeliveryProvider, OpenShellTokenDeliveryEnv))
	check(validateOpenShellNonNegative("workdir.max_upload_mb", o.Workdir.MaxUploadMB))
	check(validateOpenShellNonNegative("workdir.git_depth", o.Workdir.GitDepth))
	check(validateOpenShellNonNegative("egress.large_upload_mb", o.Egress.LargeUploadMB))
	check(validateOpenShellNonNegative("approvals.debounce_ms", o.Approvals.DebounceMs))
	for i, port := range o.Egress.Ports {
		check(validateOpenShellPort(fmt.Sprintf("egress.ports[%d]", i), port, false))
	}
	for i, port := range o.MCP.HostPorts {
		check(validateOpenShellPort(fmt.Sprintf("mcp.host_ports[%d]", i), port, false))
	}
	check(validateOpenShellHostGlobs("egress.block", o.Egress.Block))
	check(validateOpenShellHostGlobs("egress.allow", o.Egress.Allow))
	check(validateOpenShellNames("harnesses", o.Harnesses))
	check(validateOpenShellNames("wrappers", o.Wrappers))
	for name := range o.Image.HarnessVersions {
		if !openShellNamePattern.MatchString(name) {
			check(fmt.Errorf("image.harness_versions: invalid harness name %q", name))
		}
	}
	check(validateOpenShellResources("resources", o.Resources))
	check(o.Admin.validate())
	return errors.Join(errs...)
}

func (a *OpenShellAdminConfig) validate() error {
	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if a.RequiredPackDigest != "" {
		if !openShellPackDigest.MatchString(a.RequiredPackDigest) {
			check(fmt.Errorf("admin.required_pack_digest %q must be sha256:<64 lowercase hex digits>", a.RequiredPackDigest))
		}
		if strings.TrimSpace(a.RequiredPack) == "" {
			check(errors.New("admin.required_pack_digest needs admin.required_pack"))
		}
	}
	check(validateOpenShellEnum("admin.min_profile", a.MinProfile, true,
		OpenShellProfileOpen, OpenShellProfileBalanced, OpenShellProfileStrict))
	check(validateOpenShellNames("admin.allowed_harnesses", a.AllowedHarnesses))
	check(validateOpenShellHostGlobs("admin.egress_block", a.EgressBlock))
	check(validateOpenShellHostGlobs("admin.egress_allow_only", a.EgressAllowOnly))
	for i, glob := range a.RequireCopyFor {
		if strings.TrimSpace(glob) == "" {
			check(fmt.Errorf("admin.require_copy_for[%d] is empty", i))
		}
	}
	check(validateOpenShellResources("admin.max_resources", a.MaxResources))
	for i, key := range a.Locked {
		if !isOpenShellLockableKey(strings.TrimSpace(key)) {
			check(fmt.Errorf("admin.locked[%d]: %q is not a lockable key (want one of %s)",
				i, key, strings.Join(OpenShellLockableKeys, ", ")))
		}
	}
	return errors.Join(errs...)
}

func isOpenShellLockableKey(key string) bool {
	for _, known := range OpenShellLockableKeys {
		if key == known {
			return true
		}
	}
	return false
}

func validateOpenShellPort(field string, port int, zeroOK bool) error {
	if port == 0 && zeroOK {
		return nil
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s %d must be between 1 and 65535", field, port)
	}
	return nil
}

func validateOpenShellNonNegative(field string, value int) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative", field)
	}
	return nil
}

func validateOpenShellEnum(field, value string, emptyOK bool, allowed ...string) error {
	if value == "" && emptyOK {
		return nil
	}
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s %q must be one of %s", field, value, strings.Join(allowed, ", "))
}

func validateOpenShellNames(field string, names []string) error {
	for i, name := range names {
		if !openShellNamePattern.MatchString(strings.TrimSpace(name)) {
			return fmt.Errorf("%s[%d]: invalid name %q", field, i, name)
		}
	}
	return nil
}

func validateOpenShellHostGlobs(field string, globs []string) error {
	for i, glob := range globs {
		if err := ValidateOpenShellHostGlob(glob); err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
	}
	return nil
}

func validateOpenShellResources(field string, r OpenShellResourcesConfig) error {
	if r.CPU != "" {
		if _, err := ParseOpenShellCPU(r.CPU); err != nil {
			return fmt.Errorf("%s.%w", field, err)
		}
	}
	if r.Memory != "" {
		if _, err := ParseOpenShellMemory(r.Memory); err != nil {
			return fmt.Errorf("%s.%w", field, err)
		}
	}
	return nil
}
