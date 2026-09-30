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
	"net/netip"
	"path"
	"path/filepath"
	"regexp"
	"slices"
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

// The model credential a sandbox run shares (openshell.llm, and `sandbox run
// --llm`, which overrides it for one run): auto takes the first one found for
// the harness, none shares none, and a provider shares that one only.
const (
	OpenShellLLMAuto        = "auto"
	OpenShellLLMNone        = "none"
	OpenShellLLMAnthropic   = "anthropic"
	OpenShellLLMClaudeOAuth = "claude-oauth"
	OpenShellLLMOpenAI      = "openai"
	OpenShellLLMBedrock     = "bedrock"
	OpenShellLLMGemini      = "gemini"
)

// OpenShellLLMChoices are the values openshell.llm and `sandbox run --llm`
// take.
var OpenShellLLMChoices = []string{
	OpenShellLLMAuto, OpenShellLLMNone, OpenShellLLMAnthropic, OpenShellLLMClaudeOAuth,
	OpenShellLLMOpenAI, OpenShellLLMBedrock, OpenShellLLMGemini,
}

// Loader defaults for the openshell section. Keys the sandbox policy pack
// governs (profile, yolo, workdir mode, upload caps, egress lists, MCP import)
// have no loader default: an unset key inherits the pack's value.
const (
	DefaultOpenShellBinary             = "openshell"
	DefaultOpenShellApprovalDebounceMs = 3000
	DefaultOpenShellGitDepth           = 200
	DefaultOpenShellOnExit             = OpenShellOnExitAsk
	DefaultOpenShellTokenDelivery      = OpenShellTokenDeliveryProvider
	DefaultOpenShellLLM                = OpenShellLLMAuto
	// DefaultOpenShellUndoIgnoredMaxMB caps the copies of
	// openshell.workdir.undo_ignored, in MiB.
	DefaultOpenShellUndoIgnoredMaxMB = 500
	// DefaultOpenShellPackDirName is the directory under <policy_dir> that
	// holds custom sandbox policy packs (<name>/pack.yaml), mirroring the
	// repository's policies/sandbox layout.
	DefaultOpenShellPackDirName = "sandbox"

	// DefaultSandboxHome is the legacy openshell-sandbox user's home.
	//
	// LEGACY(openshell-0.0.x): delete one release after cleanup.
	DefaultSandboxHome = "/home/sandbox"
)

// DefaultOpenShellUndoIgnoredDirs are the directories
// openshell.workdir.undo_ignored keeps a copy of when it names none: the
// installed-package directories whose files run on this machine.
var DefaultOpenShellUndoIgnoredDirs = []string{"node_modules", ".venv", "venv"}

// OpenShellLockableKeys are the openshell keys an administrator can list in
// openshell.admin.locked so `sandbox run` flags cannot loosen them.
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
	// transfer, port forwarding and gateway registration: a command name
	// looked up on PATH or an absolute path.
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
	// PackDir holds custom packs as <name>/pack.yaml: an absolute path or one
	// starting with "~/" (the v8 schema refuses a relative one, which the pack
	// loader would refuse for every custom pack name). Defaults to
	// <data_dir>/policies/sandbox; an explicit empty value means no custom
	// packs.
	PackDir string `mapstructure:"pack_dir" yaml:"pack_dir,omitempty"`
	// Profile overrides the pack's network profile (open|balanced|strict).
	Profile string `mapstructure:"profile" yaml:"profile,omitempty"`
	// Yolo overrides the pack's skip-permissions default for the harness.
	Yolo *bool `mapstructure:"yolo" yaml:"yolo,omitempty"`
	// LLM is the model credential a run shares with its sandbox
	// (OpenShellLLMChoices): the default of `sandbox run --llm`, so the runs
	// the shell wrappers, the TUI and the macOS app start, which pass no
	// --llm, take it too. Empty means auto.
	LLM string `mapstructure:"llm" yaml:"llm,omitempty"`
	// KeepHeadless keeps the sandbox a one-prompt `sandbox run --prompt` (or
	// a harness print mode, such as the shell wrapper's `claude -p`) creates
	// in the foreground, as `sandbox run --keep` does for one run. By default
	// that sandbox is deleted when the run ends and nothing is left in it to
	// bring back or undo, by the rules of --rm.
	KeepHeadless      bool                      `mapstructure:"keep_headless"      yaml:"keep_headless,omitempty"`
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
	// UndoIgnored keeps, with a mounted project's undo point, a copy of the
	// dependency directories git ignores, so `sandbox undo` restores them.
	UndoIgnored OpenShellUndoIgnoredConfig `mapstructure:"undo_ignored" yaml:"undo_ignored,omitempty"`
}

// OpenShellUndoIgnoredConfig is openshell.workdir.undo_ignored. The undo
// point of a mounted project (Linux mount mode) holds no copy of what git
// ignores, so undo only reports what a session changed in node_modules or
// .venv; with Enabled, each undo point keeps a copy of the directories named
// Dirs (at any depth), as file clones where the filesystem supports them and
// byte copies otherwise, up to MaxMB of file content, and undo restores
// them. A directory whose copy would pass the cap is reported as before.
// Copy mode, every sandbox on a Mac, has no undo point and is unaffected.
type OpenShellUndoIgnoredConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// MaxMB caps the copies of one undo point, in MiB; 0 means
	// DefaultOpenShellUndoIgnoredMaxMB.
	MaxMB int `mapstructure:"max_mb" yaml:"max_mb,omitempty"`
	// Dirs are directory names ("node_modules"); empty means
	// DefaultOpenShellUndoIgnoredDirs.
	Dirs []string `mapstructure:"dirs" yaml:"dirs,omitempty"`
}

// EffectiveMaxBytes is the cap on the copies, in bytes.
func (u OpenShellUndoIgnoredConfig) EffectiveMaxBytes() int64 {
	mb := u.MaxMB
	if mb <= 0 {
		mb = DefaultOpenShellUndoIgnoredMaxMB
	}
	return int64(mb) << 20
}

// EffectiveDirs are the directory names kept.
func (u OpenShellUndoIgnoredConfig) EffectiveDirs() []string {
	var out []string
	for _, d := range u.Dirs {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultOpenShellUndoIgnoredDirs...)
	}
	return out
}

// openShellUndoIgnoredDir is one path segment that is not "." or "..":
// a directory name matched at any depth.
var openShellUndoIgnoredDir = regexp.MustCompile(`^\.?[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)

func validateOpenShellUndoIgnored(u OpenShellUndoIgnoredConfig) error {
	if u.MaxMB < 0 || u.MaxMB > 1<<20 {
		return fmt.Errorf("workdir.undo_ignored.max_mb %d must be between 0 and %d", u.MaxMB, 1<<20)
	}
	for i, d := range u.Dirs {
		if !openShellUndoIgnoredDir.MatchString(d) || d == ".git" {
			return fmt.Errorf("workdir.undo_ignored.dirs[%d]: %q must be a directory name such as node_modules or .venv (not .git, no \"/\")", i, d)
		}
	}
	return nil
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
	// BlockLargeUploads also cuts the upload that crosses that threshold
	// and refuses later requests to the destination, for every sandbox;
	// false follows the pack's egress.block_large_uploads. An unblock of
	// the destination, or an allow entry naming it, lifts the block.
	BlockLargeUploads bool `mapstructure:"block_large_uploads" yaml:"block_large_uploads,omitempty"`
	// Feed is "" (the pack's feeds), "builtin", or "none".
	Feed string `mapstructure:"feed" yaml:"feed,omitempty"`
	// Unblocked are the destinations the user unblocked or approved for
	// every sandbox ("always" decisions, written by the daemon). Unlike
	// Allow, which is operator configuration and may open a private address
	// a listed name resolves to, an unblock only lifts blocklist-feed and
	// allowlist refusals: the private-address guard still applies.
	Unblocked []string `mapstructure:"unblocked" yaml:"unblocked,omitempty"`
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
	// unblocked. A host name on it also blocks every subdomain
	// (OpenShellAdminBlockPatterns).
	EgressBlock []string `mapstructure:"egress_block" yaml:"egress_block,omitempty"`
	// EgressAllowOnly forces allowlist mode: no destination outside these
	// host globs is reachable. Its entries match exactly: a host name
	// admits that host only.
	EgressAllowOnly []string `mapstructure:"egress_allow_only" yaml:"egress_allow_only,omitempty"`
	// BlockLargeUploads turns the large-upload block on for every sandbox
	// whatever its pack and the user's keys say
	// (openshell.egress.block_large_uploads), and keeps the report it acts
	// on from being turned off: a pack's large_upload_mb of 0 takes the
	// default threshold. False imposes nothing.
	BlockLargeUploads bool `mapstructure:"block_large_uploads" yaml:"block_large_uploads,omitempty"`
	// RequireCopyFor lists project path globs that must use copy mode.
	RequireCopyFor []string                 `mapstructure:"require_copy_for" yaml:"require_copy_for,omitempty"`
	MaxResources   OpenShellResourcesConfig `mapstructure:"max_resources"    yaml:"max_resources,omitempty"`
	// Locked lists openshell keys (OpenShellLockableKeys) that `sandbox run`
	// flags may not loosen. Flags that only tighten a locked key (--safe,
	// --copy, --no-mcp, a stricter --pack or --profile, a smaller resource
	// request) still apply.
	Locked []string `mapstructure:"locked" yaml:"locked,omitempty"`
}

// IsZero reports whether no administrator constraint is configured.
func (a OpenShellAdminConfig) IsZero() bool {
	return a.RequiredPack == "" && a.RequiredPackDigest == "" && a.MinProfile == "" && a.AllowYolo == nil &&
		a.AllowMount == nil && a.AllowHostPorts == nil && a.AllowUnblock == nil &&
		a.AllowLearnMode == nil && len(a.AllowedHarnesses) == 0 &&
		len(a.EgressBlock) == 0 && len(a.EgressAllowOnly) == 0 && !a.BlockLargeUploads &&
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

// openShellHarnessVersionKey is openShellNamePattern without ".": the config
// loader (viper) reads a dotted image.harness_versions key as a key path, so
// such a key never loads.
var openShellHarnessVersionKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

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

// OpenShellEgressPattern is a parsed egress host pattern: an exact host name,
// "*.<host>" (every subdomain at any depth, not the apex), an IP address or a
// CIDR prefix. It is the grammar of the DefenseClaw egress proxy's block and
// allow lists (internal/openshell/egress), so every list the configuration or
// a sandbox policy pack hands the proxy parses there too.
type OpenShellEgressPattern struct {
	// Host is the DNS name of an exact or wildcard pattern: lower case,
	// without a trailing dot.
	Host string
	// Wildcard reports a "*.<Host>" pattern.
	Wildcard bool
	// Prefix is set for an IP address (a single-address prefix) or a CIDR
	// prefix: masked, with an IPv4-mapped IPv6 address or prefix unmapped to
	// its IPv4 form, so every spelling of an address compares equal.
	Prefix netip.Prefix
}

// String returns the pattern's canonical spelling: "example.com",
// "*.example.com", "192.0.2.1", "2001:db8::1" or "10.0.0.0/8".
func (p OpenShellEgressPattern) String() string {
	switch {
	case p.Prefix.IsValid() && p.Prefix.IsSingleIP():
		return p.Prefix.Addr().String()
	case p.Prefix.IsValid():
		return p.Prefix.String()
	case p.Wildcard:
		return "*." + p.Host
	default:
		return p.Host
	}
}

// Matches reports whether a destination matches the pattern: an IP pattern
// matches the IP destinations it contains, a name pattern matches names only.
// host and addr are what NormalizeOpenShellHost returns.
func (p OpenShellEgressPattern) Matches(host string, addr netip.Addr) bool {
	switch {
	case p.Prefix.IsValid():
		return addr.IsValid() && p.Prefix.Contains(addr.Unmap().WithZone(""))
	case addr.IsValid() || p.Host == "":
		return false
	case p.Wildcard:
		return strings.HasSuffix(host, "."+p.Host)
	default:
		return host == p.Host
	}
}

// Covers reports whether every destination inner matches also matches p.
func (p OpenShellEgressPattern) Covers(inner OpenShellEgressPattern) bool {
	switch {
	case p.Prefix.IsValid() || inner.Prefix.IsValid():
		return p.Prefix.IsValid() && inner.Prefix.IsValid() &&
			p.Prefix.Bits() <= inner.Prefix.Bits() && p.Prefix.Contains(inner.Prefix.Addr())
	case p.Wildcard:
		return inner.Wildcard && inner.Host == p.Host || strings.HasSuffix(inner.Host, "."+p.Host)
	default:
		return !inner.Wildcard && inner.Host == p.Host
	}
}

// openShellPrefixBits is a CIDR prefix length without leading zeros.
var openShellPrefixBits = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})$`)

// ParseOpenShellEgressPattern parses an egress host pattern (see
// OpenShellEgressPattern). Surrounding space and case are ignored, a host
// name may end in one dot, and an IP address may be bracketed. Refused:
//   - "*" and inner wildcards: allowing or blocking every host is a network
//     mode, not a list entry (the open profile allows by default, strict
//     turns the web off);
//   - schemes, ports, paths, zoned IPv6 addresses and bracketed prefixes;
//   - host names whose labels are not 1-63 letters, digits, "_" or inner
//     "-", or that are longer than 253 characters;
//   - names whose last label does not start with a letter ("127.1",
//     "2130706433", "0x7f000001", "01.2.3.4"): resolvers read those as IPv4
//     addresses, which would slip past every name comparison.
func ParseOpenShellEgressPattern(pattern string) (OpenShellEgressPattern, error) {
	p := strings.ToLower(strings.TrimSpace(pattern))
	invalid := func() (OpenShellEgressPattern, error) {
		return OpenShellEgressPattern{}, fmt.Errorf(
			"egress pattern %q must be a host name, \"*.<host>\", an IP address or a CIDR prefix", pattern)
	}
	switch {
	case p == "":
		return OpenShellEgressPattern{}, errors.New("egress pattern is empty")
	case p == "*":
		return OpenShellEgressPattern{}, errors.New(`egress pattern "*" matches every host; choose the profile instead ` +
			`(open allows by default, strict turns the web off)`)
	case strings.HasPrefix(p, "*."):
		host, ok := openShellEgressHostName(p[2:])
		if !ok {
			return invalid()
		}
		return OpenShellEgressPattern{Host: host, Wildcard: true}, nil
	case strings.Contains(p, "*"):
		return invalid()
	case strings.Contains(p, "/"):
		addrPart, bits, _ := strings.Cut(p, "/")
		addr, err := netip.ParseAddr(addrPart)
		if err != nil || addr.Zone() != "" || !openShellPrefixBits.MatchString(bits) {
			return invalid()
		}
		n, _ := strconv.Atoi(bits)
		if n > addr.BitLen() {
			return invalid()
		}
		if addr.Is4In6() {
			if n < 96 {
				return OpenShellEgressPattern{}, fmt.Errorf("egress pattern %q: an IPv4-mapped prefix must be at least /96", pattern)
			}
			addr, n = addr.Unmap(), n-96
		}
		return OpenShellEgressPattern{Prefix: netip.PrefixFrom(addr, n).Masked()}, nil
	}
	if addr, ok := parseOpenShellAddr(p); ok {
		if addr.Zone() != "" {
			return OpenShellEgressPattern{}, fmt.Errorf("egress pattern %q: zoned IPv6 addresses are not destinations", pattern)
		}
		return OpenShellEgressPattern{Prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
	}
	host, ok := openShellEgressHostName(p)
	if !ok {
		return invalid()
	}
	return OpenShellEgressPattern{Host: host}, nil
}

// ValidateOpenShellEgressPattern checks one egress host pattern
// (ParseOpenShellEgressPattern).
func ValidateOpenShellEgressPattern(pattern string) error {
	_, err := ParseOpenShellEgressPattern(pattern)
	return err
}

// NormalizeOpenShellEgressPattern returns a pattern's canonical spelling
// (OpenShellEgressPattern.String), or, for a pattern that does not parse, the
// pattern lowercased and trimmed.
func NormalizeOpenShellEgressPattern(pattern string) string {
	if parsed, err := ParseOpenShellEgressPattern(pattern); err == nil {
		return parsed.String()
	}
	return strings.ToLower(strings.TrimSpace(pattern))
}

// OpenShellAdminBlockPatterns returns the egress patterns an
// openshell.admin.egress_block list enforces, canonically spelled and
// without duplicates. A host name blocks the host and every subdomain:
// "example.net" also yields "*.example.net", since an administrator who
// blocks a domain means all of it. Wildcards, IP addresses and CIDR
// prefixes stay as they are, and an entry that does not parse is kept
// lowercased and trimmed (validation refuses it).
//
// Only the administrator's block list widens so: openshell.egress.block and
// the packs' block lists, and openshell.admin.egress_allow_only, match
// exactly (widening an allow-only list would open more than it names).
func OpenShellAdminBlockPatterns(entries []string) []string {
	out := []string{}
	add := func(p string) {
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, entry := range entries {
		p, err := ParseOpenShellEgressPattern(entry)
		switch {
		case err != nil:
			add(strings.ToLower(strings.TrimSpace(entry)))
		case p.Prefix.IsValid() || p.Wildcard:
			add(p.String())
		default:
			add(p.String())
			add("*." + p.Host)
		}
	}
	return out
}

// NormalizeOpenShellHost canonicalizes a destination host the way egress
// patterns are: an IP address (optionally bracketed) in canonical form, an
// IPv4-mapped IPv6 address unmapped and a zone dropped, and also returned as
// addr; anything else lowercased and trimmed, without one trailing dot. It
// does not validate the host.
func NormalizeOpenShellHost(host string) (string, netip.Addr) {
	h := strings.TrimSpace(host)
	if addr, ok := parseOpenShellAddr(h); ok {
		addr = addr.WithZone("")
		return addr.String(), addr
	}
	return strings.TrimSuffix(strings.ToLower(h), "."), netip.Addr{}
}

// parseOpenShellAddr parses an IP address, optionally in brackets, and
// unmaps an IPv4-mapped IPv6 address.
func parseOpenShellAddr(s string) (netip.Addr, bool) {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// openShellEgressHostName validates the lowercased DNS name of an egress
// pattern and strips one trailing dot.
func openShellEgressHostName(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return "", false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !openShellHostLabel.MatchString(label) {
			return "", false
		}
	}
	if last := labels[len(labels)-1]; last[0] < 'a' || last[0] > 'z' {
		return "", false
	}
	return name, true
}

// MaxOpenShellProjectGlobBytes bounds one project-relative glob.
const MaxOpenShellProjectGlobBytes = 4096

// ValidateOpenShellProjectGlob accepts a project-relative glob (workdir masks
// and unmask entries, `sandbox run --unmask`, and a sandbox pack's masks and
// review globs): not empty, at most MaxOpenShellProjectGlobBytes, no NUL byte,
// forward slashes only, and neither absolute ("/…", "~…", "C:…") nor escaping
// the project through a ".." segment.
func ValidateOpenShellProjectGlob(glob string) error {
	g := strings.TrimSpace(glob)
	switch {
	case g == "":
		return errors.New("project glob is empty")
	case len(g) > MaxOpenShellProjectGlobBytes:
		return fmt.Errorf("project glob is longer than %d bytes", MaxOpenShellProjectGlobBytes)
	case strings.ContainsRune(g, 0):
		return errors.New("project glob contains a NUL byte")
	case strings.HasPrefix(g, "/") || strings.HasPrefix(g, "~") || strings.Contains(g, `\`) || hasDriveLetter(g):
		return fmt.Errorf("%q must be a project-relative glob with forward slashes", glob)
	}
	for _, segment := range strings.Split(g, "/") {
		if segment == ".." {
			return fmt.Errorf("%q must not contain \"..\"", glob)
		}
	}
	return nil
}

func hasDriveLetter(p string) bool {
	return len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// ValidateOpenShellCopyPattern accepts an openshell.admin.require_copy_for
// entry: an absolute path glob ("/src/customer-*", or "C:/src/*" with a drive
// letter), one under the home directory ("~" or "~/…"), or one that matches
// at any depth ("**" or "**/customer-*"; since any folder may hold a match
// below it, such a pattern covers every mount). A relative pattern such as
// "customer-*" is refused: it would be matched from the filesystem root and
// silently cover nothing. "*", "?" and "[…]" work within a path segment, and
// every segment must be a well-formed glob (path.Match).
func ValidateOpenShellCopyPattern(pattern string) error {
	p := strings.TrimSpace(pattern)
	switch {
	case p == "":
		return errors.New("pattern is empty")
	case strings.ContainsRune(p, 0):
		return errors.New("pattern contains a NUL byte")
	case !strings.HasPrefix(p, "/") && p != "~" && !strings.HasPrefix(p, "~/") && p != "**" &&
		!strings.HasPrefix(p, "**/") && !(hasDriveLetter(p) && len(p) > 2 && (p[2] == '/' || p[2] == '\\')):
		return fmt.Errorf("%q must be an absolute path glob or start with \"~/\"; a relative pattern would never match", pattern)
	}
	for _, segment := range strings.Split(p, "/") {
		if _, err := path.Match(segment, ""); err != nil {
			return fmt.Errorf("%q has a malformed glob segment %q", pattern, segment)
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
	check(validateOpenShellBinary(o.Binary))
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
	check(validateOpenShellEnum("llm", o.LLM, true, OpenShellLLMChoices...))
	check(validateOpenShellNonNegative("workdir.max_upload_mb", o.Workdir.MaxUploadMB))
	check(validateOpenShellNonNegative("workdir.git_depth", o.Workdir.GitDepth))
	check(validateOpenShellUndoIgnored(o.Workdir.UndoIgnored))
	check(validateOpenShellNonNegative("egress.large_upload_mb", o.Egress.LargeUploadMB))
	check(validateOpenShellNonNegative("approvals.debounce_ms", o.Approvals.DebounceMs))
	for i, port := range o.Egress.Ports {
		check(validateOpenShellPort(fmt.Sprintf("egress.ports[%d]", i), port, false))
	}
	for i, port := range o.MCP.HostPorts {
		check(validateOpenShellPort(fmt.Sprintf("mcp.host_ports[%d]", i), port, false))
	}
	check(ValidateOpenShellProjectGlobs("workdir.masks", o.Workdir.Masks))
	check(ValidateOpenShellProjectGlobs("workdir.unmask", o.Workdir.Unmask))
	check(validateOpenShellEgressPatterns("egress.block", o.Egress.Block))
	check(validateOpenShellEgressPatterns("egress.allow", o.Egress.Allow))
	check(validateOpenShellEgressPatterns("egress.unblocked", o.Egress.Unblocked))
	check(validateOpenShellNames("harnesses", o.Harnesses))
	check(validateOpenShellNames("wrappers", o.Wrappers))
	for name := range o.Image.HarnessVersions {
		if !openShellHarnessVersionKey.MatchString(name) {
			check(fmt.Errorf("image.harness_versions: invalid harness name %q (use letters, digits, \"_\" and \"-\")", name))
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
	check(validateOpenShellEgressPatterns("admin.egress_block", a.EgressBlock))
	check(validateOpenShellEgressPatterns("admin.egress_allow_only", a.EgressAllowOnly))
	for i, pattern := range a.RequireCopyFor {
		if err := ValidateOpenShellCopyPattern(pattern); err != nil {
			check(fmt.Errorf("admin.require_copy_for[%d]: %w", i, err))
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

// validateOpenShellBinary accepts the default (empty), a command name looked
// up on PATH, or an absolute path. A relative path with a separator
// ("bin/openshell", "./openshell", "~/bin/openshell": nothing expands "~")
// would run from the working directory: for `sandbox run` and `sandbox
// connect` that is the project folder, which may be an untrusted repository.
func validateOpenShellBinary(binary string) error {
	b := strings.TrimSpace(binary)
	if b == "" || filepath.IsAbs(b) || !strings.ContainsAny(b, `/\`) {
		return nil
	}
	return fmt.Errorf("binary %q must be a command name on PATH or an absolute path", binary)
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

// ValidateOpenShellProjectGlobs checks every entry of a project glob list
// (ValidateOpenShellProjectGlob) and names the first bad one by index.
func ValidateOpenShellProjectGlobs(field string, globs []string) error {
	for i, glob := range globs {
		if err := ValidateOpenShellProjectGlob(glob); err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
	}
	return nil
}

func validateOpenShellEgressPatterns(field string, patterns []string) error {
	for i, pattern := range patterns {
		if err := ValidateOpenShellEgressPattern(pattern); err != nil {
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
