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
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/routing"
)

// OpenShellGatewayPort is the local OpenShell gateway's default port. A
// sandbox must never reach the gateway: it accepts host mount requests.
// Resolve reserves Flags.OpenShellGatewayPort, the registered gateway's
// port, and this default only when the registration's port is unknown.
const OpenShellGatewayPort = 17670

// openClawGatewayPort is the config loader's default gateway.port (the
// OpenClaw gateway WebSocket), for configs built without the loader.
const openClawGatewayPort = 18789

// Source names the layer a setting came from.
type Source string

const (
	// SourceDefault is a DefenseClaw default outside any pack.
	SourceDefault Source = "default"
	// SourcePack is the selected sandbox policy pack.
	SourcePack Source = "pack"
	// SourceUser is an openshell key in config.yaml, or a runtime request
	// (an unblock, an approval) the user made.
	SourceUser Source = "user"
	// SourceFlag is a `sandbox run` flag.
	SourceFlag Source = "flag"
	// SourceAdmin is an openshell.admin constraint.
	SourceAdmin Source = "admin"
	// SourceGateway is what the OpenShell gateway the sandbox runs on
	// decides: its compute driver (ConstraintComputeDriver).
	SourceGateway Source = "gateway"
	// SourceRepo is the project's repository policy (RepoPolicyPath),
	// which only tightens.
	SourceRepo Source = "repo"
)

// Flags are the `sandbox run` inputs that take part in resolution. Zero values
// mean "not given".
type Flags struct {
	// Pack is --pack (a pack reference, see Load).
	Pack string
	// Harness is the harness to run (claudecode, codex, ...).
	Harness string
	// Project is the absolute host path of the launch folder; it is
	// matched against openshell.admin.require_copy_for. When that list is
	// set and Project is empty, the workspace falls back to copy mode.
	Project string
	// Profile is --profile open|balanced|strict.
	Profile string
	// Copy is --copy.
	Copy bool
	// Safe is --safe (keep the harness permission prompts). It wins over
	// Yolo when both are set.
	Safe bool
	// Yolo explicitly asks for skip-permissions mode.
	Yolo bool
	// Unmask are --unmask project-relative globs (see
	// config.ValidateOpenShellProjectGlob).
	Unmask []string
	// HostPorts are --host-port ports.
	HostPorts []int
	// NoMCP is --no-mcp.
	NoMCP bool
	// Learn asks for learn mode (observe-and-suggest policy discovery).
	Learn bool
	// ProcessTree is --process-tree: sample the sandbox's processes even
	// where the pack leaves the process tree off.
	ProcessTree bool
	// CPU and Memory are resource requests (see config.ParseOpenShellCPU).
	CPU    string
	Memory string
	// OpenShellGatewayPort is not a flag: it is the port of the OpenShell
	// gateway registration the run uses (metadata.json gateway_port). It is
	// reserved like DefenseClaw's own listeners; 0 reserves the default
	// OpenShellGatewayPort instead.
	OpenShellGatewayPort int
	// MountUnsupported is not a flag either: why the compute driver of the
	// gateway the run uses cannot mount host folders
	// (openshell.Driver.MountRefusal), empty when it can. Mount mode cannot
	// be honoured while it is set; ConstraintComputeDriver names the driver
	// as what stops it.
	MountUnsupported string
	// Observability is not a flag either: the compiled observability plan
	// of the gateway the sandbox reports to. The listener port of each of
	// its enabled Prometheus destinations is reserved. config.Config does
	// not carry that plan, so a caller that has it must pass it.
	Observability *config.ObservabilityV8Plan
	// RepoPolicy is not a flag either: the project's repository policy as
	// the run read it (LoadRepoPolicy), nil when it has none. It only
	// tightens; a key that would loosen refuses the run.
	RepoPolicy *RepoPolicy
}

// Authority says how far the admin block can be trusted to bind the user.
type Authority string

const (
	// AuthorityAuthoritative: managed_enterprise, the administrator owns
	// config.yaml and the user cannot write it.
	AuthorityAuthoritative Authority = "authoritative"
	// AuthorityAdvisory: the user owns config.yaml; the admin block is
	// still enforced, but the user can edit it.
	AuthorityAdvisory Authority = "advisory"
)

// AdminStatus describes openshell.admin for doctor and status surfaces.
type AdminStatus struct {
	Configured bool      `json:"configured"`
	Authority  Authority `json:"authority"`
	Detail     string    `json:"detail"`
}

// AdminStatusFor reports whether cfg carries admin constraints and whether
// they are authoritative.
func AdminStatusFor(cfg *config.Config) AdminStatus {
	status := AdminStatus{Authority: AuthorityAdvisory}
	if cfg == nil {
		status.Detail = "no configuration"
		return status
	}
	status.Configured = !cfg.OpenShell.Admin.IsZero()
	switch {
	case managed.IsManagedEnterprise(cfg.DeploymentMode):
		status.Authority = AuthorityAuthoritative
		if status.Configured {
			status.Detail = "openshell.admin is authoritative: config.yaml is administrator-owned (managed_enterprise)"
		} else {
			status.Detail = "no openshell.admin constraints in the administrator-owned config.yaml"
		}
	case status.Configured:
		status.Detail = "openshell.admin is enforced but advisory: you own config.yaml and can edit it"
	default:
		status.Detail = "no openshell.admin constraints"
	}
	return status
}

// Setting is one resolved setting and where its value came from.
type Setting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	// Source is the layer that decided the value.
	Source Source `json:"source"`
	// Origin names it precisely: "pack open", "openshell.profile",
	// "--profile", "openshell.admin.min_profile".
	Origin string `json:"origin"`
	// Requested is the value an admin constraint replaced.
	Requested string `json:"requested,omitempty"`
}

// Violation is a requested setting or action the policy refused.
type Violation struct {
	// Key is the openshell key or action ("yolo", "workdir.mode",
	// "egress.unblock", "harness").
	Key string `json:"key"`
	// Source is who asked: user, flag, or pack (a pack the user selected).
	Source Source `json:"source"`
	// Attempted and Enforced are the requested and the applied values.
	Attempted string `json:"attempted"`
	Enforced  string `json:"enforced,omitempty"`
	// Constraint is what refused it ("openshell.admin.allow_yolo",
	// "pack strict", "defenseclaw").
	Constraint string `json:"constraint"`
	// Fatal means the run cannot proceed (a refused harness).
	Fatal bool `json:"fatal"`
	// Message is the user-facing sentence; Detail explains it.
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func (v *Violation) Error() string {
	if v.Detail == "" {
		return v.Message
	}
	return v.Message + " (" + v.Detail + ")"
}

// Admin reports whether an openshell.admin constraint refused the request
// (as opposed to the pack, the profile, or a DefenseClaw invariant).
func (v *Violation) Admin() bool {
	return strings.HasPrefix(v.Constraint, "openshell.admin.")
}

// FirstFatal returns the first fatal violation, or nil.
func FirstFatal(violations []Violation) *Violation {
	for i := range violations {
		if violations[i].Fatal {
			return &violations[i]
		}
	}
	return nil
}

// Workspace is the effective project posture.
type Workspace struct {
	Mode        string   `json:"mode"`
	Masks       []string `json:"masks"`
	Unmask      []string `json:"unmask"`
	Review      []string `json:"review"`
	MaxUploadMB int      `json:"max_upload_mb"`
	GitDepth    int      `json:"git_depth"`
	OnExit      string   `json:"on_exit"`
}

// Egress is the effective egress-proxy posture. Effective.EgressOptions
// turns it into the egress proxy's decider, whose order (see egress.go) is
// the one semantics: the guard (this machine never, private networks only
// through an allow entry) → Ports → AdminBlock and AllowOnly (never
// unblockable) → Block (the pack's and openshell.egress.block; not
// unblockable: remove the entry) → unblocks → Allow (exempts a host from
// the feeds, unless openshell.admin.allow_unblock is false) → Feeds
// (unblockable) → AllowOnly entries → the network mode (open allows names
// and refuses IP literals until unblocked; allowlist refuses the rest; deny
// runs without the proxy). The host lists hold canonical egress patterns
// (config.ParseOpenShellEgressPattern): names, "*." wildcards, IP addresses
// and CIDR prefixes.
type Egress struct {
	Feeds []string `json:"feeds"`
	Block []string `json:"block"`
	// AdminBlock is openshell.admin.egress_block with each host name
	// followed by its "*." wildcard (config.OpenShellAdminBlockPatterns):
	// an administrator's domain covers its subdomains. Block and AllowOnly
	// match exactly.
	AdminBlock    []string `json:"admin_block"`
	Allow         []string `json:"allow"`
	AllowOnly     []string `json:"allow_only"`
	Ports         []int    `json:"ports"`
	LargeUploadMB int      `json:"large_upload_mb"`
	// BlockLargeUploads cuts the upload that crosses LargeUploadMB to a
	// first-seen destination and refuses later requests there
	// (egress.Principal.BlockLargeUploads): the pack's
	// egress.block_large_uploads, or openshell.egress.block_large_uploads,
	// or openshell.admin.block_large_uploads, which also keeps LargeUploadMB
	// above 0 and at most the default (or the required pack's own). Without
	// the administrator's key a LargeUploadMB of 0 leaves it off: it acts on
	// the report. Destinations an unblock, an allow entry or the
	// administrator names are exempt.
	BlockLargeUploads bool `json:"block_large_uploads"`
}

// MCP is the effective MCP posture.
type MCP struct {
	Import bool `json:"import"`
	// HostPortAccess says whether host ports may be opened at all.
	HostPortAccess bool `json:"host_port_access"`
	// HostPorts are the consented host ports that passed every check.
	HostPorts    []int    `json:"host_ports"`
	BlockedTools []string `json:"blocked_tools"`
	// ProjectServers is the pack's mcp.project_servers (block or allow).
	ProjectServers string `json:"project_servers"`
}

// Resources is the effective resource request; empty means unlimited.
type Resources struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// Effective is the resolved sandbox posture for one run. It is immutable
// after Resolve and safe for concurrent use.
type Effective struct {
	Pack *Pack `json:"pack"`
	// Profile is the OpenShell policy profile (open, balanced, strict).
	Profile string `json:"profile"`
	// NetworkMode is the egress-proxy mode (open, allowlist, deny).
	NetworkMode string `json:"network_mode"`
	// Approvals is auto, triage or manual.
	Approvals string `json:"approvals"`
	Yolo      bool   `json:"yolo"`
	// Harness is the requested harness, or empty when none was requested or
	// it was refused (see FirstFatal).
	Harness string `json:"harness,omitempty"`
	// AnyHarness reports that neither the pack nor openshell.admin limits
	// the harness: every harness may run and AllowedHarnesses is empty.
	AnyHarness bool `json:"any_harness"`
	// ProcessTree is observe.process_tree: the sandbox's processes are
	// sampled while it runs. The pack decides (an administrator's required
	// pack too); --process-tree turns it on, and nothing turns it off.
	ProcessTree bool `json:"process_tree"`
	// AllowedHarnesses is the pack ∩ admin allowlist when AnyHarness is
	// false; empty then means no harness may run. It is never nil.
	AllowedHarnesses []string  `json:"allowed_harnesses"`
	Workspace        Workspace `json:"workspace"`
	Egress           Egress    `json:"egress"`
	MCP              MCP       `json:"mcp"`
	Resources        Resources `json:"resources"`
	Learn            bool      `json:"learn"`
	HookFailMode     string    `json:"hook_fail_mode"`
	HookOnTamper     string    `json:"hook_on_tamper"`
	// HookOnSilence and HookSilenceAfter are the pack's hooks.on_silence
	// and hooks.silence_after (Explain shows the latter as the pack writes
	// it).
	HookOnSilence    string        `json:"hook_on_silence"`
	HookSilenceAfter time.Duration `json:"-"`
	Admin            AdminStatus   `json:"admin"`
	// RepoPolicy is the repository policy the run applies (nil: none), and
	// RepoTightened the settings it made stricter.
	RepoPolicy    *RepoPolicy `json:"repo_policy,omitempty"`
	RepoTightened []string    `json:"repo_tightened,omitempty"`

	admin config.OpenShellAdminConfig
	// requiredPack: Pack is openshell.admin.required_pack, whose posture is
	// a floor for runtime actions too.
	requiredPack  bool
	reservedPorts map[int]string
	// policySources: see PolicySources.
	policySources []string
	home          string
	// hostNames are this machine's own names, which reach the host.
	hostNames []string
	settings  map[string]Setting
	// firewallBlock are the Egress.Block entries the host egress firewall's
	// deny rules contribute (firewallBlock), named apart in refusals.
	firewallBlock []string
	// curatedAllow are the Egress.Allow entries only DefenseClaw's curated
	// allowlist put there (resolveAllow). They reach the decider as its
	// allowlist feed, not as operator allow entries (EgressOptions).
	curatedAllow []string
	// decider is the egress decider without unblocks (EgressDecider(nil))
	// that DecideEgress and the unblock and approval checks ask.
	decider *egress.Decider
}

// explainOrder is the order Explain reports settings in.
var explainOrder = []string{
	"pack", "profile", "network.mode", "approvals.mode", "observe.process_tree", "yolo", "harness", "harness.allowed",
	"workdir.mode", "workdir.masks", "workdir.unmask", "workdir.review", "workdir.max_upload_mb",
	"workdir.git_depth", "workdir.on_exit",
	"egress.feeds", "egress.block", "egress.admin_block", "egress.allow", "egress.allow_only",
	"egress.ports", "egress.large_upload_mb", "egress.block_large_uploads",
	"mcp.import", "mcp.host_port_access", "mcp.host_ports", "mcp.blocked_tools", "mcp.project_servers",
	"resources.cpu", "resources.memory", "learn", "hooks.fail_mode", "hooks.on_tamper",
	"hooks.on_silence", "hooks.silence_after",
}

// Explain returns every resolved setting with its provenance, in a stable
// order (`defenseclaw sandbox policy explain`).
func (e *Effective) Explain() []Setting {
	if e == nil {
		return nil
	}
	out := make([]Setting, 0, len(e.settings))
	for _, key := range explainOrder {
		if setting, ok := e.settings[key]; ok {
			out = append(out, setting)
		}
	}
	return out
}

// Setting returns the provenance of one key.
func (e *Effective) Setting(key string) (Setting, bool) {
	if e == nil {
		return Setting{}, false
	}
	setting, ok := e.settings[key]
	return setting, ok
}

// layer is a candidate value's origin.
type layer struct {
	source Source
	origin string
}

var layerDefault = layer{SourceDefault, "defenseclaw default"}

type resolver struct {
	eff       *Effective
	admin     config.OpenShellAdminConfig
	packLayer layer
	userPack  bool // the pack was selected by the user or a flag
	// required: the pack is openshell.admin.required_pack, whose posture
	// is a floor for user keys and flags.
	required bool
	// managed: managed_enterprise, where a custom required pack must be an
	// administrator-owned file.
	managed    bool
	violations []Violation
	// loaded caches the packs this Resolve read (loadPack).
	loaded map[packCacheKey]*Pack
	// firewallFile is the host egress firewall configuration
	// (firewall.config_file), whose deny rules join the block list
	// (firewallBlock).
	firewallFile string
	// repo is the run's repository policy (Flags.RepoPolicy), and
	// repoRequested the value each setting it tightened had before.
	repo          *RepoPolicy
	repoRequested map[string]string
}

const requiredPackConstraint = "openshell.admin.required_pack"

// ConstraintComputeDriver is the constraint of a setting the gateway's
// compute driver decides (Flags.MountUnsupported): a MicroVM sandbox mounts
// no host folders, so its workdir.mode is copy.
const ConstraintComputeDriver = "openshell.gateway.compute_driver"

// osHostname is swapped in tests.
var osHostname = os.Hostname

// Resolve computes the effective sandbox posture: the selected pack, then the
// user's openshell keys, then the run flags, clamped by openshell.admin.
// Every loosening the policy refuses is returned as a Violation and the
// clamped value is applied; a refused harness is Fatal, so check FirstFatal
// before starting a sandbox. An error means the posture cannot be computed at
// all (a pack failed to load, a flag is malformed) and no sandbox may start.
func Resolve(cfg *config.Config, flags Flags) (*Effective, []Violation, error) {
	if cfg == nil {
		return nil, nil, errors.New("sandbox policy: no configuration")
	}
	if err := validateFlags(flags); err != nil {
		return nil, nil, err
	}
	o := cfg.OpenShell
	if err := validateWorkdirGlobs(o); err != nil {
		return nil, nil, err
	}
	home, _ := userHomeDir()
	r := &resolver{
		admin:        o.Admin,
		managed:      managed.IsManagedEnterprise(cfg.DeploymentMode),
		firewallFile: cfg.Firewall.ConfigFile,
		eff: &Effective{
			Admin:         AdminStatusFor(cfg),
			admin:         o.Admin,
			home:          home,
			hostNames:     ownHostNames(),
			settings:      make(map[string]Setting),
			reservedPorts: reservedPorts(cfg, flags),
		},
	}
	flags = r.dropLockedFlags(o, flags)

	pack, err := r.selectPack(o, flags)
	if err != nil {
		return nil, nil, err
	}
	r.eff.Pack, r.eff.requiredPack = pack, r.required
	r.refuseRepoLoosening(flags.RepoPolicy)
	r.resolveProfile(o, flags)
	r.resolveYolo(o, flags)
	r.resolveHarness(flags)
	r.resolveWorkspace(o, flags)
	if err := r.resolveEgress(o); err != nil {
		return nil, nil, err
	}
	if r.eff.decider, err = r.eff.EgressDecider(nil); err != nil {
		return nil, nil, err
	}
	r.resolveMCP(o, flags)
	if err := r.resolveResources(o, flags); err != nil {
		return nil, nil, err
	}
	r.resolveLearn(flags)
	r.resolveProcessTree(flags)
	r.eff.HookFailMode = pack.Hooks.FailMode
	r.set("hooks.fail_mode", pack.Hooks.FailMode, r.packLayer)
	r.eff.HookOnTamper = pack.Hooks.OnTamper
	r.set("hooks.on_tamper", pack.Hooks.OnTamper, r.packLayer)
	r.eff.HookOnSilence, r.eff.HookSilenceAfter = pack.Hooks.OnSilence, pack.Hooks.SilenceAfterDuration()
	r.set("hooks.on_silence", pack.Hooks.OnSilence, r.packLayer)
	r.set("hooks.silence_after", pack.Hooks.SilenceAfter, r.packLayer)
	if r.eff.HookOnTamper != OnTamperStop && r.repo != nil && r.repo.TamperStop {
		r.eff.HookOnTamper = OnTamperStop
		r.repoRequested["hooks.on_tamper"] = pack.Hooks.OnTamper
		r.set("hooks.on_tamper", OnTamperStop, r.tightened("hooks.on_tamper"))
	}
	r.finishRepo()
	r.eff.policySources = r.policySources(o)
	return r.eff, r.violations, nil
}

// PolicySources returns the host paths the sandbox policy is read from:
// openshell.pack_dir, the files of the custom packs openshell.pack and
// openshell.admin.required_pack name, and the file of every other custom
// pack this Resolve loaded (a --pack). A custom pack is trusted because the
// current user owns it, and in mount
// mode the agent writes the project as that user, so the sandbox launcher
// must pass these paths as workspace.SourceOptions.Protected: a folder that
// holds one is never shared, and an agent cannot rewrite the policy that
// confines the next session. The default pack directory is inside the
// DefenseClaw data directory, which is protected on its own.
func (e *Effective) PolicySources() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.policySources...)
}

func (r *resolver) policySources(o config.OpenShellConfig) []string {
	var sources []string
	if dir, err := expandHome(strings.TrimSpace(o.PackDir)); err == nil && filepath.IsAbs(dir) {
		sources = append(sources, filepath.Clean(dir))
	}
	for _, ref := range []string{o.Pack, r.admin.RequiredPack} {
		if ref = strings.TrimSpace(ref); ref == "" || IsBuiltin(ref) {
			continue
		}
		if file, err := packFilePath(ref, o.PackDir); err == nil {
			sources = appendUnique(sources, file)
		}
	}
	for _, pack := range r.loaded {
		if !pack.Builtin && filepath.IsAbs(pack.Source) {
			sources = appendUnique(sources, pack.Source)
		}
		// The custom packs it extends are as much the policy as it is.
		for _, link := range pack.Chain {
			if !link.Builtin && filepath.IsAbs(link.Source) {
				sources = appendUnique(sources, link.Source)
			}
		}
	}
	sort.Strings(sources)
	return sources
}

func validateFlags(flags Flags) error {
	if p := strings.TrimSpace(flags.Profile); p != "" && config.OpenShellProfileRank(p) < 0 {
		return fmt.Errorf("sandbox policy: --profile %q must be one of %s, %s, %s", flags.Profile,
			config.OpenShellProfileOpen, config.OpenShellProfileBalanced, config.OpenShellProfileStrict)
	}
	if h := strings.TrimSpace(flags.Harness); h != "" && !harnessNamePattern.MatchString(config.NormalizeConnectorName(h)) {
		return fmt.Errorf("sandbox policy: invalid harness name %q", flags.Harness)
	}
	if flags.Project != "" && !filepath.IsAbs(flags.Project) {
		return fmt.Errorf("sandbox policy: project path %q must be absolute", flags.Project)
	}
	for _, port := range flags.HostPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("sandbox policy: --host-port %d must be between 1 and 65535", port)
		}
	}
	if port := flags.OpenShellGatewayPort; port < 0 || port > 65535 {
		return fmt.Errorf("sandbox policy: OpenShell gateway port %d must be between 1 and 65535", port)
	}
	for _, glob := range flags.Unmask {
		if err := config.ValidateOpenShellProjectGlob(glob); err != nil {
			return fmt.Errorf("sandbox policy: --unmask: %w", err)
		}
	}
	return nil
}

// validateWorkdirGlobs checks the user's mask and unmask globs the way pack
// globs are checked, for configurations that did not come through the
// loader's validation.
func validateWorkdirGlobs(o config.OpenShellConfig) error {
	if err := config.ValidateOpenShellProjectGlobs("openshell.workdir.masks", o.Workdir.Masks); err != nil {
		return fmt.Errorf("sandbox policy: %w", err)
	}
	if err := config.ValidateOpenShellProjectGlobs("openshell.workdir.unmask", o.Workdir.Unmask); err != nil {
		return fmt.Errorf("sandbox policy: %w", err)
	}
	return nil
}

// ownHostNames returns this machine's host name, its first label and the
// first label's mDNS name, lowercased.
func ownHostNames() []string {
	name, err := osHostname()
	name, _ = config.NormalizeOpenShellHost(name)
	if err != nil || name == "" {
		return nil
	}
	short, _, _ := strings.Cut(name, ".")
	names := []string{name}
	for _, alias := range []string{short, short + ".local"} {
		names = appendUnique(names, alias)
	}
	return names
}

// reservedPorts are the host listeners no policy, flag or approval ever
// opens to a sandbox: DefenseClaw's own (API, sandbox ingress, egress proxy,
// guardrail proxy, managed model router, Prometheus exporters), the OpenClaw
// gateway, and the OpenShell gateway the run is registered with.
func reservedPorts(cfg *config.Config, flags Flags) map[int]string {
	openShellGatewayPort := flags.OpenShellGatewayPort
	ports := map[int]string{}
	reserve := func(port int, what string) {
		if _, taken := ports[port]; port > 0 && !taken {
			ports[port] = what
		}
	}
	apiPort := cfg.Gateway.APIPort
	if apiPort <= 0 {
		apiPort = config.DefaultGatewayAPIPort
	}
	if openShellGatewayPort <= 0 {
		openShellGatewayPort = OpenShellGatewayPort
	}
	gatewayPort := cfg.Gateway.Port
	if gatewayPort <= 0 {
		gatewayPort = openClawGatewayPort
	}
	reserve(apiPort, "DefenseClaw's API")
	reserve(cfg.OpenShellIngressPort(), "DefenseClaw's sandbox hook ingress")
	reserve(cfg.OpenShellEgressPort(), "DefenseClaw's egress proxy")
	reserve(cfg.Guardrail.Port, "DefenseClaw's guardrail proxy")
	reserve(routerPort(cfg.Routing), "DefenseClaw's model router")
	reserve(openShellGatewayPort, "the OpenShell gateway")
	reserve(gatewayPort, "the OpenClaw gateway")
	for _, port := range prometheusPorts(flags.Observability) {
		reserve(port, "DefenseClaw's Prometheus exporter")
	}
	return ports
}

// prometheusPorts returns the listener ports of a plan's enabled Prometheus
// destinations.
func prometheusPorts(plan *config.ObservabilityV8Plan) []int {
	if plan == nil {
		return nil
	}
	var ports []int
	for _, d := range plan.Destinations() {
		if d.Kind != config.ObservabilityV8DestinationPrometheus || !d.Enabled {
			continue
		}
		_, port, err := net.SplitHostPort(strings.TrimSpace(d.Transport.Listen))
		if err != nil {
			continue
		}
		if n, err := strconv.Atoi(port); err == nil && n > 0 && n <= 65535 {
			ports = append(ports, n)
		}
	}
	return ports
}

// routerPort returns the host port of the semantic model router when routing
// is enabled and the router listens on this machine: the managed router's
// routing.port, or a loopback routing.remote.endpoint. It returns 0 otherwise.
func routerPort(r config.RoutingConfig) int {
	if !r.Enabled {
		return 0
	}
	endpoint := strings.TrimSpace(r.Remote.Endpoint)
	if endpoint == "" {
		if r.Port > 0 {
			return r.Port
		}
		return routing.DefaultAPIPort
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return 0
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	ip := net.ParseIP(host)
	if host != "localhost" && !strings.HasSuffix(host, ".localhost") && (ip == nil || !ip.IsLoopback()) {
		return 0
	}
	if port, err := strconv.Atoi(u.Port()); err == nil {
		return port
	}
	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

func (r *resolver) set(key, value string, from layer) {
	r.eff.settings[key] = Setting{Key: key, Value: value, Source: from.source, Origin: from.origin}
}

func (r *resolver) setClamped(key, value, requested, constraint string) {
	r.eff.settings[key] = Setting{Key: key, Value: value, Source: SourceAdmin, Origin: constraint, Requested: requested}
}

// attempted reports whether a value from this layer was a choice the user
// made (so an admin clamp of it is a Violation, not a silent default).
func (r *resolver) attempted(from layer) bool {
	switch from.source {
	case SourceUser, SourceFlag:
		return true
	case SourcePack:
		return r.userPack
	default:
		return false
	}
}

func (r *resolver) violate(v Violation) {
	if v.Message == "" {
		v.Message = adminMessage(v.Key)
	}
	r.violations = append(r.violations, v)
}

// record appends a Violation an Allow check produced, attributed to the
// layer that asked.
func (r *resolver) record(err error, from Source) {
	var v *Violation
	if errors.As(err, &v) {
		v.Source = from
		r.violations = append(r.violations, *v)
	}
}

func adminMessage(key string) string {
	return "blocked by your organization's DefenseClaw policy: " + key
}

func packMessage(pack, key string) string {
	return fmt.Sprintf("not allowed by the %s sandbox pack: %s", pack, key)
}

// clamp applies an admin constraint to a value and records the provenance
// and, for a user choice, the Violation.
func (r *resolver) clamp(key, requested, enforced string, from layer, constraint, detail string) {
	r.setClamped(key, enforced, requested, constraint)
	if r.attempted(from) {
		r.violate(Violation{
			Key: key, Source: from.source, Attempted: requested, Enforced: enforced,
			Constraint: constraint, Detail: detail,
		})
	}
}

// clampByDriver runs the project on a copy because the gateway's compute
// driver cannot mount it (why): the setting's source is the gateway, not
// the administrator, and a mount the user chose is reported as refused by
// the driver.
func (r *resolver) clampByDriver(requested string, from layer, why string) {
	r.eff.settings["workdir.mode"] = Setting{Key: "workdir.mode", Value: config.OpenShellWorkdirCopy, Source: SourceGateway,
		Origin: ConstraintComputeDriver, Requested: requested}
	if r.attempted(from) {
		r.violate(Violation{
			Key: "workdir.mode", Source: from.source, Attempted: requested, Enforced: config.OpenShellWorkdirCopy,
			Constraint: ConstraintComputeDriver, Message: "the project cannot be mounted live on this gateway; the agent works on a copy",
			Detail: why,
		})
	}
}

func (r *resolver) selectPack(o config.OpenShellConfig, flags Flags) (*Pack, error) {
	ref, from := "", layer{SourceDefault, "default pack"}
	switch {
	case strings.TrimSpace(flags.Pack) != "":
		ref, from = strings.TrimSpace(flags.Pack), layer{SourceFlag, "--pack"}
	case strings.TrimSpace(o.Pack) != "":
		ref, from = strings.TrimSpace(o.Pack), layer{SourceUser, "openshell.pack"}
	}
	if required := strings.TrimSpace(r.admin.RequiredPack); required != "" {
		// In managed_enterprise config.yaml is administrator-owned; a pack
		// file the user can write must not stand in for it (LoadTrusted).
		pack, err := r.loadPack(required, o.PackDir, r.managed)
		if err != nil {
			return nil, fmt.Errorf("sandbox policy: openshell.admin.required_pack: %w", err)
		}
		if digest := strings.TrimSpace(r.admin.RequiredPackDigest); digest != "" && pack.Digest != digest {
			return nil, fmt.Errorf("sandbox policy: openshell.admin.required_pack %s has digest %s, not the pinned openshell.admin.required_pack_digest %s",
				pack.Name, pack.Digest, digest)
		}
		r.required = true
		r.packLayer = layer{SourcePack, "pack " + pack.Name}
		if ref != "" && ref != required {
			// Another reference to the same content (a path to the
			// required file) is not a loosening.
			chosen, err := r.loadPack(ref, o.PackDir, false)
			if err != nil || chosen.Digest != pack.Digest {
				r.violate(Violation{
					Key: "pack", Source: from.source, Attempted: ref, Enforced: pack.Name,
					Constraint: requiredPackConstraint,
					Detail:     "your organization requires the " + pack.Name + " sandbox pack",
				})
			}
		}
		r.setClamped("pack", pack.Name, ref, requiredPackConstraint)
		return pack, nil
	}
	pack, err := r.loadPack(ref, o.PackDir, false)
	if err != nil {
		return nil, fmt.Errorf("sandbox policy: %s: %w", from.origin, err)
	}
	r.userPack = from.source == SourceUser || from.source == SourceFlag
	r.packLayer = layer{SourcePack, "pack " + pack.Name}
	r.set("pack", pack.Name, from)
	return pack, nil
}

func (r *resolver) resolveProfile(o config.OpenShellConfig, flags Flags) {
	profile, from := r.eff.Pack.Profile(), r.packLayer
	if o.Profile != "" {
		profile, from = o.Profile, layer{SourceUser, "openshell.profile"}
	}
	if p := strings.TrimSpace(flags.Profile); p != "" {
		profile, from = p, layer{SourceFlag, "--profile"}
	}
	if config.OpenShellProfileRank(profile) < 0 {
		// Unreachable for validated configs and flags; fail toward the
		// strictest profile.
		profile = config.OpenShellProfileStrict
	}
	if r.repo != nil && r.repo.NetworkMode != "" {
		// The repository's network mode is a floor; the administrator's
		// floors still apply on top.
		if want := profileForNetwork(r.repo.NetworkMode); config.OpenShellProfileRank(want) > config.OpenShellProfileRank(profile) {
			r.repoRequested["profile"], r.repoRequested["network.mode"] = profile, networkForProfile(profile)
			profile, from = want, r.tightened("network.mode")
		}
	}
	floor, constraint, detail := -1, "", ""
	raise := func(rank int, byConstraint, because string) {
		if rank > floor {
			floor, constraint, detail = rank, byConstraint, because
		}
	}
	if rank := config.OpenShellProfileRank(r.admin.MinProfile); rank >= 0 {
		raise(rank, "openshell.admin.min_profile",
			"your organization requires at least the "+r.admin.MinProfile+" profile")
	}
	if len(r.admin.EgressAllowOnly) > 0 {
		raise(config.OpenShellProfileRank(config.OpenShellProfileBalanced), "openshell.admin.egress_allow_only",
			"your organization only allows listed destinations, which needs an allowlist profile")
	}
	if r.required {
		raise(config.OpenShellProfileRank(r.eff.Pack.Profile()), requiredPackConstraint,
			"your organization requires the "+r.eff.Pack.Name+" sandbox pack, whose profile is "+r.eff.Pack.Profile())
	}
	if floor >= 0 && config.OpenShellProfileRank(profile) < floor {
		enforced := profileByRank[floor]
		r.clamp("profile", profile, enforced, from, constraint, detail)
		profile, from = enforced, layer{SourceAdmin, constraint}
	} else {
		r.set("profile", profile, from)
	}
	r.eff.Profile = profile
	r.eff.NetworkMode = networkForProfile(profile)
	r.set("network.mode", r.eff.NetworkMode, layer{from.source, "profile " + profile})

	// A stricter profile never runs with looser approvals: balanced triages
	// at least, strict asks every proposal.
	approvals, approvalsFrom := r.eff.Pack.Approvals.Mode, r.packLayer
	if minimum := minimumApprovals[profile]; minimum != "" && approvalsRank(approvals) < approvalsRank(minimum) {
		approvals, approvalsFrom = minimum, layer{from.source, "profile " + profile}
	}
	if r.repo != nil && r.repo.Approvals != "" && approvalsRank(r.repo.Approvals) > approvalsRank(approvals) {
		r.repoRequested["approvals.mode"] = approvals
		approvals, approvalsFrom = r.repo.Approvals, r.tightened("approvals.mode")
	}
	r.eff.Approvals = approvals
	r.set("approvals.mode", approvals, approvalsFrom)
}

var (
	profileByRank = []string{
		config.OpenShellProfileOpen, config.OpenShellProfileBalanced, config.OpenShellProfileStrict,
	}
	minimumApprovals = map[string]string{
		config.OpenShellProfileBalanced: ApprovalsTriage,
		config.OpenShellProfileStrict:   ApprovalsManual,
	}
)

func approvalsRank(mode string) int {
	switch mode {
	case ApprovalsAuto:
		return 0
	case ApprovalsTriage:
		return 1
	default:
		return 2
	}
}

func (r *resolver) resolveYolo(o config.OpenShellConfig, flags Flags) {
	yolo, from := r.eff.Pack.Harness.Yolo, r.packLayer
	if o.Yolo != nil {
		yolo, from = *o.Yolo, layer{SourceUser, "openshell.yolo"}
	}
	switch {
	case flags.Safe:
		yolo, from = false, layer{SourceFlag, "--safe"}
	case flags.Yolo:
		yolo, from = true, layer{SourceFlag, "--yolo"}
	}
	if yolo && r.repo != nil && r.repo.NoYolo {
		r.repoRequested["yolo"] = "true"
		yolo, from = false, r.tightened("harness.yolo")
	}
	switch {
	case yolo && isFalse(r.admin.AllowYolo):
		r.clamp("yolo", "true", "false", from, "openshell.admin.allow_yolo",
			"skip-permissions mode is disabled; the harness keeps its permission prompts")
		yolo = false
	case yolo && r.required && !r.eff.Pack.Harness.Yolo:
		r.clamp("yolo", "true", "false", from, requiredPackConstraint,
			"the required "+r.eff.Pack.Name+" sandbox pack keeps the harness permission prompts")
		yolo = false
	default:
		r.set("yolo", strconv.FormatBool(yolo), from)
	}
	r.eff.Yolo = yolo
}

func (r *resolver) resolveHarness(flags Flags) {
	packAllowed := r.eff.Pack.Harness.Allowed
	var adminAllowed []string
	for _, name := range r.admin.AllowedHarnesses {
		adminAllowed = appendUnique(adminAllowed, config.NormalizeConnectorName(name))
	}
	switch {
	case len(packAllowed) > 0 && len(adminAllowed) > 0:
		allowed := []string{}
		for _, name := range packAllowed {
			if containsString(adminAllowed, name) {
				allowed = append(allowed, name)
			}
		}
		r.eff.AllowedHarnesses = allowed
		r.set("harness.allowed", listValue(allowed),
			layer{SourceAdmin, "pack " + r.eff.Pack.Name + " ∩ openshell.admin.allowed_harnesses"})
	case len(adminAllowed) > 0:
		r.eff.AllowedHarnesses = adminAllowed
		r.set("harness.allowed", listValue(adminAllowed), layer{SourceAdmin, "openshell.admin.allowed_harnesses"})
	case len(packAllowed) > 0:
		r.eff.AllowedHarnesses = append([]string(nil), packAllowed...)
		r.set("harness.allowed", listValue(packAllowed), r.packLayer)
	default:
		r.eff.AnyHarness, r.eff.AllowedHarnesses = true, []string{}
		r.set("harness.allowed", "(any)", r.packLayer)
	}

	harness := config.NormalizeConnectorName(flags.Harness)
	if harness == "" {
		return
	}
	if err := r.eff.harnessAllowed(harness); err != nil {
		r.record(err, SourceFlag)
		refusedBy := layer{SourceAdmin, "openshell.admin.allowed_harnesses"}
		var v *Violation
		if errors.As(err, &v) && !v.Admin() {
			refusedBy = r.packLayer
		}
		r.set("harness", "(refused: "+harness+")", refusedBy)
		return
	}
	r.eff.Harness = harness
	r.set("harness", harness, layer{SourceFlag, "sandbox run"})
}

// reviewFloor are the sensitive-change globs every run's end-of-session
// review flags on top of the pack's workspace.review, so a custom pack cannot
// drop them. The workspace review's built-in risk rules already cover build
// files, git hook managers, and package- and version-manager config; these
// are the files a harness or agent tool loads and acts on without asking the
// next time anyone runs one in the project outside the sandbox (hooks, MCP
// servers, instructions), lock files, which can point the next install at
// any package source, and sandbox policy packs and the repository policy
// kept in the project (an edit to it applies from the next run on).
var reviewFloor = []string{
	"**/.claude/**", "CLAUDE.md", "CLAUDE.local.md", ".mcp.json",
	"**/.codex/**", "AGENTS.md", "AGENTS.override.md",
	"**/.cursor/**", ".cursorrules",
	"**/.gemini/**", "GEMINI.md",
	// Devin Desktop still reads its pre-rename project rules.
	"**/" + legacyconnector.InventoryDotDirs[0] + "/**", "." + legacyconnector.VendorToken + "rules",
	"**/.kiro/**", "**/.amazonq/**", "**/.continue/**", "**/.roo/**", ".roomodes",
	".clinerules", "**/.clinerules/**", "**/.opencode/**", "opencode.json", "opencode.jsonc", ".aider.conf.yml",
	"**/.devin/**", "**/.openhands/**", "**/.omnigent/**",
	".github/copilot-instructions.md", ".github/instructions/**", ".github/prompts/**", ".github/chatmodes/**",
	".github/hooks/**", ".github/copilot/**",
	"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
	"deno.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "Cargo.lock", "go.sum", "Gemfile.lock",
	"composer.lock", "mix.lock", "pubspec.lock", "Podfile.lock", "packages.lock.json", "gradle.lockfile",
	PackFileName, RepoPolicyPath,
}

func (r *resolver) resolveWorkspace(o config.OpenShellConfig, flags Flags) {
	pack := r.eff.Pack
	ws := &r.eff.Workspace

	mode, from := pack.Workspace.Mode, r.packLayer
	if o.Workdir.Mode != "" {
		mode, from = o.Workdir.Mode, layer{SourceUser, "openshell.workdir.mode"}
	}
	if flags.Copy {
		mode, from = config.OpenShellWorkdirCopy, layer{SourceFlag, "--copy"}
	}
	if mode == config.OpenShellWorkdirMount && r.repo != nil && r.repo.Copy {
		r.repoRequested["workdir.mode"] = mode
		mode, from = config.OpenShellWorkdirCopy, r.tightened("workspace.mode")
	}
	mount := mode == config.OpenShellWorkdirMount
	switch {
	case mount && flags.MountUnsupported != "":
		// Before the administrator's clamps: whatever they say, the
		// gateway's compute driver cannot mount the project.
		r.clampByDriver(mode, from, flags.MountUnsupported)
		mode = config.OpenShellWorkdirCopy
	case mount && isFalse(r.admin.AllowMount):
		r.clamp("workdir.mode", mode, config.OpenShellWorkdirCopy, from, "openshell.admin.allow_mount",
			"live project mounts are disabled; the agent works on a copy")
		mode = config.OpenShellWorkdirCopy
	case mount && r.required && pack.Workspace.Mode == config.OpenShellWorkdirCopy:
		r.clamp("workdir.mode", mode, config.OpenShellWorkdirCopy, from, requiredPackConstraint,
			"the required "+pack.Name+" sandbox pack works on a copy of the project")
		mode = config.OpenShellWorkdirCopy
	case mount && len(r.admin.RequireCopyFor) > 0 && flags.Project == "":
		// Without the project path the require_copy_for check cannot
		// pass, so fail toward copy mode.
		r.clamp("workdir.mode", mode, config.OpenShellWorkdirCopy, from, "openshell.admin.require_copy_for",
			"no project folder was given to check against the folders your organization requires copy mode for")
		mode = config.OpenShellWorkdirCopy
	case mount:
		if pattern := r.eff.requiresCopy(flags.Project); pattern != "" {
			r.clamp("workdir.mode", mode, config.OpenShellWorkdirCopy, from, "openshell.admin.require_copy_for",
				"your organization requires copy mode for projects matching "+pattern)
			mode = config.OpenShellWorkdirCopy
			break
		}
		r.set("workdir.mode", mode, from)
	default:
		r.set("workdir.mode", mode, from)
	}
	ws.Mode = mode

	ws.Masks = mergeLists(pack.Workspace.Masks, o.Workdir.Masks)
	masksFrom := mergedLayer(r.packLayer, len(o.Workdir.Masks) > 0, "openshell.workdir.masks")
	ws.Masks, masksFrom = r.addRepo("workspace.masks", ws.Masks, r.repoList(func(rp *RepoPolicy) []string { return rp.Masks }), masksFrom)
	r.set("workdir.masks", listValue(ws.Masks), masksFrom)

	ws.Unmask = mergeLists(pack.Workspace.Unmask, o.Workdir.Unmask, flags.Unmask)
	unmaskFrom := layerDefault
	if len(pack.Workspace.Unmask) > 0 {
		unmaskFrom = r.packLayer
	}
	switch {
	case len(flags.Unmask) > 0:
		unmaskFrom = layer{SourceFlag, "--unmask"}
	case len(o.Workdir.Unmask) > 0 && len(pack.Workspace.Unmask) > 0:
		unmaskFrom = mergedLayer(r.packLayer, true, "openshell.workdir.unmask")
	case len(o.Workdir.Unmask) > 0:
		unmaskFrom = layer{SourceUser, "openshell.workdir.unmask"}
	}
	r.set("workdir.unmask", listValue(ws.Unmask), unmaskFrom)

	ws.Review = mergeLists(pack.Workspace.Review, reviewFloor)
	reviewFrom := layer{r.packLayer.source, r.packLayer.origin + " + defenseclaw review floor"}
	ws.Review, reviewFrom = r.addRepo("workspace.review", ws.Review, r.repoList(func(rp *RepoPolicy) []string { return rp.Review }), reviewFrom)
	r.set("workdir.review", listValue(ws.Review), reviewFrom)

	ws.MaxUploadMB, from = pack.Workspace.MaxUploadMB, r.packLayer
	if o.Workdir.MaxUploadMB > 0 {
		ws.MaxUploadMB, from = o.Workdir.MaxUploadMB, layer{SourceUser, "openshell.workdir.max_upload_mb"}
	}
	r.set("workdir.max_upload_mb", strconv.Itoa(ws.MaxUploadMB), from)

	ws.GitDepth, from = config.DefaultOpenShellGitDepth, layerDefault
	if o.Workdir.GitDepth > 0 && o.Workdir.GitDepth != config.DefaultOpenShellGitDepth {
		ws.GitDepth, from = o.Workdir.GitDepth, layer{SourceUser, "openshell.workdir.git_depth"}
	}
	r.set("workdir.git_depth", strconv.Itoa(ws.GitDepth), from)

	ws.OnExit, from = config.DefaultOpenShellOnExit, layerDefault
	if o.Workdir.OnExit != "" && o.Workdir.OnExit != config.DefaultOpenShellOnExit {
		ws.OnExit, from = o.Workdir.OnExit, layer{SourceUser, "openshell.workdir.on_exit"}
	}
	r.set("workdir.on_exit", ws.OnExit, from)
}

func (r *resolver) resolveEgress(o config.OpenShellConfig) error {
	pack := r.eff.Pack
	eg := &r.eff.Egress
	unblockForbidden := isFalse(r.admin.AllowUnblock)

	feeds, from := append([]string{}, pack.Egress.Feeds...), r.packLayer
	switch o.Egress.Feed {
	case config.OpenShellFeedBuiltin:
		feeds, from = appendUnique(feeds, FeedBuiltin), layer{SourceUser, "openshell.egress.feed"}
	case config.OpenShellFeedNone:
		feeds, from = []string{}, layer{SourceUser, "openshell.egress.feed"}
	}
	switch {
	case !containsString(feeds, FeedBuiltin) && unblockForbidden:
		r.clamp("egress.feeds", listValue(feeds), FeedBuiltin, from, "openshell.admin.allow_unblock",
			"the exfiltration blocklist feed cannot be turned off")
		feeds = appendUnique(feeds, FeedBuiltin)
	case !containsString(feeds, FeedBuiltin) && r.required && containsString(pack.Egress.Feeds, FeedBuiltin):
		r.clamp("egress.feeds", listValue(feeds), FeedBuiltin, from, requiredPackConstraint,
			"the required "+pack.Name+" sandbox pack keeps the exfiltration blocklist feed")
		feeds = appendUnique(feeds, FeedBuiltin)
	default:
		r.set("egress.feeds", listValue(feeds), from)
	}
	eg.Feeds = feeds

	userBlock := normalizeGlobs(o.Egress.Block)
	eg.Block = mergeLists(pack.Egress.Block, userBlock)
	blockFrom := mergedLayer(r.packLayer, len(userBlock) > 0, "openshell.egress.block")
	eg.Block, blockFrom = r.addRepo("egress.block", eg.Block, r.repoList(func(rp *RepoPolicy) []string { return rp.Block }), blockFrom)
	r.set("egress.block", listValue(eg.Block), blockFrom)
	// A host name on the administrator's list blocks its subdomains too;
	// the user's block list and the allow-only list stay exact.
	eg.AdminBlock = config.OpenShellAdminBlockPatterns(r.admin.EgressBlock)
	r.set("egress.admin_block", listValue(eg.AdminBlock), layer{SourceAdmin, "openshell.admin.egress_block"})

	if err := r.resolveAllow(o, unblockForbidden); err != nil {
		return err
	}
	eg.AllowOnly = normalizeGlobs(r.admin.EgressAllowOnly)
	r.set("egress.allow_only", listValue(eg.AllowOnly), layer{SourceAdmin, "openshell.admin.egress_allow_only"})

	r.resolvePorts(o)
	r.repoPorts()
	// The host firewall's deny rules apply for the ports the proxy carries,
	// so they are read once those are known.
	fwBlock, err := firewallBlock(r.firewallFile, eg.Ports)
	if err != nil {
		return err
	}
	if len(fwBlock) > 0 {
		r.eff.firewallBlock = fwBlock
		eg.Block = mergeLists(eg.Block, fwBlock)
		r.set("egress.block", listValue(eg.Block), layer{SourceUser, blockFrom.origin + " + the deny rules of " + r.firewallFile})
	}
	eg.LargeUploadMB, from = pack.Egress.LargeUploadMB, r.packLayer
	if o.Egress.LargeUploadMB > 0 {
		eg.LargeUploadMB, from = o.Egress.LargeUploadMB, layer{SourceUser, "openshell.egress.large_upload_mb"}
	}
	if rp := r.repo; rp != nil {
		switch {
		case rp.LargeUploadMB > 0 && (eg.LargeUploadMB <= 0 || rp.LargeUploadMB < eg.LargeUploadMB):
			r.repoRequested["egress.large_upload_mb"] = strconv.Itoa(eg.LargeUploadMB)
			eg.LargeUploadMB, from = rp.LargeUploadMB, r.tightened("egress.large_upload_mb")
		case rp.BlockLargeUploads && eg.LargeUploadMB <= 0:
			// The block acts on the large-upload report, so the
			// repository's block turns the report on.
			r.repoRequested["egress.large_upload_mb"] = "0"
			eg.LargeUploadMB, from = defaultLargeUploadMB, r.tightened("egress.large_upload_mb")
		}
	}
	// The administrator's block acts on the report, so under it the report
	// can neither be turned off nor raised out of reach: the threshold is
	// at most the default, or the required pack's own when that is higher
	// (the administrator's word).
	limit := defaultLargeUploadMB
	if r.required && pack.Egress.LargeUploadMB > limit {
		limit = pack.Egress.LargeUploadMB
	}
	switch {
	case r.admin.BlockLargeUploads && eg.LargeUploadMB <= 0:
		r.clamp("egress.large_upload_mb", strconv.Itoa(eg.LargeUploadMB), strconv.Itoa(limit), from,
			adminBlockUploadsConstraint, "your organization blocks large uploads to first-seen hosts, so the large-upload report stays on")
		eg.LargeUploadMB = limit
	case r.admin.BlockLargeUploads && eg.LargeUploadMB > limit:
		r.clamp("egress.large_upload_mb", strconv.Itoa(eg.LargeUploadMB), strconv.Itoa(limit), from,
			adminBlockUploadsConstraint, fmt.Sprintf("your organization blocks large uploads to first-seen hosts, so the threshold is at most %d MiB", limit))
		eg.LargeUploadMB = limit
	default:
		r.set("egress.large_upload_mb", strconv.Itoa(eg.LargeUploadMB), from)
	}
	r.resolveUploadBlock(o)
	return nil
}

const adminBlockUploadsConstraint = "openshell.admin.block_large_uploads"

// resolveUploadBlock turns the large-upload block on when the pack, the
// user's openshell.egress.block_large_uploads or the administrator asks.
// The user's key only turns it on: a pack that blocks keeps blocking. The
// block acts on the large-upload report, so without one (large_upload_mb
// 0, which only the administrator's block overrules) it is off: nothing
// would be cut, and the policy must not say uploads are.
func (r *resolver) resolveUploadBlock(o config.OpenShellConfig) {
	eg := &r.eff.Egress
	block, from := r.eff.Pack.Egress.BlockLargeUploads, r.packLayer
	if o.Egress.BlockLargeUploads && !block {
		block, from = true, layer{SourceUser, "openshell.egress.block_large_uploads"}
	}
	if r.repo != nil && r.repo.BlockLargeUploads && !block {
		r.repoRequested["egress.block_large_uploads"] = "false"
		block, from = true, r.tightened("egress.block_large_uploads")
	}
	if r.admin.BlockLargeUploads {
		block, from = true, layer{SourceAdmin, adminBlockUploadsConstraint}
	}
	if block && eg.LargeUploadMB <= 0 {
		const key = "egress.block_large_uploads"
		r.eff.settings[key] = Setting{Key: key, Value: "false", Source: from.source, Origin: from.origin, Requested: "true"}
		if r.attempted(from) {
			r.violate(Violation{
				Key: key, Source: from.source, Attempted: "true", Enforced: "false", Constraint: "egress.large_upload_mb",
				Message: "the large-upload block is off: it cuts uploads over egress.large_upload_mb, which is 0 in the " + r.eff.Pack.Name + " pack",
				Detail:  "set openshell.egress.large_upload_mb above 0 to block large uploads",
			})
		}
		eg.BlockLargeUploads = false
		return
	}
	eg.BlockLargeUploads = block
	r.set("egress.block_large_uploads", strconv.FormatBool(block), from)
}

// resolveAllow builds the egress allow list. DefenseClaw's curated entries
// (a built-in pack's, and the balanced pack's when the profile asks for an
// allowlist the pack does not have) and a required pack's entries always
// apply. Entries of a custom pack the user picked and the user's own entries
// are lifted refusals, so openshell.admin.allow_unblock: false drops them.
// Entries that cover every host or a whole public suffix are never used.
//
// The curated entries are DefenseClaw's list of public developer services,
// not the operator's word for a destination: they admit the names but open
// no private network their DNS answers lead to, so the ones no operator
// entry repeats are kept apart (curatedAllow) for EgressOptions.
func (r *resolver) resolveAllow(o config.OpenShellConfig, unblockForbidden bool) error {
	pack := r.eff.Pack
	eg := &r.eff.Egress
	const key = "egress.allow"

	eg.Allow = []string{}
	from := r.packLayer
	var refused, curated, operator []string
	// A built-in pack's entries are DefenseClaw's curated ones, and so are
	// the entries a custom pack inherits from a built-in pack it extends.
	own := withoutEntries(pack.Egress.Allow, pack.builtinAllow)
	switch {
	case pack.Builtin:
		curated = mergeLists(pack.Egress.Allow)
	case r.required:
		curated, operator = mergeLists(pack.builtinAllow), mergeLists(own)
	default:
		curated = mergeLists(pack.builtinAllow)
	}
	eg.Allow = mergeLists(curated, operator)
	if r.eff.NetworkMode == NetworkAllowlist && pack.Network.Mode != NetworkAllowlist {
		balanced, err := Builtin(config.OpenShellProfileBalanced)
		if err != nil {
			return fmt.Errorf("sandbox policy: curated allowlist: %w", err)
		}
		curated = mergeLists(curated, balanced.Egress.Allow)
		eg.Allow = mergeLists(eg.Allow, balanced.Egress.Allow)
		from = layer{from.source, from.origin + " + the curated allowlist of pack balanced"}
	}
	if !pack.Builtin && !r.required && len(own) > 0 {
		if unblockForbidden {
			refused = append(refused, own...)
			r.violate(Violation{
				Key: key, Source: SourcePack, Attempted: listValue(own), Enforced: listValue(eg.Allow),
				Constraint: "openshell.admin.allow_unblock",
				Detail:     "allow entries of a pack you chose are ignored; ask your administrator to add destinations",
			})
		} else {
			eg.Allow = mergeLists(own, eg.Allow)
			operator = mergeLists(operator, own)
		}
	}

	var userAllow, broad []string
	for _, glob := range normalizeGlobs(o.Egress.Allow) {
		if IsBroadAllowGlob(glob) {
			broad = append(broad, glob)
			continue
		}
		userAllow = append(userAllow, glob)
	}
	if len(broad) > 0 {
		r.violate(Violation{
			Key: key, Source: SourceUser, Attempted: listValue(broad), Constraint: "defenseclaw",
			Message: "DefenseClaw ignores allow entries that cover every host or a whole top-level domain: " + key,
			Detail:  "list the destinations to allow instead",
		})
	}
	switch {
	case len(userAllow) > 0 && unblockForbidden:
		refused = append(refused, userAllow...)
		r.violate(Violation{
			Key: key, Source: SourceUser, Attempted: listValue(userAllow), Enforced: listValue(eg.Allow),
			Constraint: "openshell.admin.allow_unblock",
			Detail:     "your own allow entries are ignored; ask your administrator to add destinations",
		})
	case len(userAllow) > 0:
		eg.Allow = mergeLists(eg.Allow, userAllow)
		operator = mergeLists(operator, userAllow)
		from = mergedLayer(from, true, "openshell.egress.allow")
	}
	r.eff.curatedAllow = nil
	for _, glob := range curated {
		if !containsString(operator, glob) {
			r.eff.curatedAllow = append(r.eff.curatedAllow, glob)
		}
	}
	if len(refused) > 0 {
		r.setClamped(key, listValue(eg.Allow), listValue(mergeLists(eg.Allow, refused)), "openshell.admin.allow_unblock")
	} else {
		r.set(key, listValue(eg.Allow), from)
	}
	return nil
}

// resolvePorts applies openshell.egress.ports, which replaces the pack's
// list. Over a required pack only the pack's own ports can be kept.
//
// A deny-mode pack may list no ports, as it runs without the proxy. Under a
// profile that runs the proxy it gets the default ports, as a pack that
// leaves the list out does: the proxy's decider relays those for an empty
// list anyway (egress.DeciderOptions.Ports), and triage checks proposals
// against this list, so an empty one would refuse every proposal the
// proxy's ports allow.
func (r *resolver) resolvePorts(o config.OpenShellConfig) {
	pack := r.eff.Pack
	eg := &r.eff.Egress
	eg.Ports = append([]int{}, pack.Egress.Ports...)
	packFrom := r.packLayer
	if len(eg.Ports) == 0 && r.eff.NetworkMode != NetworkDeny {
		eg.Ports = append([]int{}, defaultPorts...)
		packFrom = layer{SourceDefault, "defenseclaw default (" + r.packLayer.origin + " lists no ports)"}
	}
	if len(o.Egress.Ports) == 0 {
		r.set("egress.ports", joinInts(eg.Ports), packFrom)
		return
	}
	requested := uniqueInts(o.Egress.Ports)
	if !r.required {
		eg.Ports = requested
		r.set("egress.ports", joinInts(eg.Ports), layer{SourceUser, "openshell.egress.ports"})
		return
	}
	kept := []int{}
	for _, port := range requested {
		if containsInt(pack.Egress.Ports, port) {
			kept = append(kept, port)
		}
	}
	if len(kept) == len(requested) {
		eg.Ports = kept
		r.set("egress.ports", joinInts(eg.Ports), layer{SourceUser, "openshell.egress.ports"})
		return
	}
	if len(kept) > 0 {
		eg.Ports = kept
	}
	r.clamp("egress.ports", joinInts(requested), joinInts(eg.Ports), layer{SourceUser, "openshell.egress.ports"},
		requiredPackConstraint, "the required "+pack.Name+" sandbox pack reaches only ports "+joinInts(pack.Egress.Ports))
}

func (r *resolver) resolveMCP(o config.OpenShellConfig, flags Flags) {
	pack := r.eff.Pack
	m := &r.eff.MCP

	imp, from := pack.MCP.Import, r.packLayer
	if o.MCP.Import != nil {
		imp, from = *o.MCP.Import, layer{SourceUser, "openshell.mcp.import"}
	}
	if flags.NoMCP {
		imp, from = false, layer{SourceFlag, "--no-mcp"}
	}
	if imp && r.repo != nil && r.repo.NoMCPImport {
		r.repoRequested["mcp.import"] = "true"
		imp, from = false, r.tightened("mcp.import")
	}
	if imp && r.required && !pack.MCP.Import {
		r.clamp("mcp.import", "true", "false", from, requiredPackConstraint,
			"the required "+pack.Name+" sandbox pack does not bring MCP servers into the sandbox")
		imp = false
	} else {
		r.set("mcp.import", strconv.FormatBool(imp), from)
	}
	m.Import = imp

	switch {
	case pack.MCP.HostPorts && isFalse(r.admin.AllowHostPorts):
		r.setClamped("mcp.host_port_access", "false", "true", "openshell.admin.allow_host_ports")
	default:
		r.set("mcp.host_port_access", strconv.FormatBool(pack.MCP.HostPorts), r.packLayer)
	}
	m.HostPortAccess = pack.MCP.HostPorts && !isFalse(r.admin.AllowHostPorts)

	m.HostPorts = []int{}
	portsFrom, refused := layerDefault, false
	for _, req := range []struct {
		ports []int
		from  layer
	}{
		{o.MCP.HostPorts, layer{SourceUser, "openshell.mcp.host_ports"}},
		{flags.HostPorts, layer{SourceFlag, "--host-port"}},
	} {
		for _, port := range req.ports {
			if err := r.eff.hostPortAllowed(port); err != nil {
				r.record(err, req.from.source)
				refused = true
				continue
			}
			if !containsInt(m.HostPorts, port) {
				m.HostPorts = append(m.HostPorts, port)
				portsFrom = req.from
			}
		}
	}
	if refused && len(m.HostPorts) == 0 {
		requested := joinInts(append(append([]int{}, o.MCP.HostPorts...), flags.HostPorts...))
		switch {
		case isFalse(r.admin.AllowHostPorts):
			r.setClamped("mcp.host_ports", "(none)", requested, "openshell.admin.allow_host_ports")
		case !pack.MCP.HostPorts:
			r.eff.settings["mcp.host_ports"] = Setting{Key: "mcp.host_ports", Value: "(none)",
				Source: SourcePack, Origin: r.packLayer.origin, Requested: requested}
		default:
			r.eff.settings["mcp.host_ports"] = Setting{Key: "mcp.host_ports", Value: "(none)",
				Source: SourceDefault, Origin: "defenseclaw reserved ports", Requested: requested}
		}
	} else {
		r.set("mcp.host_ports", joinInts(m.HostPorts), portsFrom)
	}
	toolsFrom := r.packLayer
	m.BlockedTools, toolsFrom = r.addRepo("mcp.blocked_tools", append([]string{}, pack.MCP.BlockedTools...),
		r.repoList(func(rp *RepoPolicy) []string { return rp.BlockedTools }), toolsFrom)
	r.set("mcp.blocked_tools", listValue(m.BlockedTools), toolsFrom)
	m.ProjectServers = pack.MCP.ProjectServers
	if m.ProjectServers == "" {
		m.ProjectServers = MCPProjectServersBlock
	}
	r.set("mcp.project_servers", m.ProjectServers, r.packLayer)
}

func (r *resolver) resolveResources(o config.OpenShellConfig, flags Flags) error {
	type quantity struct {
		key       string
		requested string
		from      layer
		max       string
		parse     func(string) (int64, error)
		out       *string
	}
	res := &r.eff.Resources
	quantities := []quantity{
		{"resources.cpu", o.Resources.CPU, layer{SourceUser, "openshell.resources.cpu"},
			r.admin.MaxResources.CPU, config.ParseOpenShellCPU, &res.CPU},
		{"resources.memory", o.Resources.Memory, layer{SourceUser, "openshell.resources.memory"},
			r.admin.MaxResources.Memory, config.ParseOpenShellMemory, &res.Memory},
	}
	if flags.CPU != "" {
		quantities[0].requested, quantities[0].from = flags.CPU, layer{SourceFlag, "--cpu"}
	}
	if flags.Memory != "" {
		quantities[1].requested, quantities[1].from = flags.Memory, layer{SourceFlag, "--memory"}
	}
	for _, q := range quantities {
		requested := strings.TrimSpace(q.requested)
		if requested == "" {
			q.from = layerDefault
		}
		var want int64
		if requested != "" {
			var err error
			if want, err = q.parse(requested); err != nil {
				return fmt.Errorf("sandbox policy: %s: %w", q.from.origin, err)
			}
		}
		limit := strings.TrimSpace(q.max)
		if limit == "" {
			*q.out = requested
			value := requested
			if value == "" {
				value = "(unlimited)"
			}
			r.set(q.key, value, q.from)
			continue
		}
		ceiling, err := q.parse(limit)
		if err != nil {
			return fmt.Errorf("sandbox policy: openshell.admin.max_resources: %w", err)
		}
		switch {
		case requested == "":
			*q.out = limit
			r.setClamped(q.key, limit, "(unlimited)", "openshell.admin.max_resources")
		case want > ceiling:
			*q.out = limit
			r.clamp(q.key, requested, limit, q.from, "openshell.admin.max_resources",
				"your organization caps sandbox "+strings.TrimPrefix(q.key, "resources.")+" at "+limit)
		default:
			*q.out = requested
			r.set(q.key, requested, q.from)
		}
	}
	return nil
}

func (r *resolver) resolveLearn(flags Flags) {
	if !flags.Learn {
		r.set("learn", "false", layerDefault)
		return
	}
	if err := r.eff.Allow(Action{Kind: ActionLearnMode}); err != nil {
		r.record(err, SourceFlag)
		r.setClamped("learn", "false", "true", "openshell.admin.allow_learn_mode")
		return
	}
	r.eff.Learn = true
	r.set("learn", "true", layer{SourceFlag, "--learn"})
}

// resolveProcessTree takes observe.process_tree from the pack, or on from
// --process-tree. Watching more is never a loosening, so no policy refuses
// it, and an administrator who wants it on sets it in the required pack.
func (r *resolver) resolveProcessTree(flags Flags) {
	switch {
	case r.eff.Pack.Observe.ProcessTree:
		r.eff.ProcessTree = true
		r.set("observe.process_tree", "true", r.packLayer)
	case flags.ProcessTree:
		r.eff.ProcessTree = true
		r.set("observe.process_tree", "true", layer{SourceFlag, "--process-tree"})
	default:
		r.set("observe.process_tree", "false", r.packLayer)
	}
}

// isFalse reports an explicit false in a tri-state admin switch.
func isFalse(value *bool) bool {
	return value != nil && !*value
}

func mergedLayer(base layer, userContributed bool, userOrigin string) layer {
	if userContributed {
		return layer{SourceUser, base.origin + " + " + userOrigin}
	}
	return base
}

func mergeLists(lists ...[]string) []string {
	out := []string{}
	for _, list := range lists {
		for _, item := range list {
			if item = strings.TrimSpace(item); item != "" {
				out = appendUnique(out, item)
			}
		}
	}
	return out
}

func normalizeGlobs(globs []string) []string {
	out := []string{}
	for _, glob := range globs {
		if g := config.NormalizeOpenShellEgressPattern(glob); g != "" {
			out = appendUnique(out, g)
		}
	}
	return out
}

func uniqueInts(values []int) []int {
	out := []int{}
	for _, v := range values {
		if !containsInt(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func containsInt(list []int, value int) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func listValue(list []string) string {
	if len(list) == 0 {
		return "(none)"
	}
	return strings.Join(list, ", ")
}

func joinInts(values []int) string {
	if len(values) == 0 {
		return "(none)"
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}
