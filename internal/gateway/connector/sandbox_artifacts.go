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

package connector

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// In-image layout of DefenseClaw's OpenShell overlay images. Everything under
// SandboxLibDir and the harness system-policy paths is root-owned and
// read-only to the workload; SandboxHomeDir belongs to the sandbox run-as uid.
const (
	// SandboxIngressHost is the OpenShell ingress host: the name the
	// OpenShell docker driver resolves to a synthetic address inside the
	// workload and relays to host loopback (sandboxruntime.OpenShellHostAlias).
	// A render target with a SandboxIngress names its own host.
	SandboxIngressHost = sandboxruntime.OpenShellHostAlias
	// SandboxLibDir holds DefenseClaw's in-image runtime.
	SandboxLibDir = "/usr/local/lib/defenseclaw"
	// SandboxHookDir holds the sandbox hook scripts and their helpers.
	SandboxHookDir = SandboxLibDir + "/hooks"
	// SandboxHookPATH is baked into the sandbox _hardening.sh. The workload
	// cannot write to any of these directories (Landlock read-only /usr).
	SandboxHookPATH = "/usr/bin:/bin:/usr/sbin:/sbin"
	// SandboxHomeDir is the workload HOME in the OpenShell community base.
	SandboxHomeDir = "/sandbox"
	// SandboxHookLogDir persists hook failures outside the read-only runtime.
	SandboxHookLogDir = SandboxHomeDir + "/.defenseclaw/logs"
	// SandboxFailMode is the only fail mode a sandbox hook set renders with.
	SandboxFailMode = "closed"
	// SandboxTokenEnv carries the per-sandbox binding token. OpenShell
	// delivers it as a revision-scoped provider placeholder and substitutes
	// the real value only on the ingress endpoint, so it can never be baked
	// into static configuration.
	SandboxTokenEnv = "DEFENSECLAW_SANDBOX_TOKEN"
)

// Agent Substrate transport. An actor holds no DefenseClaw credential: every
// hook request carries SandboxActorHeader with SandboxActorPlaceholder, and
// the actor's EgressPolicy rule to the gateway's actor Service replaces the
// header with the actor's signed token (replace_headers actor_jwt). With no
// header sent Substrate injects nothing, so a Substrate render always sends
// it, and never the binding token's Authorization header.
const (
	// SandboxActorHeader names the header Substrate egress replaces.
	SandboxActorHeader = "x-defenseclaw-actor"
	// SandboxActorPlaceholder is the value the actor sends; only the
	// injected token is ever trusted.
	SandboxActorPlaceholder = "defenseclaw-actor-placeholder"
	// SandboxSubstrateTokenPlaceholder is SandboxTokenEnv in a Substrate
	// actor. It is not a credential and no Substrate hook request carries
	// it as one: it only satisfies the token presence checks the hook
	// scripts share with OpenShell.
	SandboxSubstrateTokenPlaceholder = "substrate-actor"
)

// SandboxIngress is where a sandbox's hooks reach DefenseClaw. The zero
// value with a port is the OpenShell ingress.
type SandboxIngress struct {
	// Runtime is sandboxruntime.OpenShell ("" selects it) or
	// sandboxruntime.Substrate.
	Runtime string
	// Host is the ingress host. OpenShell: empty or SandboxIngressHost.
	// Substrate: required, the gateway's actor Service DNS name.
	Host string
	// Port is the ingress port. Required.
	Port int
	// Scheme is "http" (empty selects it) or "https". OpenShell relays
	// plain HTTP only; a Substrate actor may use https when its rule to the
	// actor Service is an inspected https rule.
	Scheme string
	// CAFile is the absolute in-image CA bundle an https ingress is
	// verified with (Substrate's projected bundle). It is baked into the
	// hooks as curl --cacert, because they drop every inherited variable.
	// Empty keeps curl's default trust. https only.
	CAFile string
	// ActorHeader sends SandboxActorHeader: SandboxActorPlaceholder on every
	// hook request in place of the binding token's Authorization header.
	// Substrate requires it; OpenShell refuses it.
	ActorHeader bool
}

// Addr is the ingress host:port.
func (in SandboxIngress) Addr() string {
	return net.JoinHostPort(in.Host, strconv.Itoa(in.Port))
}

// URL is the ingress URL of an absolute request path.
func (in SandboxIngress) URL(requestPath string) string {
	scheme := in.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + in.Addr() + requestPath
}

// Substrate reports an Agent Substrate ingress.
func (in SandboxIngress) Substrate() bool {
	return sandboxruntime.Normalize(in.Runtime) == sandboxruntime.Substrate
}

// Tamper tiers published for a sandboxed connector.
const (
	// SandboxTamperTierManaged: the hook registration lives in the harness's
	// system/managed policy tier, root-owned in the image, and user or
	// project settings cannot switch it off.
	SandboxTamperTierManaged = "managed"
	// SandboxTamperTierUser: the agent or a repository can switch the hooks
	// off, because the registration lives in a user-scope file the agent can
	// edit, or because code they add runs beside the hooks (OpenCode's
	// in-process plugins); hook-silence detection is the backstop.
	SandboxTamperTierUser = "user"
)

// Sandbox ingress request budgets (seconds). Two attempts must fit inside the
// harness's 30-second hook envelope with room for parsing; Codex caps
// SessionEnd at three seconds overall.
const (
	sandboxHookConnectTimeoutSeconds    = 2
	sandboxHookMaxTimeSeconds           = 9
	sandboxHookRetryMaxTimeSeconds      = 12
	sandboxHookSessionEndMaxTimeSeconds = 1
)

// SandboxHookAttemptBudgets is how long the rendered sandbox hook waits for
// its first ingress attempt and for its keyed retry (curl --max-time).
func SandboxHookAttemptBudgets() (first, retry time.Duration) {
	return sandboxHookMaxTimeSeconds * time.Second, sandboxHookRetryMaxTimeSeconds * time.Second
}

// SandboxOwner is the in-image owner of a rendered file.
type SandboxOwner string

const (
	// SandboxOwnerRoot files are root:root and read-only to the workload.
	SandboxOwnerRoot SandboxOwner = "root"
	// SandboxOwnerUser files belong to the sandbox run-as uid/gid (the
	// overlay build chowns them together with SandboxHomeDir).
	SandboxOwnerUser SandboxOwner = "user"
)

// SandboxFile is one file DefenseClaw places in an overlay image.
type SandboxFile struct {
	// Path is the absolute, clean in-image path.
	Path string
	// Mode holds the permission bits only.
	Mode os.FileMode
	// Owner selects root or the sandbox run-as user.
	Owner SandboxOwner
	// Data is the exact file content.
	Data []byte
}

// SandboxBinaryRole says why an image must provide a binary.
type SandboxBinaryRole string

const (
	// SandboxBinaryHarness is the agent CLI itself.
	SandboxBinaryHarness SandboxBinaryRole = "harness"
	// SandboxBinaryRuntime is a tool the rendered hooks or helpers execute.
	SandboxBinaryRuntime SandboxBinaryRole = "runtime"
)

// SandboxBinary is a command the rendered artifacts depend on. Image builds
// resolve each one inside the image (runtime tools on SandboxHookPATH, the
// harness on the image PATH) and record its realpath and digest; a missing
// binary, or one whose realpath the workload could write, fails the build.
type SandboxBinary struct {
	Name string
	Role SandboxBinaryRole
}

// SandboxRenderTarget describes the overlay image a connector renders for.
// Every field is image-scoped: nothing here depends on a particular project,
// sandbox name or credential, so one image serves every sandbox of its
// harness, uid and ingress port.
type SandboxRenderTarget struct {
	// IngressPort is the host-loopback hook ingress port the sandbox reaches
	// as host.openshell.internal:<IngressPort>. Required unless Ingress is
	// set; with Ingress it must be zero or Ingress.Port.
	IngressPort int
	// Ingress is a remote ingress (ResolveIngress): an Agent Substrate
	// actor's gateway Service. Nil renders for OpenShell on IngressPort.
	Ingress *SandboxIngress
	// FailMode must be empty or "closed": sandbox hooks always fail closed.
	// Every request crosses the OpenShell relay and carries a token from the
	// workload's environment, so the workload can make the ingress answer
	// any status, and a fail-open image would let it turn a deny into an
	// allow. "open" (and any other value) is refused.
	FailMode string
	// AgentVersion is the exact harness version installed in the image. It
	// must resolve to a Known Linux hook contract.
	AgentVersion string
	// HookContractID optionally pins the contract; it must equal the one
	// AgentVersion resolves to.
	HookContractID string
	// OtelEnvironment labels native Codex telemetry (otel.environment).
	// Empty selects "openshell".
	OtelEnvironment string
}

// SandboxArtifacts is everything a connector contributes to an overlay image
// and to sandbox creation.
type SandboxArtifacts struct {
	Connector string
	// HookContract is the resolved hook contract the image is pinned to.
	HookContract string
	// TamperTier is SandboxTamperTierManaged or SandboxTamperTierUser.
	TamperTier string
	// Files are sorted by Path.
	Files []SandboxFile
	// Env must be passed at sandbox creation (openshell sandbox create --env):
	// OpenShell does not propagate image ENV, and managed-settings env
	// applies too late for harness startup traffic.
	Env map[string]string
	// Binaries the image must provide, sorted by Name.
	Binaries []SandboxBinary
}

// SandboxArtifactProvider is implemented by connectors that can run inside
// a sandbox: an OpenShell sandbox, or an Agent Substrate actor when the
// target names a Substrate SandboxIngress (SandboxRenderTarget.Ingress).
type SandboxArtifactProvider interface {
	SandboxArtifacts(SandboxRenderTarget) (SandboxArtifacts, error)
}

// ResolveSandboxHookContract resolves a harness version against the Linux
// hook contracts, which are the ones every overlay image runs. A connector
// with sandbox-only contracts resolves against those instead: one whose host
// hooks are not version-gated (Kiro), as an overlay image always pins a
// reviewed harness build, and one whose sandbox needs a narrower range than
// its host. A version the host contract accepts and the sandbox
// refuses gets the sandbox's reason. Overlay images pin reviewed builds, so
// sandbox resolution keeps exact-range matching.
func ResolveSandboxHookContract(connectorName, agentVersion string) HookContractResolution {
	name := normalizeConnectorName(connectorName)
	if contracts := sandboxOnlyHookContracts(name); len(contracts) > 0 {
		resolution := strictHookContractResolutionOf(resolveHookContractAgainstIn(name, agentVersion, contracts, true))
		if why := sandboxOnlyRefusals[name]; why != "" && resolution.Status == HookCompatibilityUnknown &&
			resolveHookContractForOSModeIn(name, agentVersion, "linux", true, true).Status == HookCompatibilityKnown {
			resolution.Reason = why
		}
		return resolution
	}
	return resolveHookContractForOSModeIn(connectorName, agentVersion, "linux", true, true)
}

// sandboxOnlyHookContractsByConnector are reviewed hook contracts that apply
// only inside DefenseClaw's OpenShell overlay images, for connectors whose
// host hooks are not version-gated or whose sandbox needs a narrower range.
// Each connector keeps its contracts in its own <connector>_sandbox.go file.
var sandboxOnlyHookContractsByConnector = map[string]func() []HookContract{
	"kiro": kiroSandboxHookContracts,
}

// sandboxOnlyRefusals say why a sandbox refuses a version its connector's
// host contract accepts.
var sandboxOnlyRefusals = map[string]string{}

// sandboxOnlyHookContracts returns fresh copies of connector's sandbox-only
// hook contracts (none for most connectors).
func sandboxOnlyHookContracts(connectorName string) []HookContract {
	contracts, ok := sandboxOnlyHookContractsByConnector[normalizeConnectorName(connectorName)]
	if !ok {
		return nil
	}
	return contracts()
}

// ResolveIngress returns the validated ingress of t: the OpenShell ingress
// (SandboxIngressHost, plain HTTP, binding token) on IngressPort when
// Ingress is nil, else Ingress with its defaults filled in.
//
// OpenShell refuses another host, https and the actor header: its relay
// carries plain HTTP to host loopback and the binding token is its only
// credential. Substrate needs a DNS host other than the OpenShell alias and
// the actor header, and takes a CA bundle only with https.
func (t SandboxRenderTarget) ResolveIngress() (SandboxIngress, error) {
	in := SandboxIngress{Port: t.IngressPort}
	if t.Ingress != nil {
		in = *t.Ingress
		if t.IngressPort != 0 && t.IngressPort != in.Port {
			return SandboxIngress{}, fmt.Errorf("sandbox ingress port %d contradicts the ingress's port %d", t.IngressPort, in.Port)
		}
	}
	if in.Port < 1 || in.Port > 65535 {
		return SandboxIngress{}, fmt.Errorf("sandbox ingress port %d is out of range", in.Port)
	}
	runtimeName := sandboxruntime.Normalize(in.Runtime)
	if runtimeName == "" {
		return SandboxIngress{}, fmt.Errorf("sandbox runtime %q is not supported", in.Runtime)
	}
	in.Runtime = runtimeName
	switch in.Scheme {
	case "":
		in.Scheme = "http"
	case "http", "https":
	default:
		return SandboxIngress{}, fmt.Errorf("sandbox ingress scheme %q is not http or https", in.Scheme)
	}
	if in.CAFile != "" {
		if in.Scheme != "https" {
			return SandboxIngress{}, fmt.Errorf("a sandbox ingress CA bundle needs https")
		}
		if !path.IsAbs(in.CAFile) || path.Clean(in.CAFile) != in.CAFile || strings.ContainsAny(in.CAFile, "\x00\n\r") {
			return SandboxIngress{}, fmt.Errorf("sandbox ingress CA bundle %q is not an absolute, clean in-image path", in.CAFile)
		}
	}
	if runtimeName == sandboxruntime.OpenShell {
		switch {
		case in.Host != "" && in.Host != SandboxIngressHost:
			return SandboxIngress{}, fmt.Errorf("an OpenShell sandbox reaches DefenseClaw only at %s, not %q", SandboxIngressHost, in.Host)
		case in.Scheme != "http":
			return SandboxIngress{}, fmt.Errorf("the OpenShell relay carries plain HTTP only")
		case in.ActorHeader:
			return SandboxIngress{}, fmt.Errorf("an OpenShell sandbox authenticates with its binding token, not the actor header")
		}
		in.Host = SandboxIngressHost
		return in, nil
	}
	if !validSandboxIngressDNSName(in.Host) || sandboxruntime.IsOpenShellHostAlias(in.Host) {
		return SandboxIngress{}, fmt.Errorf("a Substrate sandbox ingress needs the gateway Service's DNS name, not %q", in.Host)
	}
	if !in.ActorHeader {
		return SandboxIngress{}, fmt.Errorf("a Substrate sandbox ingress always sends the %s header: Substrate injects the actor token only into a header the request carries", SandboxActorHeader)
	}
	return in, nil
}

// validSandboxIngressDNSName reports a lowercase DNS name of at most 253
// bytes whose labels are 1 to 63 letters, digits and inner hyphens. It is
// baked into shell scripts, so nothing else is allowed.
func validSandboxIngressDNSName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// sandboxHookScriptsByConnector lists the connector-owned lifecycle scripts
// whose templates carry the {{if .Sandbox}} variant. Rendering any other
// connector in sandbox mode would silently produce host-shaped scripts that
// read host token files, so it is refused.
var sandboxHookScriptsByConnector = map[string][]string{
	"antigravity": {"antigravity-hook.sh"},
	"claudecode":  {"claude-code-hook.sh"},
	"codex":       {"codex-hook.sh"},
	"copilot":     {"copilot-hook.sh"},
	"cursor":      {"cursor-hook.sh"},
	"devin":       {"devin-hook.sh"},
	"hermes":      {"hermes-hook.sh"},
	"kiro":        {"kiro-hook.sh"},
}

// SandboxSubstrateHookBinary is the actor kit's hook command in an Agent
// Substrate image (kit.HookBinary; a test pins the two together).
const SandboxSubstrateHookBinary = SandboxHookDir + "/defenseclaw-actor-hook"

// substratePluginTransports are the in-agent plugin connectors whose
// Substrate variant execs "defenseclaw-actor-hook hook-post". Amp's plugin
// has no such variant yet, so a Substrate render of it is refused.
var substratePluginTransports = map[string]bool{"opencode": true, "amp": true}

// sandboxHookHostOnlyMarkers must never survive into a rendered sandbox
// script: each one is a host-only credential, fail-mode or data-dir input.
var sandboxHookHostOnlyMarkers = []string{
	"DEFENSECLAW_GATEWAY_TOKEN:-",
	"DEFENSECLAW_FAIL_MODE:-",
	"defenseclaw_handle_missing_token",
	"defenseclaw_shared_runtime_connector",
	"defenseclaw_shared_runtime_fail_mode",
	"defenseclaw_shared_hook_token_file",
	`DEFENSECLAW_HOME:-`,
}

// resolvedSandboxTarget is a validated SandboxRenderTarget.
type resolvedSandboxTarget struct {
	// ingress is the validated ingress; ingressAddr is its host:port.
	ingress     SandboxIngress
	ingressAddr string
	failMode    string
	contract    HookContract
	opts        SetupOpts
}

func resolveSandboxTarget(connectorName string, target SandboxRenderTarget) (resolvedSandboxTarget, error) {
	if runtime.GOOS == "windows" {
		return resolvedSandboxTarget{}, fmt.Errorf("OpenShell sandbox artifacts cannot be rendered on Windows hosts")
	}
	ingress, err := target.ResolveIngress()
	if err != nil {
		return resolvedSandboxTarget{}, err
	}
	name := normalizeConnectorName(connectorName)
	if _, shell := sandboxHookScriptsByConnector[name]; ingress.Substrate() && !shell && !substratePluginTransports[name] {
		// The shared shell transport (_sandbox.sh) and the plugins that exec
		// the actor kit's hook-post (substratePluginTransports) send the
		// actor header; any other plugin transport would send the bearer and
		// no header, and Substrate would inject no token.
		return resolvedSandboxTarget{}, fmt.Errorf("%s has no Agent Substrate transport yet: its in-agent plugin does not send the %s header", connectorName, SandboxActorHeader)
	}
	version := strings.TrimSpace(target.AgentVersion)
	if version == "" {
		return resolvedSandboxTarget{}, fmt.Errorf("%s sandbox artifacts need the pinned harness version", connectorName)
	}
	resolution := ResolveSandboxHookContract(connectorName, version)
	if resolution.Status != HookCompatibilityKnown {
		return resolvedSandboxTarget{}, fmt.Errorf(
			"%s %s has no reviewed Linux hook contract (%s): refusing to render sandbox artifacts",
			connectorName, version, resolution.Reason,
		)
	}
	if pinned := strings.TrimSpace(target.HookContractID); pinned != "" && pinned != resolution.Contract.ContractID {
		return resolvedSandboxTarget{}, fmt.Errorf(
			"%s %s resolves to hook contract %s, not the pinned %s",
			connectorName, version, resolution.Contract.ContractID, pinned,
		)
	}
	if mode := strings.TrimSpace(target.FailMode); mode != "" && mode != SandboxFailMode {
		return resolvedSandboxTarget{}, fmt.Errorf(
			"%s sandbox hooks always fail closed: fail mode %q is refused (the workload can make the ingress answer any status)",
			connectorName, target.FailMode,
		)
	}
	return resolvedSandboxTarget{
		ingress:     ingress,
		ingressAddr: ingress.Addr(),
		failMode:    SandboxFailMode,
		contract:    resolution.Contract,
		opts: SetupOpts{
			// DataDir anchors the existing hook-matrix verifiers: they expect
			// <DataDir>/hooks/<script>, which is SandboxHookDir here.
			DataDir:           SandboxLibDir,
			APIAddr:           ingress.Addr(),
			AgentVersion:      version,
			HookContractID:    resolution.Contract.ContractID,
			HookFailMode:      SandboxFailMode,
			ManagedEnterprise: true,
		},
	}, nil
}

// renderSandboxHookFiles renders the in-image hook directory for one
// connector: the shared inspect-* scripts and the connector's lifecycle
// scripts in their sandbox variants, _hardening.sh with the baked PATH, and
// the sandbox transport helper _sandbox.sh.
func renderSandboxHookFiles(connectorName string, rt resolvedSandboxTarget) ([]SandboxFile, error) {
	name := normalizeConnectorName(connectorName)
	extras, ok := sandboxHookScriptsByConnector[name]
	if !ok {
		return nil, fmt.Errorf("connector %q has no sandbox hook variant", connectorName)
	}
	data := templateData{
		APIAddr:                  rt.ingressAddr,
		FailMode:                 rt.failMode,
		Managed:                  true,
		ConnectorName:            name,
		Sandbox:                  true,
		SandboxConnectTimeout:    sandboxHookConnectTimeoutSeconds,
		SandboxMaxTime:           sandboxHookMaxTimeSeconds,
		SandboxRetryMaxTime:      sandboxHookRetryMaxTimeSeconds,
		SandboxSessionEndMaxTime: sandboxHookSessionEndMaxTimeSeconds,
		SandboxHookDirSH:         shellSingleQuote(SandboxHookDir),
	}
	if rt.ingress.Substrate() {
		data.SandboxSubstrate = true
		data.SandboxScheme = rt.ingress.Scheme
		data.SandboxActorHeaderSH = shellSingleQuote(SandboxActorHeader + ": " + SandboxActorPlaceholder)
		if rt.ingress.CAFile != "" {
			data.SandboxCAFileSH = shellSingleQuote(rt.ingress.CAFile)
		}
	}
	// One harness per image: the shared scripts bake the same connector.
	scripts, err := renderHookScriptSet(data, data, extras)
	if err != nil {
		return nil, err
	}
	files := make([]SandboxFile, 0, len(scripts)+2)
	for _, script := range scripts {
		body, err := sandboxHookShebang(script.Name, script.Data)
		if err != nil {
			return nil, err
		}
		if marker := sandboxHookHostOnlyReference(body); marker != "" {
			return nil, fmt.Errorf("sandbox hook %s still references host-only %q", script.Name, marker)
		}
		files = append(files, SandboxFile{
			Path:  path.Join(SandboxHookDir, script.Name),
			Mode:  0o755,
			Owner: SandboxOwnerRoot,
			Data:  body,
		})
	}
	hardening, err := renderSandboxHardening()
	if err != nil {
		return nil, err
	}
	transport, err := renderHookTemplate("_sandbox.sh", data)
	if err != nil {
		return nil, err
	}
	files = append(files,
		SandboxFile{Path: path.Join(SandboxHookDir, "_hardening.sh"), Mode: 0o644, Owner: SandboxOwnerRoot, Data: hardening},
		SandboxFile{Path: path.Join(SandboxHookDir, "_sandbox.sh"), Mode: 0o644, Owner: SandboxOwnerRoot, Data: transport},
	)
	return files, nil
}

// sandboxHookHostOnlyReference returns the first host-only marker used on a
// non-comment line of a rendered sandbox script, or "".
func sandboxHookHostOnlyReference(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, marker := range sandboxHookHostOnlyMarkers {
			if strings.Contains(trimmed, marker) {
				return marker
			}
		}
	}
	return ""
}

// sandboxHookShebang switches a rendered hook to `bash -p`: privileged mode
// ignores BASH_ENV/ENV and never imports exported shell functions, so the
// workload cannot inject code into the hook through its environment.
func sandboxHookShebang(name string, body []byte) ([]byte, error) {
	const host = "#!/bin/bash\n"
	if !bytes.HasPrefix(body, []byte(host)) {
		return nil, fmt.Errorf("sandbox hook %s does not start with %q", name, strings.TrimSpace(host))
	}
	return append([]byte("#!/bin/bash -p\n"), body[len(host):]...), nil
}

// renderSandboxHardening bakes the runtime PATH and the writable workload
// log directory into the helper. Host and Secure Client helpers keep their
// original PATH and log destination.
func renderSandboxHardening() ([]byte, error) {
	content, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		return nil, fmt.Errorf("read hook helper _hardening.sh: %w", err)
	}
	const sentinel = `DEFENSECLAW_BAKED_HOOK_PATH=""` + "\n"
	if bytes.Count(content, []byte(sentinel)) != 1 {
		return nil, fmt.Errorf("_hardening.sh must carry exactly one baked-PATH sentinel")
	}
	baked := `DEFENSECLAW_BAKED_HOOK_PATH="` + SandboxHookPATH + `"` + "\n"
	content = bytes.Replace(content, []byte(sentinel), []byte(baked), 1)
	// DEFENSECLAW_HOME names the root-owned runtime in a sandbox, and the
	// hardening helper replaces HOME with a temporary directory. Neither is
	// a persistent writable log destination. Bake the workload path rather
	// than accepting a destination from the agent's environment.
	const logSentinel = `  local log_dir="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}/logs"`
	if bytes.Count(content, []byte(logSentinel)) != 1 {
		return nil, fmt.Errorf("_hardening.sh must carry exactly one hook-failure log directory")
	}
	logDir := `  local log_dir="` + SandboxHookLogDir + `"`
	content = bytes.Replace(content, []byte(logSentinel), []byte(logDir), 1)
	// The per-user helper creates only logs, never the DefenseClaw folder a
	// purge removed (GAP-0654). The workload data home is the sandbox's own
	// and has no purge, so its log directory is created with its parents.
	const mkdirSentinel = `  [ -d "$log_dir" ] || mkdir "$log_dir" 2>/dev/null || return 0`
	if bytes.Count(content, []byte(mkdirSentinel)) != 1 {
		return nil, fmt.Errorf("_hardening.sh must create the hook-failure log directory once")
	}
	return bytes.Replace(content, []byte(mkdirSentinel), []byte(`  mkdir -p "$log_dir" 2>/dev/null || return 0`), 1), nil
}

// finalizeSandboxArtifactsFor is finalizeSandboxArtifacts for rt's runtime: a
// Substrate actor's create-time env carries SandboxSubstrateTokenPlaceholder
// as SandboxTokenEnv, which no connector may set itself.
func finalizeSandboxArtifactsFor(rt resolvedSandboxTarget, a SandboxArtifacts) (SandboxArtifacts, error) {
	if rt.ingress.Substrate() {
		if _, set := a.Env[SandboxTokenEnv]; set {
			return SandboxArtifacts{}, fmt.Errorf("sandbox artifacts may not set %s", SandboxTokenEnv)
		}
		env := make(map[string]string, len(a.Env)+1)
		for key, value := range a.Env {
			env[key] = value
		}
		env[SandboxTokenEnv] = SandboxSubstrateTokenPlaceholder
		a.Env = env
	}
	return finalizeSandboxArtifacts(a)
}

// finalizeSandboxArtifacts validates paths, rejects duplicates and sorts the
// file and binary lists so artifact sets are deterministic.
func finalizeSandboxArtifacts(a SandboxArtifacts) (SandboxArtifacts, error) {
	seen := make(map[string]struct{}, len(a.Files))
	for _, file := range a.Files {
		if !path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path {
			return SandboxArtifacts{}, fmt.Errorf("sandbox artifact path %q is not absolute and clean", file.Path)
		}
		if file.Mode&^os.ModePerm != 0 {
			return SandboxArtifacts{}, fmt.Errorf("sandbox artifact %s mode %v carries non-permission bits", file.Path, file.Mode)
		}
		if file.Owner != SandboxOwnerRoot && file.Owner != SandboxOwnerUser {
			return SandboxArtifacts{}, fmt.Errorf("sandbox artifact %s has unknown owner %q", file.Path, file.Owner)
		}
		if file.Owner == SandboxOwnerUser && !strings.HasPrefix(file.Path, SandboxHomeDir+"/") {
			return SandboxArtifacts{}, fmt.Errorf("user-owned sandbox artifact %s is outside %s", file.Path, SandboxHomeDir)
		}
		if _, dup := seen[file.Path]; dup {
			return SandboxArtifacts{}, fmt.Errorf("duplicate sandbox artifact %s", file.Path)
		}
		seen[file.Path] = struct{}{}
	}
	sort.Slice(a.Files, func(i, j int) bool { return a.Files[i].Path < a.Files[j].Path })
	sort.Slice(a.Binaries, func(i, j int) bool { return a.Binaries[i].Name < a.Binaries[j].Name })
	if a.Env == nil {
		a.Env = map[string]string{}
	}
	return a, nil
}

// sandboxHookRuntimeTools are the tools the sandbox hooks and their helpers
// execute from SandboxHookPATH (bash is the shebang interpreter, readlink
// resolves a symlinked hook, od derives an idempotency key where
// /proc/sys/kernel/random/uuid is unreadable). The image probe resolves each
// one on SandboxHookPATH and requires a root-owned realpath the workload
// cannot write; TestSandboxHookRuntimeBinariesCoverEveryTool keeps the list
// complete.
var sandboxHookRuntimeTools = []string{
	"awk", "bash", "chmod", "curl", "date", "find", "head", "id", "jq", "mkdir", "mktemp", "od", "readlink", "rm", "sed", "tail", "tr",
}

// sandboxHookRuntimeBinaries are the tools every sandbox hook set executes.
func sandboxHookRuntimeBinaries() []SandboxBinary {
	out := make([]SandboxBinary, 0, len(sandboxHookRuntimeTools))
	for _, name := range sandboxHookRuntimeTools {
		out = append(out, SandboxBinary{Name: name, Role: SandboxBinaryRuntime})
	}
	return out
}

var (
	_ SandboxArtifactProvider = (*ClaudeCodeConnector)(nil)
	_ SandboxArtifactProvider = (*CodexConnector)(nil)
	_ SandboxArtifactProvider = (*AMPConnector)(nil)
	_ SandboxArtifactProvider = (*KiroConnector)(nil)
)
