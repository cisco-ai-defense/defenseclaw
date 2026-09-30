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
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
)

// In-image layout of DefenseClaw's OpenShell overlay images. Everything under
// SandboxLibDir and the harness system-policy paths is root-owned and
// read-only to the workload; SandboxHomeDir belongs to the sandbox run-as uid.
const (
	// SandboxIngressHost is the name the OpenShell docker driver resolves to
	// a synthetic address inside the workload and relays to host loopback.
	SandboxIngressHost = "host.openshell.internal"
	// SandboxLibDir holds DefenseClaw's in-image runtime.
	SandboxLibDir = "/usr/local/lib/defenseclaw"
	// SandboxHookDir holds the sandbox hook scripts and their helpers.
	SandboxHookDir = SandboxLibDir + "/hooks"
	// SandboxHookPATH is baked into the sandbox _hardening.sh. The workload
	// cannot write to any of these directories (Landlock read-only /usr).
	SandboxHookPATH = "/usr/bin:/bin:/usr/sbin:/sbin"
	// SandboxHomeDir is the workload HOME in the OpenShell community base.
	SandboxHomeDir = "/sandbox"
	// SandboxFailMode is the only fail mode a sandbox hook set renders with.
	SandboxFailMode = "closed"
	// SandboxTokenEnv carries the per-sandbox binding token. OpenShell
	// delivers it as a revision-scoped provider placeholder and substitutes
	// the real value only on the ingress endpoint, so it can never be baked
	// into static configuration.
	SandboxTokenEnv = "DEFENSECLAW_SANDBOX_TOKEN"
)

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
	// as host.openshell.internal:<IngressPort>. Required.
	IngressPort int
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
// an OpenShell sandbox.
type SandboxArtifactProvider interface {
	SandboxArtifacts(SandboxRenderTarget) (SandboxArtifacts, error)
}

// ResolveSandboxHookContract resolves a harness version against the Linux
// hook contracts, which are the ones every overlay image runs. A connector
// with sandbox-only contracts resolves against those instead: one whose host
// hooks are not version-gated (Kiro), as an overlay image always pins a
// reviewed harness build, and one whose sandbox needs a narrower range than
// its host (OmniGent). A version the host contract accepts and the sandbox
// refuses gets the sandbox's reason.
func ResolveSandboxHookContract(connectorName, agentVersion string) HookContractResolution {
	name := normalizeConnectorName(connectorName)
	if contracts := sandboxOnlyHookContracts(name); len(contracts) > 0 {
		resolution := resolveHookContractAgainst(name, agentVersion, contracts)
		if why := sandboxOnlyRefusals[name]; why != "" && resolution.Status == HookCompatibilityUnknown &&
			resolveHookContractForOS(name, agentVersion, "linux").Status == HookCompatibilityKnown {
			resolution.Reason = why
		}
		return resolution
	}
	return resolveHookContractForOS(connectorName, agentVersion, "linux")
}

// sandboxOnlyHookContractsByConnector are reviewed hook contracts that apply
// only inside DefenseClaw's OpenShell overlay images, for connectors whose
// host hooks are not version-gated or whose sandbox needs a narrower range.
// Each connector keeps its contracts in its own <connector>_sandbox.go file.
var sandboxOnlyHookContractsByConnector = map[string]func() []HookContract{
	"kiro":     kiroSandboxHookContracts,
	"omnigent": omnigentSandboxHookContracts,
}

// sandboxOnlyRefusals say why a sandbox refuses a version its connector's
// host contract accepts.
var sandboxOnlyRefusals = map[string]string{
	"omnigent": omnigentSandboxRefusal,
}

// sandboxOnlyHookContracts returns fresh copies of connector's sandbox-only
// hook contracts (none for most connectors).
func sandboxOnlyHookContracts(connectorName string) []HookContract {
	contracts, ok := sandboxOnlyHookContractsByConnector[normalizeConnectorName(connectorName)]
	if !ok {
		return nil
	}
	return contracts()
}

// SandboxIngressAddr returns host.openshell.internal:<port>.
func SandboxIngressAddr(port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("sandbox ingress port %d is out of range", port)
	}
	return fmt.Sprintf("%s:%d", SandboxIngressHost, port), nil
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
	"openhands":   {"openhands-hook.sh"},
}

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
	ingressAddr string
	failMode    string
	contract    HookContract
	opts        SetupOpts
}

func resolveSandboxTarget(connectorName string, target SandboxRenderTarget) (resolvedSandboxTarget, error) {
	if runtime.GOOS == "windows" {
		return resolvedSandboxTarget{}, fmt.Errorf("OpenShell sandbox artifacts cannot be rendered on Windows hosts")
	}
	ingress, err := SandboxIngressAddr(target.IngressPort)
	if err != nil {
		return resolvedSandboxTarget{}, err
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
		ingressAddr: ingress,
		failMode:    SandboxFailMode,
		contract:    resolution.Contract,
		opts: SetupOpts{
			// DataDir anchors the existing hook-matrix verifiers: they expect
			// <DataDir>/hooks/<script>, which is SandboxHookDir here.
			DataDir:           SandboxLibDir,
			APIAddr:           ingress,
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

// renderSandboxHardening bakes SandboxHookPATH into _hardening.sh through its
// reserved DEFENSECLAW_BAKED_HOOK_PATH sentinel; the host helper keeps the
// empty sentinel and its default PATH.
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
	return bytes.Replace(content, []byte(sentinel), []byte(baked), 1), nil
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
	"bash", "chmod", "curl", "date", "find", "head", "id", "jq", "mkdir", "mktemp", "od", "readlink", "rm", "sed", "tail", "tr",
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
