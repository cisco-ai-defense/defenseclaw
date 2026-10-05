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

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// Sandbox hook requests carry an authenticated sandboxauth binding in their
// context (see api_sandbox_ingress.go). Handlers consult these helpers
// wherever host behaviour would otherwise leak into a sandbox request:
//
//   - The connector profile comes from the binding's reviewed contract and
//     image agent version, never from the host contract lock or version
//     cache, because the harness runs from the sandbox image.
//   - A payload working directory is translated through the binding's
//     FSView: in mount mode it becomes the real host path of the mounted
//     project directory (so path-based inspections see the files the agent
//     actually edited), and in copy mode it becomes empty. Absolute paths the
//     agent names elsewhere stay in the sandbox namespace and reach the host
//     only through FSView.
//   - Tool results never take the source-scope proofs that read the host
//     tree (sandboxToolResultUntrusted).
//   - Session state is per binding. Session IDs are chosen by the agent,
//     and the host and each sandbox are separate trust domains, so a
//     sandbox that names another domain's session must land in its own
//     state: correlation resolves a connector instance per binding
//     (resolveConnectorInstanceForRequest), and in-memory per-session maps
//     key on sandboxSessionStateKey.
//   - Nothing runs git or a subprocess scanner against the agent-writable
//     tree on the host. The agent controls .git internals other than hooks
//     and config (for example .git/commondir and nested repositories), so
//     host git could be steered into running configured filters as the
//     host user; subprocess scanners may follow symlinks out of the project
//     and forward file content to remote analyzers.

// sandboxHookView returns the filesystem view of a sandbox request.
func sandboxHookView(ctx context.Context) (*sandboxauth.FSView, bool) {
	return sandboxauth.ViewFromContext(ctx)
}

// isSandboxHookRequest reports whether ctx belongs to an authenticated
// sandbox request.
func isSandboxHookRequest(ctx context.Context) bool {
	_, ok := sandboxauth.FromContext(ctx)
	return ok
}

// sandboxHookForConnector reports whether ctx is a sandbox request whose
// binding was minted for connectorName.
func sandboxHookForConnector(ctx context.Context, connectorName string) bool {
	binding, ok := sandboxauth.FromContext(ctx)
	return ok && sandboxauth.CanonicalConnector(connectorName) == binding.Connector
}

// sandboxHookMode is the verdict mode of a hook request: hostMode for host
// traffic, and always "action" for a request authenticated with a sandbox
// binding minted for connectorName. DefenseClaw launched that harness
// itself, usually with its own permission prompts off, so the host's
// guardrail mode (observe by default) must not turn the sandbox's blocks
// into warnings: its hooks are the only gate on every tool call.
func sandboxHookMode(ctx context.Context, connectorName, hostMode string) string {
	if sandboxHookForConnector(ctx, connectorName) {
		return "action"
	}
	return hostMode
}

// hookCWDForContext resolves a payload working directory: unchanged host
// behaviour for host requests, FSView translation for sandbox requests.
func hookCWDForContext(ctx context.Context, cwd string) string {
	if view, ok := sandboxHookView(ctx); ok {
		return sandboxHookCWD(view, cwd)
	}
	return sanitizeHookCWD(cwd)
}

// hookActiveHome is the directory "~" names in a request's tool calls: the
// verified caller's home for host traffic (trustedActiveHome) and the fixed
// sandbox HOME for a sandbox, whose agent has no access to the host home.
// The sandbox working directory is still mapped to its host project
// (hookCWDForContext), so project-relative operands resolve where the
// gateway can inspect them, while "~/.ssh" is matched as the agent's
// /sandbox/.ssh and never as a host path the command cannot reach.
func hookActiveHome(ctx context.Context) string {
	if isSandboxHookRequest(ctx) {
		return sandboxauth.SandboxHome
	}
	return trustedActiveHome(ctx)
}

// sandboxHookCWD maps a sandbox working directory to the real host
// directory it is mounted from, or "" when it has no host counterpart.
func sandboxHookCWD(view *sandboxauth.FSView, cwd string) string {
	cwd = strings.TrimSpace(cwd)
	if view == nil || cwd == "" {
		return ""
	}
	host, err := view.HostDir(cwd)
	if err != nil {
		return ""
	}
	return host
}

// recordsConnectorHealth reports whether a hook request counts toward its
// connector's /health row (requests, last activity, load heartbeat,
// inspections, blocks). A sandbox request does not: the row describes the
// host's connector, and a sandbox runs its own harness from its image, so
// its hooks made a host connector look active (or added a running row for
// one the host does not use). Sandbox hook activity is reported per sandbox
// (observeSandboxHookDecision).
func (a *APIServer) recordsConnectorHealth(ctx context.Context) bool {
	return a.health != nil && !isSandboxHookRequest(ctx)
}

// sandboxToolResultUntrusted reports whether a tool result must skip the
// source-scope proofs and stay in the untrusted detector scope. Those proofs
// (codexToolResultContentScope, codexObserveWorkspaceSourceProofForRequest
// and the git-diff line verifier) stat, open, walk and compare files on the
// host under the payload's working directory. For a sandbox that tree is
// agent-writable and may hold masked secrets the agent was shown as empty
// files: comparing agent-supplied diff text with a masked file's real lines
// turns the verdict scope into an oracle on the secret, and a swapped-in
// FIFO could park the read. Sandbox tool results therefore never earn the
// source-scope downgrade; they are inspected like any other untrusted output.
func sandboxToolResultUntrusted(ctx context.Context) bool {
	return isSandboxHookRequest(ctx)
}

// sandboxSessionStateKey is the key under which in-memory per-session state
// for sessionID is kept: the bare ID for host traffic, and the ID qualified
// by the binding for a sandbox request.
func sandboxSessionStateKey(ctx context.Context, sessionID string) string {
	if sessionID == "" {
		return ""
	}
	if binding, ok := sandboxauth.FromContext(ctx); ok {
		return "sandbox\x00" + binding.ID + "\x00" + sessionID
	}
	return sessionID
}

// sandboxConnectorInstanceNamespace domain-separates derived sandbox
// connector instance IDs.
const sandboxConnectorInstanceNamespace = "defenseclaw/openshell/sandbox-connector-instance/v1"

// sandboxConnectorInstanceID derives a binding's correlation connector
// instance: a UUIDv7 whose timestamp is the binding's creation time and
// whose remaining bits come from its ID and connector. It is stable for the
// binding's life (rotation keeps the ID) and across daemon restarts, so
// nothing needs to be stored to find it again.
func sandboxConnectorInstanceID(binding sandboxauth.Binding) audit.ConnectorInstanceID {
	sum := sha256.Sum256([]byte(sandboxConnectorInstanceNamespace + "\x00" + binding.ID + "\x00" + binding.Connector))
	var id uuid.UUID
	copy(id[:], sum[:16])
	var ms uint64
	if created := binding.CreatedAt.UnixMilli(); !binding.CreatedAt.IsZero() && created > 0 {
		ms = uint64(created)
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], ms<<16)
	copy(id[:6], stamp[:6])
	id[6] = 0x70 | id[6]&0x0f // version 7
	id[8] = 0x80 | id[8]&0x3f // RFC 9562 variant
	return audit.ConnectorInstanceID(id.String())
}

// resolveConnectorInstanceForRequest resolves the correlation connector
// instance for a request's occurrences: the connector's default instance for
// host traffic and the binding's own instance for a sandbox. Cursors,
// pending operations, receipts, identifiers and tool-chain state are keyed
// by the instance, so a sandbox can neither attach to nor reset host
// correlation state, or another sandbox's, by naming its session or
// replaying its identifiers.
func resolveConnectorInstanceForRequest(
	ctx context.Context,
	repo *audit.CorrelationRepository,
	connectorName string,
	profileVersion string,
	custody audit.ConnectorExportCustody,
) (audit.ConnectorInstance, error) {
	binding, sandboxed := sandboxauth.FromContext(ctx)
	if !sandboxed {
		return repo.ResolveConnectorInstance(ctx, connectorName, profileVersion, custody)
	}
	if sandboxauth.CanonicalConnector(connectorName) != binding.Connector {
		return audit.ConnectorInstance{}, fmt.Errorf(
			"correlation connector %q does not match the sandbox binding", connectorName)
	}
	return repo.ResolveScopedConnectorInstance(ctx, sandboxConnectorInstanceID(binding),
		connectorName, profileVersion, custody)
}

// Sandbox coverage gaps name host-side checks that a sandbox request could
// not run because the files they read have no host counterpart the gateway
// may open (copy mode, or a path outside the mounted project). Each hook
// request records its gaps and reports them on its audit row
// (extra.sandbox_coverage_gaps), so a skipped check reads as partial
// coverage rather than as a clean result. Verdicts are unchanged: an
// unreadable script stays an opaque artifact to the command analysis, as
// it is on the host, and the sandbox boundary still contains it.
const (
	// sandboxGapArtifactUnreadable: a script a tool call executes or
	// sources could not be read for artifact analysis.
	sandboxGapArtifactUnreadable = "artifact_unreadable"
	// sandboxGapStopScanNoHostView: a Stop scan was skipped because the
	// sandbox's files are not on the host.
	sandboxGapStopScanNoHostView = "stop_scan_no_host_view"
	// sandboxGapStopScanNoChangedFiles: a Stop scan covered only the
	// configured scan paths; changed-file discovery needs host git, which
	// never runs against a sandbox tree.
	sandboxGapStopScanNoChangedFiles = "stop_scan_no_changed_files"
	// sandboxGapEventFileUnreadable: a file named by a hook event could not
	// be scanned, so only the event text was inspected.
	sandboxGapEventFileUnreadable = "event_file_unreadable"
	// sandboxGapComponentScanSkipped: a requested or scheduled component
	// scan (skills, plugins, MCP) does not run for a sandbox.
	sandboxGapComponentScanSkipped = "component_scan_skipped"
	// sandboxGapStopScanDirectoryPath: a Stop scan path was a directory;
	// directory walking is not yet implemented through FSView.
	sandboxGapStopScanDirectoryPath = "stop_scan_directory_path"
)

type sandboxCoverage struct {
	mu   sync.Mutex
	gaps map[string]struct{}
	// unblocked names the egress unblocks ("host:scope") that lifted the
	// request's destination rules (liftUnblockedDestinations).
	unblocked []string
	// refused names the egress refusals ("host:category") the request's
	// answer told the agent of (addSandboxEgressRefusals).
	refused []string
}

type sandboxCoverageContextKey struct{}

// withSandboxCoverage gives a sandbox request a gap recorder. Host requests
// and requests that already have one are returned unchanged.
func withSandboxCoverage(ctx context.Context) context.Context {
	if !isSandboxHookRequest(ctx) {
		return ctx
	}
	if _, ok := ctx.Value(sandboxCoverageContextKey{}).(*sandboxCoverage); ok {
		return ctx
	}
	return context.WithValue(ctx, sandboxCoverageContextKey{}, &sandboxCoverage{})
}

// noteSandboxCoverageGap records gap for the request, if it is a sandbox
// request with a recorder.
func noteSandboxCoverageGap(ctx context.Context, gap string) {
	coverage, ok := ctx.Value(sandboxCoverageContextKey{}).(*sandboxCoverage)
	if !ok {
		return
	}
	coverage.mu.Lock()
	if coverage.gaps == nil {
		coverage.gaps = make(map[string]struct{}, 2)
	}
	coverage.gaps[gap] = struct{}{}
	coverage.mu.Unlock()
}

// sandboxCoverageGaps returns the request's recorded gaps, sorted.
func sandboxCoverageGaps(ctx context.Context) []string {
	coverage, ok := ctx.Value(sandboxCoverageContextKey{}).(*sandboxCoverage)
	if !ok {
		return nil
	}
	coverage.mu.Lock()
	defer coverage.mu.Unlock()
	gaps := make([]string, 0, len(coverage.gaps))
	for gap := range coverage.gaps {
		gaps = append(gaps, gap)
	}
	slices.Sort(gaps)
	return gaps
}

// sandboxHookAuditExtra is the sandbox identity stamped onto hook audit
// envelopes, taken from the authenticated binding only, plus the request's
// coverage gaps.
func sandboxHookAuditExtra(ctx context.Context) map[string]string {
	binding, ok := sandboxauth.FromContext(ctx)
	if !ok {
		return nil
	}
	extra := map[string]string{
		"sandbox_binding_id": binding.ID,
		"sandbox_name":       binding.SandboxName,
		"sandbox_workdir":    string(binding.Workdir.Mode),
	}
	if binding.SandboxID != "" {
		extra["sandbox_id"] = binding.SandboxID
	}
	if binding.PolicyProfile != "" {
		extra["sandbox_profile"] = binding.PolicyProfile
	}
	if gaps := sandboxCoverageGaps(ctx); len(gaps) > 0 {
		extra["sandbox_coverage_gaps"] = strings.Join(gaps, ",")
	}
	if lifted := sandboxEgressUnblocks(ctx); len(lifted) > 0 {
		extra[sandboxEgressUnblockExtra] = strings.Join(lifted, ",")
	}
	if refused := sandboxEgressRefused(ctx); len(refused) > 0 {
		extra[sandboxEgressRefusalExtra] = strings.Join(refused, ",")
	}
	return extra
}

// hookRequestAuditExtra combines the contract compatibility fields with the
// sandbox identity and the agent host tag for one request's hook audit
// envelope.
func hookRequestAuditExtra(ctx context.Context, profile connector.HookProfile) map[string]string {
	extra := mergeHookEnvelopeExtra(hookCompatibilityExtra(profile), sandboxHookAuditExtra(ctx))
	return mergeHookEnvelopeExtra(extra, agentHostExtra(ctx))
}

// sandboxBindingEnvelope overlays the binding's identity onto env.
func sandboxBindingEnvelope(env audit.CorrelationEnvelope, binding sandboxauth.Binding) audit.CorrelationEnvelope {
	env.SandboxID = binding.SandboxID
	env.SandboxName = binding.SandboxName
	if env.Connector == "" {
		env.Connector = binding.Connector
	}
	return env
}

// sandboxStopTargetLimit matches the host Stop-scan cap.
const sandboxStopTargetLimit = 200

// sandboxStopTargets returns the configured Stop-scan paths that resolve
// inside the sandbox's mounted project, relative ones joined to the mapped
// working directory. There is no changed-file discovery: host git never
// runs against a sandbox tree. Both that and a copy-mode sandbox, which has
// nothing to scan on the host, are recorded as coverage gaps.
func sandboxStopTargets(ctx context.Context, view *sandboxauth.FSView, hostCWD string, scanPaths []string) []string {
	if view == nil || !view.HostAccess() {
		noteSandboxCoverageGap(ctx, sandboxGapStopScanNoHostView)
		return nil
	}
	noteSandboxCoverageGap(ctx, sandboxGapStopScanNoChangedFiles)
	var out []string
	seen := map[string]bool{}
	for _, p := range scanPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			if hostCWD == "" {
				continue
			}
			p = filepath.Join(hostCWD, p)
		}
		real, err := view.ContainHostPath(p)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		out = append(out, real)
		if len(out) == sandboxStopTargetLimit {
			break
		}
	}
	return out
}

// claudeCodeWatchPathsForRequest returns the FileChanged watch list in the
// namespace of the process that will watch it. For a sandbox the list is
// computed from the mapped project and translated back to sandbox paths;
// host-only entries (the host user's Claude home) are dropped.
func claudeCodeWatchPathsForRequest(req claudeCodeHookRequest, root string) []string {
	if req.sandboxView == nil {
		return connector.ClaudeCodeWatchPaths(root)
	}
	out := []string{}
	if root == "" {
		return out
	}
	for _, p := range connector.ClaudeCodeWatchPaths(root) {
		if sandboxPath, ok := req.sandboxView.SandboxPath(p); ok {
			out = append(out, sandboxPath)
		}
	}
	return out
}

// sandboxHookFileMaxBytes bounds a single CodeGuard read through FSView.
// It matches the largest source file CodeGuard's walker scans.
const sandboxHookFileMaxBytes = 8 << 20

// sandboxCodeGuardScan scans the files named by paths through view, reading
// each one inside the mounted project only, and returns one ScanResult per
// readable file. Masked, escaping, missing and non-regular paths are
// skipped. Directory paths are recorded as a coverage gap.
func sandboxCodeGuardScan(ctx context.Context, view *sandboxauth.FSView, rulesDir string, paths []string) []*scanner.ScanResult {
	if view == nil || !view.HostAccess() || len(paths) == 0 {
		return nil
	}
	cg := scanner.NewCodeGuardScanner(rulesDir)
	var results []*scanner.ScanResult
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		started := time.Now()
		data, _, err := view.ReadFile(p, sandboxHookFileMaxBytes)
		if err != nil {
			if errors.Is(err, sandboxauth.ErrNotRegular) {
				// Directory path: FSView walking is not yet implemented.
				noteSandboxCoverageGap(ctx, sandboxGapStopScanDirectoryPath)
			}
			continue
		}
		target := p
		if sandboxPath, ok := view.SandboxPath(p); ok {
			target = sandboxPath
		}
		findings := cg.ScanContent(target, string(data))
		results = append(results, &scanner.ScanResult{
			Scanner:    cg.Name(),
			Target:     target,
			Timestamp:  started,
			Findings:   findings,
			Duration:   time.Since(started),
			TargetType: scanner.InferTargetType(cg.Name()),
		})
	}
	return results
}
