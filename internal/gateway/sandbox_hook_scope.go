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
	"path/filepath"
	"strings"
	"time"

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

// hookCWDForContext resolves a payload working directory: unchanged host
// behaviour for host requests, FSView translation for sandbox requests.
func hookCWDForContext(ctx context.Context, cwd string) string {
	if view, ok := sandboxHookView(ctx); ok {
		return sandboxHookCWD(view, cwd)
	}
	return sanitizeHookCWD(cwd)
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

// sandboxHookAuditExtra is the sandbox identity stamped onto hook audit
// envelopes, taken from the authenticated binding only.
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
	return extra
}

// hookRequestAuditExtra combines the contract compatibility fields with the
// sandbox identity for one request's hook audit envelope.
func hookRequestAuditExtra(ctx context.Context, profile connector.HookProfile) map[string]string {
	return mergeHookEnvelopeExtra(hookCompatibilityExtra(profile), sandboxHookAuditExtra(ctx))
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
// runs against a sandbox tree.
func sandboxStopTargets(view *sandboxauth.FSView, hostCWD string, scanPaths []string) []string {
	if view == nil || !view.HostAccess() {
		return nil
	}
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
// skipped.
func sandboxCodeGuardScan(view *sandboxauth.FSView, rulesDir string, paths []string) []*scanner.ScanResult {
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
