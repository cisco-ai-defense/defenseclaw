// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedHookRenderGOOS selects the hosts whose guardian verifies managed
// shell hook bytes. On macOS the hook scripts, _hardening.sh, the runtime
// sidecars and the token are user-owned files the user can edit; other hosts
// keep their existing verification.
var managedHookRenderGOOS = runtime.GOOS

// ManagedHookRenderFinding names one generated hook artifact that no longer
// matches what the guardian renders for the target.
type ManagedHookRenderFinding struct {
	Path   string
	Reason string
}

// ErrManagedHookRenderDrift reports that a managed shell hook artifact differs
// from the guardian's rendering. Setup is the repair: it re-renders every
// artifact from the embedded templates.
var ErrManagedHookRenderDrift = errors.New("managed hook runtime differs from the guardian's rendering")

// managedShellHookConnector reports whether conn's managed runtime is the
// rendered shell hook set this check knows how to re-derive.
func managedShellHookConnector(conn Connector) bool {
	if conn == nil {
		return false
	}
	switch normalizeConnectorName(conn.Name()) {
	case "claudecode", "codex", "cursor":
		_, ok := conn.(HookScriptOwner)
		return ok
	default:
		return false
	}
}

// VerifyManagedHookRender compares the managed hook runtime on disk with the
// contract the guardian renders now: the connector's hook scripts and the
// generic inspect-* scripts byte for byte (and executable), _hardening.sh
// against the embedded helper, the runtime sidecars, and the connector's
// token sidecar. The expected bytes come from the embedded templates and the
// guardian's own settings, never from a digest stored in the user's folder, so
// an edit to both the script and a recorded digest is still found.
//
// Every finding is logged as defenseclaw_boundary (a code integrity finding:
// critical, not fatal) and the call returns ErrManagedHookRenderDrift, so the
// guardian re-renders the target through Setup on the same pass.
func VerifyManagedHookRender(opts SetupOpts, conn Connector) error {
	findings, err := managedHookRenderFindings(opts, conn)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return nil
	}
	parts := make([]string, 0, len(findings))
	for _, finding := range findings {
		emitManagedResilience(managed.MarkerBoundary, finding.Path, "hook_runtime_tampered", map[string]string{
			"connector": normalizeConnectorName(conn.Name()),
			"detail":    finding.Reason,
		})
		parts = append(parts, filepath.Base(finding.Path)+": "+finding.Reason)
	}
	return fmt.Errorf("%w: %s", ErrManagedHookRenderDrift, strings.Join(parts, "; "))
}

func managedHookRenderFindings(opts SetupOpts, conn Connector) ([]ManagedHookRenderFinding, error) {
	// Secure Client only: the standalone guardian verifies its renders
	// itself (HookScriptRenderDrift).
	if managedHookRenderGOOS != "darwin" || !opts.ManagedEnterprise || !shellHookSecureClientProfile(opts) ||
		!managedShellHookConnector(conn) {
		return nil, nil
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil, nil
	}
	name := normalizeConnectorName(conn.Name())
	hookDir := filepath.Join(opts.DataDir, "hooks")

	// The helpers and scripts exactly as the managed Setup writes them
	// (renderedHookRuntimeFiles mirrors WriteHookScriptsForConnectorObjectWithOpts).
	files, err := renderedHookRuntimeFiles(conn, opts)
	if err != nil {
		return nil, err
	}
	helpers := make(map[string]bool, len(hookHelperScripts))
	for _, helper := range hookHelperScripts {
		helpers[filepath.Join(hookDir, helper)] = true
	}
	var findings []ManagedHookRenderFinding
	for _, file := range files {
		if reason := compareManagedHookArtifact(file.path, file.body, !helpers[file.path]); reason != "" {
			findings = append(findings, ManagedHookRenderFinding{Path: file.path, Reason: reason})
		}
	}
	render := resolveConnectorHookRender(opts, conn)
	if err := ValidateManagedNativeHookRuntime(opts.DataDir, opts.APIAddr, name, render.failMode); err != nil {
		findings = append(findings, ManagedHookRenderFinding{
			Path:   filepath.Join(hookDir, hookConfigSidecarName),
			Reason: "runtime sidecar: " + err.Error(),
		})
	}
	tokenPath := filepath.Join(hookDir, ".token")
	if render.scopedToken {
		scoped, err := HookTokenFilePath(hookDir, conn.Name())
		if err != nil {
			return nil, err
		}
		tokenPath = scoped
	}
	if reason := compareManagedHookToken(tokenPath, render.token, render.scopedToken); reason != "" {
		findings = append(findings, ManagedHookRenderFinding{Path: tokenPath, Reason: reason})
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, nil
}

// compareManagedHookArtifact returns why the file at path is not the expected
// regular file, or "" when it matches.
func compareManagedHookArtifact(path string, want []byte, executable bool) string {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	case err != nil:
		return "unreadable: " + err.Error()
	case !info.Mode().IsRegular():
		return "not a regular file"
	case executable && info.Mode().Perm()&0o100 == 0:
		return "not executable"
	}
	got, err := ReadManagedHookRuntimeFile(path, "managed hook artifact", managedHookRuntimeArtifactMaxBytes)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	if !bytes.Equal(got, want) {
		return "content differs from the rendered hook"
	}
	return ""
}

// compareManagedHookToken checks the connector's token sidecar is present and,
// when the guardian knows the token, that it carries it.
func compareManagedHookToken(path, token string, scoped bool) string {
	data, err := ReadManagedHookRuntimeFile(path, "managed hook token", hookRuntimeSidecarMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return "token missing"
	}
	if err != nil {
		return "token unreadable: " + err.Error()
	}
	token = strings.TrimSpace(token)
	if token == "" {
		if len(bytes.TrimSpace(data)) == 0 {
			return "token empty"
		}
		return ""
	}
	want := []byte(token + "\n")
	if !scoped {
		want = []byte(fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%q\n", token))
	}
	if subtle.ConstantTimeCompare(data, want) != 1 {
		return "token differs from the rendered token"
	}
	return ""
}

// cursorUserHooksMatrixGOOS selects the hosts that report a managed per-user
// Cursor hooks.json left with a partial per-event matrix.
var cursorUserHooksMatrixGOOS = runtime.GOOS

// verifyCursorUserHooksMatrix requires exactly one DefenseClaw entry, in the
// shape the writer emits (type, command, timeout and failClosed), on every
// Cursor event. A user who deletes some of the entries, or flips failClosed,
// leaves a partial bypass that a "the hook is referenced somewhere" check
// does not see. Unrelated entries are allowed.
func verifyCursorUserHooksMatrix(data []byte, hookScript string, failClosed bool) error {
	cfg, err := decodeCursorHooksJSON(data)
	if err != nil {
		return err
	}
	if err := requireCursorHooksVersionOne(cfg, false); err != nil {
		return err
	}
	hooks, err := cursorHooksObject(cfg, false)
	if err != nil {
		return err
	}
	command := shellWord(hookScript)
	mode := "open"
	if failClosed {
		mode = "closed"
	}
	for _, event := range cursorHookEvents {
		entries, ok := cursorHookEntryList(hooks[event])
		if !ok {
			return fmt.Errorf("Cursor hooks event %q must be an array", event) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		owned := 0
		for _, raw := range entries {
			if !managedHookCommandEntry(raw, hookScript) {
				continue
			}
			owned++
			if !isExactWindowsCursorEnterpriseHookEntry(raw, command, mode, false) {
				return fmt.Errorf("Cursor hooks event %q has a drifted DefenseClaw entry", event) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			}
		}
		if owned != 1 {
			return fmt.Errorf("Cursor hooks event %q has %d DefenseClaw entries, want exactly 1", event, owned) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
	}
	return nil
}

// reportCursorUserHooksPartial logs, on a Secure Client Mac, a managed
// per-user Cursor hooks.json that still names the DefenseClaw hook but no
// longer carries the full matrix (verifyCursorUserHooksMatrix): entries
// removed from some events, or failClosed flipped. The exact contract check
// already reads it as absent, so Setup re-merges the canonical entries and
// keeps the user's own; this is the boundary line for the finding. A file
// that names no DefenseClaw hook is a fresh install, not a finding.
func (c *hookOnlyConnector) reportCursorUserHooksPartial(opts SetupOpts) {
	if c.name != "cursor" || !opts.ManagedEnterprise || cursorUserHooksMatrixGOOS != "darwin" ||
		!shellHookSecureClientProfile(opts) {
		return
	}
	path := c.configPath(opts)
	data, err := readHookConfigFile(path)
	if err != nil || !bytes.Contains(data, []byte(c.hookCommand(opts))) {
		return
	}
	if err := verifyCursorUserHooksMatrix(data, c.hookCommand(opts), c.effectiveFailClosed(opts)); err != nil {
		emitManagedResilience(managed.MarkerBoundary, path, "cursor_hooks_partial", map[string]string{
			"connector": "cursor",
			"detail":    err.Error(),
		})
	}
}

// codexTrustUnverified remembers, per data folder, the Codex version already
// reported as unverified, so the line is logged once per streak.
var codexTrustUnverified sync.Map

// noteCodexTrustVerification reports when DefenseClaw cannot vouch that Codex
// trusts the hooks it wrote. DefenseClaw computes the hooks.state trusted_hash
// itself, with the algorithm of the Codex releases its hook contracts cover.
// For a Codex version outside a known contract, a changed algorithm would
// leave the hooks untrusted while the matrix check passes, so the target is
// reported as defenseclaw_degraded reason=codex_trust_unverified. Codex does
// not expose its hook trust verdict through a stable interface, so the
// contract registry is the only confirmation available.
func noteCodexTrustVerification(opts SetupOpts, resolution HookContractResolution) {
	if managedHookRenderGOOS != "darwin" || !opts.ManagedEnterprise || !shellHookSecureClientProfile(opts) ||
		strings.TrimSpace(opts.DataDir) == "" {
		return
	}
	key := filepath.Clean(opts.DataDir)
	if resolution.Status == HookCompatibilityKnown {
		codexTrustUnverified.Delete(key)
		return
	}
	version := strings.TrimSpace(opts.AgentVersion)
	if previous, seen := codexTrustUnverified.Load(key); seen && previous == version {
		return
	}
	codexTrustUnverified.Store(key, version)
	if version == "" {
		version = "unknown"
	}
	managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
		"subsystem":     "hooks",
		"connector":     "codex",
		"path":          codexConfigPath(),
		"agent_version": version,
		"reason":        "codex_trust_unverified",
		"detail":        resolution.Reason,
	})
}
