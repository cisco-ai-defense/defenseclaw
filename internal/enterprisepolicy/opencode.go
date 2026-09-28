// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// OpenCode merges its managed config (/etc/opencode, %ProgramData%\opencode,
// /Library/Application Support/opencode) above user, project and
// OPENCODE_CONFIG_CONTENT layers. A managed "plugin" entry naming an
// absolute plugin path survived every user override in live tests and ran
// after user and project plugins (it saw the final input). That ordering is
// observed, not documented, so the foreign-plugin guard stays on.
//
// The route needs the administrator-owned managed plugin artifact
// (Options.OpenCodePluginPath, the file OpenCodeManagedPlugin returns). The
// standalone payload installs it on every platform; without a trusted copy
// OpenCode falls back to the per-user route.
const opencodeConnector = ConnectorOpenCode

type opencodeTarget struct{}

func (opencodeTarget) Name() string { return opencodeConnector }

// openCodeManagedPlugin is the managed OpenCode plugin this release ships.
// It holds no per-user or per-host value: every call goes through the
// administrator-owned hook binary beside it (<InstallRoot>/bin), which
// resolves the user's gateway transport from protected machine state.
//
//go:embed opencode_managed_plugin.js
var openCodeManagedPlugin []byte

// OpenCodeManagedPlugin returns the managed OpenCode plugin the standalone
// payload installs at OpenCodeManagedPluginPath.
func OpenCodeManagedPlugin() []byte {
	return append([]byte(nil), openCodeManagedPlugin...)
}

// openCodeManagedPluginVendorLimit is the OpenCode behavior no machine file
// can override (observed with OpenCode 1.18.32): pure mode drops managed
// config plugins too, and a variable release builds honor replaces the
// managed config directory. Such a session never calls DefenseClaw, so
// status can report the entry in place while that session runs without it.
const openCodeManagedPluginVendorLimit = "OpenCode skips the managed plugin in pure mode (--pure or OPENCODE_PURE=1) and when OPENCODE_TEST_MANAGED_CONFIG_DIR points at another directory; a session started that way runs without DefenseClaw's hooks on either route"

// OpenCodeManagedPluginPath is where a standalone install places the
// administrator-owned managed OpenCode plugin. StandaloneOptions always
// sets it as Options.OpenCodePluginPath; OpenCode moves onto machine policy
// only while a trusted file is installed there.
func OpenCodeManagedPluginPath(layout managed.StandaloneLayout) string {
	if layout.GOOS == "windows" {
		return strings.TrimRight(layout.InstallRoot, `\`) + `\share\opencode\defenseclaw.js`
	}
	return path.Join(layout.InstallRoot, "share", "opencode", "defenseclaw.js")
}

// OpenCodeManagedConfigPath returns the managed config file, preferring an
// existing opencode.jsonc.
func OpenCodeManagedConfigPath(opts Options) (string, error) {
	dir, err := machinePath(opts,
		"/etc/opencode",
		"/Library/Application Support/opencode",
		func(_, programData string) string { return programData + `\opencode` })
	if err != nil {
		return "", err
	}
	jsonc := joinFor(opts, dir, "opencode.jsonc")
	if _, err := os.Lstat(platformPath(opts, jsonc)); err == nil {
		return jsonc, nil
	}
	return joinFor(opts, dir, "opencode.json"), nil
}

// openCodeArtifactFile is where this process inspects the artifact.
// OpenCodePluginPath is the path OpenCode loads, written into the managed
// config; like every other unix machine path it is joined under Root in
// rooted test trees.
func (o Options) openCodeArtifactFile() string {
	if o.goos() == "windows" {
		return o.OpenCodePluginPath
	}
	return rooted(o, o.OpenCodePluginPath)
}

// openCodeArtifact reads the installed managed plugin. installed is true only
// for a regular file that passes the machine policy trust rules (owned by an
// administrator, not writable by other users, trusted ancestors): OpenCode
// runs it for every user, so a file a standard user could write must never
// become the machine route.
func (o Options) openCodeArtifact() (data []byte, installed bool, err error) {
	if o.OpenCodePluginPath == "" {
		return nil, false, nil
	}
	data, exists, err := readPolicyFile(o, o.openCodeArtifactFile())
	if err != nil || !exists {
		return nil, false, err
	}
	return data, true, nil
}

func (o Options) openCodeArtifactInstalled() bool {
	_, installed, err := o.openCodeArtifact()
	return installed && err == nil
}

// openCodeMachineRoute reports whether OpenCode's route is machine policy:
// the trusted artifact is installed, or the caller installs it before it
// publishes (OpenCodePluginPlanned).
func (o Options) openCodeMachineRoute() bool {
	if o.OpenCodePluginPath == "" {
		return false
	}
	return o.OpenCodePluginPlanned || o.openCodeArtifactInstalled()
}

// InstallOpenCodeManagedPlugin writes the managed plugin this release ships
// to OpenCodePluginPath, administrator-owned and readable by every user
// (the Windows guardian installs it before it publishes OpenCode's managed
// config; the unix lifecycle renders it with the deployment's files). An
// existing copy is replaced unless it already matches. It reports whether it
// wrote.
func InstallOpenCodeManagedPlugin(opts Options) (bool, error) {
	if strings.TrimSpace(opts.OpenCodePluginPath) == "" {
		return false, errors.New("enterprise policy: the managed OpenCode plugin path is not set")
	}
	if err := validOpenCodePluginPath(opts); err != nil {
		return false, fmt.Errorf("enterprise policy: %w", err)
	}
	current, installed, err := opts.openCodeArtifact()
	if err == nil && installed && bytes.Equal(current, openCodeManagedPlugin) {
		return false, nil
	}
	if _, err := writePolicyFile(opts, opts.openCodeArtifactFile(), openCodeManagedPlugin); err != nil {
		return false, fmt.Errorf("enterprise policy: install the managed OpenCode plugin: %w", err)
	}
	return true, nil
}

// RemoveOpenCodeManagedPlugin deletes the installed managed plugin and the
// share/opencode and share directories when they are left empty.
func RemoveOpenCodeManagedPlugin(opts Options) error {
	if strings.TrimSpace(opts.OpenCodePluginPath) == "" {
		return nil
	}
	file := opts.openCodeArtifactFile()
	if err := removePolicyFile(opts, file); err != nil {
		return fmt.Errorf("enterprise policy: remove the managed OpenCode plugin: %w", err)
	}
	dir := dirFor(opts, file)
	if err := removeDirIfEmpty(opts, dir); err != nil {
		return err
	}
	return removeDirIfEmpty(opts, dirFor(opts, dir))
}

func (opencodeTarget) Paths(opts Options) ([]string, error) {
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return nil, err
	}
	return []string{path}, nil
}

func opencodeEntryIsOwned(opts Options, raw any) bool {
	value, ok := raw.(string)
	if !ok || opts.OpenCodePluginPath == "" {
		return false
	}
	return value == opts.OpenCodePluginPath || value == "file://"+opts.OpenCodePluginPath
}

func mergeOpenCodeConfig(opts Options, current []byte) ([]byte, bool, error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return nil, false, fmt.Errorf("parse OpenCode managed config (comments in .jsonc cannot be merged): %w", err)
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	if value != nil && list == nil {
		return nil, false, fmt.Errorf("OpenCode managed config plugin has unsupported type %T", value)
	}
	kept := make([]any, 0, len(list)+1)
	owned := 0
	for _, item := range list {
		if opencodeEntryIsOwned(opts, item) {
			owned++
			if owned > 1 {
				continue
			}
		}
		kept = append(kept, item)
	}
	exact := owned == 1
	if owned == 0 {
		kept = append(kept, opts.OpenCodePluginPath)
	}
	doc.set("plugin", kept)
	rendered, err := encodeOrdered(doc)
	return rendered, exact && len(kept) == len(list), err
}

// stripOpenCodeConfig is the ownership stripFunc for the managed OpenCode
// config.
func stripOpenCodeConfig(opts Options, current []byte) ([]byte, bool, error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return nil, false, err
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	kept := make([]any, 0, len(list))
	for _, item := range list {
		if !opencodeEntryIsOwned(opts, item) {
			kept = append(kept, item)
		}
	}
	if len(kept) == len(list) {
		// Nothing of ours: leave the administrator's bytes alone.
		return current, false, nil
	}
	if len(kept) == 0 {
		doc.delete("plugin")
	} else {
		doc.set("plugin", kept)
	}
	if doc.len() == 0 {
		return nil, true, nil
	}
	rendered, err := encodeOrdered(doc)
	return rendered, true, err
}

func inspectOpenCode(opts Options, current []byte, state *State) error {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return err
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	for _, item := range list {
		if opencodeEntryIsOwned(opts, item) {
			state.OwnedEntries++
		} else {
			state.ForeignEntries++
		}
	}
	if state.OwnedEntries != 1 {
		state.conflict("OpenCode managed config has %d DefenseClaw plugin entries, want exactly one", state.OwnedEntries)
	}
	artifact, installed, artifactErr := opts.openCodeArtifact()
	switch {
	case artifactErr != nil:
		state.conflict("managed OpenCode plugin %s is not trusted: %v", opts.OpenCodePluginPath, artifactErr)
	case !installed:
		state.conflict("managed OpenCode plugin %s is missing", opts.OpenCodePluginPath)
	case !bytes.Equal(artifact, openCodeManagedPlugin):
		state.conflict("managed OpenCode plugin %s does not match this release (sha256 %s, want %s)",
			opts.OpenCodePluginPath, sha256Hex(artifact), sha256Hex(openCodeManagedPlugin))
	}
	state.detail("OpenCode ran the managed plugin after user and project plugins in live tests, but plugin order is not a documented contract; the foreign-plugin guard stays on")
	state.detail("%s", openCodeManagedPluginVendorLimit)
	return nil
}

func newOpenCodeState(opts Options, policy config.ResolvedConnectorPolicy, path string) State {
	return State{Connector: opencodeConnector, Route: RouteMachinePolicy, Ownership: policy.Ownership, ForeignHooks: policy.ForeignHooks, Paths: []string{path}}
}

// openCodePerUserFallback moves state onto the per-user route, saying why,
// when ownership is off or no trusted managed plugin is installed.
func openCodePerUserFallback(opts Options, policy config.ResolvedConnectorPolicy, state *State) bool {
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RoutePerUser
		return true
	}
	_, installed, artifactErr := opts.openCodeArtifact()
	if artifactErr == nil && installed {
		return false
	}
	state.Route = RoutePerUser
	if artifactErr != nil {
		state.detail("managed OpenCode plugin %s is not trusted (%v); OpenCode uses the per-user plugin, guardian repair and the foreign-plugin guard", opts.OpenCodePluginPath, artifactErr)
	} else {
		state.detail("no managed OpenCode plugin artifact is installed; OpenCode uses the per-user plugin, guardian repair and the foreign-plugin guard")
	}
	return true
}

func (t opencodeTarget) Reconcile(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(opencodeConnector)
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return State{}, err
	}
	state := newOpenCodeState(opts, policy, path)
	if openCodePerUserFallback(opts, policy, &state) {
		return state, nil
	}
	var created []string
	if policy.Ownership == config.MachinePolicyOwnershipMerge {
		if created, err = takeBackPolicyPath(opts, path, &state); err != nil {
			return state, err
		}
		// A config an unprivileged user planted in the folder before
		// DefenseClaw took it back (Windows ProgramData) stays theirs to
		// edit, and OpenCode loads it as managed config for every account:
		// move it aside and publish, as for Copilot.
		displaced := false
		for _, name := range []string{"opencode.jsonc", "opencode.json"} {
			if displaceUntrustedPolicyFile(opts, joinFor(opts, dirFor(opts, path), name), &state) {
				displaced = true
			}
		}
		if displaced {
			if path, err = OpenCodeManagedConfigPath(opts); err != nil {
				return state, err
			}
			state.Paths = []string{path}
		}
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipMerge {
		rendered, exact, err := mergeOpenCodeConfig(opts, current)
		if err != nil {
			state.conflict("%v; use ownership: verify_only", err)
			state.finish()
			return state, nil
		}
		changed, err := publishWithRecord(opts, opencodeConnector, path, current, exists, rendered, exact, func(current []byte) ([]byte, bool, error) {
			return stripOpenCodeConfig(opts, current)
		}, &state, created...)
		if err != nil {
			return state, err
		}
		state.Changed = changed
		current = rendered
	}
	if err := inspectOpenCode(opts, current, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (t opencodeTarget) Verify(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(opencodeConnector)
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return State{}, err
	}
	state := newOpenCodeState(opts, policy, path)
	if openCodePerUserFallback(opts, policy, &state) {
		return state, nil
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return state, err
	}
	if !exists {
		state.conflict("%s does not exist", path)
	} else if err := inspectOpenCode(opts, current, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (t opencodeTarget) RemoveOwned(opts Options) (State, error) {
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return State{}, err
	}
	// Removal recognizes DefenseClaw's entry by the artifact path, which
	// StandaloneOptions always sets, even after the artifact is deleted.
	// Without it only a byte-identical postimage is restored.
	state := State{Connector: opencodeConnector, Route: RouteMachinePolicy, Paths: []string{path}}
	err = restoreOrStrip(opts, opencodeConnector, path, func(current []byte) ([]byte, bool, error) {
		return stripOpenCodeConfig(opts, current)
	}, false, &state)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return state, err
}

func (opencodeTarget) Export(opts Options, format string) ([]byte, error) {
	if opts.OpenCodePluginPath == "" {
		return nil, errors.New("opencode export needs the managed plugin artifact path")
	}
	if format != "" && format != "json" {
		return nil, fmt.Errorf("opencode policy export supports format json, not %q", format)
	}
	rendered, _, err := mergeOpenCodeConfig(opts, nil)
	return rendered, err
}

func validOpenCodePluginPath(opts Options) error {
	if opts.OpenCodePluginPath == "" {
		return nil
	}
	if opts.goos() == "windows" {
		if !windowsAbsolute(opts.OpenCodePluginPath) {
			return fmt.Errorf("OpenCode plugin path %q is not an absolute Windows path", opts.OpenCodePluginPath)
		}
		return nil
	}
	if !strings.HasPrefix(opts.OpenCodePluginPath, "/") {
		return fmt.Errorf("OpenCode plugin path %q is not absolute", opts.OpenCodePluginPath)
	}
	return nil
}
