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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const publicPolicySchemaVersion = 1

// PublicConnectorPolicy is the part of a connector's machine policy the
// admin-owned hook binary needs while running as a standard user: whether
// to guard against foreign hooks and which foreign hooks are allowlisted.
// It never carries credentials.
type PublicConnectorPolicy struct {
	Route        string   `json:"route"`
	ForeignHooks string   `json:"foreign_hooks"`
	Guard        bool     `json:"guard"`
	AllowedHooks []string `json:"allowed_hooks"`
}

// PublicPolicy is the world-readable, administrator-owned summary written
// next to the managed config (machine-policy.json).
type PublicPolicy struct {
	SchemaVersion int                              `json:"schema_version"`
	HookBinary    string                           `json:"hook_binary"`
	Connectors    map[string]PublicConnectorPolicy `json:"connectors"`
}

// guardConnectors lists connectors whose foreign hooks or plugins can
// rewrite tool input or approve it after DefenseClaw inspected it and whose
// vendor offers no managed-only lock.
var guardConnectors = map[string]bool{
	ConnectorCursor:  true,
	ConnectorCopilot: true,
	"devin":          true,
	"opencode":       true,
	"amp":            true,
}

// unixGuardConnectors are guarded on Linux and macOS only. Hermes runs
// every shell hook registered for an event and lets a later one rewrite the
// tool call; its standalone hermes-hook.sh runs the guard there. The
// Windows Hermes registration does not run it, so Windows keeps its
// current behavior.
var unixGuardConnectors = map[string]bool{
	ConnectorHermes: true,
}

// lockConnectors have a vendor managed-hooks-only lock; the guard covers
// them only when the lock is not in effect.
var lockConnectors = map[string]bool{
	ConnectorCodex:      true,
	ConnectorClaudeCode: true,
}

// GuardApplies reports whether the foreign-hook guard protects connector
// on goos under policy (the vendor lock covers Codex and Claude when
// enforced).
func GuardApplies(connector, goos string, policy config.ResolvedConnectorPolicy) bool {
	if policy.ForeignHooks == config.ForeignHooksAllow {
		return false
	}
	if guardConnectors[connector] {
		return true
	}
	if unixGuardConnectors[connector] {
		return goos != "windows"
	}
	return lockConnectors[connector] && policy.ManagedHooksOnly != config.ManagedHooksOnlyEnforce
}

// BuildPublicPolicy renders the summary for connectors.
func BuildPublicPolicy(opts Options, connectors []string) PublicPolicy {
	summary := PublicPolicy{SchemaVersion: publicPolicySchemaVersion, HookBinary: opts.HookBinary, Connectors: map[string]PublicConnectorPolicy{}}
	for _, name := range normalizeConnectors(connectors) {
		policy := opts.PolicyFor(name)
		allowed := append([]string{}, policy.AllowedHooks...)
		sort.Strings(allowed)
		summary.Connectors[name] = PublicConnectorPolicy{
			Route:        publicRoute(opts, name),
			ForeignHooks: policy.ForeignHooks,
			Guard:        GuardApplies(name, opts.goos(), policy),
			AllowedHooks: allowed,
		}
	}
	return summary
}

// publicRoute is the route the summary reports for connector. On machine
// policy the per-user plugin and per-user registration commands are
// foreign, so OpenCode is reported there only while OpenCode actually loads
// the managed plugin: ownership is not off and OpenCode's managed config
// names the trusted installed plugin (the check the Unix enumerator and the
// Windows guardian route OpenCode rows by). An installed plugin file alone
// is not enough: every deployment installs it, and until the config names it
// the per-user plugin is DefenseClaw's own, which the guard must not deny on
// or clean up.
func publicRoute(opts Options, name string) string {
	route := opts.Route(name)
	if name != ConnectorOpenCode || route != RouteMachinePolicy {
		return route
	}
	if opts.PolicyFor(name).Ownership == config.MachinePolicyOwnershipOff {
		return RouteFor(name, opts.goos())
	}
	if present, err := opencodePresent(opts); err != nil || !present {
		return RouteFor(name, opts.goos())
	}
	return RouteMachinePolicy
}

// MarshalPublicPolicy renders canonical bytes.
func MarshalPublicPolicy(summary PublicPolicy) ([]byte, error) {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// WritePublicPolicy writes the summary (0644, administrator-owned) and
// reports whether it changed.
func WritePublicPolicy(opts Options, connectors []string) (bool, error) {
	data, err := MarshalPublicPolicy(BuildPublicPolicy(opts, connectors))
	if err != nil {
		return false, err
	}
	current, exists, err := readPolicyFile(opts, opts.PublicPolicyPath)
	if err != nil {
		return false, err
	}
	if exists && bytes.Equal(current, data) {
		return false, nil
	}
	_, err = writePolicyFile(opts, opts.PublicPolicyPath, data)
	return err == nil, err
}

// ErrNoPublicPolicy reports that the host has no standalone machine policy.
var ErrNoPublicPolicy = errors.New("no machine policy summary")

// LoadPublicPolicy reads the summary with the same trust checks as the
// managed config: administrator-owned file and ancestors, no symlinks.
func LoadPublicPolicy(path string) (*PublicPolicy, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoPublicPolicy
	}
	if err := managed.ValidateTrustedFilePath(path, "machine policy summary"); err != nil {
		return nil, err
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := readBounded(file, 1<<20)
	if err != nil {
		return nil, err
	}
	return ParsePublicPolicy(data)
}

// ParsePublicPolicy strictly decodes summary bytes.
func ParsePublicPolicy(data []byte) (*PublicPolicy, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var summary PublicPolicy
	if err := decoder.Decode(&summary); err != nil {
		return nil, fmt.Errorf("decode machine policy summary: %w", err)
	}
	if summary.SchemaVersion != publicPolicySchemaVersion {
		return nil, fmt.Errorf("machine policy summary schema_version %d is not supported", summary.SchemaVersion)
	}
	for name, policy := range summary.Connectors {
		switch policy.ForeignHooks {
		case config.ForeignHooksRemove, config.ForeignHooksReport, config.ForeignHooksAllow:
		default:
			return nil, fmt.Errorf("machine policy summary connector %s has invalid foreign_hooks %q", name, policy.ForeignHooks)
		}
	}
	return &summary, nil
}
