// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Payload binaries. The ACP mediator is optional.
const (
	binGateway      = "defenseclaw-gateway"
	binHook         = "defenseclaw-hook"
	binSensorHelper = "defenseclaw-sensor-helper"
	binACP          = "defenseclaw-acp"
)

var requiredBinaries = []string{binGateway, binHook, binSensorHelper}
var optionalBinaries = []string{binACP}

// desiredDir is a directory the lifecycle owns or must be able to rely on.
type desiredDir struct {
	Path  string
	Mode  os.FileMode
	Owner fileOwner
	// External directories (vendor policy parents, shared parents such as
	// /opt/cisco) are created when absent and recorded for uninstall, but an
	// existing one is never re-moded or re-owned.
	External bool
}

// desiredFile is a file the lifecycle installs.
type desiredFile struct {
	Path  string
	Data  []byte
	Src   string // rooted source for streamed binaries; Data is nil then
	SHA   string
	Mode  os.FileMode
	Owner fileOwner
	Kind  string
	// KeepContent marks a file whose bytes are the administrator's input
	// read from the installed path (config.yaml without --config): the
	// transaction only fixes its mode and owner and never writes its bytes,
	// so a change made after the plan read it is not replaced.
	KeepContent bool
}

// managedDirs returns the DefenseClaw tree for the service account.
func (e *Env) managedDirs(account Account, loadCredential bool) []desiredDir {
	root := rootOwner()
	service := fileOwner{UID: account.UID, GID: account.GID}
	rootService := fileOwner{UID: 0, GID: account.GID}
	l := e.Layout
	secretsMode, secretsOwner := os.FileMode(0o750), rootService
	if loadCredential {
		secretsMode, secretsOwner = 0o700, root
	}
	if e.GOOS == "darwin" {
		return []desiredDir{
			{Path: "/opt", Mode: 0o755, Owner: root, External: true},
			{Path: "/opt/cisco", Mode: 0o755, Owner: root, External: true},
			{Path: l.InstallRoot, Mode: 0o755, Owner: root},
			{Path: l.BinDir, Mode: 0o755, Owner: root},
			{Path: filepath.Dir(l.VendorPolicyDir), Mode: 0o755, Owner: root},
			{Path: l.VendorPolicyDir, Mode: 0o755, Owner: root},
			{Path: openCodePluginDir(l), Mode: 0o755, Owner: root},
			{Path: l.ConfigDir, Mode: 0o755, Owner: root},
			{Path: l.PolicyDir, Mode: 0o750, Owner: rootService},
			{Path: l.SecretsDir, Mode: secretsMode, Owner: secretsOwner},
			{Path: filepath.Dir(l.ManifestPath), Mode: 0o750, Owner: rootService},
			{Path: l.DataDir, Mode: 0o700, Owner: service}, // the device identity key requires a private directory
			{Path: l.GuardianAuthDir, Mode: 0o750, Owner: rootService},
			{Path: l.LifecycleDir, Mode: 0o700, Owner: root},
			{Path: "/Library/Logs/Cisco", Mode: 0o755, Owner: root, External: true},
			{Path: l.LogDir, Mode: 0o755, Owner: root},
			{Path: filepath.Join(l.LogDir, "gateway"), Mode: 0o750, Owner: service},
			{Path: l.HookSocketDir, Mode: 0o755, Owner: service},
		}
	}
	return []desiredDir{
		{Path: l.InstallRoot, Mode: 0o755, Owner: root},
		{Path: l.BinDir, Mode: 0o755, Owner: root},
		{Path: filepath.Dir(l.VendorPolicyDir), Mode: 0o755, Owner: root},
		{Path: l.VendorPolicyDir, Mode: 0o755, Owner: root},
		{Path: openCodePluginDir(l), Mode: 0o755, Owner: root},
		{Path: l.ConfigDir, Mode: 0o755, Owner: root},
		{Path: l.PolicyDir, Mode: 0o750, Owner: rootService},
		{Path: l.SecretsDir, Mode: secretsMode, Owner: secretsOwner},
		{Path: filepath.Dir(l.ManifestPath), Mode: 0o750, Owner: rootService},
		{Path: l.DataDir, Mode: 0o700, Owner: service}, // the device identity key requires a private directory
		{Path: l.GuardianAuthDir, Mode: 0o750, Owner: rootService},
		{Path: l.LifecycleDir, Mode: 0o700, Owner: root},
		{Path: l.LogDir, Mode: 0o750, Owner: service},
		// tmpfiles recreates it at boot; the gateway binds hook.sock here
		// when it runs without socket activation.
		{Path: l.HookSocketDir, Mode: 0o755, Owner: service},
	}
}

// checkSharedParentsTraversable refuses, before any change, an existing
// shared parent the lifecycle does not own (External, so it is never
// re-moded) that other accounts cannot traverse while a managed directory
// below it must be reachable by the service account or by agent users.
// launchd opens the gateway's log below /Library/Logs/Cisco as the service
// account; with that parent closed (a tool running under umask 077 created
// it first) the gateway never starts and the install would only fail at
// activation, after the readiness timeout.
func (e *Env) checkSharedParentsTraversable(dirs []desiredDir) error {
	for _, parent := range dirs {
		if !parent.External {
			continue
		}
		info, err := os.Lstat(e.P(parent.Path))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o001 != 0 {
			// An absent parent is created with its desired mode; applyDirs
			// refuses a link or a non-directory.
			continue
		}
		prefix := strings.TrimSuffix(parent.Path, "/") + "/"
		for _, child := range dirs {
			if child.External || !strings.HasPrefix(child.Path, prefix) ||
				(child.Owner == rootOwner() && child.Mode&0o001 == 0) {
				continue
			}
			return fmt.Errorf(
				"%s is %04o, so the %s service account and agent users cannot reach %s below it; make it traversable (for example: chmod %04o %s) and retry",
				parent.Path, info.Mode().Perm(), e.Layout.ServiceUser, child.Path, parent.Mode, parent.Path,
			)
		}
	}
	return nil
}

// machinePolicyDirs are the vendor machine-policy parents the guardian may
// write, per connector and OS. Only connectors whose vendor documents a
// machine policy location appear here; the machine-policy stream owns the
// contents of these directories.
func machinePolicyDirs(goos, connector string) []string {
	if goos == "darwin" {
		switch connector {
		case "codex":
			return []string{"/etc/codex"}
		case "claudecode":
			return []string{"/Library/Application Support/ClaudeCode", "/Library/Application Support/ClaudeCode/managed-settings.d"}
		case "cursor":
			return []string{"/Library/Application Support/Cursor"}
		case "copilot":
			return []string{"/etc/github-copilot", "/etc/github-copilot/policy.d"}
		case "opencode":
			return []string{"/Library/Application Support/opencode"}
		}
		return nil
	}
	switch connector {
	case "codex":
		return []string{"/etc/codex"}
	case "claudecode":
		return []string{"/etc/claude-code", "/etc/claude-code/managed-settings.d"}
	case "cursor":
		return []string{"/etc/cursor"}
	case "copilot":
		return []string{"/etc/github-copilot", "/etc/github-copilot/policy.d"}
	case "opencode":
		return []string{"/etc/opencode"}
	}
	return nil
}

// openCodePluginDir holds the managed OpenCode plugin the lifecycle renders
// (<InstallRoot>/share/opencode).
func openCodePluginDir(l managed.StandaloneLayout) string {
	return filepath.Dir(enterprisepolicy.OpenCodeManagedPluginPath(l))
}

// MachinePolicyConnectors are the connectors whose DefenseClaw hooks can be
// published through vendor machine policy on goos.
func MachinePolicyConnectors(goos string, enabled []string) []string {
	out := []string{}
	for _, connector := range enabled {
		if len(machinePolicyDirs(goos, connector)) > 0 {
			out = append(out, connector)
		}
	}
	sort.Strings(out)
	return out
}

// legacyLinuxUnits are unit files earlier manual Linux deployments and
// test harnesses left behind. Adoption stops, disables and removes them.
var legacyLinuxUnits = []string{
	"defenseclaw-hook-guardian.timer",
	"defenseclaw-hook-guardian@.service",
	"defenseclaw-hook-guardian-watch.service",
	"defenseclaw-enterprise-test.service",
}

// packageTmpfilesOverride turns off the package's tmpfiles.d entries after
// an uninstall that removed the service account but left the package
// installed (systemd-tmpfiles reads a file in /etc instead of the one with
// the same name in /usr/lib). The next install and the package removal
// delete it.
const (
	packageTmpfilesOverride       = "/etc/tmpfiles.d/defenseclaw.conf"
	packageTmpfilesOverrideMarker = "# defenseclaw-uninstall-override"
	packageTmpfilesOverrideText   = packageTmpfilesOverrideMarker + "\n" +
		"# Written by `defenseclaw-gateway enterprise linux uninstall`: the defenseclaw\n" +
		"# account is removed, so the package's /usr/lib/tmpfiles.d/defenseclaw.conf\n" +
		"# stays off until the next install, which removes this file.\n"
)

// tmpfilesInstallPath and sysusersInstallPath depend on the channel: the
// package owns /usr/lib, the payload channel writes /etc.
func tmpfilesInstallPath(channel string) string {
	if channel == ChannelPackage {
		return "/usr/lib/tmpfiles.d/defenseclaw.conf"
	}
	return "/etc/tmpfiles.d/defenseclaw.conf"
}

func sysusersInstallPath(channel string) string {
	if channel == ChannelPackage {
		return "/usr/lib/sysusers.d/defenseclaw.conf"
	}
	return "/etc/sysusers.d/defenseclaw.conf"
}

// secureClientPresent reports a Secure Client DefenseClaw layout, whose
// services share the port and are mutually exclusive with standalone.
func (e *Env) secureClientPresent() (bool, string) {
	candidates := []string{"/opt/cisco/secureclient/defenseclaw"}
	if e.GOOS == "darwin" {
		matches, _ := filepath.Glob(e.P("/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw*.plist"))
		for _, match := range matches {
			return true, match
		}
	}
	for _, candidate := range candidates {
		if exists(e.P(candidate)) {
			return true, candidate
		}
	}
	return false, ""
}

// unmanagedLeftovers lists pre-existing DefenseClaw machine state that no
// committed deployment record accounts for. Inputs an MDM may stage before
// installing (config, policies, secrets, manifest) are not leftovers, and
// neither are binaries a package placed for the package channel. Drop-ins
// in a unit's .d directory are an administrator extension point and are
// not leftovers either.
func (e *Env) unmanagedLeftovers(services ServiceManager, channel string) []string {
	l := e.Layout
	candidates := []string{l.DescriptorPath}
	if channel != ChannelPackage {
		candidates = append(candidates, filepath.Join(l.BinDir, binGateway))
	}
	retained := e.loadRetainedState()
	for _, dir := range []string{l.DataDir, l.GuardianAuthDir} {
		if e.retainedByLifecycle(dir, retained) {
			// State this lifecycle kept on a non-purge uninstall.
			continue
		}
		if entries, err := os.ReadDir(e.P(dir)); err == nil && len(entries) > 0 {
			candidates = append(candidates, dir)
		}
	}
	for _, unit := range services.Units() {
		// On the package channel a Linux unit file in /etc/systemd/system
		// is not the package's: systemd prefers it over the packaged
		// /usr/lib definition, so it is a leftover on every channel.
		candidates = append(candidates, services.DefinitionPath(unit, ChannelPayload))
	}
	if e.GOOS == "linux" {
		for _, name := range legacyLinuxUnits {
			candidates = append(candidates, filepath.Join("/etc/systemd/system", name))
		}
	}
	found := []string{}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		if exists(e.P(candidate)) {
			found = append(found, candidate)
		}
	}
	sort.Strings(found)
	return found
}

// ownedParent reports whether dir is a directory the lifecycle may remove
// once empty: a systemd drop-in directory of a DefenseClaw unit.
func ownedParent(dir string) bool {
	return strings.HasPrefix(dir, "/etc/systemd/system/defenseclaw-") && strings.HasSuffix(dir, ".d")
}
