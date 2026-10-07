// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"path"
	"strings"
)

// Standalone service identities. The gateway never runs as root or
// LocalSystem in the standalone profile.
const (
	StandaloneLinuxServiceUser  = "defenseclaw"
	StandaloneDarwinServiceUser = "_defenseclaw"
	StandaloneWindowsGatewaySvc = "DefenseClawGateway"

	// StandaloneAPIAddr is the loopback address every standalone gateway
	// listens on. Hooks verify the listener's owner before sending bytes.
	StandaloneAPIAddr = "127.0.0.1:18970"
)

// StandaloneLayout is the fixed filesystem layout of a standalone managed
// deployment. The lifecycle installers, the services, the hook runtime and
// the MDM scripts all derive paths from this one definition, so an
// installer cannot place state where the runtime does not look for it.
//
// Every path is absolute. Unix layouts use forward slashes; the Windows
// layout uses the trusted Program Files and ProgramData roots.
type StandaloneLayout struct {
	GOOS string

	// Administrator-owned, never writable by a service identity.
	InstallRoot string // parent of BinDir
	BinDir      string // gateway, hook, sensor helper, acp binaries
	ConfigDir   string
	ConfigPath  string
	PolicyDir   string // administrator policy inputs (custom rule packs, Rego)
	// VendorPolicyDir holds the default policies and rule packs the product
	// ships. The lifecycle replaces it on every upgrade; administrators point
	// policy_dir or rule_pack_dir at PolicyDir to customize instead.
	VendorPolicyDir string
	SecretsDir      string // AI Defense / judge credentials
	ManifestPath    string // guardian target manifest (enumerator output)
	DescriptorPath  string // public, non-secret runtime descriptor for hooks
	LifecycleDir    string // transaction state, snapshots, preimages, lock

	// Service-owned runtime state.
	DataDir         string // gateway state (audit DB, runtime tokens)
	GuardianAuthDir string // root-owned authorization ledger, readable by the gateway
	LogDir          string

	// Local IPC endpoints. The directories are writable only by root or
	// the service identity so a standard user cannot pre-create an
	// impostor socket.
	HookSocketDir string
	// HookRuntimeDir (Windows only) holds the user-readable, administrator-
	// written hook runtime state: the per-user connector enrollments and
	// runtime selectors and the public machine policy summary. The state
	// root is not readable by standard users, so it cannot live there.
	HookRuntimeDir  string
	HookSocketPath  string
	SensorSocketDir string

	ServiceUser  string // unix gateway account; Windows virtual account name
	ServiceGroup string
	APIAddr      string
}

// StandaloneLayoutFor returns the unix standalone layout for goos
// ("linux" or "darwin"). Use StandaloneWindowsLayout for Windows, which
// resolves the protected machine roots at runtime.
func StandaloneLayoutFor(goos string) (StandaloneLayout, error) {
	switch goos {
	case "linux":
		return StandaloneLayout{
			GOOS:            goos,
			InstallRoot:     "/opt/defenseclaw",
			BinDir:          "/opt/defenseclaw/bin",
			ConfigDir:       "/etc/defenseclaw",
			ConfigPath:      "/etc/defenseclaw/config.yaml",
			PolicyDir:       "/etc/defenseclaw/policies",
			VendorPolicyDir: "/opt/defenseclaw/share/policies",
			SecretsDir:      "/etc/defenseclaw/secrets",
			ManifestPath:    "/etc/defenseclaw/hook-guardian/targets.yaml",
			DescriptorPath:  "/etc/defenseclaw/managed-runtime.json",
			LifecycleDir:    "/var/lib/defenseclaw-enterprise",
			DataDir:         "/var/lib/defenseclaw",
			GuardianAuthDir: "/var/lib/defenseclaw-hook-guardian",
			LogDir:          "/var/log/defenseclaw",
			HookSocketDir:   "/run/defenseclaw-hook",
			HookSocketPath:  "/run/defenseclaw-hook/hook.sock",
			SensorSocketDir: "/run/defenseclaw-sensor",
			ServiceUser:     StandaloneLinuxServiceUser,
			ServiceGroup:    StandaloneLinuxServiceUser,
			APIAddr:         StandaloneAPIAddr,
		}, nil
	case "darwin":
		const root = "/opt/cisco/defenseclaw"
		return StandaloneLayout{
			GOOS:            goos,
			InstallRoot:     root,
			BinDir:          root + "/bin",
			ConfigDir:       root + "/etc",
			ConfigPath:      root + "/etc/config.yaml",
			PolicyDir:       root + "/etc/policies",
			VendorPolicyDir: root + "/share/policies",
			SecretsDir:      root + "/etc/secrets",
			ManifestPath:    root + "/etc/hook-guardian/targets.yaml",
			DescriptorPath:  root + "/etc/managed-runtime.json",
			LifecycleDir:    root + "/lifecycle",
			DataDir:         root + "/runtime",
			GuardianAuthDir: root + "/hook-guardian-state",
			LogDir:          "/Library/Logs/Cisco/DefenseClaw",
			// macOS clears /var/run at boot and launchd socket hand-off
			// needs cgo, so the gateway binds the hook socket itself in a
			// lifecycle-created directory that only _defenseclaw can write.
			HookSocketDir:   root + "/run",
			HookSocketPath:  root + "/run/hook.sock",
			SensorSocketDir: "/var/run/defenseclaw-sensor",
			ServiceUser:     StandaloneDarwinServiceUser,
			ServiceGroup:    StandaloneDarwinServiceUser,
			APIAddr:         StandaloneAPIAddr,
		}, nil
	default:
		return StandaloneLayout{}, fmt.Errorf("no unix standalone layout for %q", goos)
	}
}

// StandaloneWindowsLayoutForRoots builds the Windows standalone layout from
// already-trusted Program Files and ProgramData roots. It is pure so it can
// be tested on every platform; production callers use
// StandaloneWindowsLayout, which resolves the roots from protected HKLM
// registration rather than the caller's environment.
func StandaloneWindowsLayoutForRoots(programFiles, programData string) (StandaloneLayout, error) {
	programFiles = strings.TrimRight(strings.TrimSpace(programFiles), `\`)
	programData = strings.TrimRight(strings.TrimSpace(programData), `\`)
	if !windowsDriveAbsolute(programFiles) || !windowsDriveAbsolute(programData) {
		return StandaloneLayout{}, fmt.Errorf("standalone Windows roots must be absolute drive paths: %q, %q", programFiles, programData)
	}
	install := programFiles + `\Cisco\DefenseClaw`
	state := programData + `\Cisco\DefenseClaw`
	return StandaloneLayout{
		GOOS:            "windows",
		InstallRoot:     install,
		BinDir:          install + `\bin`,
		ConfigDir:       state + `\etc`,
		ConfigPath:      state + `\etc\config.yaml`,
		PolicyDir:       state + `\policies`,
		VendorPolicyDir: install + `\share\policies`,
		SecretsDir:      state + `\secrets`,
		ManifestPath:    state + `\hook-guardian\targets.yaml`,
		DescriptorPath:  state + `\etc\managed-runtime.json`,
		LifecycleDir:    state + `\install`,
		DataDir:         state + `\runtime`,
		GuardianAuthDir: state + `\hook-guardian-state`,
		LogDir:          state + `\logs`,
		HookSocketDir:   install + `\ipc`,
		HookSocketPath:  "",
		HookRuntimeDir:  programData + `\Cisco\DefenseClaw-HookRuntime`,
		SensorSocketDir: install + `\ipc`,
		ServiceUser:     `NT SERVICE\` + StandaloneWindowsGatewaySvc,
		ServiceGroup:    "",
		APIAddr:         StandaloneAPIAddr,
	}, nil
}

// StandaloneWindowsScannerRuntimeDirForRoot is where the standalone Windows
// lifecycle installs the scanner runtime (defenseclaw-scanners.exe and the
// Python runtime it unpacks): its own administrator-owned root beside the
// state root, so the lifecycle's retained-runtime and install-tree checks
// never walk its thousands of files. Only LocalSystem and Administrators
// write it; the gateway service reads and runs it.
func StandaloneWindowsScannerRuntimeDirForRoot(programData string) string {
	return strings.TrimRight(strings.TrimSpace(programData), `\`) + `\Cisco\DefenseClaw-ScannerRuntime`
}

// StandaloneWindowsScannerRuntimeName is the scanner runtime executable.
const StandaloneWindowsScannerRuntimeName = "defenseclaw-scanners.exe"

// StandaloneSecretsDirForConfig derives the protected secrets directory from
// the trusted managed config path, so certification roots and production
// roots resolve the same way: <config dir>/secrets on unix and
// <state root>\secrets (the parent of etc\) on Windows.
func StandaloneSecretsDirForConfig(goos, configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return ""
	}
	if goos == "windows" {
		configDir := windowsParent(configPath)
		return windowsParent(configDir) + `\secrets`
	}
	return path.Join(path.Dir(path.Clean(configPath)), "secrets")
}

func windowsParent(value string) string {
	value = strings.TrimRight(value, `\`)
	if index := strings.LastIndex(value, `\`); index > 0 {
		return value[:index]
	}
	return value
}

func windowsDriveAbsolute(value string) bool {
	if len(value) < 3 {
		return false
	}
	drive := value[0]
	if !((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) {
		return false
	}
	return value[1] == ':' && value[2] == '\\' && !strings.Contains(value, "/")
}

// Validate checks that every unix path in the layout is absolute and
// clean, so a hand-built layout cannot smuggle relative components into
// the installers.
func (l StandaloneLayout) Validate() error {
	if l.GOOS == "windows" {
		for _, value := range []string{l.InstallRoot, l.BinDir, l.ConfigDir, l.ConfigPath, l.DataDir, l.LogDir} {
			if !windowsDriveAbsolute(value) {
				return fmt.Errorf("standalone layout path %q is not an absolute Windows path", value)
			}
		}
		return nil
	}
	for _, value := range []string{
		l.InstallRoot, l.BinDir, l.ConfigDir, l.ConfigPath, l.PolicyDir, l.VendorPolicyDir, l.SecretsDir,
		l.ManifestPath, l.DescriptorPath, l.LifecycleDir, l.DataDir, l.GuardianAuthDir,
		l.LogDir, l.HookSocketDir, l.HookSocketPath, l.SensorSocketDir,
	} {
		if value == "" || !path.IsAbs(value) || path.Clean(value) != value {
			return fmt.Errorf("standalone layout path %q is not absolute and clean", value)
		}
	}
	return nil
}
