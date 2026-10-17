// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedIPCConfig controls the local UDS gRPC server that external
// consumers (Cisco Secure Client GUI) use to observe DefenseClaw
// health, aggregate stats, and user-visible notifications.
//
// The server only starts when Config.ManagedIPCEnabled() returns
// true. In v1 that requires deployment_mode == managed_enterprise
// (installer path) — the IPC surface is intentionally unavailable
// in unmanaged / BYOD / CI / sandboxed / server / saas modes so a
// misconfigured host cannot expose it by accident.
//
// Access is defended by two independent layers:
//
//  1. Filesystem perms: the socket is created as root:staff 0660 in
//     managed_enterprise, so only root and processes running as the
//     console user (member of group staff on macOS) can connect at
//     all. Non-staff callers are rejected by the kernel before any
//     bytes are read.
//
//  2. Codesign peer-auth at accept-time: managed_enterprise ships a
//     strict Secure-Client allowlist by default (see
//     DefaultSecureClientPolicy). Every incoming connection has its
//     peer identity extracted (LOCAL_PEERPID / LOCAL_PEERCRED) and
//     enriched with codesign metadata (Team ID, signing identifier,
//     bundle id). A peer passes only when ALL three identity fields
//     match the allowlists AND the peer connected via a real UDS
//     (Kind == "UnixPeer"). Any missing field, wrong value, or
//     non-UDS transport is rejected. Operator config can override
//     one or more of the three allowlists per-list; unset lists
//     fall back to the compiled defaults.
//
// On Windows the socket DACL admits Authenticated Users, and the
// accept path authenticates the peer process instead: its PID comes
// from SIO_AF_UNIX_GETPEERPID, its executable must be one of
// AllowedWindowsImages inside the Cisco Secure Client install
// directory under the trusted Program Files roots, and WinVerifyTrust
// must accept that executable's embedded Authenticode signature from
// a signer in AllowedWindowsSigners.
//
// Socket path and mode are resolved at server start when left empty;
// the resolver in internal/ipc/paths.go picks per-platform defaults
// so the installer does not have to hard-code them into the rendered
// config.yaml.
type ManagedIPCConfig struct {
	// SocketPath overrides the resolver-picked path. Empty is the
	// normal case in production — the resolver lands the socket at
	// the standard per-platform location under the install prefix.
	SocketPath string `mapstructure:"socket_path" yaml:"socket_path,omitempty"`

	// SocketMode overrides the resolver-picked octal mode. Empty
	// means the resolver uses 0660 (managed_enterprise, gated by
	// group=staff ownership) or 0600 (unmanaged/dev). Wider than
	// the per-mode ceiling is refused at server start; the
	// managed_enterprise ceiling is 0660 so an operator override
	// cannot re-open the world-writable path.
	SocketMode string `mapstructure:"socket_mode" yaml:"socket_mode,omitempty"`

	// AllowedTeamIDs is the codesign Team-ID allowlist. Empty in
	// managed_enterprise means "use DefaultSecureClientPolicy's
	// team id"; non-empty replaces the default entirely.
	AllowedTeamIDs []string `mapstructure:"allowed_team_ids" yaml:"allowed_team_ids,omitempty"`

	// AllowedSigningIDs is the codesign signing-identifier allowlist
	// (the `Identifier=` line from `codesign -dv`). Empty in
	// managed_enterprise means "use DefaultSecureClientPolicy's
	// signing id"; non-empty replaces the default entirely.
	AllowedSigningIDs []string `mapstructure:"allowed_signing_ids" yaml:"allowed_signing_ids,omitempty"`

	// AllowedBundleIDs is the CFBundleIdentifier allowlist (read
	// from the peer app's Info.plist via plutil). Empty in
	// managed_enterprise means "use DefaultSecureClientPolicy's
	// bundle id"; non-empty replaces the default entirely. Only
	// applied on darwin — Linux peers have no bundle id concept
	// and the check is skipped there.
	AllowedBundleIDs []string `mapstructure:"allowed_bundle_ids" yaml:"allowed_bundle_ids,omitempty"`

	// AllowedWindowsSigners is the Authenticode signer allowlist for
	// Windows IPC peers. A peer passes only when WinVerifyTrust accepts
	// the embedded signature of its executable and the subject common
	// name (and every subject organization) of the signing leaf
	// certificate is in this list. Empty means "use
	// DefaultSecureClientPolicy's Cisco signer"; non-empty replaces the
	// default entirely. Only applied on Windows.
	AllowedWindowsSigners []string `mapstructure:"allowed_windows_signers" yaml:"allowed_windows_signers,omitempty"`

	// AllowedWindowsImages lists the Secure Client GUI executables
	// admitted on Windows, as backslash-separated paths relative to the
	// Cisco Secure Client install directory under the trusted Program
	// Files or Program Files (x86) root (for example `UI\csc_ui.exe`).
	// Entries are relative by construction, so config can narrow or
	// rename the admitted executable but never move it outside the
	// administrator-owned Secure Client tree. Empty means "use
	// DefaultSecureClientPolicy's GUI image"; non-empty replaces the
	// default entirely. Only applied on Windows.
	AllowedWindowsImages []string `mapstructure:"allowed_windows_images" yaml:"allowed_windows_images,omitempty"`
}

// ManagedIPCEnabled reports whether the local UDS gRPC server should
// start. True only when deployment_mode is managed_enterprise. The
// IPC surface has no unmanaged escape hatch: it is either an
// enterprise-installed feature or absent.
func (c *Config) ManagedIPCEnabled() bool {
	if c == nil {
		return false
	}
	// The Secure Client GUI is the only consumer; a standalone deployment
	// has no GUI and exposes no IPC surface.
	return c.SecureClientIntegration()
}

// SecureClientTeamID is the Cisco Team Identifier under which the
// Cisco Secure Client GUI is signed. Compiled-in default for the
// strict peer-auth policy applied in managed_enterprise.
const SecureClientTeamID = "DE8Y96K9QP"

// SecureClientSigningID is the codesign `Identifier=` value the
// Secure Client GUI ships with. Doubles as the CFBundleIdentifier
// value (see SecureClientBundleID), which is expected for a
// bundle-signed app.
const SecureClientSigningID = "com.cisco.secureclient.gui"

// SecureClientBundleID is the CFBundleIdentifier of the Cisco
// Secure Client GUI. Extracted from the peer executable's
// enclosing .app / Contents/Info.plist at accept time.
const SecureClientBundleID = "com.cisco.secureclient.gui"

// SecureClientWindowsSigner is the Authenticode signer subject
// (common name and organization) of Cisco Secure Client binaries on
// Windows. It matches the publisher the Windows packaging already
// requires for Cisco-signed payloads.
const SecureClientWindowsSigner = "Cisco Systems, Inc."

// SecureClientWindowsGUIImage is the Cisco Secure Client GUI
// executable, relative to the Secure Client install directory
// (`<Program Files (x86)>\Cisco\Cisco Secure Client`, or the same
// directory under Program Files).
const SecureClientWindowsGUIImage = `UI\csc_ui.exe`

// DefaultSecureClientPolicy is the compiled-in peer-auth allowlist
// applied to every managed_enterprise install that has not
// overridden AllowedTeamIDs / AllowedSigningIDs / AllowedBundleIDs
// (macOS) or AllowedWindowsSigners / AllowedWindowsImages (Windows)
// in config.yaml. Only the Cisco Secure Client GUI matches; every
// other peer is rejected at accept-time.
func DefaultSecureClientPolicy() ManagedIPCConfig {
	return ManagedIPCConfig{
		AllowedTeamIDs:        []string{SecureClientTeamID},
		AllowedSigningIDs:     []string{SecureClientSigningID},
		AllowedBundleIDs:      []string{SecureClientBundleID},
		AllowedWindowsSigners: []string{SecureClientWindowsSigner},
		AllowedWindowsImages:  []string{SecureClientWindowsGUIImage},
	}
}

// maxWindowsPeerAuthEntryLength bounds a single Windows signer or image
// allowlist entry. Both are compared verbatim, so a longer value can
// only be a mistake.
const maxWindowsPeerAuthEntryLength = 256

// ValidateWindowsSecureClientSigner reports whether name is an
// acceptable AllowedWindowsSigners entry: a non-empty, unpadded
// certificate subject name without control characters.
func ValidateWindowsSecureClientSigner(name string) error {
	if name == "" || strings.TrimSpace(name) != name {
		return fmt.Errorf("signer name must be non-empty and unpadded")
	}
	if len(name) > maxWindowsPeerAuthEntryLength {
		return fmt.Errorf("signer name exceeds %d bytes", maxWindowsPeerAuthEntryLength)
	}
	if strings.IndexFunc(name, isControlRune) >= 0 {
		return fmt.Errorf("signer name contains a control character")
	}
	return nil
}

// ValidateWindowsSecureClientImage reports whether rel is an acceptable
// AllowedWindowsImages entry. The entry must be a canonical relative
// Windows path to an .exe: backslash separators only, no drive,
// stream, UNC or rooted prefix, no empty, "." or ".." segment, no
// segment the Win32 layer would silently rewrite (trailing dot or
// space, DOS device names), and no wildcard characters. The checks are
// string-only so they behave identically on every build platform.
func ValidateWindowsSecureClientImage(rel string) error {
	if rel == "" || strings.TrimSpace(rel) != rel {
		return fmt.Errorf("image path must be non-empty and unpadded")
	}
	if len(rel) > maxWindowsPeerAuthEntryLength {
		return fmt.Errorf("image path exceeds %d bytes", maxWindowsPeerAuthEntryLength)
	}
	if strings.IndexFunc(rel, isControlRune) >= 0 {
		return fmt.Errorf("image path contains a control character")
	}
	if strings.ContainsAny(rel, `/:*?"<>|`) {
		return fmt.Errorf("image path must be relative and use only backslash separators")
	}
	if strings.HasPrefix(rel, `\`) {
		return fmt.Errorf("image path must be relative to the Secure Client install directory")
	}
	segments := strings.Split(rel, `\`)
	for _, segment := range segments {
		switch {
		case segment == "":
			return fmt.Errorf("image path has an empty segment")
		case segment == "." || segment == "..":
			return fmt.Errorf("image path must not contain %q segments", segment)
		case strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " "):
			return fmt.Errorf("image path segment %q ends in a dot or space", segment)
		case isWindowsReservedDeviceName(segment):
			return fmt.Errorf("image path segment %q is a reserved device name", segment)
		}
	}
	last := segments[len(segments)-1]
	if len(last) <= len(".exe") || !strings.EqualFold(last[len(last)-len(".exe"):], ".exe") {
		return fmt.Errorf("image path must name an .exe file")
	}
	return nil
}

func isControlRune(r rune) bool { return r < 0x20 || r == 0x7f }

// isWindowsReservedDeviceName reports whether a path segment names a
// DOS device (CON, NUL, COM1, ...) once Win32 drops its extension.
func isWindowsReservedDeviceName(segment string) bool {
	base := segment
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
		return base[3] >= '0' && base[3] <= '9'
	}
	return false
}

// validateManagedIPCPeerAuthKnobs checks the managed_enterprise IPC
// peer-auth allowlists against the platform whose accept path will
// enforce them. Each platform authenticates the Secure Client GUI with
// its own identity model — codesign team / signing / bundle ids on
// macOS, the Authenticode signer and install-relative image path on
// Windows — so an allowlist for the other platform would be silently
// ignored. Refusing it keeps config honest: an operator who sets a
// list expecting it to take effect learns at load time that it would
// not. Windows entries are also shape-checked here; the IPC server
// validates them again before use.
func validateManagedIPCPeerAuthKnobs(cfg *Config, goos string) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	var offending []string
	if goos == "windows" {
		if len(cfg.Managed.AllowedTeamIDs) != 0 {
			offending = append(offending, "managed.allowed_team_ids")
		}
		if len(cfg.Managed.AllowedSigningIDs) != 0 {
			offending = append(offending, "managed.allowed_signing_ids")
		}
		if len(cfg.Managed.AllowedBundleIDs) != 0 {
			offending = append(offending, "managed.allowed_bundle_ids")
		}
		if len(offending) != 0 {
			return fmt.Errorf(
				"config: %s cannot be set on Windows: these are macOS code-signing "+
					"identities and would be ignored. The Windows IPC peer check uses "+
					"managed.allowed_windows_signers and managed.allowed_windows_images.",
				strings.Join(offending, ", "),
			)
		}
		for index, signer := range cfg.Managed.AllowedWindowsSigners {
			if err := ValidateWindowsSecureClientSigner(signer); err != nil {
				return fmt.Errorf("config: managed.allowed_windows_signers[%d]: %w", index, err)
			}
		}
		for index, image := range cfg.Managed.AllowedWindowsImages {
			if err := ValidateWindowsSecureClientImage(image); err != nil {
				return fmt.Errorf("config: managed.allowed_windows_images[%d]: %w", index, err)
			}
		}
		return nil
	}
	if len(cfg.Managed.AllowedWindowsSigners) != 0 {
		offending = append(offending, "managed.allowed_windows_signers")
	}
	if len(cfg.Managed.AllowedWindowsImages) != 0 {
		offending = append(offending, "managed.allowed_windows_images")
	}
	if len(offending) != 0 {
		return fmt.Errorf(
			"config: %s only apply on Windows and would be ignored on %s; "+
				"remove them from config.yaml.",
			strings.Join(offending, ", "),
			goos,
		)
	}
	return nil
}

// peerAuthKindUnixPeer is the peer-auth Kind literal the IPC accept
// path reports. Duplicated here (rather than imported from
// internal/ipc) to avoid an import cycle: the ipc package imports
// internal/config. The value MUST stay in sync with ipc.KindUnixPeer.
const peerAuthKindUnixPeer = "UnixPeer"

// EffectivePeerAuthKind reports which peer-auth kind the IPC accept
// path will report for peers on the current runtime, given a config.
// Returns "" when ManagedIPCEnabled() is false — no IPC server, no
// peer-auth surface.
//
// Every platform reports "UnixPeer": the identity is read from the
// live AF_UNIX connection (LOCAL_PEERPID / LOCAL_PEERCRED on macOS,
// SO_PEERCRED on Linux, SIO_AF_UNIX_GETPEERPID on Windows) and then
// checked against the platform's Secure Client signing policy
// (codesign on macOS, Authenticode signer plus install-relative image
// path on Windows). There is no unauthenticated kind.
func (c *Config) EffectivePeerAuthKind() string {
	if !c.ManagedIPCEnabled() {
		return ""
	}
	return peerAuthKindUnixPeer
}
