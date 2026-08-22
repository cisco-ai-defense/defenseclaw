// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// profileListRegistryKey is the Windows registry key that holds one
// subkey per local user profile. Each subkey's name IS a stringified
// SID (e.g. "S-1-5-21-1234-567-89-1001"); its `ProfileImagePath`
// REG_SZ / REG_EXPAND_SZ value is the profile's on-disk home
// directory.
//
// See MS docs:
//
//	https://learn.microsoft.com/en-us/windows/win32/win7appqual/user-profile-service---policy
//
// The macOS analogue is `dscl . -list /Users UniqueID`; the shape is
// identical (one row per profile, keyed on SID vs. uid). Documented
// stable across Windows XP → Windows 11 / Server 2025.
const profileListRegistryKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// windowsHookConnectors is the closed set of hook-based connectors
// the Windows per-user hook installer supports today. The enumerator
// filters `cfg.Guardrail.Connector` + `cfg.Guardrail.Connectors` down
// to this set: an operator can list "openclaw" or "zeptoclaw" in the
// primary Connector field (they are proxy-only connectors) but the
// enumerator has nothing to install per-user for those, so it drops
// them.
//
// Kept in sync with the switch in
// `internal/cli/enterprise_hooks_platform_windows.go:
// windowsEnterpriseDesiredEnrollments` — if a third hook-based
// connector appears there, add it here too.
var windowsHookConnectors = map[string]struct{}{
	"claudecode": {},
	"codex":      {},
	"cursor":     {},
}

// EnumerationLogger receives one line per user profile the enumerator
// dropped or annotated, so an operator can debug WHY a specific user
// isn't getting hooked. Matches the macOS `_enumerate_users_warn`
// shape. Nil is safe (drops are silent).
type EnumerationLogger func(subject, reason string)

// EnumerateOptions controls a single enumeration cycle. All fields
// are optional.
type EnumerateOptions struct {
	// ExistingManifestPath, when non-empty, is loaded before
	// enumeration so per-target `AgentVersion` + `Enabled` state
	// carries over between cycles. This is the primary mechanism by
	// which the enumerator preserves admin-supplied fields it has no
	// independent way to discover: the enumerator DISCOVERS profile
	// membership, but AgentVersion for a given (SID, Connector) is
	// authoritative-in-file. If the file is unreadable / malformed /
	// missing, enumeration proceeds and rows start with empty
	// AgentVersion + `Enabled=false` (safe default — a new row
	// without a discovered agent version does not auto-hook the
	// user; the admin promotes it explicitly).
	//
	// Callers that want to force a from-scratch generation (e.g. F1
	// targeted-uninstall regeneration after the target user's rows
	// have been removed) leave this empty.
	ExistingManifestPath string

	// ExcludeSIDs is a list of SID strings to drop from the output.
	// Used by spec 005 F1 targeted-uninstall to regenerate the
	// manifest with a specific user excluded, without doing per-row
	// surgery on the on-disk file.
	ExcludeSIDs []string

	// Logger receives one line per filter-drop / warn event. Nil
	// silences all diagnostics.
	Logger EnumerationLogger
}

// EnumerateWindows walks the local user profile registry, filters per
// spec 005 REQ-08 + REQ-11, and produces a Manifest matching the
// shape the hook-guardian's LoadManifest already accepts.
//
// Filter chain (each step drops the profile with a logf line if opts.Logger is set):
//
//  1. SID must be a syntactically-valid Windows SID string.
//  2. SID must be an interactive-user SID: `S-1-5-21-…` (NT
//     AUTHORITY, SECURITY_NT_NON_UNIQUE base RID) with at least 5
//     sub-authorities so the SID names a specific user (the trailing
//     RID), not the bare domain (`S-1-5-21-A-B-C` has 4 sub-auths
//     and is rejected). Refuses well-known SIDs (Everyone S-1-1-0,
//     Anonymous S-1-5-7, SYSTEM S-1-5-18, Authenticated Users
//     S-1-5-11, BUILTIN S-1-5-32-*, NT SERVICE S-1-5-80-*, etc.) by
//     construction. Belt-and-braces on top of the CLI-input filter
//     at spec 005 REQ-15.
//  3. ProfileImagePath registry value must resolve to an absolute
//     path under the local filesystem.
//  4. Home directory must exist as a real directory (not a reparse
//     point, junction, or symlink; `winpath.RejectReparseChain`
//     walks the ancestor chain up to the volume root — a junction
//     anywhere in the path is refused).
//  5. `opts.ExcludeSIDs`: any SID listed here is dropped. Used by
//     spec 005 F1's targeted uninstall.
//
// Deduplication (REQ-10): if two profiles have the same SID (e.g. a
// re-created account whose registry entry conflicts with a stale
// row), the enumerator prefers the one whose `ProfileImagePath`
// mtime is newer.
//
// AgentVersion + Enabled preservation: for each (SID, Connector) row
// that already exists in `opts.ExistingManifestPath` (if set), the
// pre-existing AgentVersion + Enabled fields are carried over. New
// rows — those discovered by the ProfileList walk that had no
// counterpart in the file — start with `Enabled: false` and empty
// AgentVersion so the guardian's LoadManifest skips schema-validation
// (which requires AgentVersion ≥ Windows minimum on enabled rows).
// An admin / UCB flow promotes the row to enabled by patching
// targets.yaml with a real AgentVersion. This preserves the security
// posture: a new user profile is DISCOVERED by the enumerator but
// only receives hooks when the admin explicitly promotes it.
//
// Rows sorted by (SID, Connector) for deterministic YAML output —
// the byte-identical-no-op-no-write invariant in
// `WriteTargetsManifestAtomic` depends on stable serialisation.
func EnumerateWindows(ctx context.Context, cfg *config.Config, opts EnumerateOptions) (Manifest, error) {
	if cfg == nil {
		return Manifest{}, fmt.Errorf("enterprise hooks: enumerate windows: nil config")
	}
	if ctx == nil {
		// A nil context is a caller bug — every real call comes
		// from the CLI subcommand that wraps a cycle in
		// context.WithTimeout. Use context.Background() as a
		// defensive fallback so we don't panic on a stray
		// unit-test invocation.
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	connectors := effectiveWindowsHookConnectors(cfg)
	if len(connectors) == 0 {
		// No enabled hook-based connector → no per-user rows to
		// emit. Return an empty (but valid) manifest so the atomic
		// write path lands a `version: 1\ntargets: []` document
		// rather than a missing file — the guardian's LoadManifest
		// accepts an empty target list, and this keeps the on-disk
		// state well-defined during a mid-configuration window where
		// the operator has disabled every connector.
		return Manifest{Version: 1, Targets: []ManifestTarget{}}, nil
	}

	exclude := make(map[string]struct{}, len(opts.ExcludeSIDs))
	for _, sid := range opts.ExcludeSIDs {
		if canon := canonicalManifestTargetSID(sid); canon != "" {
			exclude[canon] = struct{}{}
		}
	}

	previous := loadPreviousManifestForEnumeration(opts.ExistingManifestPath, opts.Logger)

	profiles, err := listWindowsUserProfiles(ctx, opts.Logger)
	if err != nil {
		return Manifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}

	targets := make([]ManifestTarget, 0, len(profiles)*len(connectors))
	for _, profile := range profiles {
		// Fast-fail per row so a wedged cycle never runs to
		// completion after ctx has been cancelled — spec 005
		// REQ-19's 60 s cycle ceiling depends on this loop
		// noticing the deadline. See CR
		// spec-005:PRRT_kwDORuAK-s6atyfD.
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		if _, skip := exclude[canonicalManifestTargetSID(profile.SID)]; skip {
			logfSafely(opts.Logger, profile.SID, "excluded by caller (targeted uninstall)")
			continue
		}
		for _, conn := range connectors {
			dataDir := filepath.Join(filepath.Clean(profile.Home), ".defenseclaw")
			row := ManifestTarget{
				SID:       profile.SID,
				UserHome:  filepath.Clean(profile.Home),
				Connector: conn,
				DataDir:   dataDir,
			}
			applyPreviousRowState(&row, previous, opts.Logger)
			targets = append(targets, row)
		}
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].SID != targets[j].SID {
			return targets[i].SID < targets[j].SID
		}
		return targets[i].Connector < targets[j].Connector
	})

	return Manifest{Version: 1, Targets: targets}, nil
}

// WriteTargetsManifestAtomic serialises `m` to YAML, compares it
// byte-for-byte to the on-disk file at `path`, and — if the two
// differ — writes the serialised bytes atomically via a
// write-to-`.new` + `MoveFileEx(MOVEFILE_REPLACE_EXISTING |
// MOVEFILE_WRITE_THROUGH)` swap.
//
// Returns `changed=false, err=nil` when the on-disk file is
// byte-identical to the newly-serialised manifest. This is the
// no-op-no-write invariant from spec 005 REQ-05: without it, every
// 5-min interval tick on a stable box would fsnotify-wake the
// guardian and force it to re-reconcile identical rows (288
// wakes/day on a stable 50-user fleet).
//
// Returns `changed=true, err=nil` on a successful atomic replace.
// Returns `changed=false, err=<non-nil>` on any failure; the on-disk
// file is left untouched.
//
// The caller is responsible for the DACL on `path` — this function
// only writes the bytes. Under spec 005 the enumerator service runs
// as LocalSystem (matching guardian), so SYSTEM's inherited
// FullControl via the existing `AdminFile` ACL (from spec 003) is
// enough; no ACL mutation happens here.
func WriteTargetsManifestAtomic(path string, m Manifest) (changed bool, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return false, fmt.Errorf("enterprise hooks: write targets manifest: empty path")
	}
	if !filepath.IsAbs(path) {
		return false, fmt.Errorf("enterprise hooks: write targets manifest: path must be absolute: %s", path)
	}

	serialised, err := marshalTargetsManifest(m)
	if err != nil {
		return false, err
	}

	current, readErr := os.ReadFile(path)
	if readErr == nil && bytes.Equal(current, serialised) {
		// Byte-identical: skip the write entirely so the guardian's
		// fsnotify watch does not wake. This is the primary
		// steady-state code path — a stable box hits it every tick.
		return false, nil
	}
	if readErr != nil && !os.IsNotExist(readErr) {
		return false, fmt.Errorf("enterprise hooks: read existing manifest %s: %w", path, readErr)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".defenseclaw-targets-*.new")
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: create temp manifest under %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on failure. If MoveFileEx succeeds the
	// temp path is consumed, so os.Remove on a non-existent path is
	// silently ignored below.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, writeErr := tmp.Write(serialised); writeErr != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: write temp manifest %s: %w", tmpPath, writeErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return false, fmt.Errorf("enterprise hooks: close temp manifest %s: %w", tmpPath, closeErr)
	}

	fromPtr, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: encode temp manifest path: %w", err)
	}
	toPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: encode manifest path: %w", err)
	}
	if err := windows.MoveFileEx(
		fromPtr,
		toPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	); err != nil {
		return false, fmt.Errorf("enterprise hooks: atomic replace %s: %w", path, err)
	}
	return true, nil
}

// marshalTargetsManifest serialises the manifest to YAML with
// deterministic field ordering. yaml.Marshal is not guaranteed
// stable across releases, but for a struct with tagged fields the
// output is a function of the field-declaration order — which we
// control. `Manifest.Targets` is pre-sorted by (SID, Connector) in
// EnumerateWindows so this function is deterministic for the same
// input.
func marshalTargetsManifest(m Manifest) ([]byte, error) {
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Targets == nil {
		m.Targets = []ManifestTarget{}
	}
	raw, err := yaml.Marshal(&m)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: marshal manifest: %w", err)
	}
	return raw, nil
}

// loadPreviousManifestForEnumeration reads the on-disk manifest at
// `path`, returning a fast per-(SID, Connector) lookup that lets
// EnumerateWindows preserve `AgentVersion` + `Enabled` fields for
// rows that already exist. A missing file, a malformed body, and a
// well-formed empty file all return a nil map — the caller falls
// back to "new row" defaults for every discovered profile.
func loadPreviousManifestForEnumeration(path string, logf EnumerationLogger) map[string]ManifestTarget {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	m, err := LoadManifest(path)
	if err != nil {
		// Not fatal — an operator-hand-edited targets.yaml that
		// fails validation shouldn't crash the enumerator; we log
		// and treat every discovered row as new.
		logfSafely(logf, path, fmt.Sprintf("existing manifest failed to load; treating every row as new: %v", err))
		return nil
	}
	previous := make(map[string]ManifestTarget, len(m.Targets))
	for _, t := range m.Targets {
		key := previousManifestKey(t.SID, t.Connector)
		if key != "" {
			previous[key] = t
		}
	}
	return previous
}

// applyPreviousRowState copies AgentVersion + Enabled from the
// existing manifest into `row` if a match is found. If no match, it
// leaves both fields at their zero values — Enabled stays nil (the
// default-enabled behaviour), but since AgentVersion is empty the
// row cannot be enabled (LoadManifest's requireAgentVersion check
// runs on enabled rows). To keep new rows well-formed in that state
// we explicitly disable them so LoadManifest's per-row validation
// skips them, avoiding a load-time reject.
func applyPreviousRowState(row *ManifestTarget, previous map[string]ManifestTarget, logf EnumerationLogger) {
	if row == nil {
		return
	}
	key := previousManifestKey(row.SID, row.Connector)
	if prev, ok := previous[key]; ok {
		row.AgentVersion = prev.AgentVersion
		row.Enabled = prev.Enabled
		row.User = prev.User
		row.UID = prev.UID
		row.GID = prev.GID
		return
	}
	// New (SID, Connector) row: keep AgentVersion empty and mark
	// Enabled=false so LoadManifest's schema validation skips this
	// target. An admin or UCB flow promotes it later by writing the
	// AgentVersion + flipping Enabled=true. This preserves the
	// security posture — a new user profile is DISCOVERED by the
	// enumerator but does not auto-hook without operator intent.
	disabled := false
	row.Enabled = &disabled
	logfSafely(logf, row.SID, fmt.Sprintf("newly-discovered (SID, %s) row emitted as disabled; admin must supply agent_version + enable", row.Connector))
}

func previousManifestKey(sid, connector string) string {
	sid = canonicalManifestTargetSID(sid)
	connector = strings.ToLower(strings.TrimSpace(connector))
	if sid == "" || connector == "" {
		return ""
	}
	return sid + "\x00" + connector
}

// windowsUserProfile is the trimmed view of a `ProfileList` subkey
// the enumerator needs. Kept package-private so the filter chain can
// vary without leaking implementation details into the exported API.
type windowsUserProfile struct {
	SID  string
	Home string
	// HomeMtime disambiguates duplicate-SID rows per REQ-10; the
	// registry doesn't have direct time-of-registration for a
	// profile, but the ProfileImagePath directory's mtime is a
	// reasonable proxy (it changes whenever the profile is
	// materialised / logged into).
	HomeMtime int64
}

// listWindowsUserProfiles walks the ProfileList registry key and
// returns one row per surviving profile. Profiles that fail any step
// of the filter chain (parse, well-known-SID, path-not-absolute,
// missing/reparse-point home) are dropped with a WARN via logf.
//
// Duplicate SIDs are deduplicated in-place — the newest
// ProfileImagePath mtime wins, per REQ-10.
//
// ctx bounds the walk: a per-subkey ctx.Err() check ensures a
// wedged os.Stat on one profile cannot starve the interval-loop's
// cycle timeout (spec 005 REQ-19).
func listWindowsUserProfiles(ctx context.Context, logf EnumerationLogger) ([]windowsUserProfile, error) {
	rootKey, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		profileListRegistryKey,
		registry.ENUMERATE_SUB_KEYS,
	)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: open ProfileList registry: %w", err)
	}
	defer rootKey.Close()

	subkeyNames, err := rootKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: enumerate ProfileList subkeys: %w", err)
	}

	byCanonSID := make(map[string]windowsUserProfile, len(subkeyNames))
	for _, name := range subkeyNames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sid, err := windows.StringToSid(name)
		if err != nil || sid == nil {
			logfSafely(logf, name, fmt.Sprintf("not a syntactically-valid SID: %v", err))
			continue
		}
		if !sidIsInteractiveUser(sid) {
			logfSafely(logf, name, "not an interactive-user SID (S-1-5-21-…); refusing well-known / machine-scoped principals")
			continue
		}
		home, err := readAndExpandProfileImagePath(name)
		if err != nil {
			logfSafely(logf, name, fmt.Sprintf("ProfileImagePath unresolvable: %v", err))
			continue
		}
		if home == "" || !filepath.IsAbs(home) {
			logfSafely(logf, name, "ProfileImagePath is empty or not absolute")
			continue
		}
		info, err := os.Stat(home)
		if err != nil {
			logfSafely(logf, name, fmt.Sprintf("ProfileImagePath does not resolve to an existing directory: %v", err))
			continue
		}
		if !info.IsDir() {
			logfSafely(logf, name, "ProfileImagePath is not a directory")
			continue
		}
		if err := winpath.RejectReparseChain(home); err != nil {
			logfSafely(logf, name, fmt.Sprintf("ProfileImagePath contains a reparse point in its ancestor chain: %v", err))
			continue
		}
		mtime := info.ModTime().UnixNano()

		canon := canonicalManifestTargetSID(name)
		if canon == "" {
			logfSafely(logf, name, "SID canonicalisation returned empty")
			continue
		}
		if prev, dup := byCanonSID[canon]; dup {
			if mtime <= prev.HomeMtime {
				logfSafely(logf, name, fmt.Sprintf("duplicate SID; older ProfileImagePath mtime %d ≤ existing %d — kept existing", mtime, prev.HomeMtime))
				continue
			}
			logfSafely(logf, name, fmt.Sprintf("duplicate SID; newer ProfileImagePath mtime %d > existing %d — replacing", mtime, prev.HomeMtime))
		}
		byCanonSID[canon] = windowsUserProfile{
			SID:       name,
			Home:      filepath.Clean(home),
			HomeMtime: mtime,
		}
	}

	out := make([]windowsUserProfile, 0, len(byCanonSID))
	for _, p := range byCanonSID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SID < out[j].SID })
	return out, nil
}

// readAndExpandProfileImagePath opens the per-SID ProfileList subkey
// and reads its ProfileImagePath value, expanding any %SystemDrive%
// prefix the OS may embed.
//
// Mirrors the shape of
// `internal/cli/enterprise_hooks_platform_windows.go:
// windowsEnterpriseHookSIDProfilePath` but does NOT re-parse the SID
// (the caller already did) and does NOT enforce interactive-user
// filtering (the caller applies that separately for consistent error
// reporting).
func readAndExpandProfileImagePath(sidString string) (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		profileListRegistryKey+`\`+sidString,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", err
	}
	defer key.Close()
	profile, valueType, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	if valueType == registry.EXPAND_SZ {
		expanded, err := expandProfileImagePathSystemDrive(profile)
		if err != nil {
			return "", err
		}
		profile = expanded
	}
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return "", fmt.Errorf("ProfileImagePath is empty")
	}
	return filepath.Clean(profile), nil
}

// expandProfileImagePathSystemDrive resolves a `%SystemDrive%`-
// prefixed ProfileImagePath. Only that specific expansion is
// permitted; anything else with a `%` in it is refused so a
// malicious environment substitution cannot escape into an unrelated
// volume.
func expandProfileImagePathSystemDrive(profile string) (string, error) {
	const systemDrive = `%SystemDrive%`
	profile = strings.TrimSpace(profile)
	if len(profile) < len(systemDrive) || !strings.EqualFold(profile[:len(systemDrive)], systemDrive) {
		if strings.Contains(profile, "%") {
			return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
		}
		return profile, nil
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve trusted Windows system directory: %w", err)
	}
	drive := filepath.VolumeName(filepath.Clean(systemDir))
	if drive == "" {
		return "", fmt.Errorf("resolve trusted Windows system drive from %q", systemDir)
	}
	expanded := drive + profile[len(systemDrive):]
	if strings.Contains(expanded, "%") {
		return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
	}
	return expanded, nil
}

// sidIsInteractiveUser reports whether `sid` is an interactive local
// or domain user SID — i.e. lives under NT AUTHORITY (identifier
// authority 5) with SubAuthority[0] == SECURITY_NT_NON_UNIQUE (21)
// and at least 5 sub-authorities so the SID names a specific user
// (the trailing RID), not the bare domain. A user SID has the shape
// `S-1-5-21-A-B-C-RID` (five sub-authorities: 21, A, B, C, RID). The
// bare domain SID without the RID (`S-1-5-21-A-B-C`) has four
// sub-authorities and MUST be rejected — enumerating a bare domain
// as an interactive user would emit garbage manifest rows. See
// CR spec-005:PRRT_kwDORuAK-s6atyfL.
//
// Every well-known / machine-scoped principal (SYSTEM S-1-5-18,
// Authenticated Users S-1-5-11, Everyone S-1-1-0, Anonymous
// S-1-5-7, BUILTIN S-1-5-32-*, NT SERVICE S-1-5-80-*, LocalService
// S-1-5-19, NetworkService S-1-5-20, IIS_IUSRS S-1-5-17, etc.) fails
// the SubAuthority[0] == 21 check.
//
// Matches spec 005 REQ-11 and — together with the CLI-input
// validator at spec 005 REQ-15 — provides belt-and-braces coverage.
// Same discipline as spec 004's `sidIsNTService` (in
// internal/ipc/acl_windows.go), inverted: this filter admits ONLY
// interactive users; spec 004's admitted ONLY NT SERVICE principals.
func sidIsInteractiveUser(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IdentifierAuthority().Value != [6]byte{0, 0, 0, 0, 0, 5} {
		return false
	}
	const securityNTNonUnique uint32 = 21
	if sid.SubAuthorityCount() < 5 {
		return false
	}
	return sid.SubAuthority(0) == securityNTNonUnique
}

// effectiveWindowsHookConnectors returns the connector names for
// which the enumerator emits per-user rows. Filters the operator-
// configured connector list down to those the Windows per-user
// installer actually supports (see `windowsHookConnectors`),
// deduplicating and dropping explicitly-disabled entries.
//
// Resolution order:
//
//  1. `cfg.Guardrail.Connectors` map — each key is a candidate; a
//     PerConnectorGuardrailConfig with `Enabled != nil && !*Enabled`
//     is dropped. This matches the boot-loop precedence in
//     internal/gateway/config.go.
//  2. `cfg.Guardrail.Connector` scalar — added if not already
//     present in the map. Legacy single-connector configs surface
//     here.
//
// Return value is sorted alphabetically for deterministic output.
//
// Precedence: an explicit `Connectors[name].Enabled=false` in the map
// beats the scalar `Connector` field. A config that sets
// `guardrail.connector: claudecode` together with
// `guardrail.connectors.claudecode.enabled: false` emits ZERO
// per-user rows for claudecode — the disabled map entry is
// authoritative. See CR spec-005:PRRT_kwDORuAK-s6atyfM.
func effectiveWindowsHookConnectors(cfg *config.Config) []string {
	seen := make(map[string]struct{})
	// disabledNames captures every name the operator explicitly
	// disabled in cfg.Guardrail.Connectors. The scalar-connector
	// pass then refuses to re-add any name in this set, so the
	// map's `Enabled=false` decision cannot be silently reversed
	// by a stale scalar. Populated only by the map pass — the
	// scalar branch never adds to it, matching the semantic
	// "map is authoritative for explicit disables".
	disabledNames := make(map[string]struct{})
	ordered := make([]string, 0, len(cfg.Guardrail.Connectors)+1)
	consider := func(name string, explicitlyDisabled bool) {
		trimmed := strings.ToLower(strings.TrimSpace(name))
		if trimmed == "" {
			return
		}
		if _, ok := windowsHookConnectors[trimmed]; !ok {
			return
		}
		if explicitlyDisabled {
			disabledNames[trimmed] = struct{}{}
			return
		}
		if _, off := disabledNames[trimmed]; off {
			return
		}
		if _, dup := seen[trimmed]; dup {
			return
		}
		seen[trimmed] = struct{}{}
		ordered = append(ordered, trimmed)
	}
	for name, perConn := range cfg.Guardrail.Connectors {
		disabled := perConn.Enabled != nil && !*perConn.Enabled
		consider(name, disabled)
	}
	consider(cfg.Guardrail.Connector, false)
	sort.Strings(ordered)
	return ordered
}

// logfSafely is a nil-safe wrapper around EnumerationLogger. The
// enumerator's filter chain is peppered with logf calls; a single
// nil check up front is easier to read than a nil check per call
// site.
func logfSafely(logf EnumerationLogger, subject, reason string) {
	if logf != nil {
		logf(subject, reason)
	}
}
