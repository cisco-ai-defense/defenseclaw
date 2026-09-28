// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// Self-repair of the standalone Unix per-user runtime. The standalone
// guardian installs and verifies each user's hooks in a worker that runs
// with that user's own credentials, so it can put right what the user can
// put right on their own account. Native Windows installs never reach
// these helpers (platformInstall and platformVerify handle them).

// standalonePerUserRepair reports whether this process is the standalone
// profile's per-user worker for uid: the Secure Client guardian and every
// root process keep their earlier behavior.
func standalonePerUserRepair(uid int) bool {
	return runtime.GOOS != "windows" && standaloneProfileProcess() && uid > 0 && os.Geteuid() == uid
}

// restoreOwnedDataDirModes gives the user's DefenseClaw data directory and
// its hooks directory back their owner-only mode (0700, the mode Install
// leaves them in) before Install inspects them. A user who made either
// unreadable (chmod 000 ~/.defenseclaw) or loosened it otherwise stopped
// every repair of their hooks, and the guardian had to wait for them to
// undo it. Only a real directory inside the home that the user owns is
// changed; a link, a non-directory or a directory someone else owns is left
// for the validation that follows to refuse and report. The worker runs as
// the owner, so the chmod grants nothing the user could not do.
func restoreOwnedDataDirModes(home, dataDir string, uid int) {
	if !standalonePerUserRepair(uid) {
		return
	}
	home = filepath.Clean(home)
	for _, dir := range []string{filepath.Clean(dataDir), filepath.Join(filepath.Clean(dataDir), "hooks")} {
		if dir == home || !pathInside(home, dir) {
			return
		}
		info, err := os.Lstat(dir)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return
		}
		if owned, _ := fileOwnerMatches(dir, uid); !owned {
			return
		}
		if info.Mode().Perm() == 0o700 {
			continue
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return
		}
	}
}

// standaloneOwnedHookConfigConnectors are the connectors whose hook config
// is a file DefenseClaw writes whole, in a directory the agent reads but
// does not create until the user adds hooks of their own: Kiro's
// ~/.kiro/hooks/defenseclaw.json and Copilot's
// ~/.copilot/hooks/defenseclaw.json.
var standaloneOwnedHookConfigConnectors = map[string]bool{"kiro": true, "copilot": true}

// standaloneOwnedHookConfigName is the file name of those hook configs.
const standaloneOwnedHookConfigName = "defenseclaw.json"

// prepareOwnedHookConfigParents creates, for an installed agent whose hook
// config is a DefenseClaw-owned file, the missing directories above that
// file inside the home, as the user and owner-only. Without them a first
// install failed with "hook config parent missing" for every account that
// had not created the folder itself (for example ~/.kiro/hooks). It returns
// the hook config files that may still be missing: Setup writes them. An
// existing element that is a link, not a directory, owned by someone else
// or writable by group or others is refused, and nothing is created below
// it.
func prepareOwnedHookConfigParents(home, connectorName string, paths []string, uid int) ([]string, error) {
	if !standalonePerUserRepair(uid) || !standaloneOwnedHookConfigConnectors[strings.ToLower(strings.TrimSpace(connectorName))] {
		return nil, nil
	}
	home = filepath.Clean(home)
	var owned []string
	for _, raw := range paths {
		path := filepath.Clean(strings.TrimSpace(raw))
		if filepath.Base(path) != standaloneOwnedHookConfigName || !filepath.IsAbs(path) || !pathInside(home, path) {
			continue
		}
		if err := mkdirUserHookConfigParents(home, filepath.Dir(path), uid); err != nil {
			return nil, err
		}
		owned = append(owned, path)
	}
	return owned, nil
}

// mkdirUserHookConfigParents walks from home to dir one element at a time,
// validating each existing directory and creating each missing one with
// mode 0700.
func mkdirUserHookConfigParents(home, dir string, uid int) error {
	rel, err := filepath.Rel(home, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("enterprise hooks: refusing hook config parent outside user home: %s", dir)
	}
	if rel == "." {
		return nil
	}
	current := home
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
				return fmt.Errorf("enterprise hooks: create hook config parent %s: %w", current, err)
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("enterprise hooks: inspect hook config parent %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing symlink in hook config path: %s", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("enterprise hooks: hook config parent is not a directory: %s", current)
		}
		if owned, actual := fileOwnerMatches(current, uid); !owned {
			return fmt.Errorf("enterprise hooks: hook config parent %s owner uid=%d does not match target uid=%d", current, actual, uid)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("enterprise hooks: hook config parent %s is group/other writable", current)
		}
	}
	return nil
}

// standaloneHookRuntimeRecordMaxBytes bounds the lock and runtime records
// the verification reads from the user's data directory.
const standaloneHookRuntimeRecordMaxBytes = 4 << 20

// verifyStandaloneHookRuntime checks what Unix verification otherwise took
// on trust, so the guardian's verify-or-repair pass re-renders the user's
// hook runtime when it no longer matches: every hook runtime file Install
// recorded in the contract lock (the connector's own hook script, the
// shared inspect scripts and _hardening.sh, a managed plugin) is still there
// with the recorded bytes (a deleted hermes-hook.sh stayed missing
// and every check stayed green); the hooks were rendered for the fail mode
// and guardrail mode the configuration selects now (an
// observe-to-action change never reached ~/.defenseclaw/hooks); and the
// runtime records the hook scripts read (.hookcfg and .hookcfg.<connector>)
// carry that fail mode. The worker runs as the user and reads only the
// user's own files. Standalone per-user worker only.
func verifyStandaloneHookRuntime(conn connector.Connector, setupOpts connector.SetupOpts, guardrailMode string, lock connector.HookContractLockEntry, uid int) error {
	if !standalonePerUserRepair(uid) || conn == nil {
		return nil
	}
	name := conn.Name()
	opts := setupOpts
	opts.GuardrailMode = strings.TrimSpace(guardrailMode)
	expected, err := connector.NewHookContractLockEntryForMode(opts, conn, version.Current().BinaryVersion, false)
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s: inspect the hook runtime: %w", name, err)
	}
	if recorded := strings.TrimSpace(lock.HookFailMode); recorded != "" && recorded != expected.HookFailMode {
		return fmt.Errorf("enterprise hooks: connector %s hooks were rendered for fail mode %q; the configuration now selects %q", name, recorded, expected.HookFailMode)
	}
	if lock.RegistrationPosture != nil && expected.RegistrationPosture != nil &&
		lock.RegistrationPosture.GuardrailMode != expected.RegistrationPosture.GuardrailMode {
		return fmt.Errorf("enterprise hooks: connector %s hooks were rendered for guardrail mode %q; the configuration now selects %q", name, lock.RegistrationPosture.GuardrailMode, expected.RegistrationPosture.GuardrailMode)
	}

	shared, err := readSharedHookScriptDigests(opts.DataDir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s: %w", name, err)
	}
	hookDir := filepath.Join(filepath.Clean(opts.DataDir), "hooks")
	rendersScript := false
	for _, path := range expected.Locations.HookScriptPaths {
		path = filepath.Clean(path)
		base := filepath.Base(path)
		if filepath.Dir(path) == hookDir && strings.HasSuffix(base, "-hook.sh") {
			rendersScript = true
		}
		want, recorded := lock.HookScriptDigests[base]
		if !recorded {
			want, recorded = shared[base]
		}
		if !recorded {
			continue // not recorded by the install (an older lock)
		}
		got, present := expected.HookScriptDigests[base]
		if !present {
			return fmt.Errorf("enterprise hooks: connector %s hook runtime file is missing or unreadable: %s", name, path)
		}
		if got != want {
			return fmt.Errorf("enterprise hooks: connector %s hook runtime file changed since it was installed: %s", name, path)
		}
	}
	if !rendersScript {
		return nil // plugin-only connectors keep no per-connector runtime record
	}
	rendered := expected.HookFailMode
	if provider, ok := conn.(connector.HookCapabilityProvider); ok && rendered == "closed" && !provider.HookCapabilities(opts).SupportsFailClosed {
		rendered = "open"
	}
	return verifyHookRuntimeRecords(hookDir, name, rendered)
}

// readSharedHookScriptDigests returns the digests of the scripts every
// connector of the user shares, which the lock keeps once for all of them.
func readSharedHookScriptDigests(dataDir string) (map[string]string, error) {
	body, exists, err := readUserRuntimeRecord(filepath.Join(filepath.Clean(dataDir), "hook_contract_lock.json"), "hook contract lock")
	if err != nil || !exists {
		return nil, err
	}
	var lock struct {
		Shared map[string]string `json:"shared_hook_script_digests"`
	}
	if err := json.Unmarshal(body, &lock); err != nil {
		return nil, fmt.Errorf("parse hook contract lock: %w", err)
	}
	return lock.Shared, nil
}

// verifyHookRuntimeRecords requires the shared JSON record and the
// connector's flat record, which the hook scripts read, to name the fail
// mode the hooks are rendered with.
func verifyHookRuntimeRecords(hookDir, name, failMode string) error {
	flatPath := filepath.Join(hookDir, ".hookcfg."+name)
	flat, exists, err := readUserRuntimeRecord(flatPath, "hook runtime record")
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s: %w", name, err)
	}
	if !exists {
		return fmt.Errorf("enterprise hooks: connector %s hook runtime record is missing: %s", name, flatPath)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(flat), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	if values["DEFENSECLAW_CONNECTOR"] != name || values["DEFENSECLAW_FAIL_MODE"] != failMode {
		return fmt.Errorf("enterprise hooks: connector %s hook runtime record %s names connector %q fail mode %q, want %q %q",
			name, flatPath, values["DEFENSECLAW_CONNECTOR"], values["DEFENSECLAW_FAIL_MODE"], name, failMode)
	}
	sharedPath := filepath.Join(hookDir, ".hookcfg")
	body, exists, err := readUserRuntimeRecord(sharedPath, "hook runtime record")
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s: %w", name, err)
	}
	if !exists {
		return fmt.Errorf("enterprise hooks: connector %s hook runtime record is missing: %s", name, sharedPath)
	}
	var state struct {
		Version   int               `json:"version"`
		FailModes map[string]string `json:"fail_modes"`
	}
	if err := json.Unmarshal(body, &state); err != nil || state.Version != 2 {
		return fmt.Errorf("enterprise hooks: connector %s hook runtime record %s is not a version 2 record", name, sharedPath)
	}
	if got := state.FailModes[name]; got != failMode {
		return fmt.Errorf("enterprise hooks: connector %s hook runtime record %s has fail mode %q, want %q", name, sharedPath, got, failMode)
	}
	return nil
}

// readUserRuntimeRecord reads a small regular file of the user's own
// runtime state without following a link at its name.
func readUserRuntimeRecord(path, label string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect %s %s: %w", label, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s %s is not a regular file", label, path)
	}
	if info.Size() > standaloneHookRuntimeRecordMaxBytes {
		return nil, false, fmt.Errorf("%s %s exceeds %d bytes", label, path, standaloneHookRuntimeRecordMaxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("open %s %s: %w", label, path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, fmt.Errorf("%s %s changed while it was read", label, path)
	}
	body, err := io.ReadAll(io.LimitReader(file, standaloneHookRuntimeRecordMaxBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read %s %s: %w", label, path, err)
	}
	if len(body) > standaloneHookRuntimeRecordMaxBytes {
		return nil, false, fmt.Errorf("%s %s exceeds %d bytes", label, path, standaloneHookRuntimeRecordMaxBytes)
	}
	return body, true, nil
}
