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
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
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

// ownedDataDirs are the user's DefenseClaw data directory and its hooks
// directory, the two directories Install leaves owner-only (0700).
func ownedDataDirs(dataDir string) []string {
	return []string{filepath.Clean(dataDir), filepath.Join(filepath.Clean(dataDir), "hooks")}
}

// ownedDataDirMode returns the mode of dir when the standalone per-user
// worker may put it right: a real directory inside the home that the user
// owns. A link, a non-directory, a missing directory or a directory someone
// else owns is left for the validation that follows to refuse and report.
func ownedDataDirMode(home, dir string, uid int) (os.FileMode, bool) {
	if dir == home || !pathInside(home, dir) {
		return 0, false
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, false
	}
	if owned, _ := fileOwnerMatches(dir, uid); !owned {
		return 0, false
	}
	return info.Mode().Perm(), true
}

// restoreOwnedDataDirModes gives the user's DefenseClaw data directory and
// its hooks directory back their owner-only mode (0700, the mode Install
// leaves them in) before Install inspects them. A user who made either
// unreadable (chmod 000 ~/.defenseclaw) or loosened it otherwise stopped
// every repair of their hooks, and the guardian had to wait for them to
// undo it. Only a directory ownedDataDirMode accepts is changed. The worker
// runs as the owner, so the chmod grants nothing the user could not do.
func restoreOwnedDataDirModes(home, dataDir string, uid int) {
	if !standalonePerUserRepair(uid) {
		return
	}
	home = filepath.Clean(home)
	for _, dir := range ownedDataDirs(dataDir) {
		mode, ok := ownedDataDirMode(home, dir, uid)
		if !ok {
			return
		}
		if mode == 0o700 {
			continue
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return
		}
	}
}

// verifyOwnedDataDirModes fails verification of the standalone per-user
// worker when the user's DefenseClaw data directory or its hooks directory
// is no longer 0700. Verification did not look at these modes, so the
// guardian's interval reconcile reported no change and a loosened folder
// (chmod 755 ~/.defenseclaw/hooks) stayed loose until some other change
// started a repair (rel-1-0-4 GAP-2341). The failure makes the guardian's
// verify-or-repair pass run Install, which restores 0700 within a minute.
func verifyOwnedDataDirModes(home, dataDir string, uid int) error {
	if !standalonePerUserRepair(uid) {
		return nil
	}
	home = filepath.Clean(home)
	for _, dir := range ownedDataDirs(dataDir) {
		mode, ok := ownedDataDirMode(home, dir, uid)
		if !ok {
			return nil
		}
		if mode != 0o700 {
			return fmt.Errorf("enterprise hooks: %s has mode %04o, want 0700", dir, mode)
		}
	}
	return nil
}

// standaloneOwnedHookConfigConnectors are the connectors whose hook config
// is a file DefenseClaw writes whole, in a directory the agent reads but
// does not create until the user adds hooks of their own: Kiro's
// ~/.kiro/hooks/defenseclaw.json and Copilot's
// ~/.copilot/hooks/defenseclaw.json.
var standaloneOwnedHookConfigConnectors = map[string]bool{"kiro": true, "copilot": true}

// standaloneOwnedHookConfigName is the file name of those hook configs.
const standaloneOwnedHookConfigName = "defenseclaw.json"

// secureClientOwnedHookConfigConnectors are the connectors whose
// DefenseClaw-owned hook config the macOS Secure Client guardian also writes
// in a folder it creates as the user: Copilot's
// ~/.copilot/hooks/defenseclaw.json. Copilot reads that folder but does not
// create it, so without this an account that never added hooks of its own
// stayed unenrolled ("hook config parent missing").
var secureClientOwnedHookConfigConnectors = map[string]bool{"copilot": true}

// secureClientOwnedHookConfigGOOS is the OS secureClientOwnedHookConfigConnector
// checks: a seam for tests of the macOS rule on Linux CI.
var secureClientOwnedHookConfigGOOS = runtime.GOOS

// secureClientOwnedHookConfigConnector reports whether this process is the
// macOS Secure Client guardian and prepares connectorName's hook config
// folder itself.
func secureClientOwnedHookConfigConnector(connectorName string) bool {
	return secureClientOwnedHookConfigGOOS == "darwin" && secureClientHookDelivery() &&
		secureClientOwnedHookConfigConnectors[strings.ToLower(strings.TrimSpace(connectorName))]
}

// prepareOwnedHookConfigParents creates, for an installed agent whose hook
// config is a DefenseClaw-owned file, the missing directories above that
// file inside the home, as the user and owner-only. Without them a first
// install failed with "hook config parent missing" for every account that
// had not created the folder itself (for example ~/.kiro/hooks). It returns
// the hook config files that may still be missing (Setup writes them) and
// the folders it created, which Setup then finds already there. An
// existing element that is a link, not a directory, owned by someone else
// or writable by group or others is refused, and nothing is created below
// it.
//
// The standalone per-user worker calls it with the user's own credentials.
// The macOS Secure Client guardian runs as root and calls it inside
// withOwnerCredentials, so the folders are made by and owned by the user.
// It passes secureClientGuardian, the secureClientOwnedHookConfigConnector
// decision it made as root: the user may not be able to search the Secure
// Client install marker's folder.
func prepareOwnedHookConfigParents(home, connectorName string, paths []string, uid int, secureClientGuardian bool) ([]string, []string, error) {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	switch {
	case standalonePerUserRepair(uid):
		if !standaloneOwnedHookConfigConnectors[name] {
			return nil, nil, nil
		}
	case secureClientGuardian && secureClientOwnedHookConfigConnectors[name] && uid > 0 && os.Geteuid() == uid:
	default:
		return nil, nil, nil
	}
	home = filepath.Clean(home)
	var owned, created []string
	for _, raw := range paths {
		path := filepath.Clean(strings.TrimSpace(raw))
		if filepath.Base(path) != standaloneOwnedHookConfigName || !filepath.IsAbs(path) || !pathInside(home, path) {
			continue
		}
		made, err := mkdirUserHookConfigParents(home, filepath.Dir(path), uid)
		created = append(created, made...)
		if err != nil {
			return nil, created, err
		}
		owned = append(owned, path)
	}
	return owned, created, nil
}

// mkdirUserHookConfigParents walks from home to dir one element at a time,
// validating each existing directory and creating each missing one with
// mode 0700. It returns the directories it created.
func mkdirUserHookConfigParents(home, dir string, uid int) ([]string, error) {
	rel, err := filepath.Rel(home, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("enterprise hooks: refusing hook config parent outside user home: %s", dir)
	}
	if rel == "." {
		return nil, nil
	}
	var created []string
	current := home
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o700); err == nil {
				created = append(created, current)
			} else if !os.IsExist(err) {
				return created, fmt.Errorf("enterprise hooks: create hook config parent %s: %w", current, err)
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return created, fmt.Errorf("enterprise hooks: inspect hook config parent %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return created, fmt.Errorf("enterprise hooks: refusing symlink in hook config path: %s", current)
		}
		if !info.IsDir() {
			return created, fmt.Errorf("enterprise hooks: hook config parent is not a directory: %s", current)
		}
		if owned, actual := fileOwnerMatches(current, uid); !owned {
			return created, fmt.Errorf("enterprise hooks: hook config parent %s owner uid=%d does not match target uid=%d", current, actual, uid)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return created, fmt.Errorf("enterprise hooks: hook config parent %s is group/other writable", current)
		}
	}
	return created, nil
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
// mode the configuration selects now (an observe-to-action change that
// changes the rendered hook must reach ~/.defenseclaw/hooks); and the
// runtime records the hook scripts read (.hookcfg and .hookcfg.<connector>)
// carry that fail mode. Every hook runtime file DefenseClaw renders for the
// user (a managed in-agent plugin for Amp and OpenCode, the hook scripts
// and _hardening.sh for the rest) also matches this
// release's render byte for byte: after a package upgrade the files still
// match the digests recorded at their last write but carry the previous
// release's render, and the user can edit those digests as well. The worker
// runs as the user and reads only the user's own files. Standalone per-user
// worker only.
func verifyStandaloneHookRuntime(conn connector.Connector, setupOpts connector.SetupOpts, guardrailMode string, lock connector.HookContractLockEntry, uid int) error {
	if faults := standaloneHookRuntimeFaults(conn, setupOpts, guardrailMode, lock, uid, false); len(faults) > 0 {
		return faults[0].err
	}
	return nil
}

// hookRuntimeFault is one way the hook runtime of a target does not match what
// DefenseClaw renders, and the protected element it belongs to: one runtime
// file (hookRuntimeFileElement), or HookElementRuntime when the fault is
// about the runtime as a whole (the lock, the fail mode, the render itself).
type hookRuntimeFault struct {
	element string
	err     error
}

// standaloneHookRuntimeFaults is the check verifyStandaloneHookRuntime makes,
// kept as a list: with all set it reports every fault, each against the file
// it belongs to, so the guardian can tell which protected file a repair put
// back while another stayed broken (GAP-0754); without it, it stops at the
// first fault, which is the error verifyStandaloneHookRuntime returns.
func standaloneHookRuntimeFaults(conn connector.Connector, setupOpts connector.SetupOpts, guardrailMode string, lock connector.HookContractLockEntry, uid int, all bool) []hookRuntimeFault {
	if !standalonePerUserRepair(uid) || conn == nil {
		return nil
	}
	name := conn.Name()
	opts := setupOpts
	opts.GuardrailMode = strings.TrimSpace(guardrailMode)
	var faults []hookRuntimeFault
	// add records a fault and says whether the check goes on.
	add := func(element string, err error) bool {
		faults = append(faults, hookRuntimeFault{element: element, err: err})
		return all
	}
	expected, err := connector.NewHookContractLockEntryForMode(opts, conn, version.Current().BinaryVersion, false)
	if err != nil {
		add(HookElementRuntime, fmt.Errorf("enterprise hooks: connector %s: inspect the hook runtime: %w", name, err))
		return faults
	}
	if recorded := strings.TrimSpace(lock.HookFailMode); recorded != "" && recorded != expected.HookFailMode {
		if !add(HookElementRuntime, fmt.Errorf("enterprise hooks: connector %s hooks were rendered for fail mode %q; the configuration now selects %q", name, recorded, expected.HookFailMode)) {
			return faults
		}
	}
	// The guardrail mode in the lock records policy at the last install. A
	// mode change alone does not mean the target changed: the template,
	// sidecar, token and registration checks below establish whether the
	// current mode actually requires a new render.

	shared, err := readSharedHookScriptDigests(opts.DataDir)
	if err != nil {
		// An unreadable lock is a fault of the runtime as a whole; the files
		// are still read against the render, which does not need the lock.
		if !add(HookElementRuntime, fmt.Errorf("enterprise hooks: connector %s: %w", name, err)) {
			return faults
		}
		shared = nil
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
			if !add(hookRuntimeFileElement(path), fmt.Errorf("enterprise hooks: connector %s hook runtime file is missing or unreadable: %s", name, path)) {
				return faults
			}
			continue
		}
		if got != want {
			if !add(hookRuntimeFileElement(path), fmt.Errorf("enterprise hooks: connector %s hook runtime file changed since it was installed: %s", name, path)) {
				return faults
			}
		}
	}
	if path, err := connector.ManagedPluginArtifactDrift(conn, opts); err != nil {
		if !add(hookRuntimeFileElement(path), fmt.Errorf("enterprise hooks: inspect connector %s managed plugin %s: %w", name, path, err)) {
			return faults
		}
	} else if path != "" {
		if !add(hookRuntimeFileElement(path), fmt.Errorf("enterprise hooks: connector %s managed plugin differs from the rendered template: %s", name, path)) {
			return faults
		}
	}
	for _, path := range connector.ManagedPluginArtifacts(conn, opts) {
		matches, err := standaloneRuntimeFileMetadataMatches(path, 0o600, uid)
		if err != nil {
			if !add(hookRuntimeFileElement(path), fmt.Errorf("enterprise hooks: inspect connector %s managed plugin %s: %w", name, path, err)) {
				return faults
			}
		} else if !matches {
			if !add(hookRuntimeFileElement(path), fmt.Errorf("enterprise hooks: connector %s managed plugin protection differs from the installed mode or owner: %s", name, path)) {
				return faults
			}
		}
	}
	for _, drift := range connector.HookScriptRenderDrifts(conn, opts, func(path string, mode os.FileMode) (bool, error) {
		return standaloneRuntimeFileMetadataMatches(path, mode, uid)
	}) {
		element := hookRuntimeFileElement(drift.Path)
		if drift.Path == hookDir {
			element = HookElementRuntime // the render itself failed, no file is named
		}
		err := fmt.Errorf("enterprise hooks: connector %s hook runtime file differs from the rendered template: %s", name, drift.Path)
		if drift.Err != nil {
			err = fmt.Errorf("enterprise hooks: inspect connector %s hook runtime file %s: %w", name, drift.Path, drift.Err)
		}
		if !add(element, err) {
			return faults
		}
	}
	if !rendersScript {
		return faults // plugin-only connectors keep no per-connector runtime record
	}
	if err := verifyHookRuntimeToken(conn, opts); err != nil {
		path, _, _ := connector.HookRuntimeTokenFile(opts, conn)
		if !add(hookRuntimeFileElement(path), err) {
			return faults
		}
	}
	for _, fault := range hookRuntimeRecordFaults(hookDir, name, connector.CapableHookFailMode(opts, conn, expected.HookFailMode)) {
		if !add(fault.element, fault.err) {
			break
		}
	}
	return faults
}

func standaloneRuntimeFileMetadataMatches(path string, mode os.FileMode, uid int) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	owned, _ := fileOwnerMatches(path, uid)
	return info.Mode().IsRegular() && info.Mode().Perm() == mode && owned, nil
}

// HookCredentials are one target's per-user hook API and OTLP credentials.
type HookCredentials struct {
	APIToken      string `json:"api_token"`
	OTLPPathToken string `json:"otlp_path_token,omitempty"`
}

// PreviousHookRuntimeIntactForConfigurationChange distinguishes a configuration
// rerender from repair of a changed target. It verifies the installed runtime
// against the prior recorded configuration; independent drift keeps the
// ordinary repair classification. prior, when the guardian holds a credential
// rotation, is the target's credential pair from the other key of that
// rotation; nil otherwise.
func PreviousHookRuntimeIntactForConfigurationChange(ctx context.Context, opts InstallOptions, prior *HookCredentials) bool {
	if runtime.GOOS == "windows" || !standaloneProfileProcess() || os.Geteuid() == 0 {
		return false
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(opts.UserHome, ".defenseclaw")
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	lock, err := connector.LoadHookContractLockEntryForMode(dataDir, name, false)
	if err != nil || lock.Connector != name || lock.RegistrationPosture == nil || strings.TrimSpace(lock.HookFailMode) == "" {
		return false
	}
	previous := opts
	previous.AgentVersion = lock.RawAgentVersion
	previous.HookContractID = lock.ContractID
	previous.HookFailMode = lock.HookFailMode
	previous.GuardrailMode = lock.RegistrationPosture.GuardrailMode
	previous.HILTEnabled = lock.RegistrationPosture.HILTEnabled
	previous.WorkspaceDir = lock.RegistrationPosture.WorkspaceDir
	previous.ManagedHookSocket = lock.RegistrationPosture.HookSocket
	previous.ManagedServiceUID = lock.RegistrationPosture.HookSocketServiceUID
	previous.ForeignHookGuardBinary = lock.RegistrationPosture.ForeignHookGuard
	// The lock deliberately omits endpoints. The installed runtime record
	// retains the prior one, so use it to reproduce the previous rendering
	// when an administrator changes the endpoint and policy together.
	if endpoint, ok := previousHookRuntimeEndpoint(opts, dataDir); ok {
		previous.APIAddr = endpoint
	}
	// The scoped credential is installed alongside the runtime. Its custody
	// check and the lock's credential binding distinguish a legitimate token
	// rotation from a changed or unreadable installed token.
	if token, tokenErr := connector.LoadHookAPIToken(dataDir, name); tokenErr != nil {
		return false
	} else if token != "" {
		if token != opts.APIToken && lock.RegistrationPosture.HookCredentialBinding == "" {
			return false
		}
		previous.APIToken = token
	}
	// The binding covers the API and OTLP credentials together, and a
	// rotation replaces both. The OTLP credential need not be rendered
	// anywhere the account can read, so the prior pair comes from the
	// guardian, which derives it from the other key of the rotation it
	// holds. It is used only when it explains both the installed API token
	// and the recorded binding; any other installed credential fails below.
	if prior != nil && previous.APIToken == prior.APIToken &&
		!connector.HookCredentialDrifted(lock, connector.SetupOpts{
			HookCredentialIdentity: previous.HookCredentialIdentity,
			APIToken:               prior.APIToken,
			OTLPPathToken:          prior.OTLPPathToken,
		}) {
		previous.OTLPPathToken = prior.OTLPPathToken
	}
	if strings.TrimSpace(previous.HookFailMode) == strings.TrimSpace(opts.HookFailMode) &&
		strings.TrimSpace(previous.GuardrailMode) == strings.TrimSpace(opts.GuardrailMode) &&
		previous.APIAddr == opts.APIAddr && previous.APIToken == opts.APIToken &&
		previous.OTLPPathToken == opts.OTLPPathToken &&
		previous.AgentVersion == opts.AgentVersion && previous.HookContractID == opts.HookContractID &&
		previous.HILTEnabled == opts.HILTEnabled &&
		previous.WorkspaceDir == opts.WorkspaceDir && previous.ManagedHookSocket == opts.ManagedHookSocket &&
		previous.ManagedServiceUID == opts.ManagedServiceUID && previous.ForeignHookGuardBinary == opts.ForeignHookGuardBinary {
		return false
	}
	_, err = Verify(ctx, previous)
	return err == nil
}

func previousHookRuntimeEndpoint(opts InstallOptions, dataDir string) (string, bool) {
	path := filepath.Join(dataDir, "hooks", ".hookcfg")
	body, exists, err := readUserRuntimeRecord(path, "hook runtime record")
	if err != nil {
		return "", false
	}
	if exists {
		var record struct {
			Version     int    `json:"version"`
			GatewayAddr string `json:"gateway_addr"`
			Managed     bool   `json:"managed_enterprise"`
		}
		if err := json.Unmarshal(body, &record); err != nil || record.Version != 2 ||
			strings.TrimSpace(record.GatewayAddr) == "" || !record.Managed ||
			connector.HookSidecarJSONAmbiguous(body) {
			return "", false
		}
		return record.GatewayAddr, true
	}
	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	conn, ok := reg.Get(strings.ToLower(strings.TrimSpace(opts.ConnectorName)))
	if !ok {
		return "", false
	}
	var paths []string
	if err := connector.WithUserHomeDir(opts.UserHome, func() error {
		paths = connector.ManagedPluginArtifacts(conn, connector.SetupOpts{DataDir: dataDir, WorkspaceDir: opts.WorkspaceDir})
		return nil
	}); err != nil || len(paths) == 0 {
		return "", false
	}
	endpoint := ""
	for _, path := range paths {
		body, exists, err := readUserRuntimeRecord(path, "managed plugin")
		if err != nil || !exists {
			return "", false
		}
		value, ok := renderedPluginEndpoint(body)
		if !ok || (endpoint != "" && endpoint != value) {
			return "", false
		}
		endpoint = value
	}
	return endpoint, endpoint != ""
}

func renderedPluginEndpoint(body []byte) (string, bool) {
	endpoint := ""
	for _, line := range strings.Split(string(body), "\n") {
		left, right, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		left = strings.TrimSpace(left)
		if left != "const DC_API_ADDR" && left != "const DC_API_ADDR: string" {
			continue
		}
		if endpoint != "" {
			return "", false
		}
		raw := strings.TrimSuffix(strings.TrimSpace(right), ";")
		value, err := strconv.Unquote(raw)
		if err != nil || value == "" || len(value) > 256 {
			return "", false
		}
		endpoint = value
	}
	return endpoint, endpoint != ""
}

// verifyHookRuntimeToken requires the connector-scoped token file the hook
// script reads to hold the credential this pass renders. A user who moved
// it aside left every hook call of the account refused for a missing token
// while the guardian repaired nothing and status and verify read healthy
// (GAP-0424). The token is never part of the error.
func verifyHookRuntimeToken(conn connector.Connector, opts connector.SetupOpts) error {
	name := conn.Name()
	path, want, err := connector.HookRuntimeTokenFile(opts, conn)
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s: resolve the hook token file: %w", name, err)
	}
	if path == "" {
		return nil
	}
	body, exists, err := readUserRuntimeRecord(path, "hook token")
	if err != nil {
		return fmt.Errorf("enterprise hooks: connector %s: %w", name, err)
	}
	if !exists {
		return fmt.Errorf("enterprise hooks: connector %s hook token is missing: %s", name, path)
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(body))), []byte(strings.TrimSpace(want))) != 1 {
		return fmt.Errorf("enterprise hooks: connector %s hook token does not hold the credential DefenseClaw issued to this account: %s", name, path)
	}
	return nil
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

// hookRuntimeRecordFaults requires the shared JSON record and the
// connector flat record, which the hook scripts read, to name the fail
// mode the hooks are rendered with. Each record is its own element.
func hookRuntimeRecordFaults(hookDir, name, failMode string) []hookRuntimeFault {
	var faults []hookRuntimeFault
	flatPath := filepath.Join(hookDir, ".hookcfg."+name)
	if err := verifyHookRuntimeFlatRecord(flatPath, name, failMode); err != nil {
		faults = append(faults, hookRuntimeFault{element: hookRuntimeFileElement(flatPath), err: err})
	}
	sharedPath := filepath.Join(hookDir, ".hookcfg")
	if err := verifyHookRuntimeSharedRecord(sharedPath, name, failMode); err != nil {
		faults = append(faults, hookRuntimeFault{element: hookRuntimeFileElement(sharedPath), err: err})
	}
	return faults
}

func verifyHookRuntimeFlatRecord(flatPath, name, failMode string) error {
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
	return nil
}

func verifyHookRuntimeSharedRecord(sharedPath, name, failMode string) error {
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
	info, err := pathidentity.LstatPinned(path)
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
