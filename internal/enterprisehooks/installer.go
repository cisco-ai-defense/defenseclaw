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

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// InstallOptions describes one explicit enterprise hook install/repair target.
//
// The gateway service itself is deliberately sandboxed away from user homes in
// managed enterprise deployments. This helper is for a short-lived privileged
// guardian/MDM step that targets one real interactive user's home directory and
// then exits.
type InstallOptions struct {
	ConnectorName string
	UserHome      string
	OwnerUID      int
	OwnerGID      int
	// OwnerSID identifies the target Windows user. It is ignored on Unix. When
	// empty on Windows, the guardian resolves the owner from UserHome and then
	// pins every subsequent owner/DACL check to that SID.
	OwnerSID       string
	DataDir        string
	APIAddr        string
	ProxyAddr      string
	APIToken       string
	OTLPPathToken  string
	MasterKey      string
	HookFailMode   string
	GuardrailMode  string
	HILTEnabled    bool
	AgentVersion   string
	HookContractID string
	// Protected recovery timestamps are copied only from the administrator-
	// owned guardian authorization ledger. They make a deleted target-owned
	// hook contract lock byte-reproducible without trusting profile state.
	RecoveryHookContractLockUpdatedAt  string
	RecoveryHookContractEntryUpdatedAt string
	WorkspaceDir                       string
	Registry                           *connector.Registry
	// ManagedHookSocket and ManagedServiceUID route in-agent plugins and
	// connector shell hooks through the standalone gateway's peer-authorized
	// unix hook socket (see connector.SetupOpts). Empty keeps the TCP
	// transport.
	ManagedHookSocket string
	ManagedServiceUID int
	// HookCredentialIdentity is the uid the standalone Unix guardian bound
	// APIToken and OTLPPathToken to (see connector.SetupOpts). Empty for
	// every other install.
	HookCredentialIdentity string
	// ForeignHookGuardBinary is the administrator-owned hook binary the
	// standalone Amp and OpenCode plugins run for the foreign-hook guard
	// (see connector.SetupOpts). Empty everywhere else.
	ForeignHookGuardBinary string
	// ManagedHookBinary is the administrator-owned hook binary a standalone
	// Unix shell hook runs for the session facts (see connector.SetupOpts).
	// Empty everywhere else.
	ManagedHookBinary string

	// AllowMissingHookConfigRepair permits the guardian to recreate a missing
	// native hook config file only after an administrator-owned caller has
	// established that this target was previously protected. First-time
	// installs must leave this false so broad discovery cannot create new app
	// profiles from scratch.
	AllowMissingHookConfigRepair bool

	// MachinePolicyContractID is the hook contract a standalone Windows
	// deployment renders its single machine-wide Claude policy from (see
	// WindowsStandaloneClaudeMachinePolicyContract). Empty, and every
	// Secure Client process, render the row's own contract.
	MachinePolicyContractID string

	// WindowsTargetLogon selects the logon a Windows install acts under for
	// the target's user. The zero value is the user's active session.
	WindowsTargetLogon WindowsTargetLogon
}

// WindowsTargetLogon is the logon whose token a Windows install impersonates.
type WindowsTargetLogon int

const (
	// WindowsTargetLogonActive is the user's active session only.
	WindowsTargetLogonActive WindowsTargetLogon = iota
	// WindowsTargetLogonAnyWithS4U is the user's active session, else a
	// disconnected one (the user is still signed in), else an S4U logon for
	// a signed-out user. Without any of them the install fails with
	// ErrEnrolledUserSignedOut before it acts as the user. Only a change
	// that closes the hook fail mode uses it (rel-1-0-4 GAP-0585).
	WindowsTargetLogonAnyWithS4U
)

var publishEnterpriseHookAPIToken = connector.PublishHookAPIToken

type InstallResult struct {
	Connector       string   `json:"connector"`
	UserHome        string   `json:"user_home"`
	DataDir         string   `json:"data_dir"`
	HookConfigPaths []string `json:"hook_config_paths,omitempty"`
	HookScripts     []string `json:"hook_scripts,omitempty"`
	BackupFiles     []string `json:"backup_files,omitempty"`
	CreatedDirs     []string `json:"created_dirs,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	HookContractID  string   `json:"hook_contract_id,omitempty"`
	// AgentVersionStatus is "untested newer version" when the agent is newer
	// than every tested range and runs on the newest contract.
	AgentVersionStatus         string `json:"agent_version_status,omitempty"`
	HookContractLockUpdatedAt  string `json:"hook_contract_lock_updated_at,omitempty"`
	HookContractEntryUpdatedAt string `json:"hook_contract_entry_updated_at,omitempty"`
	// AgentConfig is what the account should know about its agent config
	// that is no protection failure (connector.AgentConfigStatus: a Hermes
	// or Devin config put back from a copy, or recreated with DefenseClaw's
	// hooks only, GAP-0564). It is not serialized: the guardian state keeps
	// the schema a prior binary reads strictly. The worker's answer carries
	// it next to the result, and the guardian records it in its own file.
	AgentConfig string `json:"-"`
}

// agentConfigReadOnVerify reports a guardian that verifies the accounts'
// agent configs without writing in their data folders: the Windows
// standalone one (agent_config_verify_windows.go).
var agentConfigReadOnVerify = func() bool { return false }

// RemoveManagedPolicy removes one target user's administrator-managed vendor
// policy registration. Per-user runtime files are intentionally retained as
// recovery evidence; the protected SID allow-list makes them inert for a
// removed target even while other registered users share the machine policy.
// The platform implementation removes only artifacts whose protected ownership
// metadata still matches the live policy bytes.
func RemoveManagedPolicy(ctx context.Context, opts InstallOptions) error {
	return platformRemoveManagedPolicy(ctx, opts)
}

// Verify validates one explicit enterprise hook target without repairing or
// otherwise mutating its native configuration, runtime files, or authorization
// state. Callers can use the returned InstallResult-shaped inventory alongside
// Install results without maintaining a second artifact schema.
func Verify(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if result, handled, err := platformVerify(ctx, opts); handled {
		return result, err
	}
	if errEnterpriseHooksUnsupportedWindows != nil {
		return InstallResult{}, errEnterpriseHooksUnsupportedWindows
	}
	if err := refuseStandaloneRootInProcess("verify"); err != nil {
		return InstallResult{}, err
	}
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		return InstallResult{}, err
	}
	uid, gid, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return InstallResult{}, err
	}
	if err := validateHomeOwner(home, uid); err != nil {
		return InstallResult{}, err
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	if err := validateUserDataDir(home, dataDir, uid); err != nil {
		return InstallResult{}, err
	}

	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector is required")
	}
	conn, ok := reg.Get(name)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if connector.IsProxyConnector(conn.Name()) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q is proxy/plugin setup-only; per-user hook verification is not supported", conn.Name())
	}
	if !connector.OwnsManagedHookRuntime(conn) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q does not own a managed hook runtime", conn.Name())
	}
	if !connector.ConnectorSupportedOnHostOS(conn.Name()) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q is not supported on this host OS", conn.Name())
	}

	setupOpts := connector.SetupOpts{
		DataDir:                  dataDir,
		ProxyAddr:                strings.TrimSpace(opts.ProxyAddr),
		APIAddr:                  strings.TrimSpace(opts.APIAddr),
		APIToken:                 strings.TrimSpace(opts.APIToken),
		OTLPPathToken:            strings.TrimSpace(opts.OTLPPathToken),
		Interactive:              false,
		ManagedEnterprise:        true,
		WorkspaceDir:             strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:             strings.TrimSpace(opts.HookFailMode),
		SecureClientHookDelivery: secureClientHookDelivery(),
		HILTEnabled:              opts.HILTEnabled,
		AgentVersion:             strings.TrimSpace(opts.AgentVersion),
		HookContractID:           strings.TrimSpace(opts.HookContractID),
		// The configured transport and credential binding, compared below
		// with the ones the installed hooks were rendered for.
		ManagedHookSocket:      strings.TrimSpace(opts.ManagedHookSocket),
		ManagedServiceUID:      opts.ManagedServiceUID,
		HookCredentialIdentity: strings.TrimSpace(opts.HookCredentialIdentity),
		// Verification requires the guard line the standalone Amp and
		// OpenCode plugins carry, so a plugin rendered without it (before
		// the guard existed, or edited) fails and the guardian re-renders it.
		ForeignHookGuardBinary: strings.TrimSpace(opts.ForeignHookGuardBinary),
		ManagedHookBinary:      strings.TrimSpace(opts.ManagedHookBinary),
	}
	if runtime.GOOS == "darwin" && secureClientHookDelivery() {
		setupOpts.HookExecutable = "/opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway"
	}
	if standalonePerUserRepair(uid) {
		// Install renders some hooks for the guardrail mode (Cursor's action
		// command differs from its observe command). Without the mode here
		// the presence check looked for the other rendering, so every cycle
		// after a switch to action repaired the row again.
		setupOpts.GuardrailMode = strings.TrimSpace(opts.GuardrailMode)
	}
	if setupOpts.AgentVersion == "" {
		setupOpts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, conn.Name())
	}
	if setupOpts.HookContractID == "" {
		setupOpts.HookContractID = defaultHookContractID(resolveHookContract(conn.Name(), setupOpts.AgentVersion))
	}

	var result InstallResult
	err = connector.WithUserHomeDir(home, func() error {
		secureClient := secureClientHookDelivery()
		if secureClient {
			setupOpts, err = prepareHookContract(opts.GuardrailMode, conn, setupOpts)
			if err != nil {
				return err
			}
		}
		paths := connector.HookConfigPathsForConnector(conn, setupOpts)
		if err := validateActivationSurfaces(home, paths, uid, false, nil); err != nil {
			return err
		}
		if !secureClient {
			if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
				return err
			}
		}
		footprint := connector.AgentPaths{}
		if ap, ok := conn.(connector.AgentPathProvider); ok {
			footprint = ap.AgentPaths(setupOpts)
		}
		if err := validateInstallFootprintBeforeSetup(home, dataDir, uid, conn.Name(), footprint, false); err != nil {
			return err
		}
		return withOwnerCredentials(uid, gid, func() error {
			verifyOwnedHooks := func() error {
				present, err := connector.OwnedHooksPresent(conn, setupOpts)
				if err != nil {
					return fmt.Errorf("enterprise hooks: connector %s hook verification failed: %w", conn.Name(), err)
				}
				if !present {
					return fmt.Errorf("enterprise hooks: connector %s hook verification failed: %s", conn.Name(), ownedHookAbsentDetail(conn, setupOpts))
				}
				return nil
			}
			if !standalonePerUserRepair(uid) {
				// Preserve the Secure Client check order.
				if err := verifyOwnedHooks(); err != nil {
					return err
				}
			}
			if path, driftErr := connector.ManagedPluginArtifactDrift(conn, setupOpts); driftErr != nil {
				return fmt.Errorf("enterprise hooks: inspect connector %s plugin %s: %w", conn.Name(), path, driftErr)
			} else if path != "" {
				return fmt.Errorf("enterprise hooks: connector %s plugin differs from the current template: %s", conn.Name(), path)
			}
			// Match validateHookContract's mode selection so Verify does not
			// load and re-hash the lock in bounded/managed mode on Unix
			// while the drift check reads it in legacy mode. Windows
			// managed runtimes stay strict (regular admin-published files);
			// Unix guardians keep their per-user symlink contract.
			strictManagedRuntime := setupOpts.ManagedEnterprise && runtime.GOOS == "windows"
			lock, err := connector.LoadHookContractLockEntryForMode(dataDir, conn.Name(), strictManagedRuntime)
			if err != nil {
				return fmt.Errorf("enterprise hooks: load hook contract lock: %w", err)
			}
			if lock.Connector != conn.Name() {
				return fmt.Errorf("enterprise hooks: connector %s hook contract lock is missing", conn.Name())
			}
			if strictManagedRuntime {
				if err := connector.ValidateWindowsManagedHookContractGatewayServiceBinding(lock); err != nil {
					return fmt.Errorf(
						"enterprise hooks: connector %s managed gateway binding: %w",
						conn.Name(),
						err,
					)
				}
			}
			current, err := connector.NewHookContractLockEntryForMode(
				setupOpts,
				conn,
				version.Current().BinaryVersion,
				strictManagedRuntime,
			)
			if err != nil {
				return fmt.Errorf("enterprise hooks: hash managed hook runtime: %w", err)
			}
			if connector.HookContractLockDrifted(lock, current) {
				return fmt.Errorf("enterprise hooks: connector %s hook contract lock drift detected", conn.Name())
			}
			if recorded, selected := canonicalHookFailMode(lock.HookFailMode), canonicalHookFailMode(current.HookFailMode); secureClient && recorded != selected {
				return fmt.Errorf("enterprise hooks: connector %s hook contract lock drift detected: hooks were rendered for fail mode %q; the configuration now selects %q", conn.Name(), recorded, selected)
			}
			// Outside the standalone per-user worker (see
			// verifyStandaloneHookRuntime below), Unix verification reads
			// only the agent config reference and the lock, not the hook
			// bytes. Hooks installed before the
			// standalone hook socket was configured (for example by an
			// earlier release) would otherwise pass and keep posting to the
			// TCP port with the shared connector bearer; failing here makes
			// the guardian's verify-or-repair pass reinstall them.
			if connector.HookTransportDrifted(lock, setupOpts) {
				return fmt.Errorf("enterprise hooks: connector %s hooks were installed for a different gateway transport than the configured hook socket", conn.Name())
			}
			// The same holds for credentials: hooks rendered with the
			// connector-scoped credential every user shared, or with another
			// user's or an older key's credentials, are reinstalled with the
			// target's own per-user credentials.
			if connector.HookCredentialDrifted(lock, setupOpts) {
				return fmt.Errorf("enterprise hooks: connector %s hooks were installed with credentials that are not bound to this user", conn.Name())
			}
			// A standalone Hermes hook installed before it ran the
			// foreign-hook guard (or for another hook binary) is
			// reinstalled with the guard the configuration selects.
			if connector.HookForeignGuardDrifted(lock, setupOpts) {
				return fmt.Errorf("enterprise hooks: connector %s hooks were installed with a different foreign-hook guard than the configuration selects", conn.Name())
			}
			// The standalone per-user worker also checks the hook runtime
			// itself: the recorded scripts and plugin bytes, and the fail
			// and guardrail modes the hooks were rendered for.
			if err := verifyStandaloneHookRuntime(conn, setupOpts, opts.GuardrailMode, lock, uid); err != nil {
				return err
			}
			// The standalone runtime check above names a missing or changed
			// script directly. OwnedHooksPresent also treats that condition as
			// an absent registration, which obscures the file the guardian
			// must repair. Keep the registration check after runtime integrity.
			if standalonePerUserRepair(uid) {
				if err := verifyOwnedHooks(); err != nil {
					return err
				}
			}
			result = InstallResult{
				Connector:       conn.Name(),
				UserHome:        home,
				DataDir:         dataDir,
				HookConfigPaths: sortedUnique(paths),
				HookScripts:     sortedUnique(footprint.HookScripts),
				BackupFiles:     sortedUnique(footprint.BackupFiles),
				CreatedDirs:     sortedUnique(footprint.CreatedDirs),
				AgentVersion:    lock.RawAgentVersion,
				HookContractID:  lock.ContractID,

				AgentVersionStatus: agentVersionStatus(conn.Name(), lock.RawAgentVersion),
			}
			switch {
			case standalonePerUserRepair(uid):
				// The agent config that verified (Hermes, Devin) is the
				// last known good copy; one recreated without the
				// account's settings stays reported until they are back
				// (GAP-0564).
				result.AgentConfig = connector.AgentConfigStatus(conn.Name(), setupOpts, time.Time{}, true)
			case agentConfigReadOnVerify():
				// The Windows standalone guardian verifies for the account:
				// it reads what to report and writes nothing (the copy is
				// kept by its setup, GAP-0588).
				result.AgentConfig = connector.AgentConfigStatus(conn.Name(), setupOpts, time.Time{}, false)
			}
			return nil
		})
	})
	if err != nil {
		return InstallResult{}, err
	}
	_ = ctx // reserved for bounded live-client probes
	return result, nil
}

func Install(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	if result, handled, err := platformInstall(ctx, opts); handled {
		return result, err
	}
	if errEnterpriseHooksUnsupportedWindows != nil {
		return InstallResult{}, errEnterpriseHooksUnsupportedWindows
	}
	if err := refuseStandaloneRootInProcess("install"); err != nil {
		return InstallResult{}, err
	}
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		return InstallResult{}, err
	}
	uid, gid, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return InstallResult{}, err
	}
	if err := validateHomeOwner(home, uid); err != nil {
		return InstallResult{}, err
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	// The standalone per-user worker runs as the owner: undo a mode change
	// the user made to their own DefenseClaw directories before inspecting
	// them, instead of failing every repair until the user undoes it.
	restoreOwnedDataDirModes(home, dataDir, uid)
	if err := validateUserDataDir(home, dataDir, uid); err != nil {
		return InstallResult{}, err
	}

	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector is required")
	}
	conn, ok := reg.Get(name)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if connector.IsProxyConnector(conn.Name()) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q is proxy/plugin setup-only; per-user hook install is not supported", conn.Name())
	}
	if !connector.OwnsManagedHookRuntime(conn) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q does not own a managed hook runtime", conn.Name())
	}
	if !connector.ConnectorSupportedOnHostOS(conn.Name()) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q is not supported on this host OS", conn.Name())
	}

	setupOpts := connector.SetupOpts{
		DataDir:                  dataDir,
		ProxyAddr:                strings.TrimSpace(opts.ProxyAddr),
		APIAddr:                  strings.TrimSpace(opts.APIAddr),
		APIToken:                 strings.TrimSpace(opts.APIToken),
		OTLPPathToken:            strings.TrimSpace(opts.OTLPPathToken),
		Interactive:              false,
		ManagedEnterprise:        true,
		WorkspaceDir:             strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:             strings.TrimSpace(opts.HookFailMode),
		SecureClientHookDelivery: secureClientHookDelivery(),
		GuardrailMode:            strings.TrimSpace(opts.GuardrailMode),
		HILTEnabled:              opts.HILTEnabled,
		AgentVersion:             strings.TrimSpace(opts.AgentVersion),
		HookContractID:           strings.TrimSpace(opts.HookContractID),
		ManagedHookSocket:        strings.TrimSpace(opts.ManagedHookSocket),
		ManagedServiceUID:        opts.ManagedServiceUID,
		HookCredentialIdentity:   strings.TrimSpace(opts.HookCredentialIdentity),
		// Only the standalone guardian sets this, for Amp and OpenCode.
		ForeignHookGuardBinary: strings.TrimSpace(opts.ForeignHookGuardBinary),
		ManagedHookBinary:      strings.TrimSpace(opts.ManagedHookBinary),
	}
	if runtime.GOOS == "darwin" && secureClientHookDelivery() {
		setupOpts.HookExecutable = "/opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway"
	}
	requiresScopedHookToken := connector.RequiresScopedHookToken(conn)
	if requiresScopedHookToken {
		if !validEnterpriseScopedHookToken(setupOpts.APIToken) {
			return InstallResult{}, fmt.Errorf("enterprise hooks: connector-scoped hook token is required")
		}
		setupOpts.HookAPIToken = setupOpts.APIToken
		setupOpts.HookAPITokenScoped = true
	}
	if setupOpts.AgentVersion == "" {
		setupOpts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, conn.Name())
	}
	if setupOpts.HookContractID == "" {
		setupOpts.HookContractID = defaultHookContractID(resolveHookContract(conn.Name(), setupOpts.AgentVersion))
	}

	var result InstallResult
	err = connector.WithUserHomeDir(home, func() error {
		secureClient := secureClientHookDelivery()
		requestedHookFailMode := canonicalHookFailMode(setupOpts.HookFailMode)
		if secureClient {
			setupOpts, err = prepareHookContract(opts.GuardrailMode, conn, setupOpts)
			if err != nil {
				return err
			}
		}
		if requestedHookFailMode == "closed" && canonicalHookFailMode(setupOpts.HookFailMode) == "open" {
			resolution := resolveHookContract(conn.Name(), setupOpts.AgentVersion)
			reason := resolution.Reason
			if resolution.Status == connector.HookCompatibilityKnown {
				reason = "the installed hook-contract lock does not verify the selected contract"
			}
			fmt.Fprintf(
				os.Stderr,
				"[enterprise-hooks] WARNING: %s hook contract is not verified (%s); installing %s with fail-open delivery until compatibility is verified\n",
				conn.Name(),
				reason,
				setupOpts.HookContractID,
			)
		}
		paths := connector.HookConfigPathsForConnector(conn, setupOpts)
		pluginArtifacts := connector.ManagedPluginArtifacts(conn, setupOpts)
		// A hook config file DefenseClaw owns (Kiro, Copilot) lives in a
		// folder the agent does not create: make its missing parents as the
		// user, and let Setup write the file itself.
		var ownedHookConfigs, createdHookConfigParents []string
		if standalonePerUserRepair(uid) {
			// Refuse a contract the install cannot meet before creating any
			// folder, so a refused install leaves the home as it was.
			if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
				return err
			}
			if err := withOwnerCredentials(uid, gid, func() error {
				var prepareErr error
				ownedHookConfigs, createdHookConfigParents, prepareErr = prepareOwnedHookConfigParents(home, conn.Name(), paths, uid)
				return prepareErr
			}); err != nil {
				return err
			}
		}
		// Endpoint-product bootstrap: on a fresh target where the
		// user hasn't launched the agent yet, the native hook config
		// file doesn't exist and validateActivationSurfaces below
		// would refuse with "hook config file missing". Pre-create
		// the connector's minimal-valid stub as the target user so
		// the strict validate check has something to inspect.
		//
		// Design intent: DefenseClaw ships on customer Macs where we
		// want enforcement live at pkg-install time — not deferred
		// until the user happens to open each agent once. The stub
		// is intentionally minimal (the agent's own default config
		// content) so it won't override anything the user hasn't
		// explicitly set; connector.Setup() below then patches in
		// the DefenseClaw-owned entries.
		if stub := defaultHookConfigStubForConnector(conn, setupOpts, home); stub.ContentPath != "" {
			var bootstrapped bool
			bootstrapErr := withOwnerCredentials(uid, gid, func() error {
				written, werr := bootstrapMissingHookConfig(home, stub)
				bootstrapped = written
				return werr
			})
			if bootstrapErr != nil {
				return fmt.Errorf("enterprise hooks: bootstrap missing hook config for %s: %w", conn.Name(), bootstrapErr)
			}
			_ = bootstrapped // reserved for future audit emission
		}
		if err := validateActivationSurfaces(
			home,
			paths,
			uid,
			opts.AllowMissingHookConfigRepair,
			append(append([]string{}, pluginArtifacts...), ownedHookConfigs...),
		); err != nil {
			return err
		}
		if !secureClient {
			if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
				return err
			}
		}
		footprint := connector.AgentPaths{}
		if ap, ok := conn.(connector.AgentPathProvider); ok {
			footprint = ap.AgentPaths(setupOpts)
		}
		if err := validateInstallFootprintBeforeSetup(home, dataDir, uid, conn.Name(), footprint, opts.AllowMissingHookConfigRepair); err != nil {
			return err
		}

		return withOwnerCredentials(uid, gid, func() error {
			// Held until the hook contract lock names this connector: a
			// removal of the account's last other connector would take the
			// shared scripts Setup writes (lockSharedHookRuntime).
			unlock, err := lockSharedHookRuntime(ctx, home)
			if err != nil {
				return err
			}
			defer unlock()
			conn.SetCredentials(setupOpts.APIToken, opts.MasterKey)
			previousLockEntry := connector.LoadHookContractLockEntry(dataDir, conn.Name())
			lockWriteAttempted := false
			var beforeSetup dataDirSnapshot
			var beforeHookConfigs hookConfigSnapshot
			rollback := func(cause error) error {
				failures := []error{cause}
				if lockWriteAttempted {
					var lockErr error
					if strings.TrimSpace(previousLockEntry.Connector) == "" {
						lockErr = connector.ClearHookContractLockEntry(dataDir, conn.Name())
					} else {
						lockErr = connector.SaveHookContractLockEntry(dataDir, previousLockEntry)
					}
					if lockErr != nil {
						failures = append(failures, fmt.Errorf("enterprise hooks: restore previous hook contract lock: %w", lockErr))
					}
				}
				teardownErr := conn.Teardown(ctx, setupOpts)
				if teardownErr != nil {
					failures = append(failures, fmt.Errorf("enterprise hooks: connector %s rollback failed: %w", conn.Name(), teardownErr))
				}
				// Only once no registration names them: an agent still
				// pointed at a removed script would fail its hook. Either
				// the teardown took the registration back, or the agent's
				// hook config files hold what they held before Setup (a
				// Setup that failed on an unparseable config, whose
				// teardown fails the same way).
				if teardownErr == nil || beforeHookConfigs.unchanged() {
					if residueErr := beforeSetup.removeAdded(); residueErr != nil {
						failures = append(failures, fmt.Errorf("enterprise hooks: connector %s rollback left files in %s: %w", conn.Name(), dataDir, residueErr))
					}
				}
				return errors.Join(failures...)
			}
			// A rollback removes what Setup adds below the data directory
			// (GAP-0509).
			beforeSetup = snapshotDataDir(dataDir)
			beforeHookConfigs = snapshotHookConfigs(append(append([]string{}, paths...), pluginArtifacts...))
			setupStarted := time.Now()
			// The folders Setup creates below the home (~/.codex in an
			// account that never ran Codex, say) are recorded, so the purge
			// and a per-user uninstall --all remove them once empty.
			if err := connector.SetupRecordingCreatedDirs(ctx, conn, setupOpts); err != nil {
				cause := fmt.Errorf("enterprise hooks: connector %s setup failed: %w", conn.Name(), err)
				// A Setup that fails part way (on an unparseable agent
				// config, say) has written its hook scripts, token and
				// config files and backups already (GAP-0509).
				switch {
				case beforeHookConfigs.unchanged():
					// It registered nothing, so no teardown: one would take
					// back a previous install's registration and the shims
					// every connector shares. The files it added go.
					if residueErr := beforeSetup.removeAdded(); residueErr != nil {
						return errors.Join(cause, fmt.Errorf("enterprise hooks: connector %s rollback left files in %s: %w", conn.Name(), dataDir, residueErr))
					}
					return cause
				case beforeHookConfigs.ok:
					return rollback(cause)
				default:
					// A hook config that could not be read before Setup (a
					// named pipe, say) is left as it is.
					return cause
				}
			}
			// Setup found the folders made above already there, so it did
			// not record them for its teardown.
			connector.RecordHookConfigParentDirs(conn.Name(), dataDir, createdHookConfigParents)
			present, err := connector.OwnedHooksPresent(conn, setupOpts)
			if err != nil {
				return rollback(fmt.Errorf("enterprise hooks: connector %s hook verification failed: %w", conn.Name(), err))
			}
			if !present {
				return rollback(fmt.Errorf("enterprise hooks: connector %s hook verification failed: %s", conn.Name(), ownedHookAbsentDetail(conn, setupOpts)))
			}
			if path, driftErr := connector.ManagedPluginArtifactDrift(conn, setupOpts); driftErr != nil {
				return rollback(fmt.Errorf("enterprise hooks: inspect connector %s plugin %s: %w", conn.Name(), path, driftErr))
			} else if path != "" {
				return rollback(fmt.Errorf("enterprise hooks: connector %s plugin differs from the current template: %s", conn.Name(), path))
			}
			// See Verify for the rationale: keep Install's persistence
			// mode consistent with validateHookContract's drift check.
			strictManagedRuntime := setupOpts.ManagedEnterprise && runtime.GOOS == "windows"
			lockEntry, err := connector.NewHookContractLockEntryForMode(
				setupOpts,
				conn,
				version.Current().BinaryVersion,
				strictManagedRuntime,
			)
			if err != nil {
				return rollback(fmt.Errorf("enterprise hooks: hash managed hook runtime: %w", err))
			}
			lockWriteAttempted = true
			if err := connector.SaveHookContractLockEntryForMode(dataDir, lockEntry, strictManagedRuntime); err != nil {
				return rollback(fmt.Errorf("enterprise hooks: save hook contract lock: %w", err))
			}

			if err := hardenInstallFootprint(
				uid,
				gid,
				home,
				dataDir,
				conn.Name(),
				footprint,
				paths,
				pluginArtifacts,
			); err != nil {
				return rollback(err)
			}
			// Plugin/policy runtimes load their scoped bearer from the target
			// user's stable sidecar at event time. Publish only after every other
			// fallible setup and hardening step has succeeded, so an earlier
			// failure cannot strand a replacement credential beside a rolled-back
			// runtime artifact.
			if requiresScopedHookToken {
				if err := publishEnterpriseHookAPIToken(dataDir, conn.Name(), setupOpts.HookAPIToken); err != nil {
					return rollback(fmt.Errorf("enterprise hooks: publish connector-scoped hook token: %w", err))
				}
			}
			result = InstallResult{
				Connector:       conn.Name(),
				UserHome:        home,
				DataDir:         dataDir,
				HookConfigPaths: sortedUnique(paths),
				HookScripts:     sortedUnique(footprint.HookScripts),
				BackupFiles:     sortedUnique(footprint.BackupFiles),
				CreatedDirs:     sortedUnique(footprint.CreatedDirs),
				AgentVersion:    setupOpts.AgentVersion,
				HookContractID:  lockEntry.ContractID,

				AgentVersionStatus: agentVersionStatus(conn.Name(), setupOpts.AgentVersion),
			}
			// An agent config this setup put back or recreated (GAP-0564).
			result.AgentConfig = connector.AgentConfigStatus(conn.Name(), setupOpts, setupStarted, false)
			return nil
		})
	})
	if err != nil {
		return InstallResult{}, err
	}
	return result, nil
}

func validEnterpriseScopedHookToken(token string) bool {
	token = strings.TrimSpace(token)
	if len(token) != 64 {
		return false
	}
	for _, character := range token {
		if character < '0' || (character > '9' && character < 'a') || character > 'f' {
			return false
		}
	}
	return true
}

func validateUserHome(raw string) (string, error) {
	home := strings.TrimSpace(raw)
	if home == "" {
		return "", fmt.Errorf("enterprise hooks: user home is required")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve user home: %w", err)
	}
	clean := filepath.Clean(abs)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("enterprise hooks: refusing to target filesystem root as a user home")
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: inspect user home %s: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("enterprise hooks: refusing symlink user home %s", clean)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("enterprise hooks: user home %s is not a directory", clean)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("enterprise hooks: user home %s is group/other writable", clean)
	}
	return clean, nil
}

func validateActivationSurfaces(
	home string,
	paths []string,
	uid int,
	allowRepair bool,
	managedPluginArtifacts []string,
) error {
	if len(paths) == 0 {
		return fmt.Errorf("enterprise hooks: connector does not expose a hook config path")
	}
	pluginArtifacts := make(map[string]struct{}, len(managedPluginArtifacts))
	for _, artifact := range managedPluginArtifacts {
		if artifact = strings.TrimSpace(artifact); artifact != "" {
			pluginArtifacts[filepath.Clean(artifact)] = struct{}{}
		}
	}
	for _, raw := range paths {
		path := filepath.Clean(strings.TrimSpace(raw))
		if path == "" {
			continue
		}
		_, allowMissing := pluginArtifacts[path]
		if err := validateHookConfigSurface(home, path, uid, allowMissing, allowRepair); err != nil {
			return err
		}
	}
	return nil
}

// standaloneInHomeConfigLink returns the file an agent config symlink names
// when the per-user worker writes through it: the worker runs as the
// account (standalone Unix), and the link, followed to its end, names a
// regular file inside the home whose folders below the home are real
// directories the account owns, none of them group or other writable. A
// dotfile manager keeps ~/.codex/config.toml as a link to a file in
// ~/dotfiles; install replaced that link with a regular file and left the
// linked file without DefenseClaw's entries (rel-1-0-3 GAP-0205, rel-1-0-2
// GAP-0642). Any other link is not returned: install refuses it, or a
// repair replaces the link itself and never touches the file it names.
func standaloneInHomeConfigLink(home, path string, uid int) (string, bool) {
	if !standalonePerUserRepair(uid) {
		return "", false
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	cleanHome := filepath.Clean(home)
	realHome, err := filepath.EvalSymlinks(cleanHome)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(realHome, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	target := filepath.Join(cleanHome, rel)
	if err := validateExistingUserFile(cleanHome, target, uid, "linked hook config"); err != nil {
		return "", false
	}
	return target, true
}

func validateHookConfigSurface(home, path string, uid int, allowMissing, allowRepair bool) error {
	if target, ok := standaloneInHomeConfigLink(home, path, uid); ok {
		// The link stays; the file it names is the one checked and written.
		path = target
	}
	if !allowMissing && !allowRepair {
		if !standaloneProfileProcess() {
			return validateExistingUserFile(home, path, uid, "hook config")
		}
		if err := validateExistingUserParentPrefix(home, path, uid, "hook config"); err != nil {
			return err
		}
		if err := tightenLooseUserHookConfig(path, uid); err != nil {
			return err
		}
		return validateExistingUserFile(home, path, uid, "hook config")
	}
	if err := validateOptionalUserPathPrefix(home, path, uid, "hook config", false); err != nil {
		return err
	}
	if standaloneProfileProcess() {
		if err := tightenLooseUserHookConfig(path, uid); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("enterprise hooks: inspect hook config %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if allowRepair {
			if err := removeRepairSymlink(path, uid, "hook config"); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("enterprise hooks: refusing symlink hook config: %s", path)
	}
	if info.IsDir() {
		return fmt.Errorf("enterprise hooks: hook config path is a directory: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		if !standaloneProfileProcess() {
			if allowRepair {
				if ok, actual := fileOwnerMatches(path, uid); !ok {
					return fmt.Errorf("enterprise hooks: hook config %s owner uid=%d does not match target uid=%d", path, actual, uid)
				}
				return chmodOwnedPath(path, 0o600)
			}
			return fmt.Errorf("enterprise hooks: hook config %s is group/other writable", path)
		}
		// tightenLooseUserHookConfig already fixed a file the account owns.
		if ok, actual := fileOwnerMatches(path, uid); !ok {
			return fmt.Errorf("enterprise hooks: hook config %s owner uid=%d does not match target uid=%d; make the account own it (chown) and retry", path, actual, uid)
		}
		return fmt.Errorf("enterprise hooks: hook config %s is group/other writable; as that account, run: chmod go-w %s", path, path)
	}
	if ok, actual := fileOwnerMatches(path, uid); !ok {
		return fmt.Errorf("enterprise hooks: hook config %s owner uid=%d does not match target uid=%d", path, actual, uid)
	}
	return nil
}

func validateUserDataDir(home, dataDir string, uid int) error {
	dataDir = filepath.Clean(strings.TrimSpace(dataDir))
	if dataDir == "" {
		return fmt.Errorf("enterprise hooks: data dir is required")
	}
	if !filepath.IsAbs(dataDir) {
		return fmt.Errorf("enterprise hooks: data dir %q is not absolute", dataDir)
	}
	if !pathInside(home, dataDir) {
		return fmt.Errorf("enterprise hooks: refusing data dir outside user home: %s", dataDir)
	}
	return validateExistingUserPathPrefix(home, dataDir, uid, "data dir")
}

func validateExistingUserFile(home, path string, uid int, label string) error {
	if err := validateExistingUserParentPrefix(home, path, uid, label); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("enterprise hooks: %s file missing: %s", label, path)
		}
		return fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, path)
	}
	if info.IsDir() {
		return fmt.Errorf("enterprise hooks: %s path is a directory: %s", label, path)
	}
	if ok, actual := fileOwnerMatches(path, uid); !ok {
		return fmt.Errorf("enterprise hooks: %s %s owner uid=%d does not match target uid=%d; make the account own it (chown) and retry", label, path, actual, uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("enterprise hooks: %s %s is group/other writable; as that account, run: chmod go-w %s", label, path, path)
	}
	return nil
}

func validateExistingUserPathPrefix(home, path string, uid int, label string) error {
	return validateUserPathPrefix(home, path, uid, label, true, false)
}

func validateExistingUserParentPrefix(home, path string, uid int, label string) error {
	return validateUserPathPrefix(home, path, uid, label, false, false)
}

func validateOptionalUserPathPrefix(home, path string, uid int, label string, includeLeaf bool) error {
	return validateUserPathPrefix(home, path, uid, label, includeLeaf, true)
}

func validateUserPathPrefix(home, path string, uid int, label string, includeLeaf bool, allowMissing bool) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return fmt.Errorf("enterprise hooks: %s path %q is not absolute", label, path)
	}
	if !pathInside(home, path) {
		return fmt.Errorf("enterprise hooks: refusing %s outside user home: %s", label, path)
	}
	rel, err := filepath.Rel(home, path)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve %s relative to user home: %w", label, err)
	}
	cur := filepath.Clean(home)
	if err := validateExistingUserDir(cur, uid, "user home"); err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if i == len(parts)-1 && !includeLeaf {
			return nil
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				if allowMissing || i == len(parts)-1 {
					return nil
				}
				return fmt.Errorf("enterprise hooks: %s parent missing: %s", label, cur)
			}
			return fmt.Errorf("enterprise hooks: inspect %s path %s: %w", label, cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing symlink in %s path: %s", label, cur)
		}
		if i < len(parts)-1 {
			if !info.IsDir() {
				return fmt.Errorf("enterprise hooks: %s parent is not a directory: %s", label, cur)
			}
			if err := validateExistingUserDir(cur, uid, label+" parent"); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOptionalExistingUserFileRepair(home, path string, uid int, label string, allowRepairSymlink bool) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return nil
	}
	if target, ok := standaloneInHomeConfigLink(home, path, uid); ok {
		path = target
	}
	if err := validateOptionalUserPathPrefix(home, path, uid, label, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if allowRepairSymlink {
			return removeRepairSymlink(path, uid, label)
		}
		return fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, path)
	}
	if info.IsDir() {
		return fmt.Errorf("enterprise hooks: %s path is a directory: %s", label, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		if allowRepairSymlink {
			if ok, actual := fileOwnerMatches(path, uid); !ok {
				return fmt.Errorf("enterprise hooks: %s %s owner uid=%d does not match target uid=%d", label, path, actual, uid)
			}
			return chmodOwnedPath(path, 0o600)
		}
		return fmt.Errorf("enterprise hooks: %s %s is group/other writable", label, path)
	}
	if ok, actual := fileOwnerMatches(path, uid); !ok {
		return fmt.Errorf("enterprise hooks: %s %s owner uid=%d does not match target uid=%d", label, path, actual, uid)
	}
	return nil
}

func validateOptionalExistingUserDir(home, path string, uid int, label string) error {
	return validateOptionalExistingUserDirRepair(home, path, uid, label, false)
}

func validateOptionalExistingUserDirRepair(home, path string, uid int, label string, allowRepairSymlink bool) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" {
		return nil
	}
	if !pathInside(home, path) {
		return fmt.Errorf("enterprise hooks: refusing %s outside user home: %s", label, path)
	}
	if err := validateOptionalUserPathPrefix(home, path, uid, label, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if allowRepairSymlink {
			return removeRepairSymlink(path, uid, label)
		}
		return fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, path)
	}
	if !info.IsDir() {
		return fmt.Errorf("enterprise hooks: %s is not a directory: %s", label, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("enterprise hooks: %s %s is group/other writable", label, path)
	}
	if ok, actual := fileOwnerMatches(path, uid); !ok {
		return fmt.Errorf("enterprise hooks: %s %s owner uid=%d does not match target uid=%d", label, path, actual, uid)
	}
	return nil
}

func validateExistingUserDir(path string, uid int, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, path)
	}
	if !info.IsDir() {
		return fmt.Errorf("enterprise hooks: %s is not a directory: %s", label, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("enterprise hooks: %s %s is group/other writable", label, path)
	}
	if ok, actual := fileOwnerMatches(path, uid); !ok {
		return fmt.Errorf("enterprise hooks: %s %s owner uid=%d does not match target uid=%d", label, path, actual, uid)
	}
	return nil
}

func validateInstallFootprintBeforeSetup(home, dataDir string, uid int, connectorName string, footprint connector.AgentPaths, allowRepairSymlink bool) error {
	for _, dir := range sortedUnique(append([]string{filepath.Join(dataDir, "hooks")}, footprint.CreatedDirs...)) {
		if err := validateOptionalExistingUserDirRepair(home, dir, uid, "footprint dir", allowRepairSymlink); err != nil {
			return err
		}
	}
	files := append([]string{}, footprint.PatchedFiles...)
	files = append(files, footprint.BackupFiles...)
	files = append(files, footprint.HookScripts...)
	files = append(files, footprint.GeneratedFiles...)
	files = append(files, footprint.GeneratedExecutables...)
	sidecarFiles, err := hookSidecarFiles(dataDir, connectorName)
	if err != nil {
		return err
	}
	files = append(files, sidecarFiles...)
	for _, path := range sortedUnique(files) {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if !pathInside(home, filepath.Clean(path)) {
			return fmt.Errorf("enterprise hooks: refusing footprint file outside user home: %s", filepath.Clean(path))
		}
		if err := validateOptionalExistingUserFileRepair(home, path, uid, "footprint file", allowRepairSymlink); err != nil {
			return err
		}
	}
	return nil
}

func removeRepairSymlink(path string, uid int, label string) error {
	if ok, actual := fileOwnerMatches(path, uid); !ok {
		return fmt.Errorf("enterprise hooks: symlink %s %s owner uid=%d does not match target uid=%d", label, path, actual, uid)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("enterprise hooks: remove symlink %s %s: %w", label, path, err)
	}
	return nil
}

func hardenInstallFootprint(
	uid, gid int,
	home, dataDir, connectorName string,
	footprint connector.AgentPaths,
	hookConfigPaths, managedPluginArtifacts []string,
) error {
	if err := validateExistingUserDir(dataDir, uid, "data dir"); err != nil {
		return err
	}
	if err := chmodOwnedPath(dataDir, 0o700); err != nil {
		return err
	}
	for _, dir := range append([]string{filepath.Join(dataDir, "hooks")}, footprint.CreatedDirs...) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		dir = filepath.Clean(dir)
		if !pathInside(home, dir) {
			return fmt.Errorf("enterprise hooks: refusing created dir outside user home: %s", dir)
		}
		if _, err := os.Lstat(dir); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("enterprise hooks: inspect created dir %s: %w", dir, err)
		}
		if err := validateExistingUserDir(dir, uid, "created dir"); err != nil {
			return err
		}
		if err := chmodOwnedPath(dir, 0o700); err != nil {
			return err
		}
	}
	for _, path := range sortedUnique(append(append([]string{}, hookConfigPaths...), footprint.PatchedFiles...)) {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if target, ok := standaloneInHomeConfigLink(home, filepath.Clean(path), uid); ok {
			path = target
		}
		if err := validateExistingUserFile(home, filepath.Clean(path), uid, "patched file"); err != nil {
			return err
		}
		if err := chmodOwnedPath(path, 0o600); err != nil {
			return err
		}
	}
	footprintFiles := append([]string{}, footprint.BackupFiles...)
	footprintFiles = append(footprintFiles, footprint.HookScripts...)
	footprintFiles = append(footprintFiles, footprint.GeneratedFiles...)
	footprintFiles = append(footprintFiles, footprint.GeneratedExecutables...)
	sidecarFiles, err := hookSidecarFiles(dataDir, connectorName)
	if err != nil {
		return err
	}
	footprintFiles = append(footprintFiles, sidecarFiles...)
	pluginArtifacts := make(map[string]struct{}, len(managedPluginArtifacts))
	for _, artifact := range managedPluginArtifacts {
		if artifact = strings.TrimSpace(artifact); artifact != "" {
			pluginArtifacts[filepath.Clean(artifact)] = struct{}{}
		}
	}
	for _, path := range sortedUnique(footprintFiles) {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("enterprise hooks: inspect footprint file %s: %w", path, err)
		}
		if err := validateExistingUserFile(home, filepath.Clean(path), uid, "footprint file"); err != nil {
			return err
		}
		mode := os.FileMode(0o600)
		if _, isManagedPlugin := pluginArtifacts[filepath.Clean(path)]; !isManagedPlugin {
			for _, script := range footprint.HookScripts {
				if filepath.Clean(script) == filepath.Clean(path) {
					mode = 0o700
					break
				}
			}
			for _, script := range footprint.GeneratedExecutables {
				if filepath.Clean(script) == filepath.Clean(path) {
					mode = 0o700
					break
				}
			}
		}
		if err := chmodOwnedPath(path, mode); err != nil {
			return err
		}
	}
	return lchownInstallFootprint(uid, gid, dataDir, footprint, hookConfigPaths)
}

func hookSidecarFiles(dataDir, connectorName string) ([]string, error) {
	hookDir := filepath.Join(dataDir, "hooks")
	files := []string{
		filepath.Join(hookDir, ".token"),
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, "_hardening.sh"),
	}
	scopedToken, err := connector.HookTokenFilePath(hookDir, connectorName)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: resolve connector-scoped token sidecar: %w", err)
	}
	return append(files, scopedToken), nil
}

// prepareHookContract selects the effective contract and delivery-failure mode
// while preserving each platform's established lock and runtime trust boundary.
//
// Under Secure Client (#1163) missing, unsupported or incompatible version
// evidence selects the reviewed best-effort contract in open delivery instead
// of refusing installation. Every other profile keeps validateHookContract:
// an unverified contract in action mode and a contract drift are refused, and
// the delivery mode is left as configured (fail-closed).
func prepareHookContract(guardrailMode string, conn connector.Connector, opts connector.SetupOpts) (connector.SetupOpts, error) {
	if !secureClientHookDelivery() {
		if strings.TrimSpace(opts.HookContractID) == "" {
			opts.HookContractID = defaultHookContractID(resolveHookContract(conn.Name(), opts.AgentVersion))
		}
		if err := validateHookContract(guardrailMode, conn, opts); err != nil {
			return connector.SetupOpts{}, err
		}
		return opts, nil
	}
	resolution := resolveHookContract(conn.Name(), opts.AgentVersion)
	if strings.TrimSpace(opts.HookContractID) == "" {
		opts.HookContractID = connector.BestEffortHookContract(resolution).ContractID
	}
	strictManagedRuntime := opts.ManagedEnterprise && runtime.GOOS == "windows"
	if envvars.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") == "1" && !strictManagedRuntime {
		return opts, nil
	}
	if connector.HookContractNeedsActionOverride(resolution) {
		opts.HookFailMode = "open"
	}
	// Native Windows managed runtimes are administrator-published regular
	// files. Unix guardians intentionally install hardened per-user symlinks,
	// so keep their established contract reader and digest semantics. The
	// strict readers apply in every guardrail mode on managed Windows.
	previous, current, err := loadHookContractLockPair(conn, opts, strictManagedRuntime)
	if err != nil {
		return connector.SetupOpts{}, err
	}
	if err := checkStandaloneNotGatedFloor(conn, opts, resolution, previous, current); err != nil {
		return connector.SetupOpts{}, err
	}
	if hookContractsIncompatible(previous, current) {
		opts.HookFailMode = "open"
	}
	return opts, nil
}

// checkStandaloneNotGatedFloor keeps the standalone floor of a not-gated
// connector (Kiro). The floor gates new enrollments only: a user whose hooks
// an earlier release installed below the floor already has a contract lock,
// and keeps being repaired at the version they were rendered for, because
// refusing the repair would leave the row not OK and the gateway would then
// refuse the user's hook calls. A version change below the floor is refused.
func checkStandaloneNotGatedFloor(
	conn connector.Connector,
	opts connector.SetupOpts,
	resolution connector.HookContractResolution,
	previous, current connector.HookContractLockEntry,
) error {
	if !standaloneProfileProcess() || standaloneNotGatedAgentFloor(conn.Name()) == "" ||
		resolution.Status != connector.HookCompatibilityNotGated {
		return nil
	}
	admitted, reason := standaloneNotGatedVersionAdmitted(resolution)
	if admitted {
		return nil
	}
	if previous.Connector == "" {
		return fmt.Errorf("enterprise hooks: connector %s agent version %q is not certified for the standalone profile: %s", conn.Name(), opts.AgentVersion, reason)
	}
	if connector.HookContractLockDrifted(previous, current) {
		floorNote := ""
		if reason != "" {
			floorNote = "; " + reason
		}
		return fmt.Errorf("enterprise hooks: connector %s hook contract drift detected: previous version=%q contract=%s current version=%q contract=%s%s", conn.Name(), previous.RawAgentVersion, previous.ContractID, current.RawAgentVersion, current.ContractID, floorNote)
	}
	return nil
}

// loadHookContractLockPair returns the recorded contract lock and, when one
// exists, the lock entry the current setup would record.
func loadHookContractLockPair(
	conn connector.Connector,
	opts connector.SetupOpts,
	strictManagedRuntime bool,
) (connector.HookContractLockEntry, connector.HookContractLockEntry, error) {
	var previous, current connector.HookContractLockEntry
	if strictManagedRuntime {
		loaded, err := connector.LoadHookContractLockEntryForMode(
			opts.DataDir,
			conn.Name(),
			true,
		)
		if err != nil {
			return previous, current, fmt.Errorf("enterprise hooks: load hook contract lock: %w", err)
		}
		previous = loaded
	} else {
		previous = connector.LoadHookContractLockEntry(opts.DataDir, conn.Name())
	}
	if previous.Connector == "" {
		return previous, current, nil
	}
	if strictManagedRuntime {
		generated, err := connector.NewHookContractLockEntryForMode(
			opts,
			conn,
			version.Current().BinaryVersion,
			true,
		)
		if err != nil {
			return previous, current, fmt.Errorf("enterprise hooks: hash managed hook runtime: %w", err)
		}
		current = generated
	} else {
		current = connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
	}
	return previous, current, nil
}

// validateHookContract is the contract gate outside Secure Client (origin/main
// semantics): in action mode an agent version without a verified hook
// contract is refused, and a drifted contract lock is refused unless the
// standalone profile accepts the version change.
func validateHookContract(mode string, conn connector.Connector, opts connector.SetupOpts) error {
	if envvars.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") == "1" {
		return nil
	}
	resolution := resolveHookContract(conn.Name(), opts.AgentVersion)
	if !strings.EqualFold(strings.TrimSpace(mode), "action") {
		// The standalone guardian installs no hooks for an agent version
		// with no hook contract, in any guardrail mode: they were rendered
		// without one and status and verify reported the agent as covered
		// (GAP-0151). Status and verify name it hook_contract_unverified.
		if standaloneProfileProcess() && resolution.Status == connector.HookCompatibilityUnknown {
			return fmt.Errorf("enterprise hooks: connector %s agent version %q is not verified against a known hook contract: %s", conn.Name(), opts.AgentVersion, resolution.Reason)
		}
		return nil
	}
	if connector.HookContractNeedsActionOverride(resolution) {
		return fmt.Errorf("enterprise hooks: connector %s agent version %q is not verified against a known hook contract: %s", conn.Name(), opts.AgentVersion, resolution.Reason)
	}
	// Native Windows managed runtimes are administrator-published regular
	// files. Unix guardians intentionally install hardened per-user symlinks,
	// so keep their established contract reader and digest semantics.
	strictManagedRuntime := opts.ManagedEnterprise && runtime.GOOS == "windows"
	previous, err := connector.LoadHookContractLockEntryForMode(
		opts.DataDir,
		conn.Name(),
		strictManagedRuntime,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: load hook contract lock: %w", err)
	}
	// The standalone floor of a not-gated connector (Kiro) gates new
	// enrollments only. A user whose hooks an earlier release installed
	// below the floor already has a contract lock: keep repairing that
	// user's hooks at the version they were rendered for (a version change
	// below the floor is still refused as drift, below), because refusing
	// the repair would leave the row not OK, the gateway would then refuse
	// the user's hook calls, and the hook script fails open by default.
	if standaloneProfileProcess() && standaloneNotGatedAgentFloor(conn.Name()) != "" &&
		resolution.Status == connector.HookCompatibilityNotGated && previous.Connector == "" {
		if admitted, reason := standaloneNotGatedVersionAdmitted(resolution); !admitted {
			return fmt.Errorf("enterprise hooks: connector %s agent version %q is not certified for the standalone profile: %s", conn.Name(), opts.AgentVersion, reason)
		}
	}
	if previous.Connector != "" {
		current, err := connector.NewHookContractLockEntryForMode(
			opts,
			conn,
			version.Current().BinaryVersion,
			strictManagedRuntime,
		)
		if err != nil {
			return fmt.Errorf("enterprise hooks: hash managed hook runtime: %w", err)
		}
		if connector.HookContractLockDrifted(previous, current) {
			if standaloneAcceptsAgentVersionChange(resolution) {
				return nil
			}
			floorNote := ""
			if standaloneProfileProcess() && standaloneNotGatedAgentFloor(conn.Name()) != "" {
				if _, reason := standaloneNotGatedVersionAdmitted(resolution); reason != "" {
					floorNote = "; " + reason
				}
			}
			return fmt.Errorf("enterprise hooks: connector %s hook contract drift detected: previous version=%q contract=%s current version=%q contract=%s%s", conn.Name(), previous.RawAgentVersion, previous.ContractID, current.RawAgentVersion, current.ContractID, floorNote)
		}
	}
	return nil
}

// standaloneAcceptsAgentVersionChange reports whether an install may follow
// an agent version that changed since its hooks were rendered. The standalone
// enumerator re-discovers every enrolled user's agent version each cycle, and
// the standalone guardian re-renders and re-verifies the hooks when the new
// version resolves to a known, verified hook contract; the install then writes
// a new contract lock. A version without a verified contract never gets here:
// validateHookContract refuses it first, and status and verify report it as
// hook_contract_unverified. A connector whose hook contract is not
// version-gated (Kiro) has no known contract, so it follows a new version at
// or above its standalone floor instead; without this every kiro-cli
// self-update stopped the guardian repairing that user's hooks. The Secure
// Client profile does not use this gate: prepareHookContract installs a
// changed version in open delivery instead (#1163).
func standaloneAcceptsAgentVersionChange(resolution connector.HookContractResolution) bool {
	if !standaloneProfileProcess() {
		return false
	}
	if resolution.Status == connector.HookCompatibilityKnown {
		return true
	}
	admitted, _ := standaloneNotGatedVersionAdmitted(resolution)
	return admitted
}

// secureClientHookDelivery reports whether this process serves the Secure
// Client profile: the only profile whose unset hook fail mode is open and
// whose unverified, unsupported or drifted agent versions install in open
// delivery (#1163). The enterprise guardian serves either Secure Client or
// the standalone profile; standalone keeps fail-closed delivery, its version
// gates and its refusals.
func secureClientHookDelivery() bool {
	return secureClientHookDeliveryHost && !standaloneProfileProcess() && connector.SecureClientDeploymentVerified()
}

// secureClientHookDeliveryHost reports whether this OS has a Secure Client
// profile at all. Linux has none (managed.ResolveEnterpriseProfile refuses
// it), so no Linux process renders the Secure Client fail-open delivery
// contract, even one that never set the standalone process mode (GAP-0002).
// A seam for tests of the Secure Client contract on Linux CI.
var secureClientHookDeliveryHost = runtime.GOOS != "linux"

// defaultHookContractID is the contract an install renders when the caller
// did not pin one: the reviewed best-effort contract under Secure Client, and
// the resolved contract (origin/main) everywhere else.
func defaultHookContractID(resolution connector.HookContractResolution) string {
	if secureClientHookDelivery() {
		return connector.BestEffortHookContract(resolution).ContractID
	}
	return resolution.Contract.ContractID
}

// hookContractsIncompatible reports whether current evidence requires the
// compatibility fallback policy on both Unix and managed Windows.
func hookContractsIncompatible(previous, current connector.HookContractLockEntry) bool {
	if strings.TrimSpace(previous.Connector) == "" {
		return false
	}
	previousID := strings.TrimSpace(previous.ContractID)
	currentID := strings.TrimSpace(current.ContractID)
	// A connector whose hooks are not version-gated (Kiro) has no
	// contract to verify; it stays compatible while it keeps the not-gated
	// status and contract it was installed with. Without this every install
	// after the first, and every verify, would select open delivery and
	// disagree with the lock the first install wrote.
	if current.CompatibilityStatus == connector.HookCompatibilityNotGated {
		return previous.CompatibilityStatus != connector.HookCompatibilityNotGated || previousID != currentID
	}
	if current.CompatibilityStatus != connector.HookCompatibilityKnown {
		return true
	}
	return previousID == "" || currentID == "" || previousID != currentID
}

// canonicalHookFailMode resolves a configured delivery policy: "open" (any
// case) is open and every other non-empty value is closed. Unset policy is
// open only under Secure Client (#1163) and closed for every other profile.
func canonicalHookFailMode(mode string) string {
	return canonicalHookFailModeFor(mode, secureClientHookDelivery())
}

// canonicalHookFailModeFor is canonicalHookFailMode for an explicit profile:
// an unset mode is open only under Secure Client (#1163) on an authenticated
// Secure Client deployment (connector.SecureClientDeploymentVerified, the
// strict host classifier): a process or config profile alone never opens an
// unset mode (main-sync review finding 5).
func canonicalHookFailModeFor(mode string, secureClient bool) string {
	trimmed := strings.TrimSpace(mode)
	if strings.EqualFold(trimmed, "open") || (trimmed == "" && secureClient && connector.SecureClientDeploymentVerified()) {
		return "open"
	}
	return "closed"
}

func pathInside(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func sortedUnique(vals []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// resolveHookContract resolves an agent version for this process's
// enterprise profile. The standalone profile treats a version newer than
// every tested range as compatible (untested newer version); Secure Client
// keeps exact-range gating even in a process that has not loaded config.
func resolveHookContract(connectorName, agentVersion string) connector.HookContractResolution {
	if standaloneProfileProcess() {
		// Managed Windows Kiro resolves against its reviewed contracts.
		return connector.ResolveManagedHookContract(connectorName, agentVersion)
	}
	return connector.ResolveHookContractStrict(connectorName, agentVersion)
}

// agentVersionStatus labels an agent version newer than every tested range
// for status and verify output.
func agentVersionStatus(connectorName, agentVersion string) string {
	if resolveHookContract(connectorName, agentVersion).UntestedVersion {
		return connector.UntestedNewerVersionReasonPrefix
	}
	return ""
}

// ownedHookAbsentDetail is the reason an owned-hook check found no accepted
// registration, for verify and install errors. The guardian's watch log and
// status show it, so an agent rewriting its own config is diagnosable without
// rerunning the check by hand.
func ownedHookAbsentDetail(conn connector.Connector, opts connector.SetupOpts) string {
	reason := strings.TrimSpace(connector.OwnedHooksAbsentReason(conn, opts))
	if reason == "" {
		return "owned hook command not present"
	}
	return "owned hook command not present: " + reason
}
