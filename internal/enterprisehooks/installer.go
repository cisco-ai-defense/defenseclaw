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
}

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
}

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
		DataDir:           dataDir,
		ProxyAddr:         strings.TrimSpace(opts.ProxyAddr),
		APIAddr:           strings.TrimSpace(opts.APIAddr),
		APIToken:          strings.TrimSpace(opts.APIToken),
		OTLPPathToken:     strings.TrimSpace(opts.OTLPPathToken),
		Interactive:       false,
		ManagedEnterprise: true,
		WorkspaceDir:      strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:      strings.TrimSpace(opts.HookFailMode),
		HILTEnabled:       opts.HILTEnabled,
		AgentVersion:      strings.TrimSpace(opts.AgentVersion),
		HookContractID:    strings.TrimSpace(opts.HookContractID),
		// The configured transport and credential binding, compared below
		// with the ones the installed hooks were rendered for.
		ManagedHookSocket:      strings.TrimSpace(opts.ManagedHookSocket),
		ManagedServiceUID:      opts.ManagedServiceUID,
		HookCredentialIdentity: strings.TrimSpace(opts.HookCredentialIdentity),
		// Verification requires the guard line the standalone Amp and
		// OpenCode plugins carry, so a plugin rendered without it (before
		// the guard existed, or edited) fails and the guardian re-renders it.
		ForeignHookGuardBinary: strings.TrimSpace(opts.ForeignHookGuardBinary),
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
		resolution := resolveHookContract(conn.Name(), setupOpts.AgentVersion)
		setupOpts.HookContractID = resolution.Contract.ContractID
	}

	var result InstallResult
	err = connector.WithUserHomeDir(home, func() error {
		paths := connector.HookConfigPathsForConnector(conn, setupOpts)
		if err := validateActivationSurfaces(home, paths, uid, false, nil); err != nil {
			return err
		}
		if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
			return err
		}
		footprint := connector.AgentPaths{}
		if ap, ok := conn.(connector.AgentPathProvider); ok {
			footprint = ap.AgentPaths(setupOpts)
		}
		if err := validateInstallFootprintBeforeSetup(home, dataDir, uid, conn.Name(), footprint, false); err != nil {
			return err
		}
		return withOwnerCredentials(uid, gid, func() error {
			present, err := connector.OwnedHooksPresent(conn, setupOpts)
			if err != nil {
				return fmt.Errorf("enterprise hooks: connector %s hook verification failed: %w", conn.Name(), err)
			}
			if !present {
				return fmt.Errorf("enterprise hooks: connector %s hook verification failed: owned hook command not present", conn.Name())
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
		DataDir:                dataDir,
		ProxyAddr:              strings.TrimSpace(opts.ProxyAddr),
		APIAddr:                strings.TrimSpace(opts.APIAddr),
		APIToken:               strings.TrimSpace(opts.APIToken),
		OTLPPathToken:          strings.TrimSpace(opts.OTLPPathToken),
		Interactive:            false,
		ManagedEnterprise:      true,
		WorkspaceDir:           strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:           strings.TrimSpace(opts.HookFailMode),
		GuardrailMode:          strings.TrimSpace(opts.GuardrailMode),
		HILTEnabled:            opts.HILTEnabled,
		AgentVersion:           strings.TrimSpace(opts.AgentVersion),
		HookContractID:         strings.TrimSpace(opts.HookContractID),
		ManagedHookSocket:      strings.TrimSpace(opts.ManagedHookSocket),
		ManagedServiceUID:      opts.ManagedServiceUID,
		HookCredentialIdentity: strings.TrimSpace(opts.HookCredentialIdentity),
		// Only the standalone guardian sets this, for Amp and OpenCode.
		ForeignHookGuardBinary: strings.TrimSpace(opts.ForeignHookGuardBinary),
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
		resolution := resolveHookContract(conn.Name(), setupOpts.AgentVersion)
		setupOpts.HookContractID = resolution.Contract.ContractID
	}

	var result InstallResult
	err = connector.WithUserHomeDir(home, func() error {
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
		if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
			return err
		}
		footprint := connector.AgentPaths{}
		if ap, ok := conn.(connector.AgentPathProvider); ok {
			footprint = ap.AgentPaths(setupOpts)
		}
		if err := validateInstallFootprintBeforeSetup(home, dataDir, uid, conn.Name(), footprint, opts.AllowMissingHookConfigRepair); err != nil {
			return err
		}

		return withOwnerCredentials(uid, gid, func() error {
			conn.SetCredentials(setupOpts.APIToken, opts.MasterKey)
			previousLockEntry := connector.LoadHookContractLockEntry(dataDir, conn.Name())
			lockWriteAttempted := false
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
				if teardownErr := conn.Teardown(ctx, setupOpts); teardownErr != nil {
					failures = append(failures, fmt.Errorf("enterprise hooks: connector %s rollback failed: %w", conn.Name(), teardownErr))
				}
				return errors.Join(failures...)
			}
			// OpenHands on macOS admits only a protected, setup-selected
			// executable: record the user's own image before setup.
			if err := selectManagedAgentExecutable(home, dataDir, conn.Name(), &setupOpts); err != nil {
				return err
			}
			// The folders Setup creates below the home (~/.codex in an
			// account that never ran Codex, say) are recorded, so the purge
			// and a per-user uninstall --all remove them once empty.
			if err := connector.SetupRecordingCreatedDirs(ctx, conn, setupOpts); err != nil {
				return fmt.Errorf("enterprise hooks: connector %s setup failed: %w", conn.Name(), err)
			}
			// Setup found the folders made above already there, so it did
			// not record them for its teardown.
			connector.RecordHookConfigParentDirs(conn.Name(), dataDir, createdHookConfigParents)
			present, err := connector.OwnedHooksPresent(conn, setupOpts)
			if err != nil {
				return rollback(fmt.Errorf("enterprise hooks: connector %s hook verification failed: %w", conn.Name(), err))
			}
			if !present {
				return rollback(fmt.Errorf("enterprise hooks: connector %s hook verification failed: owned hook command not present", conn.Name()))
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

func validateHookConfigSurface(home, path string, uid int, allowMissing, allowRepair bool) error {
	if !allowMissing && !allowRepair {
		return validateExistingUserFile(home, path, uid, "hook config")
	}
	if err := validateOptionalUserPathPrefix(home, path, uid, "hook config", false); err != nil {
		return err
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
		if allowRepair {
			if ok, actual := fileOwnerMatches(path, uid); !ok {
				return fmt.Errorf("enterprise hooks: hook config %s owner uid=%d does not match target uid=%d", path, actual, uid)
			}
			return chmodOwnedPath(path, 0o600)
		}
		return fmt.Errorf("enterprise hooks: hook config %s is group/other writable", path)
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
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("enterprise hooks: %s %s is group/other writable", label, path)
	}
	if ok, actual := fileOwnerMatches(path, uid); !ok {
		return fmt.Errorf("enterprise hooks: %s %s owner uid=%d does not match target uid=%d", label, path, actual, uid)
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

func validateHookContract(mode string, conn connector.Connector, opts connector.SetupOpts) error {
	if !strings.EqualFold(strings.TrimSpace(mode), "action") || os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") == "1" {
		return nil
	}
	resolution := resolveHookContract(conn.Name(), opts.AgentVersion)
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
// Client profile keeps refusing every change, because its versions come from
// an administrator-authored manifest.
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
