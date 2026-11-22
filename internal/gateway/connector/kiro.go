// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const (
	kiroHookScriptName          = "kiro-hook.sh"
	kiroHookAPIPath             = "/api/v1/kiro/hook"
	kiroManagedHooksName        = "defenseclaw.json"
	kiroManagedAgentName        = "defenseclaw"
	kiroBuiltInDefaultAgentName = "kiro_default"
	kiroV3HooksLogicalName      = "hooks"
	kiroGlobalHooksLogicalName  = "hooks-global"
	kiroV2AgentLogicalName      = "agent-defenseclaw"
	kiroSettingsLogicalName     = "settings-cli"
	kiroDefaultAgentSettingKey  = "chat.defaultAgent"
)

// KiroCLIHookFloor is the oldest kiro-cli on which every engine runs
// DefenseClaw's hooks. Before 2.27.1 a V3 non-interactive run (`kiro-cli
// chat --v3 --no-interactive`) loads no hooks at all (kiro.dev/docs/cli/headless:
// "Starting with Kiro CLI 2.27.1, V3 non-interactive runs load Hooks"): a
// real 2.26.1 run completed a tool call that sent DefenseClaw nothing
// (rel-1-0-4 GAP-0227). The managed profiles do not enroll an older kiro-cli,
// and per-user setup and doctor refuse it (cli_hook_floor in
// hook_contracts.json).
const KiroCLIHookFloor = "2.27.1"

// KiroCLIBelowHookFloorReason says why a kiro-cli below KiroCLIHookFloor
// is refused.
func KiroCLIBelowHookFloorReason(normalized string) string {
	return fmt.Sprintf("kiro-cli %s is below %s: before %s a non-interactive kiro-cli --v3 run loads no hooks, "+
		"so its tool calls never reach DefenseClaw; update Kiro CLI to %s or later", normalized, KiroCLIHookFloor, KiroCLIHookFloor, KiroCLIHookFloor)
}

// KiroHooksPathOverride and KiroHomeOverride are test seams. Production
// Setup always writes the user-global ~/.kiro/hooks/defenseclaw.json file
// and, when a workspace is selected, the matching workspace copy.
var (
	KiroHooksPathOverride string
	KiroHomeOverride      string
)

// KiroConnector is the regular Kiro IDE/CLI connector. Native hooks are the
// enforcement path; optional ACP support remains available through
// defenseclaw-acp.
type KiroConnector struct {
	gatewayToken string

	loopbackWarn sync.Once
}

func NewKiroConnector() *KiroConnector { return &KiroConnector{} }
func (*KiroConnector) Name() string    { return "kiro" }
func (*KiroConnector) Description() string {
	return "Kiro IDE or CLI connector; they share native hooks, with optional ACP through defenseclaw-acp"
}
func (*KiroConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (*KiroConnector) SubprocessPolicy() SubprocessPolicy     { return SubprocessNone }
func (*KiroConnector) HookAPIPath() string                    { return kiroHookAPIPath }
func (*KiroConnector) HookScriptNames(SetupOpts) []string     { return []string{kiroHookScriptName} }

func (c *KiroConnector) Setup(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	if err := migrateKiroGlobalHooksBackup(opts); err != nil {
		return fmt.Errorf("kiro migrate hook backup: %w", err)
	}
	defer recordKiroCreatedDirs(opts, missingKiroScaffoldDirs())
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("kiro hook script: %w", err)
	}
	command := c.hookCommand(opts)
	v3Command := c.hookCommandForV3Surface(opts)
	// A workspace copy an earlier Setup wrote for another (or no longer
	// selected) workspace runs a DefenseClaw hook nothing maintains, for
	// example after a failed setup rolled the workspace setting back. A
	// managed Setup reclaims it with the rest of the per-user footprint.
	var staleErr error
	if !kiroManaged(opts) {
		for _, path := range c.staleRecordedKiroHookPaths(opts, c.hookConfigPaths(opts)) {
			if kiroFileUnparsable(path) {
				// It runs no hook and failed every Setup; Teardown reports
				// it and keeps its record.
				continue
			}
			staleErr = errors.Join(staleErr, c.reclaimKiroHookFile(opts, path, v3Command, nil))
		}
	}
	for _, path := range c.hookConfigPaths(opts) {
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), kiroBackupLogicalName(path), path); err != nil {
			return fmt.Errorf("kiro capture hook backup %s: %w", path, err)
		}
		if err := patchKiroV3Hooks(path, v3Command); err != nil {
			return fmt.Errorf("kiro hook config %s: %w", path, err)
		}
		if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), kiroBackupLogicalName(path), path); err != nil {
			return fmt.Errorf("kiro record hook backup %s: %w", path, err)
		}
	}
	for _, path := range c.agentConfigPaths(opts) {
		logical := kiroAgentBackupLogicalName(path)
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), logical, path); err != nil {
			return fmt.Errorf("kiro capture agent backup %s: %w", path, err)
		}
		if err := patchKiroV2AgentHooks(path, command); err != nil {
			return fmt.Errorf("kiro agent hooks %s: %w", path, err)
		}
		if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), logical, path); err != nil {
			return fmt.Errorf("kiro record agent backup %s: %w", path, err)
		}
	}
	if err := removeStaleKiroDefaultOverlay(command, nil); err != nil {
		return fmt.Errorf("kiro remove stale kiro_default overlay: %w", err)
	}
	var reclaimErr error
	if kiroManaged(opts) {
		// Before the setting below names the defenseclaw agent, while it can
		// still name the user's own default agent. A failure is reported
		// after the switch: the reclaim may already have removed the hooks
		// from the user's own agent, and stopping here would leave that
		// unhooked agent as the default until the next repair.
		if err := c.reclaimEarlierKiroFootprint(opts, command); err != nil {
			reclaimErr = fmt.Errorf("kiro reclaim earlier per-user footprint: %w", err)
		}
	}
	settingsPath := kiroSettingsPath()
	if err := captureManagedFileBackup(opts.DataDir, c.Name(), kiroSettingsLogicalName, settingsPath); err != nil {
		return errors.Join(reclaimErr, fmt.Errorf("kiro capture settings backup: %w", err))
	}
	if err := patchKiroDefaultAgentSetting(settingsPath, kiroManaged(opts)); err != nil {
		return errors.Join(reclaimErr, fmt.Errorf("kiro default agent setting: %w", err))
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), kiroSettingsLogicalName, settingsPath); err != nil {
		return errors.Join(reclaimErr, fmt.Errorf("kiro record settings backup: %w", err))
	}
	return errors.Join(staleErr, reclaimErr)
}

// kiroPathError wraps err with what failed and the file. A parse error names
// the file itself, and naming it again made one broken file read as two
// (rel-1-0-10 GAP-1745).
// kiroErrorNamesPath reports whether msg holds path as a whole path element:
// not inside a longer path such as <path>.bak or a parent folder's name.
func kiroErrorNamesPath(msg, path string) bool {
	isPathChar := func(b byte) bool {
		return b == '/' || b == '\\' || b == '.' || b == '_' || b == '-' || b == '~' ||
			b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
	}
	for from := 0; from < len(msg); {
		at := strings.Index(msg[from:], path)
		if at < 0 || path == "" {
			return false
		}
		start, end := from+at, from+at+len(path)
		if (start == 0 || !isPathChar(msg[start-1])) && (end == len(msg) || !isPathChar(msg[end]) || msg[end] == '.' && (end+1 == len(msg) || !isPathChar(msg[end+1]))) {
			return true
		}
		from = start + 1
	}
	return false
}

func kiroPathError(what, path string, err error) error {
	if kiroErrorNamesPath(err.Error(), path) {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s %s: %w", what, path, err)
}

func (c *KiroConnector) Teardown(_ context.Context, opts SetupOpts) error {
	command := c.hookCommand(opts)
	scope, err := c.reclaimScope(opts)
	if err != nil {
		return err
	}
	var errs []error
	if err := migrateKiroGlobalHooksBackup(opts); err != nil {
		errs = append(errs, fmt.Errorf("kiro migrate hook backup: %w", err))
	}
	hooks := c.hookCleanupPaths(opts)
	agents := c.agentCleanupPaths(opts)
	// The files only this install's backup records still name: a workspace
	// hook file Setup wrote before claw.workspace_dir changed (RHEL-U3-09), a
	// custom default agent the user has since switched away from. Every
	// teardown drops this install's records at the end, so each one cleans
	// them first. They are no longer the files the settings name, so even the
	// teardown of a configured connector takes only this install's exact
	// entries out of them (recordScope): the teardown that left them kept the
	// records, and on Windows that kept this data folder an owner of the
	// account's launcher commands, whose later reclaim stripped the live hooks
	// of an install that set Kiro up afterwards (review round 5 P2 of
	// GAP-1092). A file that cannot be read as JSON is left with its record.
	recorded := c.recordedKiroFiles(opts, hooks, append(slices.Clone(agents), kiroBuiltInDefaultAgentPath()))
	if scope == nil && !kiroManaged(opts) && opts.ReportUnreadableResidue {
		// `connector teardown` fails on it and `connector verify` reports it
		// (kiroUnreadableRecordedFiles): skipped silently, the removal
		// succeeded with this install's hooks possibly still in it
		// (rel-1-0-10 GAP-1298). Its record stays for the retry.
		if err := kiroUnreadableRecordedFiles(recorded); err != nil {
			errs = append(errs, err)
		}
	} else {
		// The boot teardowns, the boot reclaim and the managed teardown
		// skip it: failing there came back on every gateway start until the
		// file was fixed (rel-1-0-10 GAP-1304). Its record stays and proves
		// no ownership while the file cannot be read (kiroPendingRecords);
		// once it can, the record is pending again and the boot reclaim
		// finishes the cleanup (kiroUnfinishedTeardown).
		for _, path := range recorded.unreadable {
			fmt.Fprintf(os.Stderr, "[guardrail] connector kiro: %s is not a JSON object, so its DefenseClaw hooks, if any, stay; "+
				"its backup record is kept and the cleanup retried once the file can be read\n", path)
		}
	}
	recordScope := scope
	if scope == nil && kiroManaged(opts) {
		// The managed teardown is unchanged: it reclaims a recorded workspace
		// hook file whole, as it always has, and no recorded agent (a
		// managed install never writes the user's agents).
		recorded.agents = nil
	} else if scope == nil {
		recordScope, err = c.exactScope(opts, recorded)
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, path := range hooks {
		if !scope.covers(path) {
			continue
		}
		if err := c.reclaimKiroHookFile(opts, path, command, scope); err != nil {
			errs = append(errs, err)
		}
	}
	for _, path := range recorded.hooks {
		if !recordScope.covers(path) {
			continue
		}
		if err := c.reclaimKiroHookFile(opts, path, command, recordScope); err != nil {
			errs = append(errs, err)
		}
	}
	written := map[string]bool{}
	for _, path := range c.agentConfigPaths(opts) {
		written[path] = true
	}
	for _, path := range agents {
		if !scope.covers(path) {
			continue
		}
		if !written[path] {
			// A managed install never writes the user's default agent; only
			// remove DefenseClaw hooks an earlier build left there, and
			// otherwise leave the file byte for byte.
			if present, err := kiroV2AgentReferencesAnyHook(path, command); err != nil || !present {
				if err != nil {
					errs = append(errs, kiroPathError("kiro inspect agent", path, err))
				}
				continue
			}
		}
		if err := c.reclaimKiroAgentFile(opts, path, command, scope); err != nil {
			errs = append(errs, err)
		}
	}
	if scope == nil && !kiroManaged(opts) {
		// The user's own default agents (the one the settings name, the one
		// the settings backup names) are not files Setup writes. The pass
		// above takes the exact and edited entries out of them; this install's
		// own hook script in an older command form stays unless the exact
		// scope removes it, and VerifyClean (exactScope) counts it as this
		// install's, so the teardown failed on it (rel-1-0-10 GAP-1548).
		var userAgents []string
		for _, path := range agents {
			// A file Kiro cannot parse was named by the pass above
			// (kiro inspect agent): reading it again would name it twice
			// (rel-1-0-10 GAP-1745).
			if !written[path] && !kiroFileUnparsable(path) {
				userAgents = append(userAgents, path)
			}
		}
		userScope, err := c.exactScope(opts, kiroRecordedFiles{agents: userAgents})
		if err != nil {
			errs = append(errs, err)
		}
		for _, path := range userAgents {
			if !userScope.covers(path) {
				continue
			}
			if err := c.reclaimKiroAgentFile(opts, path, command, userScope); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, path := range recorded.agents {
		// The scope holds only the files with one of this install's exact
		// commands, so a covered agent has DefenseClaw hooks to remove.
		if !recordScope.covers(path) {
			continue
		}
		if err := c.reclaimKiroAgentFile(opts, path, command, recordScope); err != nil {
			errs = append(errs, err)
		}
	}
	if scope.covers(kiroBuiltInDefaultAgentPath()) {
		if err := removeStaleKiroDefaultOverlay(command, scope); err != nil {
			errs = append(errs, fmt.Errorf("kiro remove stale kiro_default overlay: %w", err))
		}
	}
	// The settings file is the user's: only DefenseClaw's default-agent
	// setting comes out, never a whole earlier copy, which would drop the
	// keys added since Setup captured it. A reclaim takes it out only with
	// this install's defenseclaw agent: the setting selects that agent, which
	// may now be another install's.
	if scope.covers(kiroManagedAgentPath()) {
		settingsPath := kiroSettingsPath()
		backup, err := loadManagedFileBackupForTransform(opts.DataDir, c.Name(), kiroSettingsLogicalName, settingsPath)
		if err == nil {
			err = removeKiroDefaultAgentSetting(settingsPath, backup)
		}
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("kiro remove default agent setting: %w", err))
		} else if err := dropManagedFileBackup(opts.DataDir, c.Name(), kiroSettingsLogicalName); err != nil {
			errs = append(errs, fmt.Errorf("kiro drop the settings backup record: %w", err))
		}
	}
	if err := writeDisabledHookTombstone(opts, kiroHookScriptName, c.Name()); err != nil {
		errs = append(errs, fmt.Errorf("kiro disabled hook tombstone: %w", err))
	}
	if strings.TrimSpace(opts.DataDir) != "" {
		removeCreatedDirs(filepath.Join(opts.DataDir, kiroCreatedDirsFile), filepath.Dir(kiroHomeDir()))
	}
	if err := errors.Join(errs...); err != nil {
		// The records of what was not cleaned stay, the token is not
		// revoked, and VerifyClean reports both, so the teardown is retried
		// (kiroUnfinishedTeardown).
		return err
	}
	if opts.ManagedEnterprise || strings.TrimSpace(opts.DataDir) == "" {
		// The hook guardian owns a managed install's records and credential.
		return nil
	}
	if scope != nil {
		// Another install's entries may stay: what must be gone is this
		// install's own, in every file the reclaim set out to clean.
		left, err := scope.remaining()
		if err != nil {
			return fmt.Errorf("kiro verify clean before token revocation: %w", err)
		}
		if len(left) != 0 {
			return fmt.Errorf("kiro verify clean before token revocation: this install's hooks remain in %v", left)
		}
	} else if err := c.verifyHooksClean(opts); err != nil {
		return fmt.Errorf("kiro verify clean before token revocation: %w", err)
	}
	// None of this install's entries is left, so none of its Kiro records is
	// needed any more. A record that stayed (a file no step cleaned: one the
	// user deleted or edited, another install's, the settings file without
	// the proven agent) kept this data folder an owner of the account's
	// Windows launcher commands (kiroDataDirSetUpKiro), and its next reclaim
	// then stripped the identical entries of an install that set Kiro up
	// later. The records go before the token: a record kept for a failed
	// revocation would keep that ownership until the retry, and the retry
	// does not need it, because a disabled hook script beside a token still
	// on disk flags the teardown unfinished (kiroUnfinishedTeardown).
	if err := c.discardKiroBackupRecords(opts.DataDir); err != nil {
		return fmt.Errorf("kiro drop the backup records of this install: %w", err)
	}
	return revokePerUserHookAPIToken(opts, c.Name())
}

// kiroRecordedFiles are the hook and agent files only this install's Kiro
// backup records name (KiroConnector.recordedKiroFiles).
type kiroRecordedFiles struct {
	hooks, agents []string
	// unreadable are the ones that cannot be read as a JSON object
	// (kiroFileUnparsable): no entry in them is proven, and their records
	// stay (discardKiroBackupRecords).
	unreadable []string
}

// kiroUnreadableRecordedFiles reports the files only this install's records
// name that cannot be read as a JSON object: their DefenseClaw hooks, if
// any, stay until they parse. The message does not say "teardown
// incomplete", the boot reclaim's trigger: such a file proves nothing, and a
// reclaim started on it would fail on every boot.
func kiroUnreadableRecordedFiles(recorded kiroRecordedFiles) error {
	if len(recorded.unreadable) == 0 {
		return nil
	}
	return fmt.Errorf("kiro cleanup incomplete: %s, which a backup record of this install names, is not a JSON object, "+
		"so its DefenseClaw hooks, if any, stay; fix or remove the file and run the removal again (its record is kept for that)",
		strings.Join(recorded.unreadable, ", "))
}

// recordedKiroFiles lists the v3 hook files and CLI 2.x agent files this
// install's backup records name that are not in currentHooks or
// currentAgents.
func (c *KiroConnector) recordedKiroFiles(opts SetupOpts, currentHooks, currentAgents []string) kiroRecordedFiles {
	var out kiroRecordedFiles
	for _, path := range c.staleRecordedKiroHookPaths(opts, currentHooks) {
		if kiroFileUnparsable(path) {
			out.unreadable = append(out.unreadable, path)
		} else {
			out.hooks = append(out.hooks, path)
		}
	}
	for _, path := range c.staleRecordedKiroAgentPaths(opts, currentAgents) {
		if kiroFileUnparsable(path) {
			out.unreadable = append(out.unreadable, path)
		} else {
			out.agents = append(out.agents, path)
		}
	}
	return out
}

// exactScope is the reclaim scope, for the teardown of a configured
// connector, of the files only this install's records name: those that hold
// an entry of this install, and in them only those entries. An entry is this
// install's when it runs one of its exact commands or, on POSIX, its own hook
// script in a command form an earlier build or an edit left
// (kiroCommandRunsScript): such a file held only that form and was skipped
// while its record was dropped (rel-1-0-10 GAP-1297). Windows commands run
// the account's launcher and stay exact.
func (c *KiroConnector) exactScope(opts SetupOpts, recorded kiroRecordedFiles) (*kiroReclaimScope, error) {
	scope := &kiroReclaimScope{files: map[string]bool{}, commands: c.installHookCommands(opts)}
	if len(scope.commands) == 0 {
		return scope, nil
	}
	if runtime.GOOS != "windows" {
		scope.script = filepath.Join(opts.DataDir, "hooks", kiroHookScriptName)
	}
	var errs []error
	for _, path := range slices.Concat(recorded.hooks, recorded.agents) {
		if held, err := scope.holds(path); err != nil {
			errs = append(errs, kiroPathError("kiro inspect", path, err))
		} else if held {
			scope.files[filepath.Clean(path)] = true
		}
	}
	return scope, errors.Join(errs...)
}

// reclaimScope is the part of the Kiro footprint the teardown of an
// unconfigured connector may touch (SetupOpts.ReclaimOwnHooksOnly): the
// files that hold one of this install's exact commands (orphanedHookFiles,
// which also reads the files only this install's backup records name), and
// in them only those entries. The hook files and agents under ~/.kiro are
// shared by every data folder of the account: a data folder that set Kiro up
// for a workspace, while another install later took over the global files,
// proved ownership by its workspace file, then had its teardown strip the
// other install's live global hooks by name (review P2 of GAP-1092). nil, for
// the teardown of a configured connector, is the whole footprint.
func (c *KiroConnector) reclaimScope(opts SetupOpts) (*kiroReclaimScope, error) {
	if !opts.ReclaimOwnHooksOnly {
		return nil, nil
	}
	files, err := c.orphanedHookFiles(opts)
	if err != nil {
		return nil, fmt.Errorf("kiro find the files that hold this install's hooks: %w", err)
	}
	scope := &kiroReclaimScope{files: map[string]bool{}, commands: c.installHookCommands(opts)}
	for _, path := range files {
		scope.files[filepath.Clean(path)] = true
	}
	return scope, nil
}

// discardKiroBackupRecords drops this install's Kiro backup records once
// none of its entries is left. A record whose file cannot be read as JSON
// stays (kiroRecordedFiles.unreadable), so the cleanup of that file is retried
// once it can be read; until then it proves nothing (kiroPendingRecords). A
// record that cannot be removed is an error.
func (c *KiroConnector) discardKiroBackupRecords(dataDir string) error {
	var errs []error
	for _, b := range kiroPendingRecords(dataDir) {
		if err := dropManagedFileBackup(dataDir, b.Connector, b.LogicalName); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// kiroBackupRecords lists the Kiro backup records in dataDir.
func kiroBackupRecords(dataDir string) []managedFileBackup {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	var records []managedFileBackup
	_ = forEachManagedFileBackup(dataDir, func(b managedFileBackup) error {
		if strings.EqualFold(b.Connector, "kiro") {
			records = append(records, b)
		}
		return nil
	})
	return records
}

// kiroPendingRecords are the Kiro backup records in dataDir that a finished
// teardown drops: all of them but a record of a file that cannot be read as a
// JSON object (kiroFileUnparsable). Such a record is kept for a retry and
// proves nothing until the file can be read: counted, it kept the data folder
// an owner of the account's Windows launcher commands for good.
func kiroPendingRecords(dataDir string) []managedFileBackup {
	var pending []managedFileBackup
	for _, b := range kiroBackupRecords(dataDir) {
		if !kiroFileUnparsable(b.Path) {
			pending = append(pending, b)
		}
	}
	return pending
}

// kiroUnfinishedTeardown reports what an unfinished teardown of a per-user
// install left in its data folder, which flags it for a retry (the boot
// reclaim, InstallOwnsHookEntries): a Kiro backup record it did not drop
// (kiroPendingRecords), or, beside the disabled hook script the teardown
// writes, the Kiro hook token it did not revoke. A data folder that never set
// Kiro up has neither, so this reads only.
func (c *KiroConnector) kiroUnfinishedTeardown(opts SetupOpts) error {
	if kiroManaged(opts) || strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	if pending := kiroPendingRecords(opts.DataDir); len(pending) != 0 {
		return fmt.Errorf("kiro teardown incomplete: %d Kiro backup records of this install remain in %s",
			len(pending), filepath.Dir(managedFileBackupPath(opts.DataDir, c.Name(), kiroSettingsLogicalName)))
	}
	if kiroDisabledHookScript(filepath.Join(opts.DataDir, "hooks", kiroHookScriptName)) {
		// It also refuses the token on the hook route until it is gone.
		if err := HookAPITokenRevocationPending(opts, c.Name()); err != nil {
			return fmt.Errorf("kiro teardown incomplete: %w", err)
		}
	}
	return nil
}

// kiroCreatedDirsFile, in the DefenseClaw data directory, lists the Kiro
// folders Setup created in a home that never ran Kiro (the guardian enrolls
// every user with kiro-cli on PATH), so teardown removes them while empty.
const kiroCreatedDirsFile = "kiro-created-dirs.json"

func kiroScaffoldDirs() []string {
	home := kiroHomeDir()
	return []string{home, filepath.Join(home, "agents"), filepath.Join(home, "hooks"), filepath.Join(home, "settings")}
}

func missingKiroScaffoldDirs() []string {
	var missing []string
	for _, dir := range kiroScaffoldDirs() {
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			missing = append(missing, dir)
		}
	}
	return missing
}

// RecordHookConfigParentDirs records the hook config folders an installer
// created for the named connector before its Setup ran, so they are removed
// while they are still empty: by the purge and a per-user uninstall --all
// (the data directory's created-folder list), and for Kiro also by its
// teardown (its own list). It is best effort.
func RecordHookConfigParentDirs(name, dataDir string, dirs []string) {
	if strings.TrimSpace(dataDir) == "" || len(dirs) == 0 {
		return
	}
	// Every connector's go in the data directory's created-folder list,
	// which the purge and a per-user uninstall --all clear.
	_ = RecordWatcherCreatedDirs(dataDir, dirs)
	if name != "kiro" {
		return
	}
	_ = recordCreatedDirs(filepath.Join(dataDir, kiroCreatedDirsFile), dirs)
}

// recordKiroCreatedDirs records the folders of missing that Setup created.
// It is best effort: an unrecorded folder only stays behind after teardown.
func recordKiroCreatedDirs(opts SetupOpts, missing []string) {
	if strings.TrimSpace(opts.DataDir) == "" {
		return
	}
	var created []string
	for _, dir := range missing {
		if info, err := os.Lstat(dir); err == nil && info.IsDir() {
			created = append(created, dir)
		}
	}
	if len(created) > 0 {
		_ = recordCreatedDirs(filepath.Join(opts.DataDir, kiroCreatedDirsFile), created)
	}
}

// VerifyClean reports DefenseClaw Kiro hooks left in the files the settings
// name (verifyHooksClean), this install's entries left in a file only its
// backup records name, what an unfinished teardown left in the data folder
// (kiroUnfinishedTeardown), and, for `connector verify`
// (SetupOpts.ReportUnreadableResidue), a file only its records name that
// cannot be read as JSON (kiroUnreadableRecordedFiles), which `connector
// teardown` fails on. The boot teardowns log that file and go on (GAP-1304).
func (c *KiroConnector) VerifyClean(opts SetupOpts) error {
	if err := c.verifyHooksClean(opts); err != nil {
		return err
	}
	if err := c.kiroUnfinishedTeardown(opts); err != nil {
		return err
	}
	if kiroManaged(opts) || !opts.ReportUnreadableResidue {
		return nil
	}
	hooks := c.hookCleanupPaths(opts)
	agents := append(c.agentCleanupPaths(opts), kiroBuiltInDefaultAgentPath())
	return kiroUnreadableRecordedFiles(c.recordedKiroFiles(opts, hooks, agents))
}

// verifyHooksClean is VerifyClean without kiroUnfinishedTeardown: the check
// a teardown makes before it drops the records and revokes the token.
func (c *KiroConnector) verifyHooksClean(opts SetupOpts) error {
	command := c.hookCommand(opts)
	hooks := c.hookCleanupPaths(opts)
	for _, path := range hooks {
		if present, err := kiroV3FileReferencesHook(path, command); err != nil {
			return err
		} else if present {
			return fmt.Errorf("kiro teardown incomplete: hook config still references %s", path)
		}
	}
	agents := append(c.agentCleanupPaths(opts), kiroBuiltInDefaultAgentPath())
	for _, path := range agents {
		if present, err := kiroV2AgentReferencesAnyHook(path, command); err != nil {
			return err
		} else if present {
			return fmt.Errorf("kiro teardown incomplete: agent config still references %s", path)
		}
	}
	if present, err := kiroSettingsSelectsManagedAgent(kiroSettingsPath()); err != nil {
		return err
	} else if present {
		return fmt.Errorf("kiro teardown incomplete: %s still selects %s", kiroDefaultAgentSettingKey, kiroManagedAgentName)
	}
	// A file only a record names holds only this install's entries as proof
	// (exactScope): another install's entries there are named defenseclaw-*
	// too. The settings record is read above (agentCleanupPaths names the
	// agent it recorded as the default). A file that cannot be read as JSON
	// proves nothing here (kiroRecordedFiles.unreadable); VerifyClean reports
	// it.
	scope, err := c.exactScope(opts, c.recordedKiroFiles(opts, hooks, agents))
	if err != nil {
		return err
	}
	if left := slices.Sorted(maps.Keys(scope.files)); len(left) != 0 {
		return fmt.Errorf("kiro teardown incomplete: %s, which only a backup record of this install names, still holds its hooks", left[0])
	}
	return nil
}

// orphanedHookFiles are the Kiro files that still hold a DefenseClaw hook
// entry, read as the decoded entries Setup writes rather than as raw bytes: a
// Windows command is an -EncodedCommand wrapper that holds no plain
// "hook --connector kiro", so the raw match of OrphanedHookConfigPaths reported
// an unconfigured connector "already absent" with its hook file still there
// (rel-1-0-10 GAP-1092, GAP-1174).
func (c *KiroConnector) orphanedHookFiles(opts SetupOpts) ([]string, error) {
	return c.orphanedHookFilesFor(runtime.GOOS, opts)
}

// orphanedHookFilesFor is orphanedHookFiles for the commands Setup writes on
// goos (installHookCommandsFor), so the Windows rule is tested on every host.
// Besides the files the current settings name it reads the ones only this
// install's backup records still name: a workspace hook file Setup wrote
// before claw.workspace_dir changed (RHEL-U3-09), a custom default agent the
// user has since switched away from. Their entries are this install's too,
// and the reclaim that drops the records must remove them first.
func (c *KiroConnector) orphanedHookFilesFor(goos string, opts SetupOpts) ([]string, error) {
	commands := c.installHookCommandsFor(goos, opts)
	if len(commands) == 0 {
		return nil, nil
	}
	var found []string
	hooks := c.hookCleanupPaths(opts)
	agents := append(c.agentCleanupPaths(opts), kiroBuiltInDefaultAgentPath())
	// A recorded file that cannot be read as JSON is skipped, not an error: it
	// failed the whole reclaim and prune on every boot (`connector teardown`
	// fails on it and `connector verify` reports it,
	// kiroUnreadableRecordedFiles).
	recorded := c.recordedKiroFiles(opts, hooks, agents)
	for _, path := range slices.Concat(hooks, recorded.hooks) {
		if present, err := kiroV3FileHoldsCommand(path, commands); err != nil {
			return nil, err
		} else if present {
			found = append(found, path)
		}
	}
	for _, path := range slices.Concat(agents, recorded.agents) {
		if present, err := kiroAgentFileHoldsCommand(path, commands); err != nil {
			return nil, err
		} else if present {
			found = append(found, path)
		}
	}
	return uniqueNonEmptyStrings(found), nil
}

// installHookCommands are the exact commands this install's per-user Setup
// writes into Kiro's files, in the forms an earlier release wrote them. The
// hook files under ~/.kiro are shared by every DefenseClaw data folder of the
// account, so a file that merely holds an entry named defenseclaw-* may be
// another install's: ownership is the decoded action.command being one of
// these, and the reclaim of an unconfigured connector removes only entries
// that run one of them (reclaimScope). A managed install's footprint belongs
// to the hook guardian, so no command is owned there.
func (c *KiroConnector) installHookCommands(opts SetupOpts) []string {
	return c.installHookCommandsFor(runtime.GOOS, opts)
}

// installHookCommandsFor is installHookCommands on goos. A POSIX command runs
// the hook script under opts.DataDir, so it names this data folder by itself
// and is owned with no other proof (a rollback's data swap drops the script,
// GAP-1092). A Windows command runs the account's launcher and is the same
// for every data folder of the account: alone it took the live hooks of the
// install that guards Kiro for those of another data folder that never set
// Kiro up (a second DEFENSECLAW_HOME, `connector prune-orphans --data-dir`),
// whose boot reclaim or prune then removed them and left Kiro unguarded
// (review P2 of GAP-1092). The Windows commands are this install's only when
// this data folder shows that its own Setup set Kiro up
// (kiroDataDirSetUpKiro), or, in the prune after a rollback's data swap, the
// saved folder of the newer install the rollback left does
// (SetupOpts.RollbackSavedDataDir): its hooks, which the rollback converted
// into a form these commands include, stayed in an install that never set
// Kiro up (rel-1-0-10 GAP-1221).
func (c *KiroConnector) installHookCommandsFor(goos string, opts SetupOpts) []string {
	if kiroManaged(opts) {
		return nil
	}
	if goos == "windows" {
		if !kiroDataDirSetUpKiro(opts.DataDir) && !kiroDataDirSetUpKiro(opts.RollbackSavedDataDir) {
			return nil
		}
		return kiroWindowsOwnedHookCommandsFor(false)
	}
	script := filepath.Join(opts.DataDir, "hooks", kiroHookScriptName)
	agent := kiroHookInvocationCommandFor(goos, script, "", false)
	v3 := kiroHookInvocationCommandFor(goos, script, KiroHookSurfaceV3, false)
	return uniqueNonEmptyStrings([]string{agent, posixHookCommandUnquoted(agent), v3, posixHookCommandUnquoted(v3)})
}

// kiroDataDirSetUpKiro reports whether dataDir shows that its own Setup set
// Kiro up and its teardown did not finish: the hook script Setup writes is in
// its hooks folder (not the disabled tombstone a teardown leaves there), or
// one of its Kiro backup records is (kiroPendingRecords). Every teardown, of
// a configured connector or a reclaim, drops all of them once none of this
// install's entries is left, so a torn-down data folder owns nothing
// afterwards.
func kiroDataDirSetUpKiro(dataDir string) bool {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return false
	}
	if kiroLiveHookScript(filepath.Join(dataDir, "hooks", kiroHookScriptName)) {
		return true
	}
	return len(kiroPendingRecords(dataDir)) != 0
}

// kiroDisabledHookScript reports whether path is the disabled tombstone a
// teardown writes (hookBodyIsDisabledTombstone).
func kiroDisabledHookScript(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<16 {
		return false
	}
	body, err := os.ReadFile(path)
	return err == nil && hookBodyIsDisabledTombstone(string(body))
}

// kiroLiveHookScript reports whether path is a regular file other than the
// disabled tombstone (hookBodyIsDisabledTombstone).
func kiroLiveHookScript(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if info.Size() > 1<<16 {
		return true
	}
	body, err := os.ReadFile(path)
	return err == nil && !hookBodyIsDisabledTombstone(string(body))
}

// InstallOwnsHookEntries reports whether a Kiro file still holds a hook entry
// whose command is one this install wrote (installHookCommands), or this data
// folder holds an unfinished teardown (kiroUnfinishedTeardown). The boot
// reclaim of an unguarded connector uses it as the proof of ownership. Its
// reclaim touches only the files with this install's exact entries, so one
// that finishes a teardown with none left changes only this data folder: it
// drops the records and revokes the token.
func (c *KiroConnector) InstallOwnsHookEntries(opts SetupOpts) (bool, error) {
	files, err := c.orphanedHookFiles(opts)
	if err != nil {
		return false, err
	}
	return len(files) > 0 || c.kiroUnfinishedTeardown(opts) != nil, nil
}

// reclaimKiroHookFile puts one v3 hook file back as Setup found it when it is
// unchanged since, and otherwise removes only DefenseClaw's entries; either
// way its backup record is settled.
func (c *KiroConnector) reclaimKiroHookFile(opts SetupOpts, path, command string, scope *kiroReclaimScope) error {
	logical := kiroBackupLogicalName(path)
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), logical, path)
	if err != nil {
		return kiroPathError("kiro restore hook", path, err)
	}
	if !restored {
		operatorFile := kiroPristineIsOperators(opts.DataDir, c.Name(), logical, command)
		if err := removeKiroV3HooksKeeping(path, command, operatorFile, scope); err != nil && !os.IsNotExist(err) {
			return kiroPathError("kiro remove hook", path, err)
		}
		if err := keepPristineEmptyHooks(opts.DataDir, c.Name(), logical, path); err != nil {
			return kiroPathError("kiro keep the empty hooks of", path, err)
		}
	} else if present, err := kiroV3FileReferencesHook(path, command); err != nil {
		return kiroPathError("kiro inspect restored hook", path, err)
	} else if present {
		// A backup captured while the account still held an earlier
		// enrollment's hooks (whose own backup is gone) put DefenseClaw's
		// entries back; they go too (GAP-1932).
		if err := removeKiroV3HooksKeeping(path, command, false, scope); err != nil && !os.IsNotExist(err) {
			return kiroPathError("kiro remove hook", path, err)
		}
	}
	dropErr := dropManagedFileBackup(opts.DataDir, c.Name(), logical)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		removeKiroFileResidue(path, command, false, scope)
	}
	if dropErr != nil {
		return fmt.Errorf("kiro drop the backup record of %s: %w", path, dropErr)
	}
	return nil
}

// kiroPristineIsOperators reports whether the copy Setup captured of a Kiro
// file shows the operator's own file: it existed and held none of
// DefenseClaw's hooks. A surgical teardown (the file changed since Setup,
// even only reformatted) keeps such a file when DefenseClaw's entries were
// all it held. A copy that already held DefenseClaw's hooks (an earlier
// enrollment whose own backup is gone, GAP-1932) shows no operator file.
func kiroPristineIsOperators(dataDir, connectorName, logical, command string) bool {
	b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connectorName, logical))
	if err != nil || !b.Existed {
		return false
	}
	if len(bytes.TrimSpace(b.PristineBytes)) == 0 {
		return true
	}
	var cfg map[string]interface{}
	if json.Unmarshal(b.PristineBytes, &cfg) != nil {
		return false
	}
	if containsHookScript(cfg, kiroOwnedHookCommands(command)...) {
		return false
	}
	hooks, _ := cfg["hooks"].([]interface{})
	for _, item := range hooks {
		if kiroOwnedV3Hook(item, command) {
			return false
		}
	}
	return true
}

// reclaimKiroAgentFile is reclaimKiroHookFile for a CLI 2.x agent file.
func (c *KiroConnector) reclaimKiroAgentFile(opts SetupOpts, path, command string, scope *kiroReclaimScope) error {
	logical := kiroAgentBackupLogicalName(path)
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), logical, path)
	if err != nil {
		return kiroPathError("kiro restore agent", path, err)
	}
	if !restored {
		operatorFile := kiroPristineIsOperators(opts.DataDir, c.Name(), logical, command)
		if err := removeKiroV2AgentHooksKeeping(path, command, operatorFile, scope); err != nil && !os.IsNotExist(err) {
			return kiroPathError("kiro remove agent hooks", path, err)
		}
		if err := keepPristineEmptyHooks(opts.DataDir, c.Name(), logical, path); err != nil {
			return kiroPathError("kiro keep the empty hooks of", path, err)
		}
	} else if present, err := kiroV2AgentReferencesAnyHook(path, command); err != nil {
		return kiroPathError("kiro inspect restored agent", path, err)
	} else if present {
		// The restored agent came from a backup that already held
		// DefenseClaw's hooks (GAP-1932).
		if err := removeKiroV2AgentHooksKeeping(path, command, false, scope); err != nil && !os.IsNotExist(err) {
			return kiroPathError("kiro remove agent hooks", path, err)
		}
	}
	dropErr := dropManagedFileBackup(opts.DataDir, c.Name(), logical)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		removeKiroFileResidue(path, command, true, scope)
	}
	if dropErr != nil {
		return fmt.Errorf("kiro drop the backup record of %s: %w", path, dropErr)
	}
	return nil
}

// reclaimEarlierKiroFootprint removes what an earlier per-user footprint
// wrote that the managed footprint does not: DefenseClaw's hooks in the
// user's own default agent, and the workspace copy of the v3 hook file.
// Managed Setup then makes the defenseclaw agent the default, after which
// teardown could no longer tell which agent the earlier build hooked; and a
// workspace copy under the machine-wide workspace directory is shared by
// every enrolled user. A file that holds no DefenseClaw entry is left byte
// for byte; one Kiro cannot parse runs no hooks and is left for teardown
// and VerifyClean to report.
func (c *KiroConnector) reclaimEarlierKiroFootprint(opts SetupOpts, command string) error {
	var errs []error
	written := map[string]bool{}
	for _, path := range c.agentConfigPaths(opts) {
		written[filepath.Clean(path)] = true
	}
	for _, path := range kiroEarlierDefaultAgentPaths(opts.DataDir) {
		if written[filepath.Clean(path)] {
			continue
		}
		if present, err := kiroV2AgentReferencesAnyHook(path, command); err != nil || !present {
			continue
		}
		if err := c.reclaimKiroAgentFile(opts, path, command, nil); err != nil {
			errs = append(errs, err)
		}
	}
	configured := map[string]bool{}
	for _, path := range c.hookConfigPaths(opts) {
		configured[filepath.Clean(path)] = true
	}
	for _, path := range c.hookCleanupPaths(opts) {
		if configured[filepath.Clean(path)] {
			continue
		}
		if present, err := kiroV3FileReferencesHook(path, command); err != nil || !present {
			continue
		}
		if err := c.reclaimKiroHookFile(opts, path, command, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *KiroConnector) Authenticate(r *http.Request) bool {
	return authenticateHookBridgeRequest(r, c.gatewayToken, c.Name(),
		"Kiro hook and ACP traffic is authenticated by the scoped connector token", &c.loopbackWarn)
}

func (c *KiroConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{RawBody: body, RawModel: ParseModelFromBody(body), Stream: ParseStreamFromBody(body), PassthroughMode: true, ConnectorName: c.Name()}, nil
}

func (c *KiroConnector) SetCredentials(gatewayToken string) {
	c.gatewayToken = gatewayToken
}

func (c *KiroConnector) Capabilities(opts SetupOpts) ConnectorCapabilities {
	unsupported := unsupportedSurface("Kiro native hooks do not mutate this asset surface.")
	return ConnectorCapabilities{
		LLMTrafficMode: LLMTrafficModeHooksOnly,
		Hooks:          c.HookCapabilities(opts),
		MCP:            unsupported, Skills: unsupported, Rules: unsupported, Plugins: unsupported, Agents: unsupported,
		CodeGuard: CodeGuardCapability{OptInOnly: true, Idempotent: true, ConflictSafe: true},
		Telemetry: TelemetryCapability{HookSignals: []string{"logs", "metrics", "traces"}, AuthMode: "scoped-header-token-loopback", SourceModes: []string{"hooks", "acp"}},
		ACP:       ACPAgentCapabilityForConnector("kiro"),
	}
}

func (c *KiroConnector) HookCapabilities(opts SetupOpts) HookCapability {
	// Kiro merges hooks from every scope, and its global scope is
	// ~/.kiro/hooks/ (kiro.dev/docs/configuration: "Hooks: All scopes
	// merged"), read by Kiro IDE 1.0.182 and later and by kiro-cli --v3.
	// The managed (standalone enterprise) footprint writes only that global
	// file, so it claims the user scope. A per-user install still reports
	// the workspace scope it has always reported; correcting that for older
	// IDE builds, which read only the project's .kiro/hooks, is a separate
	// per-user change.
	scope := "workspace"
	if kiroManaged(opts) {
		scope = "user"
	}
	return HookCapability{
		CanBlock:           true,
		SupportsFailClosed: true,
		Scope:              scope,
		ConfigPath:         kiroHooksPath(opts),
		// The declared surface is what the v3 hook config honors. Requests
		// arriving from the CLI 2.x agent-hook config are narrowed
		// per-request by KiroBlockEventsForSurface, because the two configs
		// are indistinguishable by release version.
		BlockEvents: KiroBlockEventsForSurface(KiroHookSurfaceV3),
	}
}

// Kiro hook surfaces. DefenseClaw installs two hook configs and each one is
// read by a different Kiro surface with a different veto contract:
//
//	KiroHookSurfaceV3  .kiro/hooks/*.json, read by Kiro IDE and `kiro-cli --v3`
//	KiroHookSurfaceV2  ~/.kiro/agents/<agent>.json, read by bare `kiro-cli`
//
// The marker travels on the installed hook command so each request states
// which config invoked it. It is NOT derivable from the release: v3 ships as
// a flag on the 2.x binary ("Try it out with: kiro-cli --v3. V3 runs
// alongside your existing 2.x install" -- kiro.dev/docs/cli/v3), so
// `kiro-cli --version` reports 2.x for both surfaces and a version
// comparison can never answer the question. An earlier build compared
// against 3.0.0 and therefore disabled prompt blocking for every user on
// the latest CLI, with no future release that would re-enable it.
const (
	KiroHookSurfaceV2 = "v2"
	KiroHookSurfaceV3 = "v3"
)

// HookDialectHeader is the generic header in which the native hook binary
// forwards its --hook-surface value; KiroSurfaceHeader is the one kiro-hook.sh
// sends. The gateway reads both for Kiro.
const (
	HookDialectHeader = hookexec.HookDialectHeader
	KiroSurfaceHeader = "X-DefenseClaw-Kiro-Surface"
)

// KiroBlockEventsForSurface returns the events the named surface honors as a
// veto, so action mode blocks everywhere Kiro will act on it and nowhere it
// will not.
//
//   - v3 / IDE: "Exit code 2: Block execution (PreToolUse, UserPromptSubmit,
//     PreTaskExec only)" (kiro.dev/docs/hooks/actions). DefenseClaw installs
//     no PreTaskExecution hook, so it claims the two it installs.
//     kiro-cli 2.24.1 --v3 does not apply the UserPromptSubmit veto: it
//     attaches the hook's result to the prompt and calls the model. A
//     request cannot tell it from Kiro IDE, so the block is still reported.
//   - CLI 2.x: "Exit code 2: (preToolUse only) Block tool execution" and
//     "Other exit codes: Hook failed. STDERR is shown as a warning"
//     (kiro.dev/docs/cli/2x-reference). Its trigger table lists
//     userPromptSubmit as "Not evaluated".
//
// An unset or unrecognized marker resolves to the 2.x set. That is the
// conservative direction: a hook config written by an older DefenseClaw
// carries no marker, and reporting a block Kiro silently ignores is worse
// than reporting a would-block it honors. Re-running setup adds the marker.
func KiroBlockEventsForSurface(surface string) []string {
	if strings.EqualFold(strings.TrimSpace(surface), KiroHookSurfaceV3) {
		return []string{"UserPromptSubmit", "PreToolUse"}
	}
	return []string{"PreToolUse"}
}

func (c *KiroConnector) HookProfile(opts SetupOpts) HookProfile {
	return ApplyHookContract(HookProfile{
		Name:                c.Name(),
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: true,
		MapVerdict:          hookOnlyProfileMapVerdict,
		Respond:             hookOnlyProfileRespond,
	}, opts)
}

func (c *KiroConnector) AgentPaths(opts SetupOpts) AgentPaths {
	patched := append([]string(nil), c.hookConfigPaths(opts)...)
	patched = append(patched, c.agentConfigPaths(opts)...)
	patched = append(patched, kiroSettingsPath())
	backups := []string{managedFileBackupPath(opts.DataDir, c.Name(), kiroSettingsLogicalName)}
	for _, path := range c.hookConfigPaths(opts) {
		backups = append(backups, managedFileBackupPath(opts.DataDir, c.Name(), kiroBackupLogicalName(path)))
	}
	for _, path := range c.agentConfigPaths(opts) {
		backups = append(backups, managedFileBackupPath(opts.DataDir, c.Name(), kiroAgentBackupLogicalName(path)))
	}
	return AgentPaths{
		PatchedFiles: uniqueNonEmptyStrings(patched),
		BackupFiles:  uniqueNonEmptyStrings(backups),
		HookScripts:  hookScriptPathsForConnector(opts, c),
	}
}

func (c *KiroConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

func (c *KiroConnector) hookCommand(opts SetupOpts) string {
	return kiroHookInvocationCommandFor(runtime.GOOS, filepath.Join(opts.DataDir, "hooks", kiroHookScriptName), "", kiroManaged(opts))
}

// kiroHookInvocationCommandFor renders one Kiro hook command. surface marks
// the .kiro/hooks configuration (KiroHookSurfaceV3); the CLI 2.x agent
// configuration is unmarked. On Windows, managed adds --enterprise-managed,
// as every managed Windows hook command does.
//
// On Windows both commands start cmd.exe, which runs the system Windows
// PowerShell with an encoded script that starts the GUI-subsystem launcher,
// waits for it and exits with its status. Exit 2 (Kiro's only block) reaches
// Kiro whether Kiro runs the command through `pwsh -Command` or
// `powershell -Command` (what Kiro CLI 2.24 does), through cmd.exe (Node's
// shell: true, `cmd /C`) or directly (windowsKiroHookCommandForBinary). The
// earlier `& '<launcher>' ...` form failed under cmd.exe ("& was unexpected
// at this time", exit 1) and, under PowerShell, returned before the GUI
// launcher finished; either way Kiro proceeded.
func kiroHookInvocationCommandFor(goos, unixCommand, surface string, managed bool) string {
	if goos != "windows" {
		unixCommand = posixHookCommandWord(unixCommand)
		if surface != "" {
			return unixCommand + " --hook-surface " + surface
		}
		return unixCommand
	}
	return windowsKiroHookCommandForBinary(defenseclawHookBinary(), surface, managed)
}

// windowsKiroHookCommandForBinary renders the Windows Kiro command:
// `<system>\cmd.exe /d /c <bridge>`, a line feed, then `exit $LASTEXITCODE`.
// A PowerShell host (`pwsh -Command`, `powershell -Command`) reports any
// native exit status other than 0 as 1 unless the command itself exits with
// it, so a block came back as 1 and Kiro proceeded. The second line is that
// exit. cmd.exe stops reading a command line at the line feed, so cmd.exe
// never sees it: not when the host is cmd.exe (`cmd /d /s /c`, `cmd /C`) and
// not when the command line is started directly, where cmd.exe is the
// program. Starting cmd.exe rather than the bridge also keeps a direct start
// working, because powershell.exe refuses any argument after
// -EncodedCommand's value. /d skips cmd.exe AutoRun commands; the command has
// no quotes, percent signs or cmd.exe operators.
func windowsKiroHookCommandForBinary(hookBinary, surface string, managed bool) string {
	return windowsKiroHookCommandForBridge(windowsKiroPowerShellBridgeForBinary(hookBinary, surface, managed))
}

// preStartAnswerWindowsKiroHookCommand is the per-user Kiro command releases
// before 1.0.9 wrote: the bridge without the launcher-start answer. It stays
// owned, so setup rewrites it and teardown removes it.
func preStartAnswerWindowsKiroHookCommand(hookBinary, surface string) string {
	return windowsKiroHookCommandForBridge(windowsKiroPowerShellBridge(hookBinary, surface, false, nil))
}

func windowsKiroHookCommandForBridge(bridge string) string {
	return windowsSystemCmdExe() + " /d /c " + bridge + "\nexit $LASTEXITCODE"
}

// windowsKiroPowerShellBridgeForBinary renders the encoded system PowerShell
// bridge the Kiro command runs: the shared awaited-hook bridge
// (windowsAwaitedHookStatements), which starts the launcher with Process.Start
// and returns a fast-exiting launcher's block, with a Constrained Language
// mode fallback. Per-user, the bridge exits 2 with the guard sentence when
// the launcher cannot start (kiroLauncherStartAnswer, rel-1-0-6 GAP-0676);
// before, the start error ended the script with 1, which Kiro proceeds past.
// Managed Windows writes the bridge without that answer under the target
// user token with managed set; there hookBinary is the standalone
// defenseclaw-hook.exe and the arguments add --enterprise-managed.
func windowsKiroPowerShellBridgeForBinary(hookBinary, surface string, managed bool) string {
	var answer *launcherStartAnswer
	if !managed {
		answer = kiroLauncherStartAnswer()
	}
	return windowsKiroPowerShellBridge(hookBinary, surface, managed, answer)
}

func windowsKiroPowerShellBridge(hookBinary, surface string, managed bool, answer *launcherStartAnswer) string {
	var extra []string
	if managed {
		extra = append(extra, "--enterprise-managed")
	}
	if surface != "" {
		extra = append(extra, "--hook-surface", surface)
	}
	return windowsAnsweringPowerShellHookCommand("kiro", "", "", hookBinary, answer, extra...)
}

// kiroWindowsOwnedHookCommands are the Windows Kiro commands DefenseClaw
// writes for every launcher it may have registered: the per-user and the
// managed command, for the v2 and v3 surfaces. Setup replaces and teardown
// removes them in the CLI 2.x agent files, whose entries are otherwise
// matched by exact command.
func kiroWindowsOwnedHookCommands() []string {
	return kiroWindowsOwnedHookCommandsFor(true)
}

// kiroWindowsOwnedHookCommandsFor is kiroWindowsOwnedHookCommands with, or
// without, the commands the administrator-managed footprint writes.
func kiroWindowsOwnedHookCommandsFor(includeManaged bool) []string {
	var commands []string
	managedForms := []bool{false}
	if includeManaged {
		managedForms = append(managedForms, true)
	}
	for _, binary := range nativeHookBinaryOwnershipCandidates() {
		for _, managed := range managedForms {
			forms := []string{
				windowsKiroHookCommandForBinary(binary, "", managed),
				windowsKiroHookCommandForBinary(binary, KiroHookSurfaceV3, managed),
			}
			if !managed {
				forms = append(forms,
					preStartAnswerWindowsKiroHookCommand(binary, ""),
					preStartAnswerWindowsKiroHookCommand(binary, KiroHookSurfaceV3))
			}
			for _, command := range forms {
				// So does the pre-1.0.9 render of a profile path with a
				// typographic quote (g072 review 4 M1).
				commands = appendWithPreTypographicQuoteForm(commands, command)
				// The 1.0.x render of the bridge stays owned, so setup
				// rewrites it and teardown removes it.
				if legacy, ok := legacyWindowsAwaitedHookCommand(command); ok {
					commands = appendWithPreTypographicQuoteForm(commands, legacy)
				}
			}
		}
	}
	return uniqueNonEmptyStrings(commands)
}

// kiroOwnedHookCommands are the commands DefenseClaw recognizes as its own
// Kiro hook entries: hookScript plus, on Windows, every form in
// kiroWindowsOwnedHookCommands.
func kiroOwnedHookCommands(hookScript string) []string {
	commands := []string{hookScript}
	if runtime.GOOS == "windows" {
		commands = append(commands, kiroWindowsOwnedHookCommands()...)
	} else {
		// The unquoted form releases before GAP-0382 wrote.
		commands = append(commands, posixHookCommandUnquoted(hookScript))
	}
	return uniqueNonEmptyStrings(commands)
}

// hookCommandForV3Surface marks the .kiro/hooks command so the gateway can
// tell which config invoked the hook. Only the v3 config is marked: the CLI
// 2.x agent-hook entry is matched by exact command equality when setup
// reconciles or teardown removes it (managedHookCommandEntry), so appending
// an argument there would orphan DefenseClaw's own entry. An absent marker
// already resolves to the 2.x veto surface, which is what that config is.
func (c *KiroConnector) hookCommandForV3Surface(opts SetupOpts) string {
	return kiroHookInvocationCommandFor(runtime.GOOS, filepath.Join(opts.DataDir, "hooks", kiroHookScriptName), KiroHookSurfaceV3, kiroManaged(opts))
}

// kiroManaged reports whether opts render the administrator-managed Kiro
// footprint. Only the standalone enterprise guardian manages Kiro: the
// Secure Client profiles do not list it, so a managed Kiro install is a
// standalone one.
func kiroManaged(opts SetupOpts) bool {
	return opts.ManagedEnterprise
}

// hookConfigPaths are the v3 hook files Setup writes and verification
// requires. A managed install writes only the user's global
// ~/.kiro/hooks/defenseclaw.json, which Kiro merges into every workspace:
// a workspace copy under a machine-wide workspace directory would be shared
// by every enrolled user and is redundant with the global file.
func (c *KiroConnector) hookConfigPaths(opts SetupOpts) []string {
	paths := []string{kiroHooksPath(opts)}
	if kiroManaged(opts) {
		return paths
	}
	if workspace := kiroWorkspaceHooksPath(opts); workspace != "" && workspace != paths[0] {
		paths = append(paths, workspace)
	}
	return uniqueNonEmptyStrings(paths)
}

// hookCleanupPaths are the v3 hook files teardown reclaims: the files Setup
// writes plus, for a managed install, a workspace copy an earlier build
// wrote there (managed Setup reclaims that copy too).
func (c *KiroConnector) hookCleanupPaths(opts SetupOpts) []string {
	paths := c.hookConfigPaths(opts)
	if workspace := kiroWorkspaceHooksPath(opts); workspace != "" {
		paths = append(paths, workspace)
	}
	return uniqueNonEmptyStrings(paths)
}

// staleRecordedKiroHookPaths lists the v3 hook files a Kiro backup record
// names that are not in current. The records outlive the workspace setting,
// so a workspace copy is still found once claw.workspace_dir no longer names
// it (RHEL-U3-09).
func (c *KiroConnector) staleRecordedKiroHookPaths(opts SetupOpts, current []string) []string {
	return c.staleRecordedKiroPaths(opts, current, kiroV3HooksLogicalName+"-", kiroBackupLogicalName)
}

// staleRecordedKiroAgentPaths is staleRecordedKiroHookPaths for the CLI 2.x
// agent files Setup recorded (kiroAgentBackupLogicalName).
func (c *KiroConnector) staleRecordedKiroAgentPaths(opts SetupOpts, current []string) []string {
	return c.staleRecordedKiroPaths(opts, current, "agent-", kiroAgentBackupLogicalName)
}

// staleRecordedKiroPaths lists the files the Kiro backup records whose logical
// name starts with prefix, and is the one logical gives the file, name that
// are not in current.
func (c *KiroConnector) staleRecordedKiroPaths(opts SetupOpts, current []string, prefix string, logical func(string) string) []string {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	known := map[string]bool{}
	for _, path := range current {
		known[filepath.Clean(path)] = true
	}
	var stale []string
	for _, b := range kiroBackupRecords(opts.DataDir) {
		if !strings.HasPrefix(b.LogicalName, prefix) || b.LogicalName != logical(b.Path) || known[filepath.Clean(b.Path)] {
			continue
		}
		known[filepath.Clean(b.Path)] = true
		stale = append(stale, b.Path)
	}
	return stale
}

func kiroHooksPath(opts SetupOpts) string {
	if path := strings.TrimSpace(KiroHooksPathOverride); path != "" {
		return path
	}
	return filepath.Join(kiroHomeDir(), "hooks", kiroManagedHooksName)
}

func kiroWorkspaceHooksPath(opts SetupOpts) string {
	root := strings.TrimSpace(opts.WorkspaceDir)
	if root == "" || !workspaceRootOutsideDataDir(root, opts.DataDir) {
		return ""
	}
	return filepath.Join(root, ".kiro", "hooks", kiroManagedHooksName)
}

// agentConfigPaths are the CLI 2.x agent files Setup writes. A per-user
// install also adds DefenseClaw's hooks to the user's own default agent
// (chat.defaultAgent), which bare `kiro-cli` runs. A managed install never
// edits the user's agents: it writes only the defenseclaw agent and makes it
// the default (patchKiroDefaultAgentSetting), so bare `kiro-cli` runs a
// hooked agent; an agent the user picks explicitly runs without DefenseClaw's
// hooks (documented residual). The only change a managed Setup makes to a
// user's agent is removing hooks an earlier per-user footprint added there
// (reclaimEarlierKiroFootprint).
func (c *KiroConnector) agentConfigPaths(opts SetupOpts) []string {
	paths := []string{kiroManagedAgentPath()}
	if kiroManaged(opts) {
		return paths
	}
	if custom := kiroConfiguredDefaultAgentPath(); custom != "" && custom != paths[0] {
		paths = append(paths, custom)
	}
	return uniqueNonEmptyStrings(paths)
}

// agentCleanupPaths are the agent files teardown and VerifyClean check: the
// files Setup writes plus the user's default agents an earlier build may
// have added hooks to (kiroEarlierDefaultAgentPaths).
func (c *KiroConnector) agentCleanupPaths(opts SetupOpts) []string {
	paths := c.agentConfigPaths(opts)
	paths = append(paths, kiroEarlierDefaultAgentPaths(opts.DataDir)...)
	return uniqueNonEmptyStrings(paths)
}

// kiroEarlierDefaultAgentPaths are the user's own default agents: the one
// chat.defaultAgent names now and the one it named before DefenseClaw first
// changed the setting (the pristine bytes of the settings backup). A
// managed Setup replaces the setting, so after an upgrade from the per-user
// footprint only the backup still names the agent that footprint hooked.
func kiroEarlierDefaultAgentPaths(dataDir string) []string {
	managedAgent := filepath.Clean(kiroManagedAgentPath())
	var paths []string
	for _, path := range []string{kiroConfiguredDefaultAgentPath(), kiroPristineDefaultAgentPath(dataDir)} {
		if path != "" && filepath.Clean(path) != managedAgent {
			paths = append(paths, path)
		}
	}
	return uniqueNonEmptyStrings(paths)
}

// kiroPristineDefaultAgentPath is the custom default agent the settings file
// named when DefenseClaw first captured it, or "".
func kiroPristineDefaultAgentPath(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, "kiro", kiroSettingsLogicalName))
	if err != nil || backup.Connector != "kiro" || backup.LogicalName != kiroSettingsLogicalName ||
		!backup.Existed || len(bytes.TrimSpace(backup.PristineBytes)) == 0 {
		return ""
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(backup.PristineBytes, &cfg); err != nil {
		return ""
	}
	return kiroDefaultAgentPathFromSettings(cfg)
}

func kiroManagedAgentPath() string {
	return filepath.Join(kiroHomeDir(), "agents", kiroManagedAgentName+".json")
}

func kiroBuiltInDefaultAgentPath() string {
	return filepath.Join(kiroHomeDir(), "agents", kiroBuiltInDefaultAgentName+".json")
}

func kiroSettingsPath() string {
	return filepath.Join(kiroHomeDir(), "settings", "cli.json")
}

func kiroConfiguredDefaultAgentPath() string {
	cfg, err := readJSONObject(kiroSettingsPath())
	if err != nil {
		return ""
	}
	return kiroDefaultAgentPathFromSettings(cfg)
}

// kiroDefaultAgentPathFromSettings is the agent file a CLI settings object's
// chat.defaultAgent names, or "" for none, a built-in agent, or a name that
// is not a plain file name.
func kiroDefaultAgentPathFromSettings(cfg map[string]interface{}) string {
	name, _ := cfg[kiroDefaultAgentSettingKey].(string)
	name = strings.TrimSpace(name)
	if name == "" || kiroBuiltInAgentName(name) || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return ""
	}
	return filepath.Join(kiroHomeDir(), "agents", name+".json")
}

func kiroAgentBackupLogicalName(path string) string {
	if filepath.Clean(path) == filepath.Clean(kiroManagedAgentPath()) {
		return kiroV2AgentLogicalName
	}
	cleaned := filepath.Clean(path)
	return "agent-" + strings.ReplaceAll(cleaned, string(filepath.Separator), "_")
}

func kiroHomeDir() string {
	if home := strings.TrimSpace(KiroHomeOverride); home != "" {
		return home
	}
	return homePath(".kiro")
}

// kiroBackupLogicalName names a v3 hook file's backup record. On Windows the
// global ~/.kiro/hooks/defenseclaw.json has the fixed name
// kiroGlobalHooksLogicalName, so the guardian's managed-runtime cleanup,
// which accepts only fixed file names, can remove its record; every other
// file keeps its path-derived name.
func kiroBackupLogicalName(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" && cleaned == filepath.Clean(kiroHooksPath(SetupOpts{})) {
		return kiroGlobalHooksLogicalName
	}
	return kiroPathBackupLogicalName(cleaned)
}

func kiroPathBackupLogicalName(path string) string {
	return kiroV3HooksLogicalName + "-" + strings.ReplaceAll(filepath.Clean(path), string(filepath.Separator), "_")
}

// migrateKiroGlobalHooksBackup moves a Windows backup record an earlier
// release kept under the global hook file's path-derived name to
// kiroGlobalHooksLogicalName, so Setup keeps the original preimage and
// Teardown still restores it.
func migrateKiroGlobalHooksBackup(opts SetupOpts) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	path := kiroHooksPath(opts)
	return migrateManagedFileBackupLogicalName(opts.DataDir, "kiro", kiroPathBackupLogicalName(path), kiroBackupLogicalName(path))
}

// ownedHookContractPresent proves Kiro's effective hook registration for the
// sidecar's post-Setup verification.
//
// The generic config walker cannot answer this for Kiro. It matches a hook
// command against the bare script path exactly, and Kiro's v3 entry carries
// `--hook-surface v3` so the gateway can tell which config invoked the hook.
// Under the generic check that argument read as "no DefenseClaw hook found",
// so every Kiro setup was rolled back immediately after writing its files --
// the connector never became active and `/hooks` stayed empty.
//
// Both surfaces must be registered for Kiro to be guarded: the v3 config that
// Kiro IDE and `kiro-cli --v3` read, and the CLI 2.x agent config that bare
// `kiro-cli` reads. The v3 file must hold every entry as Setup renders it
// (kiroV3HooksCurrent), so the guardian repairs one that was turned off,
// removed or pointed elsewhere; the CLI 2.x agent is checked the same way
// (kiroV2AgentReferencesHook).
func (c *KiroConnector) ownedHookContractPresent(opts SetupOpts) (bool, error) {
	command := c.hookCommand(opts)
	v3Command := c.hookCommandForV3Surface(opts)
	present, err := c.ownedHookContractPresentFor(opts, command, v3Command)
	if err != nil || present || !opts.AcceptPriorReleaseRender {
		return present, err
	}
	// A verification that accepts the render of releases up to 1.0.6 takes
	// both configs when each holds exactly the bridge those releases wrote
	// (legacyWindowsAwaitedHookCommand), and nothing else (GAP-0980).
	legacy, ok := legacyWindowsAwaitedHookCommand(command)
	legacyV3, okV3 := legacyWindowsAwaitedHookCommand(v3Command)
	if !ok || !okV3 {
		return false, nil
	}
	return c.ownedHookContractPresentFor(opts, legacy, legacyV3)
}

// ownedHookContractPresentFor is ownedHookContractPresent for the given CLI 2.x
// agent command and v3 hook command.
func (c *KiroConnector) ownedHookContractPresentFor(opts SetupOpts, command, v3Command string) (bool, error) {
	for _, path := range c.hookConfigPaths(opts) {
		present, err := kiroV3HooksCurrent(path, v3Command)
		if err != nil {
			return false, err
		}
		if !present {
			return false, nil
		}
	}
	for _, path := range c.agentConfigPaths(opts) {
		present, err := kiroV2AgentReferencesHook(path, command)
		if err != nil {
			return false, err
		}
		if !present {
			return false, nil
		}
	}
	return true, nil
}
