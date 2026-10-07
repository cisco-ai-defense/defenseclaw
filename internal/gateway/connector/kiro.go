// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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
	masterKey    string
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
			staleErr = errors.Join(staleErr, c.reclaimKiroHookFile(opts, path, v3Command))
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
	if err := removeStaleKiroDefaultOverlay(command); err != nil {
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

func (c *KiroConnector) Teardown(_ context.Context, opts SetupOpts) error {
	command := c.hookCommand(opts)
	var errs []error
	if err := migrateKiroGlobalHooksBackup(opts); err != nil {
		errs = append(errs, fmt.Errorf("kiro migrate hook backup: %w", err))
	}
	cleanup := c.hookCleanupPaths(opts)
	cleanup = append(cleanup, c.staleRecordedKiroHookPaths(opts, cleanup)...)
	for _, path := range cleanup {
		if err := c.reclaimKiroHookFile(opts, path, command); err != nil {
			errs = append(errs, err)
		}
	}
	written := map[string]bool{}
	for _, path := range c.agentConfigPaths(opts) {
		written[path] = true
	}
	for _, path := range c.agentCleanupPaths(opts) {
		if !written[path] {
			// A managed install never writes the user's default agent; only
			// remove DefenseClaw hooks an earlier build left there, and
			// otherwise leave the file byte for byte.
			if present, err := kiroV2AgentReferencesAnyHook(path, command); err != nil || !present {
				if err != nil {
					errs = append(errs, fmt.Errorf("kiro inspect agent %s: %w", path, err))
				}
				continue
			}
		}
		if err := c.reclaimKiroAgentFile(opts, path, command); err != nil {
			errs = append(errs, err)
		}
	}
	if err := removeStaleKiroDefaultOverlay(command); err != nil {
		errs = append(errs, fmt.Errorf("kiro remove stale kiro_default overlay: %w", err))
	}
	// The settings file is the user's: only DefenseClaw's default-agent
	// setting comes out, never a whole earlier copy, which would drop the
	// keys added since Setup captured it.
	settingsPath := kiroSettingsPath()
	backup, err := loadManagedFileBackupForTransform(opts.DataDir, c.Name(), kiroSettingsLogicalName, settingsPath)
	if err == nil {
		err = removeKiroDefaultAgentSetting(settingsPath, backup)
	}
	if err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("kiro remove default agent setting: %w", err))
	} else {
		discardManagedFileBackup(opts.DataDir, c.Name(), kiroSettingsLogicalName)
	}
	if err := writeDisabledHookTombstone(opts, kiroHookScriptName, c.Name()); err != nil {
		errs = append(errs, fmt.Errorf("kiro disabled hook tombstone: %w", err))
	}
	if strings.TrimSpace(opts.DataDir) != "" {
		removeCreatedDirs(filepath.Join(opts.DataDir, kiroCreatedDirsFile), filepath.Dir(kiroHomeDir()))
	}
	return errors.Join(errs...)
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

func (c *KiroConnector) VerifyClean(opts SetupOpts) error {
	command := c.hookCommand(opts)
	for _, path := range c.hookCleanupPaths(opts) {
		if present, err := kiroV3FileReferencesHook(path, command); err != nil {
			return err
		} else if present {
			return fmt.Errorf("kiro teardown incomplete: hook config still references %s", path)
		}
	}
	for _, path := range append(c.agentCleanupPaths(opts), kiroBuiltInDefaultAgentPath()) {
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
	return nil
}

// reclaimKiroHookFile puts one v3 hook file back as Setup found it when it is
// unchanged since, and otherwise removes only DefenseClaw's entries; either
// way its backup record is settled.
func (c *KiroConnector) reclaimKiroHookFile(opts SetupOpts, path, command string) error {
	logical := kiroBackupLogicalName(path)
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), logical, path)
	if err != nil {
		return fmt.Errorf("kiro restore hook %s: %w", path, err)
	}
	if !restored {
		if err := removeKiroV3Hooks(path, command); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("kiro remove hook %s: %w", path, err)
		}
	} else if present, err := kiroV3FileReferencesHook(path, command); err != nil {
		return fmt.Errorf("kiro inspect restored hook %s: %w", path, err)
	} else if present {
		// A backup captured while the account still held an earlier
		// enrollment's hooks (whose own backup is gone) put DefenseClaw's
		// entries back; they go too (GAP-1932).
		if err := removeKiroV3Hooks(path, command); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("kiro remove hook %s: %w", path, err)
		}
	}
	discardManagedFileBackup(opts.DataDir, c.Name(), logical)
	return nil
}

// reclaimKiroAgentFile is reclaimKiroHookFile for a CLI 2.x agent file.
func (c *KiroConnector) reclaimKiroAgentFile(opts SetupOpts, path, command string) error {
	logical := kiroAgentBackupLogicalName(path)
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), logical, path)
	if err != nil {
		return fmt.Errorf("kiro restore agent %s: %w", path, err)
	}
	if !restored {
		if err := removeKiroV2AgentHooks(path, command); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("kiro remove agent hooks %s: %w", path, err)
		}
	} else if present, err := kiroV2AgentReferencesAnyHook(path, command); err != nil {
		return fmt.Errorf("kiro inspect restored agent %s: %w", path, err)
	} else if present {
		// The restored agent came from a backup that already held
		// DefenseClaw's hooks (GAP-1932).
		if err := removeKiroV2AgentHooks(path, command); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("kiro remove agent hooks %s: %w", path, err)
		}
	}
	discardManagedFileBackup(opts.DataDir, c.Name(), logical)
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
		if err := c.reclaimKiroAgentFile(opts, path, command); err != nil {
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
		if err := c.reclaimKiroHookFile(opts, path, command); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *KiroConnector) Authenticate(r *http.Request) bool {
	return authenticateHookBridgeRequest(r, c.gatewayToken, c.masterKey, c.Name(),
		"Kiro hook and ACP traffic is authenticated by the scoped connector token", &c.loopbackWarn)
}

func (c *KiroConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{RawBody: body, RawModel: ParseModelFromBody(body), Stream: ParseStreamFromBody(body), PassthroughMode: true, ConnectorName: c.Name()}, nil
}

func (c *KiroConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken, c.masterKey = gatewayToken, masterKey
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
	return windowsSystemCmdExe() + " /d /c " + windowsKiroPowerShellBridgeForBinary(hookBinary, surface, managed) + "\nexit $LASTEXITCODE"
}

// windowsKiroPowerShellBridgeForBinary renders the encoded system PowerShell
// bridge the Kiro command runs: the shared awaited-hook bridge
// (windowsAwaitedHookStatements), which starts the launcher with Process.Start
// and returns a fast-exiting launcher's block, with a Constrained Language
// mode fallback. Managed Windows writes the same bridge under the target user
// token with managed set; there hookBinary is the standalone
// defenseclaw-hook.exe and the arguments add --enterprise-managed.
func windowsKiroPowerShellBridgeForBinary(hookBinary, surface string, managed bool) string {
	var extra []string
	if managed {
		extra = append(extra, "--enterprise-managed")
	}
	if surface != "" {
		extra = append(extra, "--hook-surface", surface)
	}
	return windowsNativePowerShellHookCommandForBoundEvent("kiro", "", "", hookBinary, extra...)
}

// kiroWindowsOwnedHookCommands are the Windows Kiro commands DefenseClaw
// writes for every launcher it may have registered: the per-user and the
// managed command, for the v2 and v3 surfaces. Setup replaces and teardown
// removes them in the CLI 2.x agent files, whose entries are otherwise
// matched by exact command.
func kiroWindowsOwnedHookCommands() []string {
	var commands []string
	for _, binary := range nativeHookBinaryOwnershipCandidates() {
		for _, managed := range []bool{false, true} {
			commands = append(commands,
				windowsKiroHookCommandForBinary(binary, "", managed),
				windowsKiroHookCommandForBinary(binary, KiroHookSurfaceV3, managed),
			)
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
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	known := map[string]bool{}
	for _, path := range current {
		known[filepath.Clean(path)] = true
	}
	var stale []string
	_ = forEachManagedFileBackup(opts.DataDir, func(b managedFileBackup) error {
		if b.Connector != c.Name() || !strings.HasPrefix(b.LogicalName, kiroV3HooksLogicalName+"-") ||
			b.LogicalName != kiroBackupLogicalName(b.Path) || known[filepath.Clean(b.Path)] {
			return nil
		}
		known[filepath.Clean(b.Path)] = true
		stale = append(stale, b.Path)
		return nil
	})
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
