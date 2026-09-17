// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	kiroHookScriptName          = "kiro-hook.sh"
	kiroHookAPIPath             = "/api/v1/kiro/hook"
	kiroManagedHooksName        = "defenseclaw.json"
	kiroManagedAgentName        = "defenseclaw"
	kiroBuiltInDefaultAgentName = "kiro_default"
	kiroV3HooksLogicalName      = "hooks"
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
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("kiro hook script: %w", err)
	}
	command := c.hookCommand(opts)
	for _, path := range c.hookConfigPaths(opts) {
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), kiroBackupLogicalName(path), path); err != nil {
			return fmt.Errorf("kiro capture hook backup %s: %w", path, err)
		}
		if err := patchKiroV3Hooks(path, command); err != nil {
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
	settingsPath := kiroSettingsPath()
	if err := captureManagedFileBackup(opts.DataDir, c.Name(), kiroSettingsLogicalName, settingsPath); err != nil {
		return fmt.Errorf("kiro capture settings backup: %w", err)
	}
	if err := patchKiroDefaultAgentSetting(settingsPath); err != nil {
		return fmt.Errorf("kiro default agent setting: %w", err)
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), kiroSettingsLogicalName, settingsPath); err != nil {
		return fmt.Errorf("kiro record settings backup: %w", err)
	}
	return nil
}

func (c *KiroConnector) Teardown(_ context.Context, opts SetupOpts) error {
	command := c.hookCommand(opts)
	var errs []error
	for _, path := range c.hookConfigPaths(opts) {
		logical := kiroBackupLogicalName(path)
		restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), logical, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("kiro restore hook %s: %w", path, err))
			continue
		}
		if restored {
			discardManagedFileBackup(opts.DataDir, c.Name(), logical)
			continue
		}
		if err := removeKiroV3Hooks(path, command); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("kiro remove hook %s: %w", path, err))
			continue
		}
		discardManagedFileBackup(opts.DataDir, c.Name(), logical)
	}
	for _, path := range c.agentConfigPaths(opts) {
		logical := kiroAgentBackupLogicalName(path)
		restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), logical, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("kiro restore agent %s: %w", path, err))
			continue
		}
		if restored {
			discardManagedFileBackup(opts.DataDir, c.Name(), logical)
			continue
		}
		if removeErr := removeKiroV2AgentHooks(path, command); removeErr != nil && !os.IsNotExist(removeErr) {
			errs = append(errs, fmt.Errorf("kiro remove agent hooks %s: %w", path, removeErr))
			continue
		}
		discardManagedFileBackup(opts.DataDir, c.Name(), logical)
	}
	if err := removeStaleKiroDefaultOverlay(command); err != nil {
		errs = append(errs, fmt.Errorf("kiro remove stale kiro_default overlay: %w", err))
	}
	settingsPath := kiroSettingsPath()
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), kiroSettingsLogicalName, settingsPath)
	if err != nil {
		errs = append(errs, fmt.Errorf("kiro restore settings: %w", err))
	} else if restored {
		discardManagedFileBackup(opts.DataDir, c.Name(), kiroSettingsLogicalName)
	} else {
		if removeErr := removeKiroDefaultAgentSetting(settingsPath); removeErr != nil && !os.IsNotExist(removeErr) {
			errs = append(errs, fmt.Errorf("kiro remove default agent setting: %w", removeErr))
		} else {
			discardManagedFileBackup(opts.DataDir, c.Name(), kiroSettingsLogicalName)
		}
	}
	return errors.Join(errs...)
}

func (c *KiroConnector) VerifyClean(opts SetupOpts) error {
	command := c.hookCommand(opts)
	for _, path := range c.hookConfigPaths(opts) {
		if present, err := kiroV3FileReferencesHook(path, command); err != nil {
			return err
		} else if present {
			return fmt.Errorf("kiro teardown incomplete: hook config still references %s", path)
		}
	}
	for _, path := range append(c.agentConfigPaths(opts), kiroBuiltInDefaultAgentPath()) {
		if present, err := kiroV2AgentReferencesHook(path, command); err != nil {
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
	return HookCapability{
		CanBlock:           true,
		SupportsFailClosed: true,
		// Workspace only. Kiro discovers hooks from .kiro/hooks/*.json
		// relative to the project root (kiro.dev/docs/hooks: "Location:
		// .kiro/hooks/ in your project root"), and documents no user-level
		// location. ~/.kiro/hooks/defenseclaw.json is still written and
		// tracked so teardown can reclaim it, but Kiro never reads it, so
		// claiming a user scope here reports enforcement that cannot happen.
		Scope:       "workspace",
		ConfigPath:  kiroHooksPath(opts),
		BlockEvents: kiroBlockEvents(opts.AgentVersion),
	}
}

// kiroBlockEvents narrows the veto surface to what the detected Kiro release
// actually honors. CLI 2.x documents exit 2 as a block for preToolUse only;
// every other trigger treats it as a failed hook whose stderr becomes a
// warning, so claiming a UserPromptSubmit block there would report enforcement
// that never happened. The v1 hook schema (Kiro IDE 1.x, CLI 3.x) added
// prompt-submit blocking, and an unknown version is an IDE-or-newer install.
func kiroBlockEvents(agentVersion string) []string {
	normalized := NormalizeAgentVersion("kiro", agentVersion)
	if normalized != "" && compareVersion(normalized, "3.0.0") < 0 {
		return []string{"PreToolUse"}
	}
	return []string{"UserPromptSubmit", "PreToolUse"}
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
	unixCommand := filepath.Join(opts.DataDir, "hooks", kiroHookScriptName)
	return hookInvocationCommandFor(runtime.GOOS, c.Name(), unixCommand)
}

func (c *KiroConnector) hookConfigPaths(opts SetupOpts) []string {
	paths := []string{kiroHooksPath(opts)}
	if workspace := kiroWorkspaceHooksPath(opts); workspace != "" && workspace != paths[0] {
		paths = append(paths, workspace)
	}
	return uniqueNonEmptyStrings(paths)
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

func (c *KiroConnector) agentConfigPaths(opts SetupOpts) []string {
	_ = opts
	paths := []string{kiroManagedAgentPath()}
	if custom := kiroConfiguredDefaultAgentPath(); custom != "" && custom != paths[0] {
		paths = append(paths, custom)
	}
	return uniqueNonEmptyStrings(paths)
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
	name, _ := cfg[kiroDefaultAgentSettingKey].(string)
	name = strings.TrimSpace(name)
	if name == "" || kiroBuiltInAgentName(name) {
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

func kiroBackupLogicalName(path string) string {
	cleaned := filepath.Clean(path)
	return kiroV3HooksLogicalName + "-" + strings.ReplaceAll(cleaned, string(filepath.Separator), "_")
}
