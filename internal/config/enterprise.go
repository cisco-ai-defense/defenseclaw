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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// EnterpriseConfig selects and tunes the managed_enterprise profile. It is
// administrator-owned like the rest of a managed config; an enterprise
// block in a non-managed config is rejected.
type EnterpriseConfig struct {
	Profile       string                        `mapstructure:"profile"        yaml:"profile,omitempty"`
	Inspection    EnterpriseInspectionConfig    `mapstructure:"inspection"     yaml:"inspection,omitempty"`
	Enrollment    EnterpriseEnrollmentConfig    `mapstructure:"enrollment"     yaml:"enrollment,omitempty"`
	MachinePolicy EnterpriseMachinePolicyConfig `mapstructure:"machine_policy" yaml:"machine_policy,omitempty"`
	Trust         EnterpriseTrustConfig         `mapstructure:"trust"          yaml:"trust,omitempty"`
	Coexistence   EnterpriseCoexistenceConfig   `mapstructure:"coexistence"    yaml:"coexistence,omitempty"`
	Network       EnterpriseNetworkConfig       `mapstructure:"network"        yaml:"network,omitempty"`
}

// EnterpriseInspectionConfig chooses the optional remote inspection of a
// standalone deployment. Secure Client deployments always use CMID.
type EnterpriseInspectionConfig struct {
	AIDefense EnterpriseAIDefenseConfig `mapstructure:"ai_defense" yaml:"ai_defense,omitempty"`
	LLM       EnterpriseLLMConfig       `mapstructure:"llm"        yaml:"llm,omitempty"`
}

// EnterpriseLLMConfig names the protected credential that carries the API
// key of the llm: block on a standalone deployment. The LLM judge and the
// scanners' LLM analyzers read it, through ResolveLLM, instead of
// llm.api_key, api_key_env or the data-dir .env: the gateway service account
// has no user's environment, so this is how a managed gateway gets an LLM key
// (for example a Bedrock API key). The key itself never appears in config.
type EnterpriseLLMConfig struct {
	Credential string `mapstructure:"credential" yaml:"credential,omitempty"`
}

// EnterpriseAIDefenseConfig names the protected credential that carries the
// Cisco AI Defense API key. The key itself never appears in config.
type EnterpriseAIDefenseConfig struct {
	Enabled    bool   `mapstructure:"enabled"    yaml:"enabled,omitempty"`
	Credential string `mapstructure:"credential" yaml:"credential,omitempty"`
}

// Enrollment modes and policies.
const (
	EnterpriseEnrollmentAuto     = "auto"
	EnterpriseEnrollmentManifest = "manifest"

	EnterpriseUnenrolledInspect = "inspect"
	EnterpriseUnenrolledDeny    = "deny"

	EnterpriseRootInspect = "inspect"
	EnterpriseRootDeny    = "deny"
	EnterpriseRootExempt  = "exempt"

	// enterprise.enrollment.unverified_versions: what enrollment does with
	// an app or extension surface whose hook delivery has not been
	// live-verified. report (the default) enrolls it when its engine
	// version resolves a hook contract and reports it; refuse keeps it
	// unenrolled and refuses its hook calls where the route allows.
	EnterpriseUnverifiedReport = "report"
	EnterpriseUnverifiedRefuse = "refuse"
)

// EnterpriseEnrollmentConfig controls which local users the enumerator
// enrolls and how the gateway treats users it has not enrolled.
type EnterpriseEnrollmentConfig struct {
	Mode            string   `mapstructure:"mode"             yaml:"mode,omitempty"`
	IncludeUsers    []string `mapstructure:"include_users"    yaml:"include_users,omitempty"`
	ExcludeUsers    []string `mapstructure:"exclude_users"    yaml:"exclude_users,omitempty"`
	IncludeGroups   []string `mapstructure:"include_groups"   yaml:"include_groups,omitempty"`
	ExcludeGroups   []string `mapstructure:"exclude_groups"   yaml:"exclude_groups,omitempty"`
	ExemptUsers     []string `mapstructure:"exempt_users"     yaml:"exempt_users,omitempty"`
	UnenrolledUsers string   `mapstructure:"unenrolled_users" yaml:"unenrolled_users,omitempty"`
	Root            string   `mapstructure:"root"             yaml:"root,omitempty"`
	// UIDMin overrides the unix login.defs UID_MIN; 0 means "read it".
	UIDMin int `mapstructure:"uid_min" yaml:"uid_min,omitempty"`
	// UIDMax, when set, is the highest uid enrolled on Linux and macOS,
	// for local and directory accounts alike. 0 bounds only local
	// (/etc/passwd) accounts by login.defs UID_MAX: directory, SSSD
	// id-mapped, FreeIPA and systemd-homed uids routinely sit above it.
	UIDMax int `mapstructure:"uid_max" yaml:"uid_max,omitempty"`
	// HomeRoots lists extra home parents (e.g. /srv/home) the guardian may
	// write under. The lifecycle widens the guardian unit to exactly these.
	HomeRoots []string `mapstructure:"home_roots" yaml:"home_roots,omitempty"`
	// AgentPrefixes lists extra administrator-owned install prefixes (for
	// example an npm prefix such as /opt/tools) where agent CLIs live. The
	// enumerator and guardian discover agents only in known locations, so
	// agents installed elsewhere are not enrolled without this.
	AgentPrefixes []string `mapstructure:"agent_prefixes" yaml:"agent_prefixes,omitempty"`
	// UnverifiedVersions is report (default) or refuse; see
	// EnterpriseUnverifiedReport. UnverifiedVersionsByConnector overrides
	// it per connector.
	UnverifiedVersions            string            `mapstructure:"unverified_versions"              yaml:"unverified_versions,omitempty"`
	UnverifiedVersionsByConnector map[string]string `mapstructure:"unverified_versions_by_connector" yaml:"unverified_versions_by_connector,omitempty"`
}

// UnverifiedVersionsFor is the unverified-version policy for connector:
// its override, else unverified_versions, else report.
func (e EnterpriseEnrollmentConfig) UnverifiedVersionsFor(connector string) string {
	connector = strings.ToLower(strings.TrimSpace(connector))
	for name, value := range e.UnverifiedVersionsByConnector {
		if strings.ToLower(strings.TrimSpace(name)) == connector && strings.TrimSpace(value) != "" {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	if value := strings.ToLower(strings.TrimSpace(e.UnverifiedVersions)); value != "" {
		return value
	}
	return EnterpriseUnverifiedReport
}

// Machine policy knobs.
const (
	MachinePolicyOwnershipMerge      = "merge"
	MachinePolicyOwnershipVerifyOnly = "verify_only"
	MachinePolicyOwnershipOff        = "off"

	ManagedHooksOnlyEnforce  = "enforce"
	ManagedHooksOnlyPreserve = "preserve"

	ForeignHooksRemove = "remove"
	ForeignHooksReport = "report"
	ForeignHooksAllow  = "allow"

	HigherPrecedenceFail = "fail"
	HigherPrecedenceWarn = "warn"

	// Claude Code version floor modes
	// (enterprise.machine_policy.connectors.claudecode.version_floor).
	ClaudeVersionFloorEnforce = "enforce"
	ClaudeVersionFloorReport  = "report"
	ClaudeVersionFloorOff     = "off"

	// GitHub Copilot in VS Code harness knobs
	// (enterprise.machine_policy.connectors.copilot).
	CopilotHarnessPreferenceSDK       = "sdk"
	CopilotHarnessPreferenceUnmanaged = "unmanaged"
	CopilotLocalHarnessGovern         = "govern"
	CopilotLocalHarnessRetire         = "retire"

	// Windows WSL knobs (enterprise.machine_policy.windows_wsl).
	WSLAgentSessionsBlock = "block"
	WSLAgentSessionsAllow = "allow"

	WSLPlatformLeave   = "leave"
	WSLPlatformDisable = "disable"

	WSLEditorSettingsRepair = "repair"
	WSLEditorSettingsReport = "report"
	WSLEditorSettingsAllow  = "allow"

	WSLClaudeDesktopKeyMerge  = "merge"
	WSLClaudeDesktopKeyCreate = "create"
)

// EnterpriseConnectorPolicy is one connector's machine policy settings. An
// empty field inherits from the default block, then from the built-in
// secure defaults.
type EnterpriseConnectorPolicy struct {
	Ownership               string   `mapstructure:"ownership"                 yaml:"ownership,omitempty"`
	ManagedHooksOnly        string   `mapstructure:"managed_hooks_only"        yaml:"managed_hooks_only,omitempty"`
	ForeignHooks            string   `mapstructure:"foreign_hooks"             yaml:"foreign_hooks,omitempty"`
	HigherPrecedenceSources string   `mapstructure:"higher_precedence_sources" yaml:"higher_precedence_sources,omitempty"`
	AllowedHooks            []string `mapstructure:"allowed_hooks"             yaml:"allowed_hooks,omitempty"`
	// VersionFloor is valid only in connectors.claudecode (validation
	// refuses it in default and in any other connector). It controls
	// DefenseClaw's requiredMinimumVersion drop-in
	// (managed-settings.d/00-defenseclaw-version-floor.json), which sets the
	// lowest verified hook contract as the minimum. Claude Code reads the
	// setting only from 2.1.163, so older builds ignore it. enforce
	// (default) writes it while no administrator source
	// sets requiredMinimumVersion; report only reports; off does neither.
	// It does not inherit from default.
	VersionFloor string `mapstructure:"version_floor" yaml:"version_floor,omitempty"`
	// HarnessPreference and LocalHarness are valid only in
	// connectors.copilot and do not inherit from default. They govern
	// GitHub Copilot in VS Code. HarnessPreference: sdk (default) sets the
	// VS Code policy ChatEditorPreferCopilotHarness so new editor chats
	// open on the Copilot SDK harness, which reads policy.d; unmanaged
	// leaves the harness choice to VS Code and removes a value DefenseClaw
	// set. LocalHarness: govern (default) governs the Local harness with
	// the DefenseClaw plugin and user hook file; retire also sets the
	// Copilot managed setting sandbox.enabled, which keeps agent sessions
	// on sandboxed harnesses.
	HarnessPreference string `mapstructure:"harness_preference" yaml:"harness_preference,omitempty"`
	LocalHarness      string `mapstructure:"local_harness"      yaml:"local_harness,omitempty"`
}

// versionFloorConnector is the only connector with a version_floor key.
const versionFloorConnector = "claudecode"

// copilotHarnessConnector is the only connector with harness_preference and
// local_harness keys.
const copilotHarnessConnector = "copilot"

// CopilotHarnessPreference returns the effective harness_preference of
// connectors.copilot (sdk unless set).
func (m EnterpriseMachinePolicyConfig) CopilotHarnessPreference() string {
	if value := strings.ToLower(strings.TrimSpace(m.Connectors[copilotHarnessConnector].HarnessPreference)); value != "" {
		return value
	}
	return CopilotHarnessPreferenceSDK
}

// CopilotLocalHarness returns the effective local_harness of
// connectors.copilot (govern unless set).
func (m EnterpriseMachinePolicyConfig) CopilotLocalHarness() string {
	if value := strings.ToLower(strings.TrimSpace(m.Connectors[copilotHarnessConnector].LocalHarness)); value != "" {
		return value
	}
	return CopilotLocalHarnessGovern
}

// EnterpriseMachinePolicyConfig holds the default connector policy and
// per-connector overrides.
type EnterpriseMachinePolicyConfig struct {
	Default    EnterpriseConnectorPolicy            `mapstructure:"default"     yaml:"default,omitempty"`
	Connectors map[string]EnterpriseConnectorPolicy `mapstructure:"connectors"  yaml:"connectors,omitempty"`
	WindowsWSL EnterpriseWindowsWSLPolicy           `mapstructure:"windows_wsl" yaml:"windows_wsl,omitempty"`
}

// EnterpriseWindowsWSLPolicy governs agent sessions that run inside a WSL 2
// distribution on a Windows standalone deployment, where Windows machine
// policy does not reach. Other operating systems ignore it.
type EnterpriseWindowsWSLPolicy struct {
	// AgentSessions: block (default) keeps Claude Desktop WSL sessions off
	// through HKLM\SOFTWARE\Policies\Claude\disableWslSessions; allow
	// accepts them running without DefenseClaw.
	AgentSessions string `mapstructure:"agent_sessions" yaml:"agent_sessions,omitempty"`
	// Platform: leave (default), or disable, which sets
	// HKLM\SOFTWARE\Policies\WSL\AllowWSL=0 and turns WSL off for every
	// account (it also stops other WSL tooling, such as Docker Desktop's
	// WSL backend).
	Platform string `mapstructure:"platform" yaml:"platform,omitempty"`
	// EditorSettings: repair (default) resets the Codex IDE extension's
	// chatgpt.runCodexInWindowsSubsystemForLinux to false in each enrolled
	// user's VS Code, VS Code Insiders and Cursor user settings; report
	// only reports it; allow ignores it.
	EditorSettings string `mapstructure:"editor_settings" yaml:"editor_settings,omitempty"`
	// ClaudeDesktopKey: merge (default) adds disableWslSessions only when
	// HKLM\SOFTWARE\Policies\Claude already holds machine policy; create
	// also writes it into an empty key. Any value there makes Claude Desktop
	// ignore every user's HKCU policy and local third-party configuration,
	// so creating it is the administrator's explicit choice.
	ClaudeDesktopKey string `mapstructure:"claude_desktop_key" yaml:"claude_desktop_key,omitempty"`
}

// WSL returns the effective Windows WSL policy with the defaults filled in.
func (m EnterpriseMachinePolicyConfig) WSL() EnterpriseWindowsWSLPolicy {
	pick := func(value, fallback string) string {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			return value
		}
		return fallback
	}
	w := m.WindowsWSL
	return EnterpriseWindowsWSLPolicy{
		AgentSessions:    pick(w.AgentSessions, WSLAgentSessionsBlock),
		Platform:         pick(w.Platform, WSLPlatformLeave),
		EditorSettings:   pick(w.EditorSettings, WSLEditorSettingsRepair),
		ClaudeDesktopKey: pick(w.ClaudeDesktopKey, WSLClaudeDesktopKeyMerge),
	}
}

// ClaudeVersionFloor returns the effective Claude Code version floor mode
// (enterprise.machine_policy.connectors.claudecode.version_floor).
func (m EnterpriseMachinePolicyConfig) ClaudeVersionFloor() string {
	if value := strings.ToLower(strings.TrimSpace(m.Connectors[versionFloorConnector].VersionFloor)); value != "" {
		return value
	}
	return ClaudeVersionFloorEnforce
}

// Trust modes for Windows standalone payload verification.
const (
	EnterpriseTrustAuthenticode = "authenticode"
	EnterpriseTrustHashPinned   = "hash_pinned"
)

// EnterpriseTrustConfig chooses how the lifecycle trusts payload files.
type EnterpriseTrustConfig struct {
	Mode           string   `mapstructure:"mode"            yaml:"mode,omitempty"`
	AllowedSigners []string `mapstructure:"allowed_signers" yaml:"allowed_signers,omitempty"`
}

// Coexistence with per-user installs.
const (
	PerUserInstallMigrate = "migrate"
	PerUserInstallBlock   = "block"
	PerUserInstallIgnore  = "ignore"
)

// EnterpriseCoexistenceConfig controls how a managed deployment treats an
// existing per-user DefenseClaw install.
type EnterpriseCoexistenceConfig struct {
	PerUserInstall    string `mapstructure:"per_user_install"    yaml:"per_user_install,omitempty"`
	DisableSelfUpdate *bool  `mapstructure:"disable_self_update" yaml:"disable_self_update,omitempty"`
}

// EnterpriseNetworkConfig is the gateway's egress proxy.
type EnterpriseNetworkConfig struct {
	HTTPSProxy string `mapstructure:"https_proxy" yaml:"https_proxy,omitempty"`
	NoProxy    string `mapstructure:"no_proxy"    yaml:"no_proxy,omitempty"`
}

// ResolvedConnectorPolicy is a connector's effective machine policy.
type ResolvedConnectorPolicy struct {
	Connector               string
	Ownership               string
	ManagedHooksOnly        string
	ForeignHooks            string
	HigherPrecedenceSources string
	AllowedHooks            []string
}

// builtinConnectorPolicy is the secure default: DefenseClaw merges its own
// entries, locks the agent to managed hooks where the vendor supports it,
// removes foreign user-level hooks that could rewrite input, and refuses
// to claim coverage under a higher-precedence policy source it cannot see.
var builtinConnectorPolicy = EnterpriseConnectorPolicy{
	Ownership:               MachinePolicyOwnershipMerge,
	ManagedHooksOnly:        ManagedHooksOnlyEnforce,
	ForeignHooks:            ForeignHooksRemove,
	HigherPrecedenceSources: HigherPrecedenceFail,
}

// PolicyFor returns connector's effective policy: connector override, then
// the default block, then the built-in secure defaults.
func (m EnterpriseMachinePolicyConfig) PolicyFor(connector string) ResolvedConnectorPolicy {
	connector = strings.ToLower(strings.TrimSpace(connector))
	pick := func(values ...string) string {
		for _, value := range values {
			if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
				return value
			}
		}
		return ""
	}
	override := m.Connectors[connector]
	resolved := ResolvedConnectorPolicy{
		Connector:               connector,
		Ownership:               pick(override.Ownership, m.Default.Ownership, builtinConnectorPolicy.Ownership),
		ManagedHooksOnly:        pick(override.ManagedHooksOnly, m.Default.ManagedHooksOnly, builtinConnectorPolicy.ManagedHooksOnly),
		ForeignHooks:            pick(override.ForeignHooks, m.Default.ForeignHooks, builtinConnectorPolicy.ForeignHooks),
		HigherPrecedenceSources: pick(override.HigherPrecedenceSources, m.Default.HigherPrecedenceSources, builtinConnectorPolicy.HigherPrecedenceSources),
	}
	allowed := append([]string{}, m.Default.AllowedHooks...)
	allowed = append(allowed, override.AllowedHooks...)
	resolved.AllowedHooks = normalizeHookDigests(allowed)
	return resolved
}

func normalizeHookDigests(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "sha256:"))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// EnterpriseProfile is the effective profile of a managed deployment, or ""
// when the deployment is not managed. The loader resolves the per-OS
// default and stores it; a managed Config built without the loader keeps
// the historical Secure Client posture, so no code path silently gains or
// loses local detectors because it skipped resolution.
func (c *Config) EnterpriseProfile() string {
	if c == nil || !managed.IsManagedEnterprise(c.DeploymentMode) {
		return ""
	}
	if profile := managed.NormalizeEnterpriseProfile(c.Enterprise.Profile); profile != "" {
		return profile
	}
	return managed.ProfileSecureClient
}

// ManagedAIDOnly reports the Secure Client decision posture: Cisco AI
// Defense (CMID) is the only decision-maker and local detectors are off.
func (c *Config) ManagedAIDOnly() bool {
	return managed.IsSecureClientProfile(c.EnterpriseProfile())
}

// SecureClientIntegration reports whether the Secure Client integration
// surfaces (GUI IPC, env_config overlay, CMID telemetry sink) are active.
func (c *Config) SecureClientIntegration() bool {
	return managed.IsSecureClientProfile(c.EnterpriseProfile())
}

// resolvesToSecureClient reports whether a config the loader has just
// decoded resolves to the Secure Client profile, from the inputs
// resolveEnterpriseConfig reads later in the same load: the deployment mode
// and its pin, the profile pin, enterprise.profile and the OS default. A
// config whose profile does not resolve fails there.
func resolvesToSecureClient(cfg *Config, pinnedDeploymentMode string) bool {
	mode := normalizeDeploymentMode(cfg.DeploymentMode)
	if pinnedDeploymentMode != "" {
		mode = pinnedDeploymentMode
	}
	profile, err := managed.ResolveEnterpriseProfile(runtime.GOOS, mode, os.Getenv(managed.EnterpriseProfileEnv), cfg.Enterprise.Profile)
	return err == nil && managed.IsSecureClientProfile(profile)
}

// StandaloneEnterprise reports a managed deployment on the standalone
// profile, where the local policy engine decides.
func (c *Config) StandaloneEnterprise() bool {
	return managed.IsStandaloneProfile(c.EnterpriseProfile())
}

// SelfUpdateDisabled reports whether a managed deployment turns off the
// per-user installers and update notices (default true).
func (e EnterpriseCoexistenceConfig) SelfUpdateDisabled() bool {
	return e.DisableSelfUpdate == nil || *e.DisableSelfUpdate
}

var (
	enterpriseConnectorNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	enterpriseSHA256Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidEnterpriseCredentialName reports whether name is a safe protected
// credential name (it becomes a file name under the secrets directory).
func ValidEnterpriseCredentialName(name string) bool {
	return managed.ValidCredentialName(name)
}

// resolveEnterpriseConfig resolves the profile against the service pin and
// validates the enterprise block. goos is injected for tests.
func resolveEnterpriseConfig(cfg *Config, goos, pinnedProfile string) error {
	declared := managed.NormalizeEnterpriseProfile(cfg.Enterprise.Profile)
	profile, err := managed.ResolveEnterpriseProfile(goos, cfg.DeploymentMode, pinnedProfile, cfg.Enterprise.Profile)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if !enterpriseBlockEmpty(cfg.Enterprise) {
			return fmt.Errorf("config: the enterprise block requires deployment_mode %s", managed.DeploymentModeManagedEnterprise)
		}
		return nil
	}
	if err := requireDeclaredStandaloneProfile(goos, pinnedProfile, declared); err != nil {
		return err
	}
	cfg.declaredEnterpriseProfile = declared
	cfg.Enterprise.Profile = profile
	if cfg.SecureClientIntegration() {
		// Secure Client keeps exact-range hook contract gating: an agent
		// version newer than every tested range stays unknown there.
		gatewayconnector.SetStrictHookContractResolution(true)
	}
	if cfg.StandaloneEnterprise() {
		standalonePolicyDirDefault(cfg, cfg.DataDir, goos)
		standaloneRulePackDefault(cfg, cfg.DataDir, goos)
	}
	return validateEnterpriseConfig(cfg)
}

// requireDeclaredStandaloneProfile refuses a standalone-pinned load of a
// config that leaves enterprise.profile unset on an OS whose default is
// secure_client. The services would run standalone, but every process that
// reads the same file without the pin (hooks, admin shells, status) would
// resolve secure_client and reject the standalone settings, so the tools
// and the services on the host would disagree about the profile.
func requireDeclaredStandaloneProfile(goos, pinnedProfile, declared string) error {
	if !managed.IsStandaloneProfile(pinnedProfile) || declared != "" ||
		managed.DefaultEnterpriseProfile(goos) == managed.ProfileStandalone {
		return nil
	}
	return fmt.Errorf(
		"config: enterprise.profile must be set to %s: on %s a process that reads this config without the %s service pin treats an unset profile as %s",
		managed.ProfileStandalone, goos, managed.EnterpriseProfileEnv, managed.DefaultEnterpriseProfile(goos),
	)
}

// DeclaredEnterpriseProfile returns enterprise.profile as the config source
// declared it (normalized), before the service pin or the per-OS default
// filled it in. It is "" when the source leaves it unset or when the Config
// was not built by the loader.
func (c *Config) DeclaredEnterpriseProfile() string {
	if c == nil {
		return ""
	}
	return c.declaredEnterpriseProfile
}

// standaloneRulePackDefault moves the loader's implicit rule pack out of
// data_dir, which the standalone gateway service can write. The pack a
// per-user install would seed in policy_dir wins when policy_dir is outside
// data_dir. For a config read from the Linux or macOS standalone layout's
// config path, where the lifecycle installs the vendor rule packs, the
// implicit pack is the vendor default pack when that policy_dir folder does
// not exist or policy_dir is inside data_dir, so leaving rule_pack_dir unset
// always names a pack that exists. On Windows nothing stages a pack under
// data_dir (the Setup ships none), so there the implicit default selects the
// gateway's embedded rule packs instead of a directory that never exists,
// unless an administrator's own policy_dir is outside data_dir.
// An explicit rule_pack_dir is kept as written; on Windows one that equals
// the implicit data_dir path also selects the embedded packs.
func standaloneRulePackDefault(cfg *Config, dataDir, goos string) {
	implicit := filepath.Join(dataDir, "policies", "guardrail", "default")
	if cfg.Guardrail.RulePackDir != implicit {
		return
	}
	policyPack := ""
	if policyDir := strings.TrimSpace(cfg.PolicyDir); policyDir != "" &&
		filepath.Clean(policyDir) != filepath.Join(dataDir, "policies") {
		policyPack = filepath.Join(policyDir, "guardrail", "default")
	}
	layout, onLayout := standaloneUnixLayoutForConfig(cfg.ConfigFilePath)
	if !onLayout {
		if policyPack != "" {
			cfg.Guardrail.RulePackDir = policyPack
		} else if goos == "windows" {
			cfg.Guardrail.RulePackDir = ""
		}
		return
	}
	if cfg.rulePackDirDeclared {
		// An explicit value that happens to equal the implicit path stays
		// for the lifecycle to refuse (it is inside data_dir).
		return
	}
	if policyPack != "" {
		// Only a folder known to be absent falls back: any other stat
		// error keeps the policy_dir pack, which the trust checks report.
		if _, err := os.Stat(policyPack); err == nil || !errors.Is(err, fs.ErrNotExist) {
			cfg.Guardrail.RulePackDir = policyPack
			return
		}
	}
	cfg.Guardrail.RulePackDir = path.Join(layout.VendorPolicyDir, "guardrail", "default")
}

// standalonePolicyDirDefault clears a Windows standalone policy_dir that
// names the data_dir policies folder. The Setup ships no Rego bundle and the
// gateway service can write data_dir, so that folder never holds
// administrator policy: the gateway uses its built-in policy instead of
// reporting a missing data.json on every start. Like rule_pack_dir, an
// explicit value equal to the implicit path is treated the same way.
func standalonePolicyDirDefault(cfg *Config, dataDir, goos string) {
	if goos != "windows" || strings.TrimSpace(dataDir) == "" {
		return
	}
	if _, onLayout := standaloneUnixLayoutForConfig(cfg.ConfigFilePath); onLayout {
		return
	}
	if policyDir := strings.TrimSpace(cfg.PolicyDir); policyDir != "" &&
		filepath.Clean(policyDir) == filepath.Join(dataDir, "policies") {
		cfg.PolicyDir = ""
	}
}

// standaloneUnixLayoutForConfig returns the Linux or macOS standalone layout
// whose fixed config path is configFile. The services read the deployment's
// config there and the lifecycle validates a staged config under that path,
// so every process that loads it resolves the same layout, including a
// lifecycle plan checked on a host of another OS. A Windows path never
// matches.
func standaloneUnixLayoutForConfig(configFile string) (managed.StandaloneLayout, bool) {
	configFile = strings.TrimSpace(configFile)
	if !strings.HasPrefix(configFile, "/") {
		return managed.StandaloneLayout{}, false
	}
	clean := path.Clean(configFile)
	for _, goos := range []string{"linux", "darwin"} {
		if layout, err := managed.StandaloneLayoutFor(goos); err == nil && layout.ConfigPath == clean {
			return layout, true
		}
	}
	return managed.StandaloneLayout{}, false
}

// standaloneLayoutDataDir returns the layout's data directory for a managed
// standalone config read from a Linux or macOS standalone layout config path
// that leaves data_dir unset. The service sandbox lets the gateway write only
// there and the service units already point DEFENSECLAW_HOME at it, so it is
// the only value the lifecycle accepts; without this default the loader
// would use the config's own folder and the lifecycle would refuse the
// config. An explicit data_dir, even a wrong one, is kept so the lifecycle
// can refuse it.
func standaloneLayoutDataDir(configFile string, document *yaml.Node) (string, bool) {
	layout, ok := standaloneUnixLayoutForConfig(configFile)
	if !ok {
		return "", false
	}
	root := v8DocumentRoot(document)
	if root == nil || root.Kind != yaml.MappingNode || v8YAMLMapValue(root, "data_dir") != nil {
		return "", false
	}
	if !standaloneManagedDocument(layout.GOOS, root) {
		return "", false
	}
	return layout.DataDir, true
}

// resolveStandaloneLLMCredential reads a protected credential; tests replace
// it because a trusted credential file needs an administrator-owned path.
var resolveStandaloneLLMCredential = func(name, secretsDir string) ([]byte, error) {
	value, _, err := managed.ResolveServiceCredential(name, secretsDir)
	return value, err
}

// standaloneLLMKey returns the llm: API key of a standalone deployment that
// names enterprise.inspection.llm.credential. configured is true whenever the
// credential is named: a missing or untrusted credential then yields no key,
// never the environment or .env key.
func (c *Config) standaloneLLMKey() (key string, configured bool) {
	if c == nil || !c.StandaloneEnterprise() {
		return "", false
	}
	name := strings.TrimSpace(c.Enterprise.Inspection.LLM.Credential)
	if name == "" {
		return "", false
	}
	value, err := resolveStandaloneLLMCredential(name, managed.StandaloneSecretsDirForConfig(runtime.GOOS, c.ConfigFilePath))
	if err != nil {
		return "", true
	}
	return string(value), true
}

// ObservabilityCredentialsDir is where the observability credential
// references of a loaded standalone enterprise config resolve, the same
// secrets directory as the AI Defense key. Other deployments resolve none.
func (c *Config) ObservabilityCredentialsDir() string {
	if c == nil || !c.StandaloneEnterprise() {
		return ""
	}
	return managed.StandaloneSecretsDirForConfig(runtime.GOOS, c.ConfigFilePath)
}

// standaloneManagedDocument reports whether a v8 source root resolves, with
// the service pins, to the standalone managed-enterprise profile on goos.
func standaloneManagedDocument(goos string, root *yaml.Node) bool {
	profile, ok := managedDocumentProfile(goos, root)
	return ok && managed.IsStandaloneProfile(profile)
}

// secureClientManagedDocument reports whether a v8 source document resolves
// to the Secure Client profile.
func secureClientManagedDocument(goos string, root *yaml.Node) bool {
	profile, ok := managedDocumentProfile(goos, root)
	return ok && managed.IsSecureClientProfile(profile)
}

// managedDocumentProfile resolves the enterprise profile of a
// managed-enterprise v8 source document from its deployment mode (the
// pinned one first), the pinned profile, enterprise.profile and the OS
// default. ok is false for any other document.
func managedDocumentProfile(goos string, root *yaml.Node) (string, bool) {
	if root == nil || root.Kind != yaml.MappingNode {
		return "", false
	}
	mode := normalizeDeploymentMode(os.Getenv(managed.DeploymentModeEnv))
	if mode == "" {
		mode = normalizeDeploymentMode(yamlScalarValue(v8YAMLMapValue(root, "deployment_mode")))
	}
	if !managed.IsManagedEnterprise(mode) {
		return "", false
	}
	declared := yamlScalarValue(v8YAMLMapValue(v8YAMLMapValue(root, "enterprise"), "profile"))
	profile, err := managed.ResolveEnterpriseProfile(goos, mode, os.Getenv(managed.EnterpriseProfileEnv), declared)
	return profile, err == nil
}

// standaloneCredentialsDir is where the observability credential references
// of a standalone managed-enterprise source resolve: the secrets directory
// next to it, as for the AI Defense key. Any other source resolves none.
func standaloneCredentialsDir(configFile string, document *yaml.Node) string {
	root := v8DocumentRoot(document)
	if !filepath.IsAbs(strings.TrimSpace(configFile)) || root == nil || root.Kind != yaml.MappingNode ||
		!standaloneManagedDocument(runtime.GOOS, root) {
		return ""
	}
	return managed.StandaloneSecretsDirForConfig(runtime.GOOS, configFile)
}

// standaloneLayoutDataDirForSource applies standaloneLayoutDataDir to the
// source bytes the loader is about to decode. A parse error returns false;
// the loader reports it itself.
func standaloneLayoutDataDirForSource(configFile string, sourceBytes []byte) (string, bool) {
	if _, ok := standaloneUnixLayoutForConfig(configFile); !ok {
		return "", false
	}
	document, err := sourceYAMLNode(sourceBytes)
	if err != nil {
		return "", false
	}
	return standaloneLayoutDataDir(configFile, document)
}

func yamlScalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func enterpriseBlockEmpty(e EnterpriseConfig) bool {
	return strings.TrimSpace(e.Profile) == "" &&
		!e.Inspection.AIDefense.Enabled && strings.TrimSpace(e.Inspection.AIDefense.Credential) == "" &&
		strings.TrimSpace(e.Inspection.LLM.Credential) == "" &&
		enrollmentEmpty(e.Enrollment) &&
		machinePolicyEmpty(e.MachinePolicy) &&
		strings.TrimSpace(e.Trust.Mode) == "" && len(e.Trust.AllowedSigners) == 0 &&
		strings.TrimSpace(e.Coexistence.PerUserInstall) == "" && e.Coexistence.DisableSelfUpdate == nil &&
		strings.TrimSpace(e.Network.HTTPSProxy) == "" && strings.TrimSpace(e.Network.NoProxy) == ""
}

// standaloneInlineSecrets lists the inline secret keys cfg sets.
func standaloneInlineSecrets(cfg *Config) []string {
	var inline []string
	for _, field := range []struct{ key, value string }{
		{"llm.api_key", cfg.LLM.APIKey},
		{"cisco_ai_defense.api_key", cfg.CiscoAIDefense.APIKey},
		{"gateway.token", cfg.Gateway.Token},
	} {
		if strings.TrimSpace(field.value) != "" {
			inline = append(inline, field.key)
		}
	}
	return inline
}

func enrollmentEmpty(e EnterpriseEnrollmentConfig) bool {
	return strings.TrimSpace(e.Mode) == "" && len(e.IncludeUsers) == 0 && len(e.ExcludeUsers) == 0 &&
		len(e.IncludeGroups) == 0 && len(e.ExcludeGroups) == 0 && len(e.ExemptUsers) == 0 &&
		strings.TrimSpace(e.UnenrolledUsers) == "" && strings.TrimSpace(e.Root) == "" &&
		e.UIDMin == 0 && e.UIDMax == 0 && len(e.HomeRoots) == 0 && len(e.AgentPrefixes) == 0 &&
		strings.TrimSpace(e.UnverifiedVersions) == "" && len(e.UnverifiedVersionsByConnector) == 0
}

func machinePolicyEmpty(m EnterpriseMachinePolicyConfig) bool {
	return connectorPolicyEmpty(m.Default) && len(m.Connectors) == 0 && m.WindowsWSL == (EnterpriseWindowsWSLPolicy{})
}

func connectorPolicyEmpty(p EnterpriseConnectorPolicy) bool {
	return strings.TrimSpace(p.Ownership) == "" && strings.TrimSpace(p.ManagedHooksOnly) == "" &&
		strings.TrimSpace(p.ForeignHooks) == "" && strings.TrimSpace(p.HigherPrecedenceSources) == "" &&
		len(p.AllowedHooks) == 0 && strings.TrimSpace(p.VersionFloor) == "" &&
		strings.TrimSpace(p.HarnessPreference) == "" && strings.TrimSpace(p.LocalHarness) == ""
}

// validateEnterpriseConfig checks a managed deployment's enterprise block.
// Secure Client deployments may only carry the profile itself: every other
// knob belongs to the standalone profile, so a Secure Client config keeps
// its exact pre-existing behavior.
func validateEnterpriseConfig(cfg *Config) error {
	e := cfg.Enterprise
	if managed.IsSecureClientProfile(e.Profile) {
		rest := e
		rest.Profile = ""
		if !enterpriseBlockEmpty(rest) {
			return fmt.Errorf("config: enterprise settings other than profile apply only to the %s profile", managed.ProfileStandalone)
		}
		return nil
	}
	// Judge trace logs raw prompts and model responses; a managed device
	// never writes them.
	if cfg.Guardrail.Judge.Trace {
		return fmt.Errorf("config: guardrail.judge.trace is not allowed on a managed device")
	}
	ai := e.Inspection.AIDefense
	if ai.Enabled {
		if !ValidEnterpriseCredentialName(ai.Credential) {
			return fmt.Errorf("config: enterprise.inspection.ai_defense.credential %q must be a protected credential name (lowercase letters, digits and dashes)", ai.Credential)
		}
	} else if strings.TrimSpace(ai.Credential) != "" && !ValidEnterpriseCredentialName(ai.Credential) {
		return fmt.Errorf("config: enterprise.inspection.ai_defense.credential %q is not a valid credential name", ai.Credential)
	}
	if name := strings.TrimSpace(e.Inspection.LLM.Credential); name != "" && !ValidEnterpriseCredentialName(name) {
		return fmt.Errorf("config: enterprise.inspection.llm.credential %q must be a protected credential name (lowercase letters, digits and dashes)", name)
	}
	// Secrets never live in config: the gateway reads the keys from the
	// named protected credentials (it ignores cisco_ai_defense.api_key_env)
	// and the lifecycle provisions the gateway token. Every inline secret is
	// named, never its value: Windows Setup reported such a config only as
	// "could not be compiled safely" at $ (GAP-0932).
	if inline := standaloneInlineSecrets(cfg); len(inline) > 0 {
		return &V8SemanticError{
			Path:    "$." + inline[0],
			Summary: "a managed standalone config holds no secrets; remove " + strings.Join(inline, ", "),
			Action: "store each key as a protected credential with `enterprise secret set --name <name>` and name it in " +
				"enterprise.inspection.llm.credential (the LLM key) or enterprise.inspection.ai_defense.credential " +
				"(the AI Defense key); the lifecycle provisions the gateway token",
		}
	}
	en := e.Enrollment
	if err := oneOf("enterprise.enrollment.mode", en.Mode, EnterpriseEnrollmentAuto, EnterpriseEnrollmentManifest); err != nil {
		return err
	}
	if err := oneOf("enterprise.enrollment.unenrolled_users", en.UnenrolledUsers, EnterpriseUnenrolledInspect, EnterpriseUnenrolledDeny); err != nil {
		return err
	}
	if err := oneOf("enterprise.enrollment.root", en.Root, EnterpriseRootInspect, EnterpriseRootDeny, EnterpriseRootExempt); err != nil {
		return err
	}
	if err := oneOf("enterprise.enrollment.unverified_versions", en.UnverifiedVersions, EnterpriseUnverifiedReport, EnterpriseUnverifiedRefuse); err != nil {
		return err
	}
	for name, value := range en.UnverifiedVersionsByConnector {
		if !enterpriseConnectorNamePattern.MatchString(name) {
			return fmt.Errorf("config: enterprise.enrollment.unverified_versions_by_connector key %q is not a connector name", name)
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("config: enterprise.enrollment.unverified_versions_by_connector.%s must be report or refuse", name)
		}
		if err := oneOf("enterprise.enrollment.unverified_versions_by_connector."+name, value, EnterpriseUnverifiedReport, EnterpriseUnverifiedRefuse); err != nil {
			return err
		}
	}
	if en.UIDMin < 0 {
		return fmt.Errorf("config: enterprise.enrollment.uid_min must not be negative")
	}
	if en.UIDMax < 0 {
		return fmt.Errorf("config: enterprise.enrollment.uid_max must not be negative")
	}
	if en.UIDMax > 0 && en.UIDMax < en.UIDMin {
		return fmt.Errorf("config: enterprise.enrollment.uid_max must not be below uid_min")
	}
	for _, root := range en.HomeRoots {
		if err := validateEnterpriseHomeRoot(root); err != nil {
			return err
		}
	}
	for _, prefix := range en.AgentPrefixes {
		if err := validateEnterpriseAgentPrefix(prefix); err != nil {
			return err
		}
	}
	for _, list := range []struct {
		name   string
		values []string
	}{
		{"include_users", en.IncludeUsers}, {"exclude_users", en.ExcludeUsers},
		{"include_groups", en.IncludeGroups}, {"exclude_groups", en.ExcludeGroups},
		{"exempt_users", en.ExemptUsers},
	} {
		for _, value := range list.values {
			if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
				return fmt.Errorf("config: enterprise.enrollment.%s contains an empty or malformed entry", list.name)
			}
		}
	}
	if err := validateConnectorPolicy("enterprise.machine_policy.default", e.MachinePolicy.Default); err != nil {
		return err
	}
	for name, policy := range e.MachinePolicy.Connectors {
		if !enterpriseConnectorNamePattern.MatchString(name) {
			return fmt.Errorf("config: enterprise.machine_policy.connectors key %q is not a connector name", name)
		}
		if err := validateConnectorPolicy("enterprise.machine_policy.connectors."+name, policy); err != nil {
			return err
		}
	}
	wsl := e.MachinePolicy.WindowsWSL
	for _, knob := range []struct {
		name, value string
		allowed     []string
	}{
		{"agent_sessions", wsl.AgentSessions, []string{WSLAgentSessionsBlock, WSLAgentSessionsAllow}},
		{"platform", wsl.Platform, []string{WSLPlatformLeave, WSLPlatformDisable}},
		{"editor_settings", wsl.EditorSettings, []string{WSLEditorSettingsRepair, WSLEditorSettingsReport, WSLEditorSettingsAllow}},
		{"claude_desktop_key", wsl.ClaudeDesktopKey, []string{WSLClaudeDesktopKeyMerge, WSLClaudeDesktopKeyCreate}},
	} {
		if err := oneOf("enterprise.machine_policy.windows_wsl."+knob.name, knob.value, knob.allowed...); err != nil {
			return err
		}
	}
	if err := oneOf("enterprise.trust.mode", e.Trust.Mode, EnterpriseTrustAuthenticode, EnterpriseTrustHashPinned); err != nil {
		return err
	}
	for _, signer := range e.Trust.AllowedSigners {
		if !enterpriseSHA256Pattern.MatchString(strings.ToLower(strings.TrimSpace(signer))) {
			return fmt.Errorf("config: enterprise.trust.allowed_signers entry %q must be a SHA-256 certificate thumbprint", signer)
		}
	}
	if err := oneOf("enterprise.coexistence.per_user_install", e.Coexistence.PerUserInstall, PerUserInstallMigrate, PerUserInstallBlock, PerUserInstallIgnore); err != nil {
		return err
	}
	for _, proxy := range []struct{ name, value string }{
		{"https_proxy", e.Network.HTTPSProxy}, {"no_proxy", e.Network.NoProxy},
	} {
		if strings.ContainsAny(proxy.value, "\x00\r\n") {
			return fmt.Errorf("config: enterprise.network.%s is malformed", proxy.name)
		}
	}
	if strings.TrimSpace(e.Network.HTTPSProxy) != "" {
		if _, err := netguard.ParseEgressProxyURL(e.Network.HTTPSProxy); err != nil {
			return fmt.Errorf("config: enterprise.network.https_proxy: %w", err)
		}
	}
	return nil
}

// EgressProxy returns the administrator's outbound proxy for this managed
// deployment (enterprise.network). The zero value keeps the
// process-environment proxy behavior.
func (e EnterpriseConfig) EgressProxy() netguard.EgressProxy {
	return netguard.EgressProxy{
		HTTPSProxy: strings.TrimSpace(e.Network.HTTPSProxy),
		NoProxy:    strings.TrimSpace(e.Network.NoProxy),
	}
}

func validateConnectorPolicy(prefix string, p EnterpriseConnectorPolicy) error {
	if err := oneOf(prefix+".ownership", p.Ownership, MachinePolicyOwnershipMerge, MachinePolicyOwnershipVerifyOnly, MachinePolicyOwnershipOff); err != nil {
		return err
	}
	if err := oneOf(prefix+".managed_hooks_only", p.ManagedHooksOnly, ManagedHooksOnlyEnforce, ManagedHooksOnlyPreserve); err != nil {
		return err
	}
	if err := oneOf(prefix+".foreign_hooks", p.ForeignHooks, ForeignHooksRemove, ForeignHooksReport, ForeignHooksAllow); err != nil {
		return err
	}
	if err := oneOf(prefix+".higher_precedence_sources", p.HigherPrecedenceSources, HigherPrecedenceFail, HigherPrecedenceWarn); err != nil {
		return err
	}
	for _, digest := range p.AllowedHooks {
		value := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(digest), "sha256:"))
		if !enterpriseSHA256Pattern.MatchString(value) {
			return fmt.Errorf("config: %s.allowed_hooks entry %q must be a SHA-256 digest", prefix, digest)
		}
	}
	floorPrefix := "enterprise.machine_policy.connectors." + versionFloorConnector
	if prefix != floorPrefix && strings.TrimSpace(p.VersionFloor) != "" {
		return fmt.Errorf("config: %s.version_floor is not a setting; the Claude Code version floor is %s.version_floor", prefix, floorPrefix)
	}
	if err := oneOf(prefix+".version_floor", p.VersionFloor, ClaudeVersionFloorEnforce, ClaudeVersionFloorReport, ClaudeVersionFloorOff); err != nil {
		return err
	}
	harnessPrefix := "enterprise.machine_policy.connectors." + copilotHarnessConnector
	for _, knob := range [][2]string{{"harness_preference", p.HarnessPreference}, {"local_harness", p.LocalHarness}} {
		if prefix != harnessPrefix && strings.TrimSpace(knob[1]) != "" {
			return fmt.Errorf("config: %s.%s is not a setting; the GitHub Copilot in VS Code setting is %s.%s", prefix, knob[0], harnessPrefix, knob[0])
		}
	}
	if err := oneOf(prefix+".harness_preference", p.HarnessPreference, CopilotHarnessPreferenceSDK, CopilotHarnessPreferenceUnmanaged); err != nil {
		return err
	}
	return oneOf(prefix+".local_harness", p.LocalHarness, CopilotLocalHarnessGovern, CopilotLocalHarnessRetire)
}

// validateEnterpriseAgentPrefix accepts an absolute, administrator-style
// install prefix. User-writable trees are refused: an agent binary found
// there could be anything a user put there. The key applies to Linux and
// macOS only, so it is checked with Unix path semantics on every OS: a config
// shared with Windows hosts loads there too.
func validateEnterpriseAgentPrefix(prefix string) error {
	clean := strings.TrimSpace(prefix)
	if clean == "" || !strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") ||
		strings.ContainsAny(clean, ":\x00\r\n") || path.Clean(clean) != clean {
		return fmt.Errorf("config: enterprise.enrollment.agent_prefixes entry %q must be a clean absolute path", prefix)
	}
	if clean == "/" {
		return fmt.Errorf("config: enterprise.enrollment.agent_prefixes entry %q is not an install prefix", prefix)
	}
	for _, forbidden := range []string{"/home", "/Users", "/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/root", "/var/root"} {
		if clean == forbidden || strings.HasPrefix(clean, forbidden+"/") {
			return fmt.Errorf("config: enterprise.enrollment.agent_prefixes entry %q is inside %s, which users can write", prefix, forbidden)
		}
	}
	return nil
}

func validateEnterpriseHomeRoot(root string) error {
	clean := strings.TrimSpace(root)
	if clean == "" || !strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") || strings.ContainsAny(clean, "\x00\r\n") {
		return fmt.Errorf("config: enterprise.enrollment.home_roots entry %q must be an absolute path", root)
	}
	for _, forbidden := range []string{"/", "/tmp", "/var/tmp", "/dev/shm", "/etc", "/usr", "/bin", "/sbin", "/lib", "/opt", "/proc", "/sys", "/run", "/var"} {
		if strings.TrimRight(clean, "/") == forbidden || clean == forbidden {
			return fmt.Errorf("config: enterprise.enrollment.home_roots entry %q is not an allowed home parent", root)
		}
	}
	return nil
}

// validateManagedStandalonePolicyInputs requires every policy input the
// standalone local engine reads to be unwritable by standard users. The
// Secure Client profile never consults these (its local detectors are off),
// so the check applies only to standalone. Absent directories are fine:
// the engine falls back to its embedded rule packs.
func validateManagedStandalonePolicyInputs(cfg *Config) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	serviceAccount := os.Getenv(managed.WindowsServiceAccountEnv)
	seen := map[string]bool{}
	check := func(label, dir string) error {
		dir = strings.TrimSpace(dir)
		if dir == "" || seen[dir] {
			return nil
		}
		seen[dir] = true
		if _, err := os.Lstat(dir); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("config: inspect %s %s: %w", label, dir, err)
		}
		if err := managed.ValidateTrustedServiceRuntimeDir(dir, label, serviceAccount); err != nil {
			return fmt.Errorf("config: managed standalone %s is not administrator-controlled: %w", label, err)
		}
		if err := managed.ValidateServiceCanReadTree(dir, label, serviceAccount); err != nil {
			return fmt.Errorf("config: managed standalone %w", err)
		}
		return nil
	}
	if err := check("policy_dir", cfg.PolicyDir); err != nil {
		return err
	}
	// Every pack the gateway can load: the v9 rule_pack and custom_packs
	// selections, profile packs and the v8 rule_pack_dir alike.
	dirs := cfg.ReferencedRulePackDirs()
	for _, label := range RulePackCheckOrder(dirs) {
		if err := check(label, dirs[label]); err != nil {
			return err
		}
	}
	return nil
}

func oneOf(name, value string, allowed ...string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("config: %s=%q is not one of %s", name, value, strings.Join(allowed, ", "))
}
