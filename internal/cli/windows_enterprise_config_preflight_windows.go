// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsEnterpriseStandaloneLayoutForPreflight is replaceable in tests.
var windowsEnterpriseStandaloneLayoutForPreflight = managed.StandaloneWindowsLayout
var windowsEnterpriseStandaloneRuntimeCandidateCheck = config.ValidateManagedStandaloneRuntimeCandidate

// windowsEnterpriseStandaloneConfigSource refuses an administrator config
// that a standard user could change before the lifecycle reads it, naming
// the account and the icacls fix. The installer refused it later, as a
// 1603 lifecycle error that named only a SID (GAP-0562). Tests replace it.
var windowsEnterpriseStandaloneConfigSource = func(path string) error {
	err := managed.ValidateTrustedFilePath(path, "config")
	if err == nil {
		return nil
	}
	if text, ok := managed.DescribeUntrustedSource("config", path, err); ok {
		return errors.New(text)
	}
	return fmt.Errorf("refusing untrusted config: %w", err)
}

// windowsEnterpriseStandaloneConfigPreflight refuses a standalone install,
// upgrade, ensure, or repair with a supplied config the gateway could not load
// before anything changes. The compile runs with the pins the gateway service
// starts with. A host whose trusted layout cannot be resolved is left to the
// lifecycle's own checks.
func windowsEnterpriseStandaloneConfigPreflight(configPath string) error {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil
	}
	if err := windowsEnterpriseStandaloneConfigSource(configPath); err != nil {
		return err
	}
	// A destination secret read from an environment variable never
	// resolves in the gateway service, whose environment the lifecycle
	// writes. It passed this check, Setup stopped the services, the gateway
	// failed to start and the rollback ended with 1603 after almost five
	// minutes, advising the per-user `defenseclaw keys set` (GAP-0966).
	if raw, err := os.ReadFile(configPath); err == nil {
		if err := refuseUnsupportedWindowsGuardrailConnectors(raw); err != nil {
			return fmt.Errorf("%s: %w; nothing was changed", configPath, err)
		}
		if refusal, found := config.ScanManagedEnvSecretReferences(raw).Refusal(configPath,
			"from an elevated prompt with `defenseclaw.exe enterprise secret set --name <name> --from-file <key file>`",
			config.EnterpriseSettingsReferenceURL); found {
			return fmt.Errorf("%s; fix it and run again (nothing was changed)", refusal)
		}
		if candidate, err := config.LoadRuntimeV8InspectionCandidateFromBytes(configPath, raw); err == nil {
			if err := config.ValidateManagedStandaloneLiteralCandidate(candidate, raw); err != nil {
				return fmt.Errorf("%s; fix it and run again (nothing was changed)", err)
			}
		}
	}
	return windowsEnterpriseStandaloneConfigCompile(configPath)
}

// The generic config decoder accepts proxy-only and retired connector names.
// On a managed Windows host the enumerator drops those names, so accepting
// them as installed hooks would report a protected deployment that has none.
// Inspect the source before migration can discard a removed connector key.
func refuseUnsupportedWindowsGuardrailConnectors(raw []byte) error {
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil // the normal config compiler reports the syntax error
	}
	guardrail, ok := document["guardrail"].(map[string]any)
	if !ok {
		return nil
	}
	var names []string
	if connector, ok := guardrail["connector"].(string); ok && strings.TrimSpace(connector) != "" {
		names = append(names, connector)
	}
	if connectors, ok := guardrail["connectors"].(map[string]any); ok {
		for name := range connectors {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if !enterprisehooks.WindowsStandaloneHookConnectorSupported(name) {
			return fmt.Errorf("guardrail connector %q is not supported by managed Windows hooks; remove it or select a supported Windows connector", name)
		}
	}
	return nil
}

// windowsEnterpriseStandaloneConfigCompile proves the gateway service can
// load configPath, with the pins it starts with.
func windowsEnterpriseStandaloneConfigCompile(configPath string) error {
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.ConfigPathEnv] = configPath
	restore := setTemporaryEnvironment(pins)
	defer restore()
	// Before anything is stopped: the enumerator and the gateway refuse a
	// pack a standard user can change, and Setup found out only after it had
	// stopped every service (GAP-0668). A config that does not compile is
	// left to the compiler check below, which names the line.
	if runtime := standaloneGatewayRuntimeCandidate(configPath); runtime != nil {
		if err := windowsEnterpriseStandaloneRulePacksTrusted(runtime); err != nil {
			return err
		}
	}
	// The administrator's config may sit anywhere, so credential references
	// resolve from the deployment's secrets directory, as in the service.
	if err := validateStandaloneGatewayConfig(configPath, layout.DataDir, layout.SecretsDir); err != nil {
		return fmt.Errorf("%v; fix it and run again (nothing was changed)", err)
	}
	// The generic compiler accepts settings that the installed service rejects
	// against the fixed Windows layout. Check the exact candidate bytes as if
	// they were at config.yaml before the transaction can replace that file.
	raw, err := readConfigV8Source(configPath)
	if err != nil {
		return err
	}
	if layout.GOOS == "" {
		layout.GOOS = "windows"
	}
	// Resolve omitted paths with the service's installed config identity,
	// rather than the arbitrary directory holding CONFIG=.
	restoreCandidate := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv: layout.ConfigPath,
	})
	defer restoreCandidate()
	candidate, err := config.LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, raw)
	if err == nil {
		err = config.ValidateManagedStandaloneConfig(raw, candidate, nil, layout)
	}
	if err == nil {
		err = windowsEnterpriseStandaloneRuntimeCandidateCheck(candidate)
	}
	if err != nil {
		return fmt.Errorf("%v; fix it and run again (nothing was changed)", err)
	}
	return nil
}

// windowsEnterpriseStandaloneKeptConfigPreflight runs that check on the
// installed config.yaml for an upgrade that keeps it: this release's gateway
// must load it, custom_packs pins included, before the lifecycle stops the
// services. Before, a pin the new gateway refused stopped all four services
// and failed only after the 4-minute readiness wait (GAP-0188). A host with
// no installed config has nothing to keep. A config_version 8 file is left to
// the transaction, which migrates it (writing its pins with this release's
// digest) and then runs the same check.
func windowsEnterpriseStandaloneKeptConfigPreflight() error {
	// An interrupted transaction may have left the candidate in config.yaml
	// while its services are stopped. The lifecycle must restore its recorded
	// preimage before this release inspects the kept config.
	if windowsEnterpriseStandaloneTransactionPending() {
		return nil
	}
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(layout.ConfigPath)
	if err != nil || config.NeedsMigrationV9(raw) {
		return nil
	}
	// The installed config is the one the gateway runs now: only the
	// compile is checked, so an upgrade is never refused for a reference
	// the running gateway resolves.
	if err := windowsEnterpriseStandaloneConfigSource(layout.ConfigPath); err != nil {
		return err
	}
	return windowsEnterpriseStandaloneConfigCompile(layout.ConfigPath)
}

// windowsEnterpriseStandaloneRulePackTrust is managed.ValidateTrustedRulePackTree;
// tests replace it.
var windowsEnterpriseStandaloneRulePackTrust = managed.ValidateTrustedRulePackTree

// windowsEnterpriseStandaloneRulePacksTrusted refuses a config that names a
// rule pack a standard user can change: the pack folder, the folders above
// it, or any file or folder in it (GAP-0668, GAP-0672). The refusal names the
// account, what it can change and the icacls commands that fix it. A pack
// that does not exist is left to the pack loader, which names it.
func windowsEnterpriseStandaloneRulePacksTrusted(runtime *config.Config) error {
	if runtime == nil {
		return nil
	}
	serviceAccount := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	dirs := runtime.ReferencedRulePackDirs()
	seen := map[string]bool{}
	for _, label := range config.RulePackCheckOrder(dirs) {
		dir := strings.TrimSpace(dirs[label])
		if dir == "" || seen[strings.ToLower(dir)] {
			continue
		}
		seen[strings.ToLower(dir)] = true
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := windowsEnterpriseStandaloneRulePackTrust(dir, label, serviceAccount); err != nil {
			if text, ok := managed.DescribeUntrustedRulePack(label, dir, serviceAccount, err); ok {
				return errors.New(text)
			}
			return fmt.Errorf("the rule pack %s (%s) is not administrator-controlled: %v; keep the pack, the files and folders in it and the folders above it writable only by Administrators and SYSTEM, and run it again (nothing was changed)", dir, label, err)
		}
	}
	return nil
}

// windowsEnterpriseStandaloneRulePackReaders is managed.StandardUserReadersOf;
// tests replace it.
var windowsEnterpriseStandaloneRulePackReaders = managed.StandardUserReadersOf

// windowsEnterpriseRulePackPrivacyProblems names each rule pack folder of cfg
// that every standard user can list and read. A pack is one guardrail
// profile's policy, and a user may see only their own: on Linux and macOS a
// pack is 0750 root and service group, but the Windows docs and Setup's fix
// left the inherited BUILTIN\Users read entry in place (GAP-0386). Each
// problem carries the icacls commands that leave read to SYSTEM,
// Administrators and the gateway service account.
func windowsEnterpriseRulePackPrivacyProblems(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	grant := managed.RulePackServiceReadGrant(os.Getenv(managed.WindowsServiceAccountEnv))
	// The packs the product ships are the same on every computer and public.
	var shipped string
	if layout, err := managed.StandaloneWindowsLayout(); err == nil {
		shipped = strings.ToLower(filepath.Clean(layout.InstallRoot))
	}
	dirs := cfg.ReferencedRulePackDirs()
	seen := map[string]bool{}
	var problems []string
	for _, label := range config.RulePackCheckOrder(dirs) {
		dir := strings.TrimSpace(dirs[label])
		if dir == "" || seen[strings.ToLower(dir)] {
			continue
		}
		seen[strings.ToLower(dir)] = true
		if lower := strings.ToLower(filepath.Clean(dir)); shipped != "" && (lower == shipped || strings.HasPrefix(lower, shipped+`\`)) {
			continue
		}
		if _, err := os.Lstat(dir); err != nil {
			continue
		}
		readers, err := windowsEnterpriseStandaloneRulePackReaders(dir)
		if err != nil || len(readers) == 0 {
			continue
		}
		labels := make([]string, 0, len(readers))
		removals := make([]string, 0, len(readers))
		for _, sid := range readers {
			labels = append(labels, windowsPrincipalLabel(sid))
			removals = append(removals, `"*`+sid+`"`)
		}
		problems = append(problems, fmt.Sprintf(
			"the rule pack %s (%s) is readable by %s, so every standard user can read this profile's policy; "+
				`from an elevated prompt run icacls "%s" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "%s", then icacls "%s" /remove:g %s /T /C`,
			dir, label, strings.Join(labels, ", "), dir, grant, dir, strings.Join(removals, " ")))
	}
	return problems
}

// applyWindowsEnterpriseInstalledConfigWarnings adds what the administrator
// should know about the installed config on every Setup /ensure, status and
// verify; none of it is a failure.
func applyWindowsEnterpriseInstalledConfigWarnings(result *enterprisestatus.Result) {
	cfg, err := loadWindowsEnterpriseStandaloneConfig("")
	if err != nil {
		return
	}
	addWindowsEnterpriseInstalledConfigWarnings(result, cfg)
}

// addWindowsEnterpriseInstalledConfigWarnings adds, in this order, each rule
// pack of cfg that standard users can read (the pack still decides, and a
// deployment that followed the earlier docs keeps working), then the sandbox
// policy warnings Linux and macOS print: each field where default_profile is
// looser than an assigned profile, and the advisories (GAP-0536).
func addWindowsEnterpriseInstalledConfigWarnings(result *enterprisestatus.Result, cfg *config.Config) {
	for _, problem := range windowsEnterpriseRulePackPrivacyProblems(cfg) {
		result.AddWarning("rule_pack_readable_by_users", problem)
	}
	result.AddSandboxPolicyWarnings(cfg, "windows")
}

// windowsEnterpriseStandaloneTransactionPending reports a lifecycle
// transaction an interrupted run left: its recovery restores the deployment
// as it was before, config and rule packs included. Tests replace it.
var windowsEnterpriseStandaloneTransactionPending = func() bool {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil || strings.TrimSpace(roots.MetadataPath) == "" {
		return false
	}
	_, err = os.Lstat(filepath.Join(filepath.Dir(roots.MetadataPath), "pending.json"))
	return err == nil
}

// windowsEnterpriseStandaloneRecoveryPending reports a record an
// interrupted lifecycle left that the installer recovers, under its lock,
// before it reads the deployment record for a refusal
// (Invoke-DefenseClawPreLayoutRecovery): a pending transaction, in the
// production StateRoot or this run's --state-root, and a state-purge intent,
// self-uninstall receipt or install-rollback intent in the profile's
// lifecycle folder. Their recovery can change the record (an interrupted
// first install rolls back to no deployment), so a refusal read from the
// record before that is the installer's to make. Tests replace it.
var windowsEnterpriseStandaloneRecoveryPending = func(opts *windowsEnterpriseLifecycleOptions) bool {
	if windowsEnterpriseStandaloneTransactionPending() {
		return true
	}
	stateRoot, lifecycleDir := "", ""
	if opts != nil {
		stateRoot = strings.TrimSpace(opts.stateRoot)
	}
	if roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone); err == nil {
		lifecycleDir = roots.LifecycleDir
	}
	return windowsEnterpriseStandaloneRecoveryRecords(stateRoot, lifecycleDir)
}

// windowsEnterpriseLifecycleRecoveryRecord names the lifecycle-folder
// records Invoke-DefenseClawPreLayoutRecovery recovers. Each name carries
// its scope's SHA-256, which this does not compute: any scope's record
// counts, which only leaves the refusal to the installer.
var windowsEnterpriseLifecycleRecoveryRecord = regexp.MustCompile(`^(purge|self-uninstall|install-rollback)-[0-9a-f]{64}\.json$`)

// windowsEnterpriseStandaloneRecoveryRecords reports a pending transaction
// under stateRoot (when set) or a recovery record in lifecycleDir (when
// set). A folder it cannot read counts as holding one.
func windowsEnterpriseStandaloneRecoveryRecords(stateRoot, lifecycleDir string) bool {
	if stateRoot != "" {
		if _, err := os.Lstat(filepath.Join(stateRoot, "install", "pending.json")); err == nil {
			return true
		}
	}
	if lifecycleDir == "" {
		return false
	}
	entries, err := os.ReadDir(lifecycleDir)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	for _, entry := range entries {
		if !entry.IsDir() && windowsEnterpriseLifecycleRecoveryRecord.MatchString(strings.ToLower(entry.Name())) {
			return true
		}
	}
	return false
}

// windowsEnterpriseStandaloneRepairRulePackPreflight checks the rule packs
// of the installed config before a repair stops the services: the trust
// check, and the packs as the gateway builds them at start, digest pins
// included. A pack a standard user changed was rejected by the running
// gateway, which kept its last good policy, but the documented repair then
// restarted the gateway into a failed start and left it stopped for every
// user (GAP-0672). Refused here, the running gateway keeps that policy. A
// pending transaction is left to its recovery, which restores the packs the
// deployment had. A repair that supplies a config installs that config,
// whose packs its own preflight already checked, so the packs only the old
// config selects do not block it (GAP-1194).
func windowsEnterpriseStandaloneRepairRulePackPreflight(suppliedConfig string) error {
	if strings.TrimSpace(suppliedConfig) != "" || windowsEnterpriseStandaloneTransactionPending() {
		return nil
	}
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(layout.ConfigPath)
	if err != nil || config.NeedsMigrationV9(raw) {
		return nil
	}
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.ConfigPathEnv] = layout.ConfigPath
	restore := setTemporaryEnvironment(pins)
	defer restore()
	runtime := standaloneGatewayRuntimeCandidate(layout.ConfigPath)
	if runtime == nil {
		return nil
	}
	if err := windowsEnterpriseStandaloneRulePacksTrusted(runtime); err != nil {
		return err
	}
	if !runtime.Guardrail.Enabled {
		return nil
	}
	if err := windowsEnterpriseStandaloneRulePackBuild(runtime); err != nil {
		return fmt.Errorf("the gateway cannot load the guardrail rule packs that the installed config %s selects, so a repair would restart it into a failed start: %v. The running gateway keeps its last good policy. Put the pack back as its digest pin names it, or apply a config with the new digest with Setup /ensure CONFIG=, then run the repair again (nothing was changed)", layout.ConfigPath, err)
	}
	return nil
}

// windowsEnterpriseStandaloneRulePackBuild is gateway.CheckRulePacks; tests
// replace it.
var windowsEnterpriseStandaloneRulePackBuild = gateway.CheckRulePacks
