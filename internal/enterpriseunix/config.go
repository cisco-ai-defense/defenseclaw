// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// DefaultConfig is the configuration a fresh standalone install gets when
// the administrator supplies none: local policy engine in observe mode, no
// connectors, loopback listeners, the vendor default rule pack (rule_pack
// resolves under policy_dir). It is config_version 9, so a fresh install has
// nothing to migrate. Administrators replace it through their MDM; the
// apply unit or `ensure` activates the change.
func DefaultConfig(layout managed.StandaloneLayout) []byte {
	return []byte(fmt.Sprintf(`# DefenseClaw managed enterprise configuration (standalone profile).
# Administrator-owned. Edit through your MDM or configuration management;
# the lifecycle validates and applies every change.
config_version: 9
deployment_mode: managed_enterprise
data_dir: %s
policy_dir: %s
enterprise:
  profile: standalone
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
  rule_pack: default
`, layout.DataDir, layout.VendorPolicyDir))
}

// validatedConfig is an administrator config that passed every lifecycle
// check, with the settings the lifecycle renders from.
type validatedConfig struct {
	Raw                    []byte
	SHA                    string
	Connectors             []string
	HomeRoots              []string
	AgentPrefixes          []string
	HTTPSProxy             string
	NoProxy                string
	SelfUpdateDisabled     bool
	MachinePolicyOwnership map[string]string
	// RulePacks maps each rule-pack setting (config.ReferencedRulePackDirs:
	// the global, connector and profile packs and every custom_packs entry)
	// to the pack the config resolves it to. An unset pack follows
	// <policy_dir>/guardrail/default once that folder exists, which changes
	// no config byte, so the record keeps the resolved packs and ensure
	// applies (and restarts the gateway) when they change.
	RulePacks map[string]string
	// Loaded is the runtime config the checks loaded; machine policy is
	// published from it.
	Loaded *config.Config
	// Migration is set when the administrator config was config_version 8:
	// Raw is then the migrated config_version 9 document, and the apply
	// keeps the v8 bytes and the migration record next to config.yaml.
	Migration *configMigration
}

// configMigration is the v8 to v9 migration of an administrator config.
type configMigration struct {
	Source []byte
	Record config.MigrationRecord
	// EnvKey and EnvValue are the inline scanner key the migration moved
	// out of the config; the apply adds it to the service .env (secret:
	// never printed).
	EnvKey   string `json:"-"`
	EnvValue string `json:"-"`
}

// migrateConfigV9 takes a config_version 8 administrator config to 9 in
// memory (spec 2.0: ensure calls the migration library and accepts a v8
// config). It returns nil for a config that is not config_version 8. The
// data.json of policy_dir is read; audit.db operator rows are never moved
// on a managed host, only counted (local_enforcement_entries_ignored).
func (e *Env) migrateConfigV9(ctx context.Context, raw []byte, v8 *validatedConfig) (*config.MigrateV9Result, error) {
	if !config.NeedsMigrationV9(raw) {
		return nil, nil
	}
	policyDir := e.Layout.VendorPolicyDir
	if v8 != nil && v8.Loaded != nil && strings.TrimSpace(v8.Loaded.PolicyDir) != "" {
		policyDir = filepath.Clean(v8.Loaded.PolicyDir)
	}
	in := config.MigrateV9Input{
		ConfigPath:   e.Layout.ConfigPath,
		Source:       raw,
		PolicyDir:    policyDir,
		DataDir:      e.P(e.Layout.DataDir),
		DataJSONPath: e.P(filepath.Join(policyDir, "rego", "data.json")),
		AuditDBPath:  e.P(filepath.Join(e.Layout.DataDir, "audit.db")),
		Managed:      true,
		InMemory:     true,
		RulePackDigest: func(dir string) (string, error) {
			return guardrail.RulePackDigest(e.P(dir))
		},
	}
	envPinMu.Lock()
	restore := pinEnv(map[string]string{
		managed.DeploymentModeEnv:    managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	})
	result, err := config.MigrateV9(ctx, in)
	restore()
	envPinMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("migrate the config to config_version 9: %w", err)
	}
	return result, nil
}

// envPinMu serializes the temporary process-environment pins validation
// needs: the config loader reads the service pins from the environment.
var envPinMu sync.Mutex

// validateConfig checks the installed config.yaml bytes; see
// validateConfigSource.
func (e *Env) validateConfig(raw []byte) (*validatedConfig, error) {
	return e.validateConfigSource(raw, "")
}

// validateConfigSource checks raw as the standalone deployment's config: v8
// schema, observability graph, runtime load with the service pins, and the
// fixed layout the units assume. The bytes are always checked as the
// installed config.yaml; source, when set, is the file the administrator
// supplied (--config), and errors name it instead of the installed path.
func (e *Env) validateConfigSource(raw []byte, source string) (*validatedConfig, error) {
	validated, err := e.checkConfig(raw)
	if err != nil {
		if plain, ok := e.plainConfigProblem(err, source, raw); ok {
			return nil, &plainConfigError{msg: plain, err: err}
		}
		return nil, e.explainConfigError(err, source)
	}
	return validated, nil
}

// plainConfigError is a config problem in plain words; it keeps the
// diagnostic for errors.As.
type plainConfigError struct {
	msg string
	err error
}

func (e *plainConfigError) Error() string { return e.msg }
func (e *plainConfigError) Unwrap() error { return e.err }

// explainConfigError rewrites a config error for the managed host: it names
// the administrator's file, and a config_version problem says how to fix the
// file instead of pointing at `defenseclaw migrate`, a per-user command the
// enterprise packages do not ship.
func (e *Env) explainConfigError(err error, source string) error {
	message := err.Error()
	var yamlErr *config.V8YAMLError
	if errors.As(err, &yamlErr) {
		fixed := *yamlErr
		switch yamlErr.Code {
		case config.V8YAMLErrorVersionRequired, config.V8YAMLErrorVersionInvalid:
			fixed.Action = "add `config_version: 8` as the first line of the file"
		case config.V8YAMLErrorVersionUpgrade:
			fixed.Action = "write the file in the current (v8) format and set `config_version: 8`"
		case config.V8YAMLErrorVersionUnsupported:
			fixed.Action = "install the DefenseClaw enterprise package that matches this config, or set `config_version: 8`"
		}
		message = strings.Replace(message, yamlErr.Error(), fixed.Error(), 1)
	}
	if strings.Contains(message, "defenseclaw migrate") {
		message = strings.ReplaceAll(message, "run `defenseclaw migrate` to create a current source", "set `config_version: 8`")
		message = strings.ReplaceAll(message, "run `defenseclaw migrate`", "write the file in the current (v8) format and set `config_version: 8`")
	}
	if source != "" && source != e.Layout.ConfigPath {
		message = strings.ReplaceAll(message, e.Layout.ConfigPath, source)
	}
	if message == err.Error() {
		return err
	}
	return errors.New(message)
}

// checkConfig is the validation itself; the source path it reports is the
// installed config.yaml.
func (e *Env) checkConfig(raw []byte) (*validatedConfig, error) {
	if len(raw) == 0 {
		return nil, errors.New("config is empty")
	}
	if len(raw) > config.ObservabilityV8MaxSourceBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", config.ObservabilityV8MaxSourceBytes)
	}
	path := e.Layout.ConfigPath

	envPinMu.Lock()
	restore := pinEnv(map[string]string{
		managed.DeploymentModeEnv:    managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	})
	// Credential references resolve from the credentials already stored in
	// the secrets directory, so a config naming one that `enterprise secret
	// set` has not stored is refused before anything changes.
	compiled, compileErr := config.ParseCompileObservabilityV8(path, raw, config.ObservabilityV8CompileOptions{
		DefaultDataDir: e.Layout.DataDir, CredentialsDir: e.P(e.Layout.SecretsDir),
	})
	cfg, loadErr := config.LoadRuntimeV8InspectionCandidateFromBytes(path, raw)
	restore()
	envPinMu.Unlock()

	if compileErr != nil {
		return nil, fmt.Errorf("config does not compile: %w", compileErr)
	}
	if compiled == nil || compiled.Plan == nil {
		return nil, errors.New("config compiled to no observability plan")
	}
	if loadErr != nil {
		return nil, fmt.Errorf("config does not load: %w", loadErr)
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil, fmt.Errorf("config deployment_mode must be %s", managed.DeploymentModeManagedEnterprise)
	}
	if !cfg.StandaloneEnterprise() {
		return nil, fmt.Errorf("config enterprise.profile must be %s", managed.ProfileStandalone)
	}
	// On macOS an unset profile means secure_client to every process that
	// reads the config without the service pin (hooks, admin shells,
	// status), so the file itself must say standalone. The loader enforces
	// this for the host OS; checking the target OS here keeps plans built
	// on another host honest.
	if managed.DefaultEnterpriseProfile(e.GOOS) != managed.ProfileStandalone &&
		cfg.DeclaredEnterpriseProfile() != managed.ProfileStandalone {
		return nil, fmt.Errorf(
			"config must set enterprise.profile: %s: on %s a process that reads it without the service pin treats an unset profile as %s",
			managed.ProfileStandalone, e.GOOS, managed.DefaultEnterpriseProfile(e.GOOS),
		)
	}
	if clean := strings.TrimRight(cfg.DataDir, "/"); clean != e.Layout.DataDir {
		return nil, fmt.Errorf("config data_dir %q must be %s: the service sandbox only allows writes there", cfg.DataDir, e.Layout.DataDir)
	}
	if bind := strings.TrimSpace(cfg.Gateway.APIBind); bind != "" && bind != "127.0.0.1" {
		return nil, fmt.Errorf("config gateway.api_bind %q must be 127.0.0.1", bind)
	}
	if port := cfg.Gateway.APIPort; port != 0 && port != 18970 {
		return nil, fmt.Errorf("config gateway.api_port %d must be 18970: the socket unit owns that listener", port)
	}
	if err := e.checkRulePackDirs(cfg); err != nil {
		return nil, err
	}
	v := &validatedConfig{
		Raw:                    append([]byte(nil), raw...),
		SHA:                    sha256Bytes(raw),
		HomeRoots:              append([]string{}, cfg.Enterprise.Enrollment.HomeRoots...),
		AgentPrefixes:          append([]string{}, cfg.Enterprise.Enrollment.AgentPrefixes...),
		HTTPSProxy:             strings.TrimSpace(cfg.Enterprise.Network.HTTPSProxy),
		NoProxy:                strings.TrimSpace(cfg.Enterprise.Network.NoProxy),
		SelfUpdateDisabled:     cfg.Enterprise.Coexistence.SelfUpdateDisabled(),
		MachinePolicyOwnership: map[string]string{},
		Loaded:                 cfg,
	}
	v.RulePacks = map[string]string{}
	for label, dir := range cfg.ReferencedRulePackDirs() {
		if dir = strings.TrimSpace(dir); dir != "" {
			v.RulePacks[label] = filepath.Clean(dir)
		}
	}
	for name := range cfg.Guardrail.Connectors {
		connector := strings.ToLower(strings.TrimSpace(name))
		if connector == "" || !cfg.Guardrail.EffectiveEnabled(name) {
			continue
		}
		v.Connectors = append(v.Connectors, connector)
		v.MachinePolicyOwnership[connector] = cfg.Enterprise.MachinePolicy.PolicyFor(connector).Ownership
	}
	sort.Strings(v.Connectors)
	sort.Strings(v.HomeRoots)
	sort.Strings(v.AgentPrefixes)
	return v, nil
}

// checkRulePackDirs refuses rule packs the gateway cannot load or could
// rewrite itself: every effective rule pack must be outside data_dir and
// either ship with the vendor policies or already exist.
func (e *Env) checkRulePackDirs(cfg *config.Config) error {
	dirs := cfg.ReferencedRulePackDirs()
	vendor, err := policyassets.Files()
	if err != nil {
		return fmt.Errorf("embedded vendor policies: %w", err)
	}
	for _, label := range rulePackCheckOrder(dirs) {
		dir := strings.TrimSpace(dirs[label])
		if dir == "" {
			continue
		}
		clean := filepath.Clean(dir)
		if clean == e.Layout.DataDir || strings.HasPrefix(clean, e.Layout.DataDir+"/") {
			return fmt.Errorf("config %s %q is inside data_dir, which the gateway service can write; use %s or an administrator-owned directory under %s", label, dir, filepath.Join(e.Layout.VendorPolicyDir, "guardrail", "default"), e.Layout.PolicyDir)
		}
		if rel, ok := strings.CutPrefix(clean, e.Layout.VendorPolicyDir+"/"); ok {
			if !vendorPolicyDirExists(vendor, filepath.ToSlash(rel)) {
				return fmt.Errorf("config %s %q is not a rule pack the product ships", label, dir)
			}
			continue
		}
		if info, err := os.Stat(e.P(clean)); err != nil || !info.IsDir() {
			// The shipped packs exist under the vendor folder only once a
			// deployment is installed, so a first install cannot copy from
			// there (GAP-1429): the source release has the same packs.
			shipped := filepath.Join(e.Layout.VendorPolicyDir, "guardrail", "default")
			return fmt.Errorf("config %s %q does not exist; create the pack there before you apply the config, starting from a copy of policies/guardrail/default in the DefenseClaw source release (installed hosts also have it at %s), or set it to %s, which the deployment installs", label, dir, shipped, shipped)
		}
	}
	return nil
}

// checkRulePacksReadable refuses an administrator rule pack the gateway's
// service account cannot read. The lifecycle runs as root, which reads any
// mode, so a pack written under umask 077 passed every other check and
// failed only when the gateway started; an unset rule_pack_dir resolves to
// the same <policy_dir>/guardrail/default folder, so the rollback failed too.
func (e *Env) checkRulePacksReadable(v *validatedConfig, account Account) error {
	for _, label := range rulePackCheckOrder(v.RulePacks) {
		dir := v.RulePacks[label]
		if dir == e.Layout.VendorPolicyDir || strings.HasPrefix(dir, e.Layout.VendorPolicyDir+"/") {
			continue
		}
		if err := e.rulePackReadable(dir, account); err != nil {
			return fmt.Errorf("config %s %q: %w", label, dir, err)
		}
	}
	return nil
}

// RulePackServiceReadProblem says why the gateway service account could not
// read the rule pack at dir. It returns "" when the account can read it or
// the host has no service account. `rulepack validate` runs as an
// administrator, who reads any mode, so without this a pack the gateway
// cannot load still validated.
func (e *Env) RulePackServiceReadProblem(ctx context.Context, dir string) string {
	account, ok, err := e.Accounts.Lookup(ctx, e.Layout.ServiceUser)
	if err != nil || !ok {
		return ""
	}
	if err := e.rulePackReadable(filepath.Clean(dir), account); err != nil {
		return err.Error()
	}
	return ""
}

func (e *Env) rulePackReadable(dir string, account Account) error {
	for parent := filepath.Dir(dir); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
		uid, gid, mode, err := statOwnerMode(e.P(parent))
		if err == nil && mode.IsDir() && !accountMayAccess(uid, gid, mode, account, 0o1) {
			return fmt.Errorf("%s is %04o, so the %s service account cannot reach the rule pack below it; make it traversable (for example: chmod o+x %s) and retry", parent, mode.Perm(), e.Layout.ServiceUser, parent)
		}
	}
	root := e.P(dir)
	return filepath.WalkDir(root, func(full string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		uid, gid, mode, err := statOwnerMode(full)
		if err != nil {
			return err
		}
		need := os.FileMode(0o4)
		switch {
		case mode.IsDir():
			need = 0o5
		case !mode.IsRegular():
			return nil
		}
		if accountMayAccess(uid, gid, mode, account, need) {
			return nil
		}
		shown := dir
		if rel, relErr := filepath.Rel(root, full); relErr == nil && rel != "." {
			shown = filepath.Join(dir, rel)
		}
		return fmt.Errorf("%s is %04o, so the %s service account cannot read the rule pack; make it readable (for example: chmod -R u=rwX,go=rX %s) and retry", shown, mode.Perm(), e.Layout.ServiceUser, dir)
	})
}

// accountMayAccess reports whether account has the need bits (4 read,
// 1 search) on a path with this owner, group and mode. Supplementary
// groups are not considered: the service account has none.
func accountMayAccess(uid, gid int, mode os.FileMode, account Account, need os.FileMode) bool {
	perm := mode.Perm()
	switch {
	case uid == account.UID:
		perm >>= 6
	case gid == account.GID:
		perm >>= 3
	}
	return perm&need == need
}

// rulePackCheckOrder orders the rule-pack settings for a check:
// guardrail.rule_pack_dir first, then each connector setting whose pack
// differs from it. A connector that only inherits the global pack is not
// checked again, so a refusal names the key the administrator wrote: it
// named guardrail.connectors.amp.rule_pack_dir, which sorts first, for a
// config that set only guardrail.rule_pack_dir (GAP-1193).
func rulePackCheckOrder(dirs map[string]string) []string {
	global := "guardrail.rule_pack_dir"
	if _, ok := dirs["guardrail.rule_pack"]; ok {
		global = "guardrail.rule_pack"
	}
	globalDir, hasGlobal := dirs[global]
	globalDir = strings.TrimSpace(globalDir)
	order := []string{}
	if hasGlobal {
		order = append(order, global)
	}
	for _, label := range sortedKeys(dirs) {
		if label == global {
			continue
		}
		if dir := strings.TrimSpace(dirs[label]); hasGlobal && globalDir != "" && filepath.Clean(dir) == filepath.Clean(globalDir) {
			continue
		}
		order = append(order, label)
	}
	return order
}

func vendorPolicyDirExists(files []policyassets.File, rel string) bool {
	for _, file := range files {
		if strings.HasPrefix(file.Path, rel+"/") {
			return true
		}
	}
	return false
}

// machinePolicyEnabled lists connectors that publish machine policy.
func (v *validatedConfig) machinePolicyEnabled(goos string) []string {
	candidates := []string{}
	for _, connector := range v.Connectors {
		if v.MachinePolicyOwnership[connector] != config.MachinePolicyOwnershipOff {
			candidates = append(candidates, connector)
		}
	}
	return MachinePolicyConnectors(goos, candidates)
}

func pinEnv(values map[string]string) func() {
	previous := map[string]*string{}
	for key, value := range values {
		if old, ok := os.LookupEnv(key); ok {
			copyOld := old
			previous[key] = &copyOld
		} else {
			previous[key] = nil
		}
		_ = os.Setenv(key, value)
	}
	return func() {
		for key, old := range previous {
			if old == nil {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, *old)
			}
		}
	}
}
