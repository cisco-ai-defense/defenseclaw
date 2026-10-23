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
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/local"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
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
	// Tetragon is enterprise.tetragon as the sensor helper's drop-in renders
	// it, with the caps config alone decides (the OS, Plane C) applied.
	Tetragon tetragonIntent
	// Migration is set when the administrator config was config_version 8:
	// Raw is then the migrated config_version 9 document, and the apply
	// keeps the v8 bytes and the migration record next to config.yaml.
	Migration *configMigration
	// Source is the file the administrator supplied (--config), or "" for
	// the installed config.yaml; refusals name it.
	Source string
	// FailModeRepair is set when Raw is the installed config with a Cursor
	// hook_fail_mode the 1.0.0-1.0.2 migration rewrote to open restored to
	// closed; the apply stores it as migration-v9.json.
	FailModeRepair *config.MigrationRecord
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

// repairMigratedCursorFailMode is config.RepairMigratedCursorFailMode on
// the installed config: the repaired config, validated, with the migration
// record the apply stores next to it, or nil when the record proves no
// rewrite (no record means no change). A record that is there but cannot be
// read (not a regular file, too large) or decoded (G-small loop 4), or that
// decodes without the fields every migration writes (G-small loop round 2,
// config.DecodeMigrationRecord), is an error: the run never reports a Cursor
// fail mode the record proves rewritten as settled.
func (e *Env) repairMigratedCursorFailMode(installed *validatedConfig) (*validatedConfig, error) {
	if fromBundle, err := e.installedConfigFromBundle(); err != nil || fromBundle {
		return nil, err
	}
	recordPath := config.MigrationRecordPath(e.Layout.ConfigPath)
	raw, err := readBounded(e.P(recordPath), maxInputBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", recordPath, err)
	}
	record, err := config.DecodeMigrationRecord(raw)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", recordPath, err)
	}
	repaired, updated, ok := config.RepairMigratedCursorFailMode(installed.Raw, record)
	if !ok {
		return nil, nil
	}
	validated, err := e.validateConfig(repaired)
	if err != nil {
		return nil, fmt.Errorf("the config with its Cursor hook_fail_mode restored to closed does not validate: %w", err)
	}
	validated.FailModeRepair = &updated
	return validated, nil
}

// installedConfigFromBundle reports whether the installed config belongs to
// a signed policy bundle: its config generation record names a bundle, or a
// bundle is current in the bundle store. An unreadable record counts as a
// bundle's, so the v9 Cursor repair never rewrites an explicit, signed value
// (a bundle whose bytes match an old migration result).
func (e *Env) installedConfigFromBundle() (bool, error) {
	state, err := configwrite.ReadGenerationState(e.P(e.Layout.ConfigPath))
	switch {
	case err == nil && state.BundleID != "":
		return true, nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return true, nil
	}
	current, err := e.bundleStore().LoadState()
	if err != nil {
		return false, fmt.Errorf("read the policy bundle state: %w", err)
	}
	return current.Current != nil, nil
}

// envPinMu serializes the temporary process-environment pins validation
// needs: the config loader reads the service pins from the environment.
var envPinMu sync.Mutex

// loadConfigCandidate loads raw as the installed config.yaml the way the
// gateway does (the service pins set), without checkConfig's compile and
// layout checks: for the read-only views that describe a config ensure
// already accepted.
func (e *Env) loadConfigCandidate(raw []byte) (*config.Config, error) {
	envPinMu.Lock()
	defer envPinMu.Unlock()
	restore := pinEnv(map[string]string{
		managed.DeploymentModeEnv:    managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	})
	defer restore()
	return config.LoadRuntimeV8InspectionCandidateFromBytes(e.Layout.ConfigPath, raw)
}

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
	if plain, ok := e.managedEnvReferenceProblem(raw, source); ok {
		return nil, &plainConfigError{msg: plain, err: errManagedEnvReference}
	}
	validated, err := e.checkConfig(raw)
	if err != nil {
		if plain, ok := e.plainConfigProblem(err, source, raw); ok {
			return nil, &plainConfigError{msg: plain, err: err}
		}
		return nil, e.explainConfigError(err, source)
	}
	if source != "" {
		if err := config.ValidateManagedStandaloneLiteralCandidate(validated.Loaded, raw); err != nil {
			return nil, e.explainConfigError(err, source)
		}
	}
	validated.Source = source
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
// the administrator's file, and points at setting `config_version: 9`
// instead of `defenseclaw migrate`, a per-user command the enterprise
// packages do not ship. plainConfigProblem words every YAML error itself.
func (e *Env) explainConfigError(err error, source string) error {
	message := err.Error()
	if strings.Contains(message, "defenseclaw migrate") {
		message = strings.ReplaceAll(message, "run `defenseclaw migrate` to create a current source", "set `config_version: 9`")
		message = strings.ReplaceAll(message, "run `defenseclaw migrate`", "write the file in the current (v9) format and set `config_version: 9`")
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
	if err := config.ValidateManagedStandaloneConfig(raw, cfg, compiled.Plan, e.Layout); err != nil {
		return nil, err
	}
	if err := e.checkRulePackDirs(cfg); err != nil {
		return nil, err
	}
	if err := e.checkJSONLDestinations(compiled.Plan); err != nil {
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
	// The singular guardrail.connector (the shape the per-user CLI writes)
	// enrols its connector too unless guardrail.connectors disables it, as
	// in the enumerator (GAP-0263).
	names := []string{cfg.Guardrail.Connector}
	for name := range cfg.Guardrail.Connectors {
		names = append(names, name)
	}
	for _, name := range names {
		connector := strings.ToLower(strings.TrimSpace(name))
		if connector == "" || contains(v.Connectors, connector) || !cfg.Guardrail.EffectiveEnabled(name) {
			continue
		}
		v.Connectors = append(v.Connectors, connector)
		v.MachinePolicyOwnership[connector] = cfg.Enterprise.MachinePolicy.PolicyFor(connector).Ownership
	}
	sort.Strings(v.Connectors)
	sort.Strings(v.HomeRoots)
	sort.Strings(v.AgentPrefixes)
	v.Tetragon = tetragonIntentOf(cfg, e.GOOS, v.Connectors)
	return v, nil
}

// checkJSONLDestinations refuses, before anything changes, a jsonl
// destination the gateway cannot write: on Linux a path outside the
// folders its sandbox may write, and a path that is a directory, a link or
// a device, or in a folder other accounts can write. The gateway refused
// them only at start, with runtime_unavailable, and ensure rolled back
// (GAP-0890).
func (e *Env) checkJSONLDestinations(plan *config.ObservabilityV8Plan) error {
	if plan == nil {
		return nil
	}
	for _, destination := range plan.Destinations() {
		if destination.Kind != config.ObservabilityV8DestinationJSONL || !destination.Enabled || destination.Generated {
			continue
		}
		path := filepath.Clean(destination.Transport.Path)
		if problem := local.JSONLPathProblem(e.P(path)); problem != "" {
			return fmt.Errorf("observability destination %q writes %s, which %s; a jsonl destination writes a file only the gateway account can read and write (mode 0600, or a missing file it creates) in a folder only root and the gateway account can write",
				destination.Name, path, problem)
		}
		if problem, err := e.jsonlACLProblem(context.Background(), path); err != nil {
			return fmt.Errorf("inspect macOS ACL of observability destination %q at %s: %w", destination.Name, path, err)
		} else if problem != "" {
			return fmt.Errorf("observability destination %q writes %s, which %s", destination.Name, path, problem)
		}
		// The gateway opens the file as its service account, so it must pass
		// through every folder above it, whether or not the file exists yet
		// (GAP-1484).
		if problem := e.jsonlParentTraversalProblem(path); problem != "" {
			return fmt.Errorf("observability destination %q writes %s, which %s; give the %s gateway service account search (x) access to every folder above the file",
				destination.Name, path, problem, e.Layout.ServiceUser)
		}
		if _, err := os.Lstat(e.P(path)); errors.Is(err, os.ErrNotExist) {
			if problem := e.jsonlMissingParentProblem(path); problem != "" {
				return fmt.Errorf("observability destination %q writes %s, which %s; choose a directory the %s gateway service account can create and write",
					destination.Name, path, problem, e.Layout.ServiceUser)
			}
		}
		// A safe parent does not make an existing file writable. The gateway
		// opens it as the service account with O_APPEND and never changes its
		// owner or mode. A fresh install may not have that account yet.
		if info, err := os.Lstat(e.P(path)); err == nil && info.Mode().IsRegular() {
			account, ok, err := e.Accounts.Lookup(context.Background(), e.Layout.ServiceUser)
			if err != nil {
				return fmt.Errorf("look up gateway service account for observability destination %q: %w", destination.Name, err)
			}
			owner, _, err := e.OwnerOf(e.P(path))
			if err != nil {
				return fmt.Errorf("check owner of observability destination %q: %w", destination.Name, err)
			}
			if !ok || owner != account.UID || info.Mode().Perm()&0o200 == 0 || info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("observability destination %q writes %s, which the %s gateway service account cannot append to; make the existing file owned by %s with mode 0600, or remove it so the gateway can create it",
					destination.Name, path, e.Layout.ServiceUser, e.Layout.ServiceUser)
			}
		}
	}
	return nil
}

var jsonlACLReader posixacl.Reader = posixacl.System

// jsonlParentTraversalProblem reports an existing folder above path that the
// gateway service account cannot pass through. Folders the lifecycle owns
// get their owner and mode at apply and are skipped; an account that does
// not exist yet passes only where other users may.
func (e *Env) jsonlParentTraversalProblem(path string) string {
	account, ok, err := e.Accounts.Lookup(context.Background(), e.Layout.ServiceUser)
	if err != nil {
		return fmt.Sprintf("cannot be checked: looking up the %s gateway service account failed: %v", e.Layout.ServiceUser, err)
	}
	if !ok {
		account = Account{UID: -1, GID: -1}
	}
	owned := map[string]bool{}
	for _, dir := range e.managedDirs(account, false) {
		if !dir.External {
			owned[filepath.Clean(dir.Path)] = true
		}
	}
	for dir := filepath.Dir(path); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if owned[dir] {
			continue
		}
		info, err := os.Lstat(e.P(dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("is below %s, which cannot be inspected: %v", dir, err)
		}
		if !info.IsDir() {
			// A link or file in the path is refused by the path checks.
			continue
		}
		uid, gid, err := e.OwnerOf(e.P(dir))
		if err != nil {
			return fmt.Sprintf("is below %s, whose owner cannot be inspected: %v", dir, err)
		}
		allowed := accountMayAccess(uid, gid, info.Mode(), account, 0o1)
		if e.GOOS == "linux" {
			acl, err := jsonlACLReader.Read(e.P(dir), info.Mode())
			if err != nil {
				return fmt.Sprintf("is below %s, whose ACL cannot be inspected: %v", dir, err)
			}
			allowed = acl.Allows(uid, gid, info.Mode(), account.UID, account.GID, 0o1)
		}
		if !allowed {
			return fmt.Sprintf("is below %s (mode %04o, owner uid %d), which the %s gateway service account cannot pass through", dir, info.Mode().Perm(), uid, e.Layout.ServiceUser)
		}
		if _, entry, err := e.darwinServiceACLDenial(context.Background(), []string{e.P(dir)}, map[string][]string{e.P(dir): {"search"}}); err != nil {
			return fmt.Sprintf("is below %s, whose macOS ACL cannot be inspected: %v", dir, err)
		} else if entry != "" {
			return fmt.Sprintf("is below %s, whose macOS ACL entry %q keeps the %s gateway service account from passing through", dir, entry, e.Layout.ServiceUser)
		}
	}
	return ""
}

// jsonlMissingParentProblem checks the first existing parent or ancestor.
// The gateway creates missing subdirectories as its service account;
// lifecycle-created service directories are available after apply.
func (e *Env) jsonlMissingParentProblem(path string) string {
	parent := filepath.Dir(path)
	for dir := parent; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		// These roots are created for the gateway during a fresh install.
		if dir == e.Layout.DataDir ||
			(e.GOOS == "linux" && dir == e.Layout.LogDir) ||
			(e.GOOS == "darwin" && dir == filepath.Join(e.Layout.LogDir, "gateway")) {
			if _, err := os.Lstat(e.P(dir)); errors.Is(err, os.ErrNotExist) {
				return ""
			}
		}
		info, err := os.Lstat(e.P(dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("cannot inspect the existing ancestor %s: %v", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Sprintf("cannot create its missing directory below %s, which is not a regular directory", dir)
		}
		account, ok, err := e.Accounts.Lookup(context.Background(), e.Layout.ServiceUser)
		if err != nil || !ok {
			return fmt.Sprintf("cannot confirm the %s gateway service account can create its missing directory below %s", e.Layout.ServiceUser, dir)
		}
		uid, gid, err := e.OwnerOf(e.P(dir))
		if err != nil {
			return fmt.Sprintf("cannot inspect the owner of %s: %v", dir, err)
		}
		allowed := accountMayAccess(uid, gid, info.Mode(), account, 0o3)
		if e.GOOS == "linux" {
			acl, err := jsonlACLReader.Read(e.P(dir), info.Mode())
			if err != nil {
				return fmt.Sprintf("cannot inspect the ACL of %s: %v", dir, err)
			}
			allowed = acl.Allows(uid, gid, info.Mode(), account.UID, account.GID, 0o3)
		}
		if !allowed {
			return fmt.Sprintf("cannot create its missing directory below %s as the %s gateway service account", dir, e.Layout.ServiceUser)
		}
		// The gateway creates the file in an existing parent, and a missing
		// directory below an existing ancestor.
		need, what := []string{"add_file", "search"}, "cannot create the file in"
		if dir != parent {
			need, what = []string{"add_subdirectory", "search"}, "cannot create its missing directory below"
		}
		if _, entry, err := e.darwinServiceACLDenial(context.Background(), []string{e.P(dir)}, map[string][]string{e.P(dir): need}); err != nil {
			return fmt.Sprintf("cannot inspect the macOS ACL of %s: %v", dir, err)
		} else if entry != "" {
			return fmt.Sprintf("%s %s as the %s gateway service account: the macOS ACL entry %q denies it", what, dir, e.Layout.ServiceUser, entry)
		}
		return ""
	}
	return ""
}

func pathWithin(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimRight(dir, "/")+"/")
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
	for _, label := range config.RulePackCheckOrder(dirs) {
		dir := strings.TrimSpace(dirs[label])
		if dir == "" {
			continue
		}
		clean := filepath.Clean(dir)
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
		// The gateway loads every pack, profile packs included, only from an
		// administrator-controlled directory and refuses to start otherwise.
		// Refuse here, before anything is activated, instead of failing the
		// activation and rolling back (GAP-0301).
		if err := e.Trust(e.P(clean), TrustRuntimeDir); err != nil {
			return fmt.Errorf("config %s %q is not administrator-controlled, so the gateway would refuse to start with it: %w; make the directory and its parents owned by root and not writable by group or others, then retry", label, dir, err)
		}
	}
	return nil
}

// checkCandidateAssets builds the rule packs the config selects, with its
// guardrail.rules layers, the way the gateway does when it starts, and checks
// its webhook URLs. A layer the gateway would refuse (a duplicate suppression
// id, an unknown rule id, a missing protection pack) or a webhook it would
// drop is refused here, with its reason, before anything changes, instead of
// keeping the gateway from starting or going unnoticed. The check is
// registered by the gateway package; a build without it skips this.
func (e *Env) checkCandidateAssets(v *validatedConfig) error {
	if err := config.CheckCandidateAssets(v.Loaded); err != nil {
		// A pack reference or digest the gateway refuses, in the same plain
		// words as the other config refusals (GAP-0547).
		if plain, ok := e.plainConfigProblem(err, v.Source, v.Raw); ok {
			return &plainConfigError{msg: plain, err: err}
		}
		return fmt.Errorf("config does not build: %w", err)
	}
	return nil
}

// checkRulePacksReadable refuses an administrator rule pack the gateway's
// service account cannot read. The lifecycle runs as root, which reads any
// mode, so a pack written under umask 077 passed every other check and
// failed only when the gateway started; an unset rule_pack_dir resolves to
// the same <policy_dir>/guardrail/default folder, so the rollback failed too.
// It also refuses a sandbox packs folder other accounts could read or the
// gateway cannot (sandboxPackDirProblem). Every ensure plans with it, so a
// folder opened up while config.yaml stayed the same is refused as well
// (GAP-0403); the config load already refused a profile pack that is looser
// than its base or does not match its pin (GAP-0268).
func (e *Env) checkRulePacksReadable(v *validatedConfig, account Account) error {
	if problem := e.sandboxPackDirProblem(context.Background(), v.Loaded); problem != "" {
		return errors.New(problem)
	}
	for _, label := range config.RulePackCheckOrder(v.RulePacks) {
		dir := v.RulePacks[label]
		// Shipped packs are absent before the first install. Once present,
		// their files are subject to the same trust and readability checks.
		if pathWithin(dir, e.Layout.VendorPolicyDir) {
			if _, err := os.Lstat(e.P(dir)); errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		// The gateway refuses an untrusted pack only when it starts, so
		// ensure restarted it into a failed start and rolled back with a
		// cause-less activation_failed (GAP-0546).
		if err := e.Trust(e.P(dir), TrustRulePack); err != nil {
			return fmt.Errorf("config %s %q is not administrator-controlled: %v; %s", label, dir, err, rulePackTrustAdvice)
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
	// The macOS ACL rights the service account needs on each path.
	needs := map[string][]string{}
	var paths []string
	for parent := filepath.Dir(dir); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
		_, _, mode, err := statOwnerMode(e.P(parent))
		uid, gid, ownerErr := e.OwnerOf(e.P(parent))
		if err == nil {
			err = ownerErr
		}
		if err == nil && mode.IsDir() && !accountMayAccess(uid, gid, mode, account, 0o1) {
			return fmt.Errorf("%s is %04o, so the %s service account cannot reach the rule pack below it; %s", parent, mode.Perm(), e.Layout.ServiceUser, e.serviceGroupTraverseFix(parent))
		}
		if err == nil && mode.IsDir() {
			paths, needs[e.P(parent)] = append(paths, e.P(parent)), []string{"search"}
		}
	}
	root := e.P(dir)
	err := e.rulePackModesReadable(dir, root, account, func(full string, isDir bool) {
		paths, needs[full] = append(paths, full), []string{"read"}
		if isDir {
			needs[full] = []string{"list", "read", "search"}
		}
	})
	if err != nil {
		return err
	}
	// A macOS ACL entry can deny the service account what the mode bits
	// give it (GAP-1442).
	denied, entry, err := e.darwinServiceACLDenial(context.Background(), paths, needs)
	if err != nil {
		return fmt.Errorf("cannot inspect the macOS ACLs of the rule pack: %w", err)
	}
	if entry != "" {
		shown := e.canonical(denied)
		return fmt.Errorf("%s has the macOS ACL entry %q, so the %s service account cannot read the rule pack; remove that entry (`chmod -N %s` removes every entry of it) and retry",
			shown, entry, e.Layout.ServiceUser, shown)
	}
	return nil
}

// rulePackModesReadable walks the rule pack at root (dir, as shown) and
// refuses the first entry the owner and mode bits keep from the service
// account; visit sees every folder and file it passed.
func (e *Env) rulePackModesReadable(dir, root string, account Account, visit func(full string, isDir bool)) error {
	return filepath.WalkDir(root, func(full string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		_, _, mode, err := statOwnerMode(full)
		if err != nil {
			return err
		}
		uid, gid, err := e.OwnerOf(full)
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
			visit(full, mode.IsDir())
			return nil
		}
		shown := dir
		if rel, relErr := filepath.Rel(root, full); relErr == nil && rel != "." {
			shown = filepath.Join(dir, rel)
		}
		// The service group reads the pack; other accounts are not given
		// access (GAP-0258).
		return fmt.Errorf("%s is %04o, so the %s service account cannot read the rule pack; let the %s service group read it without opening it to other accounts (for example: chown -R root:%s %s && chmod -R u=rwX,g=rX %s) and retry",
			shown, mode.Perm(), e.Layout.ServiceUser, e.Layout.ServiceGroup, e.Layout.ServiceGroup, dir, dir)
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
