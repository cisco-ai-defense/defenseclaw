// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/local"
)

// validateStandaloneGatewayConfig proves the gateway service can load
// configPath before any service starts: it compiles the file with the strict
// v8 compiler the gateway runs at start, and loads every guardrail rule pack
// the gateway would load, with their custom_packs pins. Before, a config the
// gateway could not load was installed, and the administrator saw only SCM's
// "Failed to start service" while the reason stayed in a gateway log a failed
// first install's rollback deletes. dataDir is the service's DEFENSECLAW_HOME. The error
// names the file, the location in it and the reason, from the same safe
// diagnostic `config-v8 validate` prints. Environment-backed secret
// references are the gateway's to resolve in its own service identity, so
// their absence here is not an error; a protected credential reference must
// name a credential already stored in credentialsDir (empty: the secrets
// directory next to configPath). The process environment is restored
// afterwards: the compiler loads the data directory's .env.
func validateStandaloneGatewayConfig(configPath, dataDir, credentialsDir string) error {
	restore := snapshotProcessEnvironment()
	defer restore()
	var runtimeConfig *config.Config
	var compiled *config.ObservabilityV8CompiledConfig
	loaded, err := loadConfigV8FileWithCredentials(configPath, dataDir, credentialsDir)
	if err != nil {
		var secretError *config.V8SecretReferenceError
		if !errors.As(err, &secretError) || secretError.Credential {
			failure := configV8ValidationFailure(err)
			location := failure.Path
			// A syntax error is found by its line, not by a path in the
			// document (GAP-0607).
			var syntax *config.V8YAMLError
			if errors.As(err, &syntax) && syntax.Line > 0 {
				location = fmt.Sprintf("line %d", syntax.Line)
			}
			return fmt.Errorf("the gateway cannot load %s at %s: %s", configPath, location, failure.Reason)
		}
		// The service may resolve environment references that Setup cannot.
		// Continue both observability and runtime validation with the missing
		// token tolerated; unrelated semantic errors must still be refused.
		// Compile once with placeholder environment values so a missing
		// token cannot bypass the independent JSONL filesystem preflight.
		raw, readErr := readConfigV8Source(configPath)
		if readErr != nil {
			return readErr
		}
		secretsDir := credentialsDir
		if secretsDir == "" {
			secretsDir = managed.StandaloneSecretsDirForConfig(runtime.GOOS, configPath)
		}
		compiled, err = config.ParseCompileObservabilityV8(configPath, raw, config.ObservabilityV8CompileOptions{
			DefaultDataDir: dataDir,
			Secrets:        standalonePathPreflightSecrets{credentialsDir: secretsDir},
		})
		if err != nil {
			failure := configV8ValidationFailure(err)
			return fmt.Errorf("the gateway cannot load %s at %s: %s", configPath, failure.Path, failure.Reason)
		}
		runtimeConfig, err = config.LoadRuntimeV8InspectionCandidateFromBytes(configPath, raw)
		if err == nil {
			compiled.Plan, err = config.WithObservabilityV8ManagedAIDDestination(
				compiled.Plan, config.ObservabilityV8ManagedAIDOptionsFromConfig(runtimeConfig, raw))
		}
		if err == nil {
			var document *config.V8YAMLDocument
			document, err = config.ParseV8YAML(configPath, raw)
			if err == nil {
				err = validateRuntimeV8ConnectorRoster(document, runtimeConfig)
			}
		}
		if err != nil {
			failure := configV8ValidationFailure(err)
			return fmt.Errorf("the gateway cannot load %s at %s: %s", configPath, failure.Path, failure.Reason)
		}
	} else {
		runtimeConfig = loaded.runtime
		compiled = loaded.compiled
	}
	// A jsonl destination the gateway service cannot write stopped the
	// services, failed the readiness wait and rolled back (GAP-0908,
	// GAP-1118).
	var unsafe *config.V8SemanticError
	if err := checkJSONLDestinationPaths(compiled,
		strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))); errors.As(err, &unsafe) {
		return fmt.Errorf("the gateway cannot use %s: %s; %s", configPath, unsafe.Summary, unsafe.Action)
	}
	// The scanner files the config pins, which a scan loads only when they
	// match: a wrong pin was applied with no warning and failed every scan
	// that loads it (GAP-0664).
	if runtimeConfig != nil && !runtimeConfig.SecureClientIntegration() {
		if err := runtimeConfig.Scanners.CheckPinnedFiles(); err != nil {
			return fmt.Errorf("the gateway cannot use a scanner file that %s pins: %v", configPath, err)
		}
		// The inspection decode skips the listener check the gateway runs
		// at start: api_bind 0.0.0.0 was installed and failed the
		// transaction (GAP-0647).
		if err := config.ValidateManagedEnterpriseListenerBindings(runtimeConfig); err != nil {
			return fmt.Errorf("the gateway cannot use %s: %v", configPath, err)
		}
	}
	if runtimeConfig == nil || !runtimeConfig.Guardrail.Enabled {
		return nil
	}
	serviceAccount := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	for _, pack := range standaloneGatewayRulePackDirs(runtimeConfig) {
		// The check runs as an administrator or LocalSystem, who read any
		// folder, so the gateway service account's own access is checked
		// first: a pack with an explicit Deny for it loaded here, and the
		// install then failed with only "Failed to start service" (GAP-0095).
		if err := standaloneServiceCanReadTree(pack.dir, pack.label, serviceAccount); err != nil {
			return fmt.Errorf("%s that %s names: %v", standaloneRulePackUnreadableText, configPath, err)
		}
		if _, err := guardrail.LoadRulePack(pack.dir); err != nil {
			return fmt.Errorf("the gateway cannot load the guardrail rule pack %s that %s names: %v%s",
				pack.dir, configPath, err, rulePackNestedCopyHint(pack.dir, err))
		}
	}
	// The packs as the gateway builds them at start, custom_packs digest pins
	// included: a pin the gateway refuses kept it from starting, and the
	// lifecycle waited out its readiness timeout (GAP-0188).
	if err := gateway.CheckRulePacks(runtimeConfig); err != nil {
		hint := ""
		for _, pack := range standaloneGatewayRulePackDirs(runtimeConfig) {
			if hint = rulePackNestedCopyHint(pack.dir, err); hint != "" {
				break
			}
		}
		return fmt.Errorf("the gateway cannot load the guardrail rule packs that %s selects: %v%s", configPath, err, hint)
	}
	return nil
}

// compileStandaloneGatewayRepairRollbackConfig checks the installed config's
// content, startup semantics and paths outside Repair's ACL scope while a
// running gateway retains its last good policy. Repair later restamps managed
// ACLs and runs the strict service validator before activation.
func compileStandaloneGatewayRepairRollbackConfig(configPath, dataDir string) (*config.Config, error) {
	restore := snapshotProcessEnvironment()
	defer restore()
	loaded, err := loadConfigV8FileWithCredentials(configPath, dataDir, "")
	if err != nil {
		var secretError *config.V8SecretReferenceError
		if !errors.As(err, &secretError) {
			return nil, err
		}
		// Setup does not inherit environment secrets resolved by the gateway
		// service. An installed credential may also have ACL drift that Repair
		// restamps. Compile with placeholders only for environment values and
		// with a bounded, content-checked read of installed credentials.
		raw, err := readConfigV8Source(configPath)
		if err != nil {
			return nil, err
		}
		secretsDir := managed.StandaloneSecretsDirForConfig(runtime.GOOS, configPath)
		compiled, err := config.ParseCompileObservabilityV8(configPath, raw, config.ObservabilityV8CompileOptions{
			DefaultDataDir: dataDir,
			Secrets:        standaloneRepairRollbackSecrets{credentialsDir: secretsDir},
		})
		if err != nil {
			return nil, err
		}
		runtimeConfig, err := config.LoadRuntimeV8InspectionCandidateFromBytes(configPath, raw)
		if err != nil {
			return nil, err
		}
		if _, err := config.WithObservabilityV8ManagedAIDDestination(
			compiled.Plan, config.ObservabilityV8ManagedAIDOptionsFromConfig(runtimeConfig, raw)); err != nil {
			return nil, err
		}
		document, err := config.ParseV8YAML(configPath, raw)
		if err != nil {
			return nil, err
		}
		if err := validateRuntimeV8ConnectorRoster(document, runtimeConfig); err != nil {
			return nil, err
		}
		loaded = &loadedConfigV8File{runtime: runtimeConfig, compiled: compiled}
	}
	if loaded == nil || loaded.runtime == nil {
		return nil, errors.New("config compiler returned no runtime configuration")
	}
	if !loaded.runtime.StandaloneEnterprise() {
		return nil, fmt.Errorf("managed config resolves the %q enterprise profile, not %s",
			loaded.runtime.EnterpriseProfile(), managed.ProfileStandalone)
	}
	if err := config.ValidateManagedEnterpriseListenerBindings(loaded.runtime); err != nil {
		return nil, err
	}
	// The inspection loader omits the managed trust block, which also holds
	// this Windows-only content check. A configured allowlist cannot take
	// effect on Windows and would make the gateway refuse to restart.
	if err := config.ValidateManagedEnterpriseWindowsPeerAuthKnobs(loaded.runtime); err != nil {
		return nil, err
	}
	if err := checkJSONLDestinationPathsWithSkip(loaded.compiled,
		strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv)), func(path string) bool {
			return repairRollbackCanCreateJSONLInRestampedRuntime(path, dataDir)
		}); err != nil {
		return nil, fmt.Errorf("the gateway cannot use %s: %w", configPath, err)
	}
	if err := validateRepairRollbackPolicyInputs(loaded.runtime, configPath); err != nil {
		return nil, err
	}
	// Pins and rule-pack contents cannot be repaired by an ACL restamp. Read
	// them as Setup's elevated identity, without asking whether the service
	// account can currently traverse the managed paths.
	if err := loaded.runtime.Scanners.CheckPinnedFiles(); err != nil {
		return nil, err
	}
	if loaded.runtime.Guardrail.Enabled {
		for _, pack := range standaloneGatewayRulePackDirs(loaded.runtime) {
			if _, err := guardrail.LoadRulePack(pack.dir); err != nil {
				return nil, fmt.Errorf("the gateway cannot load the guardrail rule pack %s that %s names: %w",
					pack.dir, configPath, err)
			}
		}
		if err := gateway.CheckRulePacks(loaded.runtime); err != nil {
			return nil, fmt.Errorf("the gateway cannot load the guardrail rule packs that %s selects: %w",
				configPath, err)
		}
	}
	return loaded.runtime, nil
}

// standaloneRulePackUnreadableText starts the refusal of a rule pack the
// gateway service account cannot read. The Windows Setup preflight reports
// it as rule_pack_unreadable, the code the enumerator's report gets and the
// troubleshooting page documents (GAP-0314).
const standaloneRulePackUnreadableText = "the gateway service cannot read the guardrail rule pack"

// standalonePathPreflightSecrets lets compilation reach path checks when the
// service, rather than Setup, provides an environment token. Protected
// credentials still use the real resolver and cannot be invented here.
type standalonePathPreflightSecrets struct{ credentialsDir string }

func (standalonePathPreflightSecrets) ResolveObservabilitySecret(string) (string, bool) {
	return "preflight", true
}

func (secrets standalonePathPreflightSecrets) ResolveObservabilityCredential(name string) (string, bool) {
	return config.ResolveObservabilityV8ProtectedCredential(secrets.credentialsDir, name)
}

type standaloneRepairRollbackSecrets struct{ credentialsDir string }

func (standaloneRepairRollbackSecrets) ResolveObservabilitySecret(string) (string, bool) {
	return "preflight", true
}

func (secrets standaloneRepairRollbackSecrets) ResolveObservabilityCredential(name string) (string, bool) {
	return resolveRepairRollbackCredential(name, secrets.credentialsDir)
}

// checkJSONLDestinationPaths refuses the first enabled jsonl destination
// whose path local.JSONLPathProblem rejects, naming the destination, the
// path and the rule (config validate, Windows Setup). gatewayAccount, the
// Windows gateway service account Setup checks for, may also write the
// folder, and must be able to: a folder only administrators can write
// passed Setup, which runs as one, and the gateway then did not start
// (GAP-1118).
func checkJSONLDestinationPaths(compiled *config.ObservabilityV8CompiledConfig, gatewayAccount string) error {
	return checkJSONLDestinationPathsWithSkip(compiled, gatewayAccount, nil)
}

func checkJSONLDestinationPathsWithSkip(compiled *config.ObservabilityV8CompiledConfig, gatewayAccount string, skipACLForMissingFile func(string) bool) error {
	if compiled == nil || compiled.Plan == nil {
		return nil
	}
	var allowedWriters []string
	if gatewayAccount != "" {
		allowedWriters = []string{gatewayAccount}
	}
	for _, destination := range compiled.Plan.Destinations() {
		if destination.Kind != config.ObservabilityV8DestinationJSONL || !destination.Enabled || destination.Generated {
			continue
		}
		path := destination.Transport.Path
		// Repair can restamp the exact runtime root before activation. A
		// missing destination file directly under it then inherits the
		// repaired ACL; all existing files and other folders remain checked.
		if skipACLForMissingFile != nil && skipACLForMissingFile(path) {
			continue
		}
		if problem := local.JSONLPathProblem(path, allowedWriters...); problem != "" {
			return &config.V8SemanticError{
				Path:    "$.observability.destinations",
				Summary: fmt.Sprintf("destination %q writes %s, which %s", destination.Name, path, problem),
				Action:  "point it at a file only its owner can read and write (or a missing file, which the gateway creates) in a folder only its owner (an administrator or the gateway account) can write",
			}
		}
		if gatewayAccount == "" {
			continue
		}
		if err := standaloneServiceCanWriteFile(path, gatewayAccount); err != nil {
			// icacls cannot grant on a folder that is not there: name the
			// nearest one that is, which the gateway creates the rest
			// below (GAP-0027).
			folder := standaloneNearestExistingFolder(path)
			return &config.V8SemanticError{
				Path:    "$.observability.destinations",
				Summary: fmt.Sprintf("destination %q writes %s, but %v", destination.Name, path, err),
				Action: fmt.Sprintf("grant that account Modify on the folder, for example: icacls \"%s\" /grant \"%s:(OI)(CI)M\", "+
					"or point the destination at a folder it can write", folder, gatewayAccount),
			}
		}
		if rotation := destination.Transport.Rotation; rotation != nil && rotation.Compress {
			// Compression reads each rotated file back (GAP-1432).
			if err := standaloneServiceCanReadRotatedFile(path, gatewayAccount); err != nil {
				return &config.V8SemanticError{
					Path:    "$.observability.destinations",
					Summary: fmt.Sprintf("destination %q writes %s, but %v", destination.Name, path, err),
					Action:  "grant that account Modify on the existing file (or let it inherit the folder permissions), or set rotation compress to false on the destination",
				}
			}
		}
	}
	return nil
}

// standaloneNearestExistingFolder is the deepest folder above path that
// exists, or the root when none does.
func standaloneNearestExistingFolder(path string) string {
	folder := filepath.Dir(filepath.Clean(path))
	for {
		if info, err := os.Lstat(folder); err == nil && info.IsDir() {
			return folder
		}
		parent := filepath.Dir(folder)
		if parent == folder {
			return folder
		}
		folder = parent
	}
}

// standaloneServiceCanWriteFile checks that the gateway service account can
// write a jsonl destination file (a no-op off Windows). Before a first
// install the account does not exist yet; the gateway reports it at start.
// A seam for tests.
var standaloneServiceCanWriteFile = func(path, serviceAccount string) error {
	err := managed.ValidateServiceCanWriteFile(path, serviceAccount)
	if managed.IsServiceAccountUnresolved(err) {
		return nil
	}
	return err
}

// standaloneServiceCanReadRotatedFile checks that the gateway service
// account can read back the rotated files of a jsonl destination that
// compresses them (a no-op off Windows). A seam for tests.
var standaloneServiceCanReadRotatedFile = func(path, serviceAccount string) error {
	err := managed.ValidateServiceCanReadRotatedFile(path, serviceAccount)
	if managed.IsServiceAccountUnresolved(err) {
		return nil
	}
	return err
}

// standaloneGatewayRuntimeCandidate decodes configPath as the gateway does,
// without resolving secret references, or returns nil.
func standaloneGatewayRuntimeCandidate(configPath string) *config.Config {
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil
	}
	raw, err := readConfigV8Source(absPath)
	if err != nil {
		return nil
	}
	candidate, err := config.LoadRuntimeV8InspectionCandidateFromBytes(absPath, raw)
	if err != nil {
		return nil
	}
	return candidate
}

// rulePackNestedCopyHint names a copy of a pack folder inside itself, which
// copying the pack folder onto an existing one creates (Copy-Item -Recurse,
// cp -r). The loader reported only an unexpected YAML component deep inside
// it (GAP-0558).
func rulePackNestedCopyHint(dir string, err error) string {
	var packErr *guardrail.RulePackError
	if !errors.As(err, &packErr) || packErr.Code != "inventory_unexpected" {
		return ""
	}
	first, _, found := strings.Cut(packErr.Path, "/")
	if !found || !strings.EqualFold(first, filepath.Base(filepath.Clean(dir))) {
		return ""
	}
	nested := filepath.Join(dir, first)
	if info, statErr := os.Lstat(nested); statErr != nil || !info.IsDir() {
		return ""
	}
	return fmt.Sprintf("; %s is a copy of the pack inside itself (copying the pack folder onto an existing one creates it): remove that folder and run again", nested)
}

// standaloneServiceCanReadTree checks that the gateway service account can
// read a rule pack (a no-op off Windows and without an account). Before a
// first install the service, and so its account, does not exist yet; the
// install checks again once it does. A seam for tests.
var standaloneServiceCanReadTree = func(root, label, serviceAccount string) error {
	err := managed.ValidateServiceCanReadTree(root, label, serviceAccount)
	if managed.IsServiceAccountUnresolved(err) {
		return nil
	}
	return err
}

// standaloneRulePack is a rule pack directory and the config key that
// selects it.
type standaloneRulePack struct{ label, dir string }

// standaloneGatewayRulePackDirs lists the distinct rule pack directories the
// gateway loads for cfg: the global one, every connector's and every
// profile's, each under the config key the administrator wrote
// (config.RulePackCheckOrder). A custom_packs entry that nothing selects is
// not loaded. An empty directory selects the embedded packs and is always
// loadable.
func standaloneGatewayRulePackDirs(cfg *config.Config) []standaloneRulePack {
	dirs := cfg.ReferencedRulePackDirs()
	seen := map[string]bool{}
	packs := []standaloneRulePack{}
	for _, label := range config.RulePackCheckOrder(dirs) {
		dir := strings.TrimSpace(dirs[label])
		if dir == "" || seen[dir] || strings.HasPrefix(label, "guardrail.custom_packs.") {
			continue
		}
		seen[dir] = true
		packs = append(packs, standaloneRulePack{label: label, dir: dir})
	}
	return packs
}

// snapshotProcessEnvironment returns a function that restores the process
// environment exactly as it is now.
func snapshotProcessEnvironment() func() {
	saved := os.Environ()
	return func() {
		want := map[string]string{}
		for _, entry := range saved {
			if key, value, ok := strings.Cut(entry, "="); ok && key != "" {
				want[key] = value
			}
		}
		for _, entry := range os.Environ() {
			if key, _, ok := strings.Cut(entry, "="); ok && key != "" {
				if _, keep := want[key]; !keep {
					_ = os.Unsetenv(key)
				}
			}
		}
		for key, value := range want {
			if current, set := os.LookupEnv(key); !set || current != value {
				_ = os.Setenv(key, value)
			}
		}
	}
}
