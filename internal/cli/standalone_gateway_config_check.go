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
			return fmt.Errorf("the gateway service cannot read the guardrail rule pack that %s names: %v", configPath, err)
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

// checkJSONLDestinationPaths refuses the first enabled jsonl destination
// whose path local.JSONLPathProblem rejects, naming the destination, the
// path and the rule (config validate, Windows Setup). gatewayAccount, the
// Windows gateway service account Setup checks for, may also write the
// folder, and must be able to: a folder only administrators can write
// passed Setup, which runs as one, and the gateway then did not start
// (GAP-1118).
func checkJSONLDestinationPaths(compiled *config.ObservabilityV8CompiledConfig, gatewayAccount string) error {
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
			folder := filepath.Dir(filepath.Clean(path))
			return &config.V8SemanticError{
				Path:    "$.observability.destinations",
				Summary: fmt.Sprintf("destination %q writes %s, but %v", destination.Name, path, err),
				Action: fmt.Sprintf("grant that account Modify on the folder, for example: icacls \"%s\" /grant \"%s:(OI)(CI)M\", "+
					"or point the destination at a folder it can write", folder, gatewayAccount),
			}
		}
	}
	return nil
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
