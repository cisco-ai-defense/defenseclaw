// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// validateStandaloneGatewayConfig proves the gateway service can load
// configPath before any service starts: it compiles the file with the strict
// v8 compiler the gateway runs at start, and loads every guardrail rule pack
// the gateway would load. Before, a config the gateway could not load was
// installed, and the administrator saw only SCM's "Failed to start service"
// while the reason stayed in a gateway log a failed first install's rollback
// deletes. dataDir is the service's DEFENSECLAW_HOME. The error
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
	loaded, err := loadConfigV8FileWithCredentials(configPath, dataDir, credentialsDir)
	if err != nil {
		var secretError *config.V8SecretReferenceError
		if errors.As(err, &secretError) && !secretError.Credential {
			return nil
		}
		failure := configV8ValidationFailure(err)
		return fmt.Errorf("the gateway cannot load %s at %s: %s", configPath, failure.Path, failure.Reason)
	}
	runtime := loaded.runtime
	if runtime == nil || !runtime.Guardrail.Enabled {
		return nil
	}
	serviceAccount := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	for _, pack := range standaloneGatewayRulePackDirs(runtime) {
		// The check runs as an administrator or LocalSystem, who read any
		// folder, so the gateway service account's own access is checked
		// first: a pack with an explicit Deny for it loaded here, and the
		// install then failed with only "Failed to start service" (GAP-0095).
		if err := standaloneServiceCanReadTree(pack.dir, pack.label, serviceAccount); err != nil {
			return fmt.Errorf("the gateway service cannot read the guardrail rule pack that %s names: %v", configPath, err)
		}
		if _, err := guardrail.LoadRulePack(pack.dir); err != nil {
			return fmt.Errorf("the gateway cannot load the guardrail rule pack %s that %s names: %v", pack.dir, configPath, err)
		}
	}
	return nil
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
