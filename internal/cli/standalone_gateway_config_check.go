// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
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
// name a credential already stored in the secrets directory. The process
// environment is restored afterwards: the compiler loads the data
// directory's .env.
func validateStandaloneGatewayConfig(configPath, dataDir string) error {
	restore := snapshotProcessEnvironment()
	defer restore()
	loaded, err := loadConfigV8File(configPath, dataDir)
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
	for _, dir := range standaloneGatewayRulePackDirs(runtime) {
		if _, err := guardrail.LoadRulePack(dir); err != nil {
			return fmt.Errorf("the gateway cannot load the guardrail rule pack %s that %s names: %v", dir, configPath, err)
		}
	}
	return nil
}

// standaloneGatewayRulePackDirs lists the distinct rule pack directories the
// gateway loads for cfg: the global one and every connector's. An empty
// directory selects the embedded packs and is always loadable.
func standaloneGatewayRulePackDirs(cfg *config.Config) []string {
	seen := map[string]bool{}
	dirs := []string{}
	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" || seen[dir] {
			return
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	add(cfg.Guardrail.RulePackDir)
	names := make([]string, 0, len(cfg.Guardrail.Connectors))
	for name := range cfg.Guardrail.Connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		add(cfg.EffectiveRulePackDirForConnector(name))
	}
	return dirs
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
