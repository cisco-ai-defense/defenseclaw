// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// connectorConfigRootPins are the connector config roots an environment
// variable can move whose Setup binds a managed record to one file under the
// root: the record's captured target names the root that setup chose.
var connectorConfigRootPins = []struct {
	connector, variable, logical string
	defaultRoot                  []string
	file                         []string
}{
	{"claudecode", "CLAUDE_CONFIG_DIR", "settings.json", []string{".claude"}, []string{"settings.json"}},
	{"opencode", "OPENCODE_CONFIG_DIR", "config", []string{".config", "opencode"}, []string{"plugins", "defenseclaw.js"}},
	{"codex", "CODEX_HOME", "config.toml", []string{".codex"}, []string{"config.toml"}},
}

// PinConnectorConfigRootsForCommand pins the config roots for one connector
// command and returns a func that puts the variables back, so the pin does not
// outlive the command in a longer-lived process.
func PinConnectorConfigRootsForCommand(dataDir string) func() {
	saved := make(map[string]*string, len(connectorConfigRootPins))
	for _, pin := range connectorConfigRootPins {
		if value, ok := os.LookupEnv(pin.variable); ok {
			saved[pin.variable] = &value
		} else {
			saved[pin.variable] = nil
		}
	}
	PinConnectorConfigRootsToSetup(dataDir)
	return func() {
		for variable, value := range saved {
			if value == nil {
				_ = os.Unsetenv(variable)
			} else {
				_ = os.Setenv(variable, *value)
			}
		}
	}
}

// An explicit setup command passes its selected root to the gateway it starts.
// Other gateway starts keep the root recorded in the managed backup.
func codexExplicitSetupTarget() string {
	requested := strings.TrimSpace(os.Getenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP"))
	if requested == "" || !filepath.IsAbs(requested) {
		return ""
	}
	current := codexHomeDir()
	if !sameManagedTargetPath(requested, current) {
		return ""
	}
	return current
}

// PinConnectorConfigRootsToSetup points the gateway process at the connector
// config roots its setup bound, whatever the shell that started the gateway
// has set. A restart with only CLAUDE_CONFIG_DIR set to another directory
// otherwise stopped at "managed backup target mismatch" in connector setup,
// and the agent identity and profile were gone until a normal start
// (GAP-0433). It returns one sentence per variable it changed.
func PinConnectorConfigRootsToSetup(dataDir string) []string {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	var notes []string
	for _, pin := range connectorConfigRootPins {
		if pin.connector == "codex" && codexExplicitSetupTarget() != "" {
			continue
		}
		b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, pin.connector, pin.logical))
		if err != nil || b.Connector != pin.connector || b.LogicalName != pin.logical {
			continue
		}
		captured, err := normalizeManagedTargetPath(b.Path)
		if err != nil {
			continue
		}
		root := captured
		for range pin.file {
			root = filepath.Dir(root)
		}
		if !sameManagedTargetPath(filepath.Join(append([]string{root}, pin.file...)...), captured) {
			continue
		}
		defaultRoot := homePath(pin.defaultRoot...)
		current := defaultRoot
		if configured := strings.TrimSpace(os.Getenv(pin.variable)); configured != "" {
			if abs, err := filepath.Abs(configured); err == nil {
				current = filepath.Clean(abs)
			}
		}
		if sameManagedTargetPath(current, root) {
			continue
		}
		started := "without " + pin.variable
		if _, set := os.LookupEnv(pin.variable); set {
			started = "with " + pin.variable + "=" + current
		}
		if sameManagedTargetPath(root, defaultRoot) {
			_ = os.Unsetenv(pin.variable)
		} else {
			_ = os.Setenv(pin.variable, root)
		}
		notes = append(notes, fmt.Sprintf(
			"the %s hooks were set up under %s, but this gateway was started %s; it keeps %s. "+
				"To move them, run defenseclaw guardrail disable --connector %s, then enable it again with %s set.",
			pin.connector, root, started, root, pin.connector, pin.variable))
	}
	return notes
}
