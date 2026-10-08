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
