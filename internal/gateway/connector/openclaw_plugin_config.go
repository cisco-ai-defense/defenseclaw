// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// openClawPluginConfigMigrator checks the plugin config value against the
// manifest's config schema (openclawschema.Migrate). It is registered by the
// packages that run connector Setup, the gateway and the CLI, so that the
// JSON Schema library, which compiles its meta-schemas at package init, is
// not linked into the hook binary: the hook links this package for its
// hook runtime and never runs Setup. A binary that runs Setup without it
// refuses an openclaw.json that carries a plugin config instead of writing
// one it did not check.
var openClawPluginConfigMigrator func(document map[string]interface{}, current interface{}) (kept interface{}, migrated bool, removed []string, err error)

// SetOpenClawPluginConfigMigrator registers the plugin config check. Call it
// from package init. A nil check or a second registration panics, as the
// config registries do (RegisterV8SchemaCheck), so a program never runs with
// a check other than the one it linked (GAP-1862).
func SetOpenClawPluginConfigMigrator(migrate func(document map[string]interface{}, current interface{}) (kept interface{}, migrated bool, removed []string, err error)) {
	if migrate == nil {
		panic("connector: SetOpenClawPluginConfigMigrator with a nil check")
	}
	if openClawPluginConfigMigrator != nil {
		panic("connector: the OpenClaw plugin config check is registered twice")
	}
	openClawPluginConfigMigrator = migrate
}

// openClawPluginConfigSchema reads the config schema of the same manifest
// installed into OpenClaw. The manifest, rather than a second list of
// accepted keys, owns this contract.
func openClawPluginConfigSchema() (map[string]interface{}, error) {
	manifestPath := path.Join(openClawPluginRoot, "openclaw.plugin.json")
	data, err := openClawExtensionFS.ReadFile(manifestPath)
	if err != nil {
		// Source checkouts keep a placeholder until the extension is built.
		// Direct config patch tests still use the manifest's current schema;
		// Connector.Setup refuses the placeholder before reaching this path.
		if _, markerErr := openClawExtensionFS.ReadFile(path.Join(openClawPluginRoot, openClawPlaceholderName)); markerErr == nil {
			if _, sourceFile, _, ok := runtime.Caller(0); ok {
				data, err = os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "extensions", "defenseclaw", "openclaw.plugin.json"))
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read bundled OpenClaw plugin manifest: %w", err)
	}
	var manifest struct {
		ID           string                 `json:"id"`
		ConfigSchema map[string]interface{} `json:"configSchema"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.ID != "defenseclaw" || manifest.ConfigSchema == nil {
		return nil, fmt.Errorf("bundled OpenClaw plugin manifest has no DefenseClaw config schema")
	}
	return manifest.ConfigSchema, nil
}

func saveOpenClawPluginConfigBackup(configPath string, original []byte) (string, error) {
	digest := sha256.Sum256(original)
	backupPath := fmt.Sprintf("%s.defenseclaw-plugin-config.%x.bak", configPath, digest[:8])
	// safefile gives the backup the platform's owner-only protection: mode 0600
	// on POSIX and a private non-inherited DACL on Windows, where the mode bits
	// of os.OpenFile are ignored and the file would inherit the parent's access.
	file, err := safefile.CreateExclusive(backupPath)
	if errors.Is(err, fs.ErrExist) {
		if validateErr := safefile.ValidatePrivateFile(backupPath); validateErr != nil {
			return "", fmt.Errorf("existing OpenClaw plugin config backup is not a private regular file")
		}
		prior, readErr := os.ReadFile(backupPath)
		if readErr != nil || !bytes.Equal(prior, original) {
			return "", fmt.Errorf("existing OpenClaw plugin config backup differs from the current document")
		}
		return backupPath, nil
	}
	if err != nil {
		return "", fmt.Errorf("create OpenClaw plugin config backup: %w", err)
	}
	var written int
	if written, err = file.Write(original); err == nil && written != len(original) {
		err = fmt.Errorf("short OpenClaw plugin config backup write")
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("write OpenClaw plugin config backup: %w", err)
	}
	return backupPath, nil
}

func reconcileOpenClawPluginConfig(entry map[string]interface{}, configPath string, original []byte) error {
	current, exists := entry["config"]
	if !exists {
		return nil
	}
	document, err := openClawPluginConfigSchema()
	if err != nil {
		return err
	}
	if openClawPluginConfigMigrator == nil {
		return errors.New("OpenClaw plugin config check is not linked into this binary")
	}
	kept, migrated, removed, err := openClawPluginConfigMigrator(document, current)
	if err != nil || !migrated {
		return err
	}
	backupPath, err := saveOpenClawPluginConfigBackup(configPath, original)
	if err != nil {
		return err
	}
	entry["config"] = kept
	log.Printf("openclaw: migrated %d plugin config field(s) to the bundled schema; prior openclaw.json is saved at %s", len(removed), backupPath)
	return nil
}
