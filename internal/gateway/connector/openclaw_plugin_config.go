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
	"sort"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// openClawPluginConfigSchema reads the same manifest installed into OpenClaw.
// The manifest, rather than a second list of accepted keys, owns this contract.
func openClawPluginConfigSchema() (map[string]interface{}, *jsonschema.Schema, error) {
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
		return nil, nil, fmt.Errorf("read bundled OpenClaw plugin manifest: %w", err)
	}
	var manifest struct {
		ID           string                 `json:"id"`
		ConfigSchema map[string]interface{} `json:"configSchema"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.ID != "defenseclaw" || manifest.ConfigSchema == nil {
		return nil, nil, fmt.Errorf("bundled OpenClaw plugin manifest has no DefenseClaw config schema")
	}
	schema, err := compileOpenClawPluginSchema(manifest.ConfigSchema)
	if err != nil {
		return nil, nil, err
	}
	return manifest.ConfigSchema, schema, nil
}

func compileOpenClawPluginSchema(document map[string]interface{}) (*jsonschema.Schema, error) {
	data, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode OpenClaw plugin config schema: %w", err)
	}
	schema, err := jsonschema.CompileString("https://defenseclaw.invalid/openclaw-plugin-config.json", string(data))
	if err != nil {
		return nil, fmt.Errorf("compile OpenClaw plugin config schema: %w", err)
	}
	return schema, nil
}

// keepOpenClawSchemaValue retains each accepted value and removes a rejected
// property at the smallest object boundary. The full schema validates the
// resulting config before it is written; unsupported schema shapes fail setup.
func keepOpenClawSchemaValue(value interface{}, document map[string]interface{}, location string, removed *[]string) (interface{}, bool, error) {
	schema, err := compileOpenClawPluginSchema(document)
	if err != nil {
		return nil, false, err
	}
	if schema.Validate(value) == nil {
		return value, true, nil
	}
	object, ok := value.(map[string]interface{})
	if !ok {
		*removed = append(*removed, location)
		return nil, false, nil
	}
	properties, _ := document["properties"].(map[string]interface{})
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		child, known := properties[key].(map[string]interface{})
		childLocation := location + "." + key
		if !known {
			if document["additionalProperties"] == false {
				delete(object, key)
				*removed = append(*removed, childLocation)
			}
			continue
		}
		kept, valid, err := keepOpenClawSchemaValue(object[key], child, childLocation, removed)
		if err != nil {
			return nil, false, err
		}
		if valid {
			object[key] = kept
		} else {
			delete(object, key)
		}
	}
	if schema.Validate(object) == nil {
		return object, true, nil
	}
	*removed = append(*removed, location)
	return nil, false, nil
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
	document, schema, err := openClawPluginConfigSchema()
	if err != nil {
		return err
	}
	if schema.Validate(current) == nil {
		return nil
	}
	var removed []string
	kept, valid, err := keepOpenClawSchemaValue(current, document, "plugins.entries.defenseclaw.config", &removed)
	if err != nil {
		return err
	}
	if !valid {
		kept = map[string]interface{}{}
	}
	if err := schema.Validate(kept); err != nil {
		return fmt.Errorf("OpenClaw plugin config cannot be migrated to the bundled schema: %w", err)
	}
	backupPath, err := saveOpenClawPluginConfigBackup(configPath, original)
	if err != nil {
		return err
	}
	entry["config"] = kept
	log.Printf("openclaw: migrated %d plugin config field(s) to the bundled schema; prior openclaw.json is saved at %s", len(removed), backupPath)
	return nil
}
