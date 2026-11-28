// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package openclawschema checks an OpenClaw plugin config against the config
// schema of the bundled DefenseClaw plugin manifest.
//
// It is its own package so that the JSON Schema library stays out of the
// binaries that link the connector package but never run connector Setup:
// the hook (cmd/defenseclaw-hook) starts once per agent tool call, and the
// library compiles its meta-schemas at package init (1.7 ms and 1 MB per
// start). The gateway and the CLI, which run Setup, register Migrate with
// connector.SetOpenClawPluginConfigMigrator.
package openclawschema

import (
	"encoding/json"
	"fmt"
	"sort"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

// Migrate checks current, the plugins.entries.defenseclaw.config value of
// openclaw.json, against document, the manifest's configSchema. A valid
// value comes back unchanged with migrated false. Otherwise each rejected
// property is removed at the smallest object boundary, removed lists their
// locations, and the result is validated again against the full schema
// before it is returned with migrated true.
func Migrate(document map[string]interface{}, current interface{}) (kept interface{}, migrated bool, removed []string, err error) {
	schema, err := compile(document)
	if err != nil {
		return nil, false, nil, err
	}
	if schema.Validate(current) == nil {
		return current, false, nil, nil
	}
	kept, valid, err := keepValue(current, document, "plugins.entries.defenseclaw.config", &removed)
	if err != nil {
		return nil, false, nil, err
	}
	if !valid {
		kept = map[string]interface{}{}
	}
	if err := schema.Validate(kept); err != nil {
		return nil, false, nil, fmt.Errorf("OpenClaw plugin config cannot be migrated to the bundled schema: %w", err)
	}
	return kept, true, removed, nil
}

func compile(document map[string]interface{}) (*jsonschema.Schema, error) {
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

// keepValue retains each accepted value and removes a rejected property at
// the smallest object boundary. The full schema validates the resulting
// config before it is written; unsupported schema shapes fail setup.
func keepValue(value interface{}, document map[string]interface{}, location string, removed *[]string) (interface{}, bool, error) {
	schema, err := compile(document)
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
		kept, valid, err := keepValue(object[key], child, childLocation, removed)
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
