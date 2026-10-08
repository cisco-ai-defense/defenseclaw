// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	V8YAMLMaxSourceBytes    = ObservabilityV8MaxSourceBytes
	V8YAMLMaxNodes          = ObservabilityV8MaxYAMLNodes
	V8YAMLMaxDepth          = ObservabilityV8MaxYAMLDepth
	V8YAMLMaxMappingEntries = ObservabilityV8MaxMappingEntries
	v8YAMLConfigVersion     = ObservabilityV8ConfigVersion
)

// V8YAMLErrorCode is a stable machine-readable preflight failure category.
type V8YAMLErrorCode string

const (
	V8YAMLErrorSourceTooLarge      V8YAMLErrorCode = "yaml_source_too_large"
	V8YAMLErrorInvalidUTF8         V8YAMLErrorCode = "yaml_invalid_utf8"
	V8YAMLErrorSyntax              V8YAMLErrorCode = "yaml_syntax_invalid"
	V8YAMLErrorMultipleDocuments   V8YAMLErrorCode = "yaml_multiple_documents"
	V8YAMLErrorRootMappingRequired V8YAMLErrorCode = "yaml_root_mapping_required"
	V8YAMLErrorNodeLimit           V8YAMLErrorCode = "yaml_node_limit"
	V8YAMLErrorDepthLimit          V8YAMLErrorCode = "yaml_depth_limit"
	V8YAMLErrorMappingEntriesLimit V8YAMLErrorCode = "yaml_mapping_entries_limit"
	V8YAMLErrorDuplicateKey        V8YAMLErrorCode = "yaml_duplicate_key"
	V8YAMLErrorAliasForbidden      V8YAMLErrorCode = "yaml_alias_forbidden"
	V8YAMLErrorMergeKeyForbidden   V8YAMLErrorCode = "yaml_merge_key_forbidden"
	V8YAMLErrorCustomTagForbidden  V8YAMLErrorCode = "yaml_custom_tag_forbidden"
	V8YAMLErrorMappingKeyInvalid   V8YAMLErrorCode = "yaml_mapping_key_invalid"
	V8YAMLErrorScalarInvalid       V8YAMLErrorCode = "yaml_scalar_invalid"
	V8YAMLErrorVersionRequired     V8YAMLErrorCode = "config_version_required"
	V8YAMLErrorVersionInvalid      V8YAMLErrorCode = "config_version_invalid"
	V8YAMLErrorVersionUpgrade      V8YAMLErrorCode = "config_version_upgrade_required"
	V8YAMLErrorVersionUnsupported  V8YAMLErrorCode = "config_version_unsupported"
	V8YAMLErrorLegacyKeyForbidden  V8YAMLErrorCode = "legacy_config_key_forbidden"
)

// V8YAMLError never renders a mapping value or scalar payload. Paths retain
// mapping-key names so operators can locate a failure without exposing secrets.
type V8YAMLError struct {
	Code    V8YAMLErrorCode
	Source  string
	Path    string
	Line    int
	Column  int
	Summary string
	Action  string
	// FirstLine is the line of the first definition of a duplicate key, so
	// the CLI can say "the first one is at line 3" (GAP-2188).
	FirstLine int
}

func (e *V8YAMLError) Error() string {
	if e == nil {
		return ""
	}
	source := strings.TrimSpace(e.Source)
	if source == "" {
		source = "<config>"
	}
	if e.Line > 0 {
		source += ":" + strconv.Itoa(e.Line)
		if e.Column > 0 {
			source += ":" + strconv.Itoa(e.Column)
		}
	}
	if e.Code == V8YAMLErrorSyntax && e.Path == "$" {
		// The whole file does not parse: the line and the parser's reason are
		// the useful part, not the code or the root path (GAP-1767).
		message := source + ": " + e.Summary
		if e.Action != "" {
			message += "; " + e.Action
		}
		return message
	}
	path := ""
	if e.Path != "" {
		path = " " + e.Path + ":"
	}
	message := fmt.Sprintf("%s: [%s]%s %s", source, e.Code, path, e.Summary)
	if e.Action != "" {
		message += "; " + e.Action
	}
	return message
}

// V8YAMLDocument retains the yaml.Node tree for source diagnostics and a plain
// JSON-schema-friendly projection for the later schema/compiler stages.
type V8YAMLDocument struct {
	Source   string
	Document *yaml.Node
	Plain    map[string]any
}

// v8YAMLParseCacheMaxBytes bounds the source whose parse is kept: a larger
// tree would stay in memory for the life of the process.
const v8YAMLParseCacheMaxBytes = 1 << 20

// v8YAMLParseCache holds the last successful parse. One start or reload reads
// the same source through the strict parser, the schema pass, the compiler and
// the runtime decoder, and every one of them parsed it again: with 100
// profiles and 2,000 assignments (154 KB) that was eight parses and a third of
// the load, which made the gateway start 1.6 s slower (GAP-0264). The document
// is never written to after the parse.
var v8YAMLParseCache struct {
	sync.Mutex
	source string
	sum    [sha256.Size]byte
	doc    *V8YAMLDocument
}

// ParseV8YAML performs source-safety, exact-version, and targeted legacy-key
// checks. It does not apply defaults, migrations, environment overrides, schema
// validation, or observability compilation. The result is shared between
// callers that pass the same source and bytes: treat it as read-only.
func ParseV8YAML(source string, data []byte) (*V8YAMLDocument, error) {
	if len(data) > v8YAMLParseCacheMaxBytes {
		return parseV8YAML(source, data)
	}
	sum := sha256.Sum256(data)
	cache := &v8YAMLParseCache
	cache.Lock()
	if cache.doc != nil && cache.source == source && cache.sum == sum {
		doc := cache.doc
		cache.Unlock()
		return doc, nil
	}
	cache.Unlock()
	doc, err := parseV8YAML(source, data)
	if err != nil {
		return nil, err
	}
	cache.Lock()
	cache.source, cache.sum, cache.doc = source, sum, doc
	cache.Unlock()
	return doc, nil
}

func parseV8YAML(source string, data []byte) (*V8YAMLDocument, error) {
	if len(data) > V8YAMLMaxSourceBytes {
		return nil, v8Error(source, V8YAMLErrorSourceTooLarge, "$", nil,
			"configuration source exceeds the 4 MiB limit", "reduce the source to 4 MiB or less")
	}
	if !utf8.Valid(data) {
		return nil, v8Error(source, V8YAMLErrorInvalidUTF8, "$", nil,
			"configuration source is not valid UTF-8", "save the file as UTF-8 and retry")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil && !errors.Is(err, io.EOF) {
		return nil, v8SyntaxError(source, err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, v8SyntaxError(source, err)
		}
		return nil, v8Error(source, V8YAMLErrorMultipleDocuments, "$", v8DocumentRoot(&extra),
			"exactly one YAML document is allowed", "remove every document after the first")
	}

	root := v8DocumentRoot(&document)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, v8Error(source, V8YAMLErrorRootMappingRequired, "$", root,
			"the YAML document root must be a mapping",
			"define config_version and configuration sections as top-level keys")
	}

	walker := v8YAMLWalker{source: source}
	if err := walker.validate(root, "$", 1); err != nil {
		return nil, err
	}
	if err := validateV8YAMLVersion(source, root); err != nil {
		return nil, err
	}
	if v9SecureClientDocument(root) {
		// A Secure Client source stays on config_version 8 and keeps the
		// legacy-key errors of main (issue #1092); elsewhere the schema
		// refuses those keys.
		if err := rejectV8YAMLLegacyKeys(source, root); err != nil {
			return nil, err
		}
	}
	if err := rejectV9RemovedKeys(source, root); err != nil {
		return nil, err
	}
	if !v9SecureClientDocument(root) {
		dropRetiredScannerKeys(root)
	}
	plainValue, err := projectV8YAML(source, root, "$")
	if err != nil {
		return nil, err
	}
	plain, ok := plainValue.(map[string]any)
	if !ok { // Defensive: root shape was already checked.
		return nil, v8Error(source, V8YAMLErrorRootMappingRequired, "$", root,
			"the YAML root must project to an object", "use top-level string keys")
	}
	return &V8YAMLDocument{Source: source, Document: &document, Plain: plain}, nil
}

type v8YAMLWalker struct {
	source string
	nodes  int
}

func (w *v8YAMLWalker) validate(node *yaml.Node, path string, depth int) error {
	if node == nil {
		return nil
	}
	w.nodes++
	if w.nodes > V8YAMLMaxNodes {
		return v8Error(w.source, V8YAMLErrorNodeLimit, path, node,
			"parsed YAML exceeds the 65,536-node limit", "reduce repeated mappings and sequences")
	}
	if node.Kind == yaml.AliasNode {
		return v8Error(w.source, V8YAMLErrorAliasForbidden, path, node,
			"YAML aliases are not allowed in config.yaml", "replace the alias with explicit configuration")
	}
	if v8YAMLIsMerge(node) {
		return v8Error(w.source, V8YAMLErrorMergeKeyForbidden, path, node,
			"YAML merge keys are not allowed in config.yaml", "write every merged key explicitly")
	}
	if !v8YAMLTagAllowed(node) {
		return v8Error(w.source, V8YAMLErrorCustomTagForbidden, path, node,
			"custom or unsupported YAML tags are not allowed in config.yaml",
			"use ordinary mappings, sequences, and scalar values")
	}

	switch node.Kind {
	case yaml.MappingNode:
		if depth > V8YAMLMaxDepth {
			return v8Error(w.source, V8YAMLErrorDepthLimit, path, node,
				"YAML nesting exceeds the depth limit of 32", "flatten the configuration structure")
		}
		entries := len(node.Content) / 2
		if entries > V8YAMLMaxMappingEntries {
			return v8Error(w.source, V8YAMLErrorMappingEntriesLimit, path, node,
				"a YAML mapping exceeds the 1,024-entry limit", "reduce the number of entries in this mapping")
		}
		seen := make(map[string]*yaml.Node, entries)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if v8YAMLIsMerge(key) {
				return v8Error(w.source, V8YAMLErrorMergeKeyForbidden, path, key,
					"YAML merge keys are not allowed in config.yaml", "write every merged key explicitly")
			}
			// Report aliases/custom tags with their specific code before the
			// more general string-key diagnostic.
			if key.Kind == yaml.AliasNode || !v8YAMLTagAllowed(key) {
				if err := w.validate(key, path, depth); err != nil {
					return err
				}
			}
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return v8Error(w.source, V8YAMLErrorMappingKeyInvalid, path, key,
					"configuration mapping keys must be strings", "replace the key with a plain or quoted string")
			}
			keyPath := v8YAMLChildPath(path, key.Value)
			if err := w.validate(key, keyPath, depth); err != nil {
				return err
			}
			if first, exists := seen[key.Value]; exists {
				duplicate := v8Error(w.source, V8YAMLErrorDuplicateKey, keyPath, key,
					fmt.Sprintf("duplicate mapping key; the first definition is at line %d, column %d", first.Line, first.Column),
					"remove one definition so precedence is unambiguous")
				duplicate.FirstLine = first.Line
				return duplicate
			}
			seen[key.Value] = key
			childDepth := depth
			if v8YAMLContainer(value) {
				childDepth++
			}
			if err := w.validate(value, keyPath, childDepth); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if depth > V8YAMLMaxDepth {
			return v8Error(w.source, V8YAMLErrorDepthLimit, path, node,
				"YAML nesting exceeds the depth limit of 32", "flatten the configuration structure")
		}
		for index, child := range node.Content {
			childDepth := depth
			if v8YAMLContainer(child) {
				childDepth++
			}
			if err := w.validate(child, fmt.Sprintf("%s[%d]", path, index), childDepth); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		// Scalar domain constraints belong to the later JSON Schema stage.
	default:
		return v8Error(w.source, V8YAMLErrorSyntax, path, node,
			"unsupported YAML node kind", "use ordinary mappings, sequences, and scalar values")
	}
	return nil
}

func validateV8YAMLVersion(source string, root *yaml.Node) error {
	value := v8YAMLMapValue(root, "config_version")
	if value == nil {
		return v8Error(source, V8YAMLErrorVersionRequired, "$.config_version", root,
			"config_version is required in config.yaml",
			"run `defenseclaw migrate` to create a current source")
	}
	if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!int" {
		return v8Error(source, V8YAMLErrorVersionInvalid, "$.config_version", value,
			"config_version must be an integer",
			"run `defenseclaw migrate` instead of editing config_version by hand")
	}
	var version int64
	if err := value.Decode(&version); err != nil {
		return v8Error(source, V8YAMLErrorVersionInvalid, "$.config_version", value,
			"config_version must be an integer", "run `defenseclaw migrate` to create a current source")
	}
	switch {
	case version >= v8YAMLConfigVersion && version <= MaxSupportedConfigVersion:
		return nil
	case version >= 0 && version < v8YAMLConfigVersion:
		return v8Error(source, V8YAMLErrorVersionUpgrade, "$.config_version", value,
	if version == ConfigVersionV9 && v9SecureClientDocument(root) {
		return v8Error(source, V8YAMLErrorVersionUnsupported, "$.config_version", value,
			"Secure Client supports config_version 8 only",
			"use a Secure Client config_version 8 source")
	}
			fmt.Sprintf("config_version %d is older than %d", version, v8YAMLConfigVersion),
			"run `defenseclaw migrate`")
	case version > MaxSupportedConfigVersion:
		return v8Error(source, V8YAMLErrorVersionUnsupported, "$.config_version", value,
			fmt.Sprintf("config was written by a newer DefenseClaw (config_version %d)", version),
			newerConfigAction)
	default:
		return v8Error(source, V8YAMLErrorVersionInvalid, "$.config_version", value,
			"config_version must be a non-negative integer", "run `defenseclaw migrate` to create a current source")
	}
}

// newerConfigAction is the way out of a config_version this release does not
// read: a managed host keeps the pre-upgrade copy next to the config, a
// per-user install in its previous folder.
const newerConfigAction = "upgrade DefenseClaw, or restore the config saved before the upgrade " +
	"(config.yaml.v8.bak next to the config file on a managed host, ~/.defenseclaw/previous on a per-user install)"

// rejectV9RemovedKeys refuses, in a config_version 9 source, the v8 keys
// that config_version 9 replaced. A v8 source keeps them: they are the
// input of the v8 to v9 migration (MigrateV9).
func rejectV9RemovedKeys(source string, root *yaml.Node) error {
	version := v8YAMLMapValue(root, "config_version")
	var number int64
	if version == nil || version.Decode(&number) != nil || number < ConfigVersionV9 {
		return nil
	}
	for _, removed := range []struct{ key, target string }{
		{"otel", "observability.destinations"},
		{"skill_actions", "admission.skill.actions"},
		{"mcp_actions", "admission.mcp.actions"},
		{"plugin_actions", "admission.plugin.actions"},
	} {
		if node := v8YAMLMapValue(root, removed.key); node != nil {
			return v9RemovedKeyError(source, v8YAMLChildPath("$", removed.key), node, removed.target)
		}
	}
	if node := v8YAMLMapValue(root, "privacy"); node != nil {
		return v9RemovedKeyAction(source, "$.privacy", node, "remove it: config_version 9 has no privacy section")
	}
	if node := v8YAMLMapValue(v8YAMLMapValue(root, "watch"), "allow_list_bypass_scan"); node != nil {
		return v9RemovedKeyError(source, "$.watch.allow_list_bypass_scan", node,
			"admission.<type>.allow_list_bypass_scan")
	}
	guardrail := v8YAMLMapValue(root, "guardrail")
	if err := rejectV9RulePackDir(source, guardrail, "$.guardrail"); err != nil {
		return err
	}
	if err := rejectV9ConnectorRulePackDirs(source, guardrail, "$.guardrail"); err != nil {
		return err
	}
	if profiles := v8YAMLMapValue(guardrail, "profiles"); profiles != nil && profiles.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(profiles.Content); index += 2 {
			path := v8YAMLChildPath("$.guardrail.profiles", profiles.Content[index].Value)
			profile := profiles.Content[index+1]
			if err := rejectV9RulePackDir(source, profile, path); err != nil {
				return err
			}
			if err := rejectV9ConnectorRulePackDirs(source, profile, path); err != nil {
				return err
			}
		}
	}
	observability := v8YAMLMapValue(root, "observability")
	if node := v8YAMLMapValue(v8YAMLMapValue(observability, "trace_policy"), "compatibility_aliases"); node != nil {
		return v9RemovedKeyAction(source, "$.observability.trace_policy.compatibility_aliases", node,
			"remove it: telemetry carries only canonical attribute names")
	}
	attributes := v8YAMLMapValue(v8YAMLMapValue(observability, "resource"), "attributes")
	if node := v8YAMLMapValue(attributes, "deployment.environment"); node != nil {
		return v9RemovedKeyError(source, v8YAMLChildPath("$.observability.resource.attributes", "deployment.environment"),
			node, "deployment.environment.name")
	}
	scanners := v8YAMLMapValue(root, "scanners")
	for _, removed := range []struct{ scanner, key, target string }{
		{"skill_scanner", "binary", "the managed scanner install"},
		{"skill_scanner", "use_virustotal", "scanners.skill_scanner.analyzers.virustotal.enabled"},
		{"skill_scanner", "use_aidefense", "scanners.skill_scanner.analyzers.aidefense.enabled"},
		{"skill_scanner", "virustotal_api_key", "a key stored with defenseclaw keys set"},
		{"skill_scanner", "virustotal_api_key_env", "scanners.skill_scanner.analyzers.virustotal.api_key_env"},
		{"mcp_scanner", "binary", "the managed scanner install"},
	} {
		if node := v8YAMLMapValue(v8YAMLMapValue(scanners, removed.scanner), removed.key); node != nil {
			return v9RemovedKeyError(source, "$.scanners."+removed.scanner+"."+removed.key, node, removed.target)
		}
	}
	return nil
}

// retiredScannerKeys are scanner keys that no scan path ever read and that
// config_version 9 dropped (GAP-0295, GAP-0301). 1.0 pre-release builds
// accepted and wrote them, so a source that still holds one loads with the
// key ignored, and the next write leaves it out. A Secure Client document
// keeps the closed schema of main (issue #1092), which never had them.
// Remove this after 1.1, when no pre-release config is left to load.
var retiredScannerKeys = [][]string{
	{"scanners", "mcp_scanner", "api"},
	{"scanners", "mcp_scanner", "timeouts"},
	{"scanners", "skill_scanner", "timeouts", "llm_s"},
}

func dropRetiredScannerKeys(root *yaml.Node) {
	for _, path := range retiredScannerKeys {
		parent := root
		for _, key := range path[:len(path)-1] {
			parent = v8YAMLMapValue(parent, key)
		}
		if parent == nil || parent.Kind != yaml.MappingNode {
			continue
		}
		for index := 0; index+1 < len(parent.Content); index += 2 {
			if parent.Content[index].Value == path[len(path)-1] {
				parent.Content = append(parent.Content[:index], parent.Content[index+2:]...)
				break
			}
		}
	}
}

func rejectV9RulePackDir(source string, scope *yaml.Node, path string) error {
	if node := v8YAMLMapValue(scope, "rule_pack_dir"); node != nil {
		return v9RemovedKeyError(source, path+".rule_pack_dir", node, "rule_pack or custom_packs")
	}
	return nil
}

func rejectV9ConnectorRulePackDirs(source string, scope *yaml.Node, path string) error {
	connectors := v8YAMLMapValue(scope, "connectors")
	if connectors == nil || connectors.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(connectors.Content); index += 2 {
		connectorPath := v8YAMLChildPath(path+".connectors", connectors.Content[index].Value)
		if err := rejectV9RulePackDir(source, connectors.Content[index+1], connectorPath); err != nil {
			return err
		}
	}
	return nil
}

func rejectV8YAMLLegacyKeys(source string, root *yaml.Node) error {
	for _, legacy := range []struct{ key, target string }{
		{"otel", "observability resource, policies, and destinations"},
		{"audit_sinks", "observability.destinations"},
		{"audit_db", "observability.local.path"},
		{"judge_bodies_db", "observability.local.judge_bodies_path"},
	} {
		if node := v8YAMLMapValue(root, legacy.key); node != nil {
			return v8YAMLLegacyError(source, v8YAMLChildPath("$", legacy.key), node, legacy.target)
		}
	}
	if privacy := v8YAMLMapValue(root, "privacy"); privacy != nil && privacy.Kind == yaml.MappingNode {
		if node := v8YAMLMapValue(privacy, "disable_redaction"); node != nil {
			return v8YAMLLegacyError(source, "$.privacy.disable_redaction", node,
				"observability defaults, bucket policies, and destination routes")
		}
	}
	if discovery := v8YAMLMapValue(root, "ai_discovery"); discovery != nil && discovery.Kind == yaml.MappingNode {
		if node := v8YAMLMapValue(discovery, "emit_otel"); node != nil {
			return v8YAMLLegacyError(source, "$.ai_discovery.emit_otel", node,
				"the ai.discovery bucket and destination routing policy")
		}
	}
	if node := v8YAMLMapValue(root, "splunk"); node != nil {
		return v8YAMLLegacyError(source, "$.splunk", node, "an observability destination with kind: splunk_hec")
	}

	observability := v8YAMLMapValue(root, "observability")
	if observability == nil || observability.Kind != yaml.MappingNode {
		return nil
	}
	connectors := v8YAMLMapValue(observability, "connectors")
	if connectors == nil || connectors.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(connectors.Content); index += 2 {
		name, connector := connectors.Content[index], connectors.Content[index+1]
		if name.Kind != yaml.ScalarNode || connector.Kind != yaml.MappingNode {
			continue
		}
		if node := v8YAMLMapValue(connector, "audit_sinks"); node != nil {
			path := v8YAMLChildPath("$.observability.connectors", name.Value) + ".audit_sinks"
			return v8YAMLLegacyError(source, path, node, "observability destinations with connector selectors")
		}
	}
	return nil
}

func v8YAMLLegacyError(source, path string, node *yaml.Node, target string) error {
	return v8Error(source, V8YAMLErrorLegacyKeyForbidden, path, node,
		"a legacy v7 configuration key is not accepted by the v8 entrypoint",
		"run defenseclaw upgrade; use "+target)
}

func v9RemovedKeyError(source, path string, node *yaml.Node, target string) error {
	return v9RemovedKeyAction(source, path, node, "use "+target)
}

func v9RemovedKeyAction(source, path string, node *yaml.Node, action string) error {
	return v8Error(source, V8YAMLErrorLegacyKeyForbidden, path, node,
		"a retired configuration key is not accepted in config_version 9", action)
}

func projectV8YAML(source string, node *yaml.Node, path string) (any, error) {
	switch node.Kind {
	case yaml.MappingNode:
		result := make(map[string]any, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			childPath := v8YAMLChildPath(path, key.Value)
			projected, err := projectV8YAML(source, value, childPath)
			if err != nil {
				return nil, err
			}
			result[key.Value] = projected
		}
		return result, nil
	case yaml.SequenceNode:
		result := make([]any, len(node.Content))
		for index, child := range node.Content {
			projected, err := projectV8YAML(source, child, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}
			result[index] = projected
		}
		return result, nil
	case yaml.ScalarNode:
		return projectV8YAMLScalar(source, node, path)
	default:
		return nil, v8Error(source, V8YAMLErrorSyntax, path, node,
			"unsupported YAML node kind", "use ordinary mappings, sequences, and scalar values")
	}
}

func projectV8YAMLScalar(source string, node *yaml.Node, path string) (any, error) {
	switch node.ShortTag() {
	case "!!null":
		return nil, nil
	case "!!str", "!!timestamp", "!!binary":
		return node.Value, nil
	case "!!bool":
		var value bool
		if err := node.Decode(&value); err == nil {
			return value, nil
		}
	case "!!int":
		var value any
		if err := node.Decode(&value); err == nil {
			switch value.(type) {
			case int, int64, uint64:
				return value, nil
			}
		}
	case "!!float":
		var value float64
		if err := node.Decode(&value); err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
			return value, nil
		}
	}
	return nil, v8Error(source, V8YAMLErrorScalarInvalid, path, node,
		"YAML scalar cannot be represented safely for schema validation",
		"use a finite string, Boolean, integer, number, or null value")
}

func v8YAMLTagAllowed(node *yaml.Node) bool {
	if node == nil || node.Kind == yaml.DocumentNode || node.Kind == yaml.AliasNode {
		return true
	}
	switch node.ShortTag() {
	case "!!map", "!!seq", "!!str", "!!null", "!!bool", "!!int", "!!float", "!!timestamp", "!!binary":
		return true
	default:
		return false
	}
}

func v8YAMLIsMerge(node *yaml.Node) bool {
	return node != nil && (node.ShortTag() == "!!merge" || (node.Kind == yaml.ScalarNode && node.Value == "<<"))
}

func v8YAMLContainer(node *yaml.Node) bool {
	return node != nil && (node.Kind == yaml.MappingNode || node.Kind == yaml.SequenceNode)
}

func v8DocumentRoot(document *yaml.Node) *yaml.Node {
	if document == nil {
		return nil
	}
	if document.Kind != yaml.DocumentNode {
		return document
	}
	if len(document.Content) == 0 {
		return nil
	}
	return document.Content[0]
}

func v8YAMLMapValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Kind == yaml.ScalarNode && mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func v8YAMLChildPath(parent, key string) string {
	if v8YAMLSimplePathKey(key) {
		return parent + "." + key
	}
	return parent + "[" + strconv.Quote(key) + "]"
}

func v8YAMLSimplePathKey(key string) bool {
	if key == "" {
		return false
	}
	for index, char := range key {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' ||
			(index > 0 && char >= '0' && char <= '9') || (index > 0 && char == '-') {
			continue
		}
		return false
	}
	return true
}

func v8Error(source string, code V8YAMLErrorCode, path string, node *yaml.Node, summary, action string) *V8YAMLError {
	result := &V8YAMLError{Code: code, Source: source, Path: path, Summary: summary, Action: action}
	if node != nil {
		result.Line, result.Column = node.Line, node.Column
	}
	return result
}

var v8YAMLSyntaxLine = regexp.MustCompile(`(?:^|[ :])line ([0-9]+)(?:[ :]|$)`)

// yaml.v3 reports parser errors (unlike scanner errors) with the 0-based
// line of their context mark, one line before the bad line that Python and
// editors name (GAP-1430).
var v8YAMLParserError = regexp.MustCompile(
	`did not find expected (?:<document start>|node content|key|'-' indicator|',' or '\]'|',' or '\}')`)

// v8YAMLSyntaxReasonPrefix strips the "yaml: line N: " lead from a yaml.v3
// error so only the parser's reason is left.
var v8YAMLSyntaxReasonPrefix = regexp.MustCompile(`^(?:yaml: )?(?:line [0-9]+: )?`)

// v8YAMLSyntaxReason returns the parser's fixed-text reason, or "" when the
// reason could quote the file (anchor or tag names) or is not a short phrase.
func v8YAMLSyntaxReason(cause error) string {
	reason := strings.TrimSpace(v8YAMLSyntaxReasonPrefix.ReplaceAllString(cause.Error(), ""))
	lower := strings.ToLower(reason)
	if reason == "" || len(reason) > 80 || strings.ContainsAny(reason, "\"`\n") ||
		strings.Contains(lower, "anchor") || strings.Contains(lower, "tag") {
		return ""
	}
	return reason
}

func v8SyntaxError(source string, cause error) error {
	line := 0
	summary := "invalid YAML"
	if cause != nil {
		if match := v8YAMLSyntaxLine.FindStringSubmatch(cause.Error()); len(match) == 2 {
			line, _ = strconv.Atoi(match[1])
			if line > 0 && v8YAMLParserError.MatchString(cause.Error()) {
				line++
			}
		}
		if reason := v8YAMLSyntaxReason(cause); reason != "" {
			summary += " (" + reason + ")"
		}
	}
	return &V8YAMLError{
		Code: V8YAMLErrorSyntax, Source: source, Path: "$", Line: line,
		Summary: summary, Action: "fix that line",
	}
}
