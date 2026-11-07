// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// hermesEntrypointKeys are the manifest keys whose values the plugin scanner
// declares as entrypoint files (_manifest_entrypoints in
// plugin_scanner/scanner.py): main, entry and entrypoint hold a path, bin
// holds a path or a map of names to paths. Any other key (a description, a
// title, scripts, hooks) is not a declaration of a file, wherever it sits.
// TestHermesFallbackEntrypointsMatchScanner keeps this equal to the scanner.
var hermesEntrypointKeys = []string{"main", "bin", "entry", "entrypoint"}

// hermesManifestCandidates returns the entrypoint paths that manifests
// declare, read the way the scanner reads them (_parse_manifest_text and
// _manifest_entrypoints): the manifest is decoded as UTF-8 text with
// universal newlines, a .yaml or .yml manifest is loaded by PyYAML's safe
// loader (see hermes_pyyaml.go) and any other manifest by Python's json, and
// the value of main, bin, entry and entrypoint is read from the top-level
// dictionary when it is a string (a bin dictionary contributes each string
// it holds). It is the answer used only while the plugin scanner, the reader
// of the manifest grammar, cannot be asked and the policy lets ordinary
// activity continue (the per-user default and permissive tiers). The caller
// resolves each string under the plugin by file identity, exactly as for a
// scanner answer.
//
// A name in prose, a comment, a nested mapping, a shadowed duplicate, a value
// that is not a string or another key declares nothing, and a name spelled
// through an alias, an escape or an equivalent key declares what it spells. A
// manifest the loader refuses declares nothing, as in a scan. decided is
// false only when a manifest is too large or too deeply nested to read within
// the reader's bounds: the answer is then unknown, and the caller must treat
// every cache file as declared.
func hermesManifestCandidates(manifests map[string][]byte) (entrypoints []string, decided bool) {
	names := make([]string, 0, len(manifests))
	for name := range manifests {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, name := range names {
		data := manifests[name]
		if !utf8.Valid(data) {
			continue
		}
		data = bytes.ReplaceAll(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), []byte("\r"), []byte("\n"))
		var values []string
		var undecided bool
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			values, _, undecided = hermesYAMLEntrypoints(data)
		} else {
			var ok bool
			if values, ok = hermesJSONEntrypoints(data); !ok {
				// JSON the strict reader refuses but the scanner accepts
				// (NaN, Infinity) is read as YAML, which holds JSON.
				values, _, undecided = hermesYAMLEntrypoints(data)
			}
		}
		if undecided {
			return nil, false
		}
		for _, value := range values {
			if !seen[value] {
				seen[value] = true
				entrypoints = append(entrypoints, value)
			}
		}
	}
	return entrypoints, true
}

// hermesJSONObject reads one JSON object, keeping the last value of a
// repeated key, as Python's json does.
func hermesJSONObject(dec *json.Decoder) (map[string]json.RawMessage, bool) {
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	object := map[string]json.RawMessage{}
	for dec.More() {
		token, err := dec.Token()
		key, isString := token.(string)
		if err != nil || !isString {
			return nil, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		object[key] = value
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	return object, true
}

// hermesJSONPath returns the string a JSON value holds, if it holds one that
// is not blank.
func hermesJSONPath(raw json.RawMessage) (string, bool) {
	var value string
	if json.Unmarshal(raw, &value) != nil || pyBlank(value) {
		return "", false
	}
	return value, true
}

// hermesJSONEntrypoints reads the entrypoints of a JSON manifest. ok is false
// when the text is not one JSON object.
func hermesJSONEntrypoints(data []byte) (values []string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	top, ok := hermesJSONObject(dec)
	if !ok {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	for _, key := range hermesEntrypointKeys {
		raw, present := top[key]
		if !present {
			continue
		}
		if value, isPath := hermesJSONPath(raw); isPath {
			values = append(values, value)
			continue
		}
		if key != "bin" {
			continue
		}
		bin, isObject := hermesJSONObject(json.NewDecoder(bytes.NewReader(raw)))
		if !isObject {
			continue
		}
		names := make([]string, 0, len(bin))
		for name := range bin {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if value, isPath := hermesJSONPath(bin[name]); isPath {
				values = append(values, value)
			}
		}
	}
	return values, true
}

// hermesYAMLEntrypoints reads the entrypoints of a YAML manifest as the
// scanner's loader does. ok is false when the loader refuses the text: not one
// document, a character the reader rejects, a tag or value a constructor
// raises on, a key that cannot be hashed, or a root that is not a mapping.
// Such a manifest declares nothing. undecided is true when the text exceeds
// the reader's bounds, which is not a refusal.
func hermesYAMLEntrypoints(data []byte) (values []string, ok, undecided bool) {
	if !pyYAMLPrintable(string(data)) {
		return nil, false, false
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if dec.Decode(&doc) != nil {
		return nil, false, false
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, false, false
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, false, false
	}
	loader := newPyLoader()
	root, composed := loader.compose(doc.Content[0], 0)
	if !composed {
		return nil, false, loader.over
	}
	top, constructed := loader.construct(root)
	if !constructed {
		return nil, false, loader.over
	}
	if top.kind != pyDict {
		return nil, false, false
	}
	for _, key := range hermesEntrypointKeys {
		value := top.lookup("s" + key)
		if value == nil {
			continue
		}
		if value.kind == pyStr && !pyBlank(value.text) {
			values = append(values, value.text)
			continue
		}
		if key != "bin" || value.kind != pyDict {
			continue
		}
		for _, entry := range value.entries {
			if entry.value.kind == pyStr && !pyBlank(entry.value.text) {
				values = append(values, entry.value.text)
			}
		}
	}
	return values, true, false
}
