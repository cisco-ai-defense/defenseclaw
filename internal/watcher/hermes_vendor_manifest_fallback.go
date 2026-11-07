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

// hermesYAMLTags are the tags PyYAML's safe loader constructs. A document
// with any other tag is refused as a whole, as in a scan.
var hermesYAMLTags = map[string]bool{
	"!!str": true, "!!int": true, "!!float": true, "!!bool": true, "!!null": true,
	"!!binary": true, "!!timestamp": true, "!!seq": true, "!!map": true,
	"!!set": true, "!!omap": true, "!!pairs": true,
}

const (
	// hermesYAMLMaxDepth bounds the nesting the fallback follows (aliases
	// included), so a recursive anchor ends.
	hermesYAMLMaxDepth = 64
	// hermesYAMLMaxNodes bounds the nodes visited in one document.
	hermesYAMLMaxNodes = 200000
)

// hermesManifestCandidates returns the entrypoint paths that manifests
// declare, read here from the effective top-level mapping of each manifest:
// the value of main, bin, entry and entrypoint as the scanner reads them
// (_manifest_entrypoints), after last-key-wins, anchors, aliases (as a value
// and as a key), merge keys and the escapes of JSON and YAML strings. It is
// the answer used only while the plugin scanner, the reader of the manifest
// grammar, cannot be asked and the policy lets ordinary activity continue (the
// per-user default and permissive tiers). The caller resolves each string
// under the plugin by file identity, exactly as for a scanner answer.
//
// It reads a parsed tree, not text, so a name in prose, a comment, a nested
// mapping, a shadowed duplicate or another key declares nothing, and a name
// spelled through an alias or escape declares what it spells. A manifest the
// parser refuses declares nothing, as in a scan. A value the scanner would
// not read as a string (a number, a null) may still be offered when it
// resolves to a file of that name; that is a superset, never a miss.
func hermesManifestCandidates(manifests map[string][]byte) []string {
	names := make([]string, 0, len(manifests))
	for name := range manifests {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	var out []string
	for _, name := range names {
		if !utf8.Valid(manifests[name]) {
			continue
		}
		var values []string
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			values, _ = hermesYAMLEntrypoints(manifests[name])
		} else {
			var ok bool
			if values, ok = hermesJSONEntrypoints(manifests[name]); !ok {
				// JSON the strict reader refuses but the scanner accepts
				// (NaN, Infinity) is read as YAML, which holds JSON.
				values, _ = hermesYAMLEntrypoints(manifests[name])
			}
		}
		for _, value := range values {
			if !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	return out
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
	if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value) == "" {
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

// hermesYAMLPair is one key and value of an effective YAML mapping.
type hermesYAMLPair struct {
	key   *yaml.Node
	value *yaml.Node
}

// hermesYAMLReader walks a parsed YAML document the way PyYAML's safe loader
// builds it.
type hermesYAMLReader struct {
	nodes int
}

// resolve follows aliases to the node they stand for.
func (r *hermesYAMLReader) resolve(n *yaml.Node) *yaml.Node {
	for depth := 0; n != nil && n.Kind == yaml.AliasNode; depth++ {
		if depth >= hermesYAMLMaxDepth {
			return nil
		}
		n = n.Alias
	}
	return n
}

// mapping returns the effective pairs of a mapping node, in the order PyYAML
// builds the dictionary (a later pair wins): the pairs of every merge key
// first, then the pairs written in the mapping itself. Of a merged sequence
// of mappings the first wins. ok is false where PyYAML refuses: a key that is
// not a scalar (unhashable), or a merge of something other than mappings.
func (r *hermesYAMLReader) mapping(n *yaml.Node, depth int) (pairs []hermesYAMLPair, ok bool) {
	if r.nodes++; depth > hermesYAMLMaxDepth || r.nodes > hermesYAMLMaxNodes {
		return nil, false
	}
	var merged, explicit []hermesYAMLPair
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := r.resolve(n.Content[i]), r.resolve(n.Content[i+1])
		if key == nil || value == nil || key.Kind != yaml.ScalarNode {
			return nil, false
		}
		if key.ShortTag() != "!!merge" {
			explicit = append(explicit, hermesYAMLPair{key, value})
			continue
		}
		switch value.Kind {
		case yaml.MappingNode:
			sub, ok := r.mapping(value, depth+1)
			if !ok {
				return nil, false
			}
			merged = append(merged, sub...)
		case yaml.SequenceNode:
			var subs [][]hermesYAMLPair
			for _, item := range value.Content {
				item = r.resolve(item)
				if item == nil || item.Kind != yaml.MappingNode {
					return nil, false
				}
				sub, ok := r.mapping(item, depth+1)
				if !ok {
					return nil, false
				}
				subs = append(subs, sub)
			}
			for i := len(subs) - 1; i >= 0; i-- {
				merged = append(merged, subs[i]...)
			}
		default:
			return nil, false
		}
	}
	return append(merged, explicit...), true
}

// valid reports whether PyYAML's safe loader would construct the whole
// document: every tag is one it knows, every key hashable, every merge a
// mapping. A loader error anywhere refuses the manifest as a whole.
func (r *hermesYAMLReader) valid(n *yaml.Node, seen map[*yaml.Node]bool, depth int) bool {
	n = r.resolve(n)
	if n == nil || depth > hermesYAMLMaxDepth {
		return false
	}
	if r.nodes++; r.nodes > hermesYAMLMaxNodes {
		return false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return hermesYAMLTags[n.ShortTag()]
	case yaml.SequenceNode, yaml.MappingNode:
		if seen[n] {
			return true
		}
		seen[n] = true
		if n.Kind == yaml.MappingNode {
			if _, ok := r.mapping(n, 0); !ok {
				return false
			}
		}
		for i, child := range n.Content {
			if n.Kind == yaml.MappingNode && i%2 == 0 {
				if key := r.resolve(child); key != nil && key.Kind == yaml.ScalarNode && key.ShortTag() == "!!merge" {
					continue
				}
			}
			if !r.valid(child, seen, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// path returns the string a scalar value holds, if it holds one that is not
// blank. A null declares nothing.
func (r *hermesYAMLReader) path(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.ShortTag() == "!!null" || strings.TrimSpace(n.Value) == "" {
		return "", false
	}
	return n.Value, true
}

// hermesYAMLEntrypoints reads the entrypoints of a YAML manifest. ok is false
// when the text is not one document the safe loader would construct as a
// mapping; such a manifest declares nothing.
func hermesYAMLEntrypoints(data []byte) (values []string, ok bool) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if dec.Decode(&doc) != nil {
		return nil, false
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, false
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, false
	}
	r := &hermesYAMLReader{}
	root := r.resolve(doc.Content[0])
	if root == nil || root.Kind != yaml.MappingNode || !r.valid(root, map[*yaml.Node]bool{}, 0) {
		return nil, false
	}
	pairs, ok := r.mapping(root, 0)
	if !ok {
		return nil, false
	}
	top := map[string]*yaml.Node{}
	for _, pair := range pairs {
		if pair.key.ShortTag() == "!!str" {
			top[pair.key.Value] = pair.value
		}
	}
	for _, key := range hermesEntrypointKeys {
		value, present := top[key]
		if !present {
			continue
		}
		if text, isPath := r.path(value); isPath {
			values = append(values, text)
			continue
		}
		if key != "bin" || value.Kind != yaml.MappingNode {
			continue
		}
		bin, ok := r.mapping(value, 0)
		if !ok {
			continue
		}
		// A repeated name keeps its last value, as in a dictionary.
		byName := map[string]*yaml.Node{}
		var order []string
		for _, pair := range bin {
			identity := pair.key.ShortTag() + "\x00" + pair.key.Value
			if _, dup := byName[identity]; !dup {
				order = append(order, identity)
			}
			byName[identity] = pair.value
		}
		for _, identity := range order {
			if text, isPath := r.path(byName[identity]); isPath {
				values = append(values, text)
			}
		}
	}
	return values, true
}
