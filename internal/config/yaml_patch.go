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

package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PatchYAMLFile applies dotted-path scalar updates while preserving the
// existing YAML node tree, including comments and key order for untouched
// fields. Missing maps are appended in sorted update order.
func PatchYAMLFile(path string, updates map[string]any) error {
	if len(updates) == 0 {
		return nil
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("config: empty YAML path")
	}

	var (
		doc  yaml.Node
		perm os.FileMode = 0o600
	)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("config: read %s: %w", path, err)
		}
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
	} else {
		if info, statErr := os.Stat(path); statErr == nil {
			perm = info.Mode().Perm()
		}
		if len(bytes.TrimSpace(data)) == 0 {
			doc.Kind = yaml.DocumentNode
			doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
		} else if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("config: parse %s: %w", path, err)
		}
		if doc.Kind == 0 {
			doc.Kind = yaml.DocumentNode
		}
		if len(doc.Content) == 0 {
			doc.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
		}
		if doc.Content[0].Kind != yaml.MappingNode {
			return fmt.Errorf("config: %s root must be a mapping", path)
		}
	}

	keys := make([]string, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := patchYAMLPath(doc.Content[0], strings.Split(key, "."), updates[key]); err != nil {
			return err
		}
	}

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		_ = enc.Close()
		return fmt.Errorf("config: encode %s: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("config: encode %s: %w", path, err)
	}
	return writeFileAtomic(path, out.Bytes(), perm)
}

func patchYAMLPath(root *yaml.Node, parts []string, value any) error {
	if root == nil || root.Kind != yaml.MappingNode {
		return fmt.Errorf("config: YAML root must be a mapping")
	}
	if len(parts) == 0 {
		return fmt.Errorf("config: empty YAML path")
	}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("config: invalid YAML path %q", strings.Join(parts, "."))
		}
	}

	cur := root
	for i, part := range parts {
		last := i == len(parts)-1
		key, val := yamlMapLookup(cur, part)
		if key == nil {
			key = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}
			if last {
				val = yamlScalarNode(value)
			} else {
				val = &yaml.Node{Kind: yaml.MappingNode}
			}
			cur.Content = append(cur.Content, key, val)
		} else if last {
			next := yamlScalarNode(value)
			next.HeadComment = val.HeadComment
			next.LineComment = val.LineComment
			next.FootComment = val.FootComment
			*val = *next
		}
		if !last {
			if val.Kind == 0 {
				val.Kind = yaml.MappingNode
			}
			if val.Kind != yaml.MappingNode {
				return fmt.Errorf("config: YAML path %q is not a mapping", strings.Join(parts[:i+1], "."))
			}
			cur = val
		}
	}
	return nil
}

func yamlMapLookup(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func yamlScalarNode(value any) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode}
	switch v := value.(type) {
	case bool:
		n.Tag = "!!bool"
		if v {
			n.Value = "true"
		} else {
			n.Value = "false"
		}
	case int:
		n.Tag = "!!int"
		n.Value = fmt.Sprintf("%d", v)
	case string:
		n.Tag = "!!str"
		n.Value = v
	default:
		n.Tag = "!!str"
		n.Value = fmt.Sprint(v)
	}
	return n
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("config: temp file %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write temp %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: chmod temp %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close temp %s: %w", tmpName, err)
	}
	if err := replaceConfigFile(tmpName, path); err != nil {
		return fmt.Errorf("config: replace %s: %w", path, err)
	}
	return nil
}

// WriteFileAtomic replaces path with data through a same-directory temporary file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomic(path, data, perm)
}
