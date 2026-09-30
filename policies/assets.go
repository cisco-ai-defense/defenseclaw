// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package policyassets embeds the vendor default policies (Rego modules and
// data, policy presets, and the default, strict and permissive guardrail
// rule packs) so the standalone managed-enterprise lifecycle installs the
// same files a per-user `defenseclaw init` seeds, without a Python runtime.
package policyassets

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rego/*.rego rego/data.json *.yaml guardrail/default guardrail/strict guardrail/permissive
var files embed.FS

// File is one embedded policy file; Path is slash-separated and relative to
// the policy directory root.
type File struct {
	Path string
	Data []byte
}

// Files lists every vendor policy file in a stable order. Rego unit tests
// are not installed.
func Files() ([]File, error) {
	var out []File
	err := fs.WalkDir(files, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || strings.HasSuffix(path, "_test.rego") {
			return err
		}
		data, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, File{Path: path, Data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// GuardrailRuleIDs lists, sorted and without duplicates, every rule id and
// judge finding id that the embedded default, strict and permissive
// guardrail rule packs ship. Audit persistence keeps these vendor
// identities readable; ids that only a custom pack defines stay keyed.
func GuardrailRuleIDs() ([]string, error) {
	seen := make(map[string]struct{})
	err := fs.WalkDir(files, "guardrail", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || path.Ext(name) != ".yaml" {
			return err
		}
		data, err := files.ReadFile(name)
		if err != nil {
			return err
		}
		switch path.Base(path.Dir(name)) {
		case "rules":
			var doc struct {
				Rules []struct {
					ID string `yaml:"id"`
				} `yaml:"rules"`
			}
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			for _, rule := range doc.Rules {
				seen[strings.TrimSpace(rule.ID)] = struct{}{}
			}
		case "judge":
			var doc struct {
				Categories map[string]struct {
					FindingID string `yaml:"finding_id"`
				} `yaml:"categories"`
			}
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			for _, category := range doc.Categories {
				seen[strings.TrimSpace(category.FindingID)] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	delete(seen, "")
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
