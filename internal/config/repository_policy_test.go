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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryPolicyConfigValidate(t *testing.T) {
	root := repositoryPolicyTestRoot(t)
	valid := &RepositoryPolicyConfig{
		Root: root,
		ForbiddenRuleIDs: []string{
			"integrity.git_hooks_bypass",
			"source.git_remote_tamper",
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}

	outside := repositoryPolicyTestRoot(t)
	symlinkRoot := filepath.Join(filepath.Dir(root), "repository-policy-root-link")
	if err := os.Symlink(outside, symlinkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(symlinkRoot) })

	tests := []struct {
		name   string
		policy *RepositoryPolicyConfig
	}{
		{name: "missing root", policy: &RepositoryPolicyConfig{}},
		{name: "relative root", policy: &RepositoryPolicyConfig{Root: "repo"}},
		{name: "unclean root", policy: &RepositoryPolicyConfig{Root: root + string(filepath.Separator)}},
		{name: "symlink root", policy: &RepositoryPolicyConfig{Root: symlinkRoot}},
		{name: "not repository root", policy: &RepositoryPolicyConfig{Root: repositoryPolicyCanonicalTempDir(t)}},
		{
			name: "duplicate rule",
			policy: &RepositoryPolicyConfig{Root: root, ForbiddenRuleIDs: []string{
				"integrity.git_hooks_bypass", "integrity.git_hooks_bypass",
			}},
		},
		{
			name: "unknown rule",
			policy: &RepositoryPolicyConfig{Root: root, ForbiddenRuleIDs: []string{
				"impact.file_delete",
			}},
		},
		{
			name: "non canonical rule",
			policy: &RepositoryPolicyConfig{Root: root, ForbiddenRuleIDs: []string{
				"INTEGRITY.GIT_HOOKS_BYPASS",
			}},
		},
		{
			name: "oversize rule list",
			policy: &RepositoryPolicyConfig{Root: root, ForbiddenRuleIDs: []string{
				"integrity.git_hooks_bypass",
				"source.git_remote_tamper",
				"integrity.git_hooks_bypass",
			}},
		},
		{
			name:   "oversize root",
			policy: &RepositoryPolicyConfig{Root: "/" + strings.Repeat("a", repositoryPolicyMaxRootBytes)},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.policy.Validate(); err == nil {
				t.Fatal("invalid repository policy passed validation")
			}
		})
	}
}

func TestLoadFromBytesValidatesRepositoryPolicy(t *testing.T) {
	root := repositoryPolicyTestRoot(t)
	raw := []byte(fmt.Sprintf(
		"config_version: 7\nrepository_policy:\n  root: %q\n  forbidden_rule_ids:\n    - integrity.git_hooks_bypass\n",
		root,
	))
	loaded, err := LoadFromBytes(filepath.Join(root, "config.yaml"), raw)
	if err != nil {
		t.Fatalf("load repository policy: %v", err)
	}
	if loaded.RepositoryPolicy == nil || loaded.RepositoryPolicy.Root != root ||
		len(loaded.RepositoryPolicy.ForbiddenRuleIDs) != 1 {
		t.Fatalf("loaded repository policy = %#v", loaded.RepositoryPolicy)
	}

	missingRoot := []byte("config_version: 7\nrepository_policy:\n  forbidden_rule_ids:\n    - integrity.git_hooks_bypass\n")
	if _, err := LoadFromBytes(filepath.Join(root, "config.yaml"), missingRoot); err == nil {
		t.Fatal("repository policy without root loaded")
	}
}

func repositoryPolicyTestRoot(t *testing.T) string {
	t.Helper()
	root := repositoryPolicyCanonicalTempDir(t)
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func repositoryPolicyCanonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(root)
}
