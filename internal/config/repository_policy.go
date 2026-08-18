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
)

const (
	repositoryPolicyMaxRootBytes = 4096
	repositoryPolicyMaxRuleIDs   = 2
)

// RepositoryPolicyConfig is explicit server-owned policy for one physical Git
// worktree. It is intentionally limited to the two shipped Git advisories;
// rule-pack selection and request metadata are not repository policy.
type RepositoryPolicyConfig struct {
	Root             string   `mapstructure:"root"               yaml:"root"`
	ForbiddenRuleIDs []string `mapstructure:"forbidden_rule_ids" yaml:"forbidden_rule_ids,omitempty"`
}

// Validate fails closed unless Root is the exact canonical path of an
// existing Git worktree and every rule ID is an exact member of the bounded
// repository-policy vocabulary.
func (c *RepositoryPolicyConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.Root == "" {
		return fmt.Errorf("root is required")
	}
	if len(c.Root) > repositoryPolicyMaxRootBytes {
		return fmt.Errorf("root exceeds the %d-byte limit", repositoryPolicyMaxRootBytes)
	}
	if strings.TrimSpace(c.Root) != c.Root || !filepath.IsAbs(c.Root) ||
		filepath.Clean(c.Root) != c.Root {
		return fmt.Errorf("root must be an exact canonical absolute path")
	}
	physical, err := filepath.EvalSymlinks(c.Root)
	if err != nil || filepath.Clean(physical) != c.Root {
		return fmt.Errorf("root must resolve to its exact canonical path")
	}
	info, err := os.Stat(c.Root)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("root must be an existing directory")
	}
	gitMarker, err := os.Lstat(filepath.Join(c.Root, ".git"))
	if err != nil || gitMarker.Mode()&os.ModeSymlink != 0 ||
		(!gitMarker.IsDir() && !gitMarker.Mode().IsRegular()) {
		return fmt.Errorf("root must be the exact root of a Git worktree")
	}

	if len(c.ForbiddenRuleIDs) > repositoryPolicyMaxRuleIDs {
		return fmt.Errorf("forbidden_rule_ids exceeds the %d-item limit", repositoryPolicyMaxRuleIDs)
	}
	seen := make(map[string]struct{}, len(c.ForbiddenRuleIDs))
	for _, ruleID := range c.ForbiddenRuleIDs {
		switch ruleID {
		case "integrity.git_hooks_bypass", "source.git_remote_tamper":
		default:
			return fmt.Errorf("forbidden_rule_ids contains an unknown or non-canonical rule ID")
		}
		if _, duplicate := seen[ruleID]; duplicate {
			return fmt.Errorf("forbidden_rule_ids contains a duplicate rule ID")
		}
		seen[ruleID] = struct{}{}
	}
	return nil
}
