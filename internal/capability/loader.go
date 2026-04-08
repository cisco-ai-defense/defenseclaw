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

package capability

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadPolicy reads and validates a single .capability.yaml manifest file.
func LoadPolicy(path string) (*AgentPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("capability: read %s: %w", path, err)
	}

	var pol AgentPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("capability: parse %s: %w", path, err)
	}

	if err := validatePolicy(&pol, path); err != nil {
		return nil, err
	}

	return &pol, nil
}

// LoadAllPolicies loads all .capability.yaml files from dir.
// Returns valid policies keyed by agent name and a slice of errors for invalid files.
func LoadAllPolicies(_ context.Context, dir string) (map[string]*AgentPolicy, []error) {
	policies := make(map[string]*AgentPolicy)
	var errs []error

	entries, err := os.ReadDir(dir)
	if err != nil {
		return policies, []error{fmt.Errorf("capability: read dir %s: %w", dir, err)}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".capability.yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		pol, err := LoadPolicy(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		policies[pol.Agent] = pol
	}

	return policies, errs
}

func validatePolicy(pol *AgentPolicy, path string) error {
	if pol.Agent == "" {
		return fmt.Errorf("capability: %s: agent field is required", path)
	}

	for i, cap := range pol.Capabilities {
		if cap.Name == "" {
			return fmt.Errorf("capability: %s: capability[%d]: name is required", path, i)
		}
		if cap.Resource == "" {
			return fmt.Errorf("capability: %s: capability[%d] %q: resource is required", path, i, cap.Name)
		}
	}

	if pol.Conditions.RateLimit != nil {
		rl := pol.Conditions.RateLimit
		if rl.MaxCalls <= 0 {
			return fmt.Errorf("capability: %s: rate_limit.max_calls must be > 0", path)
		}
		if rl.WindowSeconds <= 0 {
			return fmt.Errorf("capability: %s: rate_limit.window_seconds must be > 0", path)
		}
	}

	return nil
}
