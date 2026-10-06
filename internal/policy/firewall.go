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

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/rego"          //nolint:staticcheck // v0 compat; migrate to opa/v1 later
	"github.com/open-policy-agent/opa/storage/inmem" //nolint:staticcheck // v0 compat; migrate to opa/v1 later
)

// SandboxDataFile is the static data firewall.rego reads. Only the
// defenseclaw-gateway policy evaluate-firewall and domains dry runs load it;
// the gateway's policy engine does not, because nothing it enforces reads it.
const SandboxDataFile = "data-sandbox.json"

// LoadSandboxData reads exactly <regoDir>/data-sandbox.json.
func LoadSandboxData(regoDir string) (map[string]interface{}, error) {
	raw, err := os.ReadFile(filepath.Join(regoDir, SandboxDataFile))
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", SandboxDataFile, err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", SandboxDataFile, err)
	}
	if data == nil {
		return nil, fmt.Errorf("policy: parse %s: top-level value must be an object", SandboxDataFile)
	}
	return data, nil
}

// EvaluateFirewallExact dry-runs firewall.rego from exactly regoDir against
// its data-sandbox.json. Nothing is quarantined.
func EvaluateFirewallExact(ctx context.Context, regoDir string, input FirewallInput) (*FirewallOutput, error) {
	modules, err := readModules(regoDir, nil)
	if err != nil {
		return nil, err
	}
	data, err := LoadSandboxData(regoDir)
	if err != nil {
		return nil, err
	}
	query, err := rego.New(append(regoOptions("data.defenseclaw.firewall", modules),
		rego.Store(inmem.NewFromObject(data)))...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: firewall eval: %w", err)
	}
	result, err := evalPrepared(ctx, query, input)
	if err != nil {
		return nil, fmt.Errorf("policy: firewall eval: %w", err)
	}
	return &FirewallOutput{
		Action:   stringVal(result, "action"),
		RuleName: stringVal(result, "rule_name"),
	}, nil
}
