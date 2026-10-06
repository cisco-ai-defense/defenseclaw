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

package gateway

import (
	"errors"
	"io/fs"
	"os"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The config writers (configwrite.Apply and `config-v8 validate`, which the
// Python writer runs) check a candidate's rule-pack references with the
// loader a generation build uses, so a rule_pack that resolves to no pack, a
// custom pack whose digest does not match, or an unknown rule ID or
// protection in guardrail.rules is refused before it is written.
func init() { config.RegisterCandidateAssetCheck(checkCandidateAssets) }

func checkCandidateAssets(cfg *config.Config) error {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	type scoped struct {
		cfg   *config.Config
		label string
	}
	configs := []scoped{{cfg, "config"}}
	if cfg.Guardrail.HasProfiles() {
		derived, err := cfg.DeriveGuardrailProfiles()
		if err != nil {
			return err
		}
		names := make([]string, 0, len(derived))
		for name := range derived {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			configs = append(configs, scoped{derived[name].Config, "guardrail profile " + name})
		}
	}
	cache := guardrail.NewRulePackCache()
	for _, c := range configs {
		for _, scope := range profileRulePackScopes(c.cfg) {
			if builtinPackNotSeeded(scope) {
				continue
			}
			if _, err := loadScopedRulePack(cache, c.cfg, scope, c.label); err != nil {
				return err
			}
		}
	}
	return nil
}

// builtinPackNotSeeded reports a built-in pack (or the default pack
// directory) that is not on disk yet. That is installation state the
// policy seeding fixes, not a reference a config change made, so the writer
// does not refuse it.
func builtinPackNotSeeded(s rulePackScope) bool {
	if s.dir == "" || (s.ref.Name != "" && !config.IsBuiltinRulePack(s.ref.Name)) {
		return false
	}
	_, err := os.Stat(s.dir)
	return errors.Is(err, fs.ErrNotExist)
}
