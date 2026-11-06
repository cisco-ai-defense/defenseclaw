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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// The config writers (configwrite.Apply and `config-v8 validate`, which the
// Python writer runs) check a candidate's rule-pack references with the
// loader a generation build uses, so a rule_pack that resolves to no pack, a
// custom pack whose digest does not match, or an unknown rule ID or
// protection in guardrail.rules is refused before it is written. On a managed
// standalone host so is a signature pack that does not match its pin.
func init() { config.RegisterCandidateAssetCheck(checkCandidateAssets) }

func checkCandidateAssets(cfg *config.Config) error {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	if err := CheckRulePacks(cfg); err != nil {
		return err
	}
	if err := inventory.CheckSignaturePackPins(cfg); err != nil {
		return err
	}
	return checkCandidateWebhooks(cfg)
}

// UnselectedCustomPackProblems names each guardrail.custom_packs entry that
// no setting selects and that the gateway would refuse once a setting did:
// its folder is missing, the pack fails validation, or its digest pin does
// not match the pack's files. CheckRulePacks loads only the selected packs,
// so a managed lifecycle applied such an entry with no notice, while config
// set says it is registered but will not load (GAP-1076). The digest check
// is unchanged: these entries are reported, not loaded.
func UnselectedCustomPackProblems(cfg *config.Config) []string {
	if cfg == nil || cfg.SecureClientIntegration() || len(cfg.Guardrail.CustomPacks) == 0 {
		return nil
	}
	configs := []*config.Config{cfg}
	if cfg.Guardrail.HasProfiles() {
		if derived, err := cfg.DeriveGuardrailProfiles(); err == nil {
			for _, profile := range derived {
				configs = append(configs, profile.Config)
			}
		}
	}
	selected := map[string]bool{}
	tuned := profileConnectorNames(cfg)
	for _, c := range configs {
		for _, scope := range profileRulePackScopes(c, tuned) {
			if scope.ref.Name != "" {
				selected[scope.ref.Name] = true
			}
		}
	}
	names := make([]string, 0, len(cfg.Guardrail.CustomPacks))
	for name := range cfg.Guardrail.CustomPacks {
		if !selected[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	cache := guardrail.NewRulePackCache()
	var problems []string
	for _, name := range names {
		pack := cfg.Guardrail.CustomPacks[name]
		head := fmt.Sprintf("guardrail.custom_packs.%s is registered but will not load", name)
		dir := strings.TrimSpace(pack.Path)
		if err := cfg.CustomRulePackError(name); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", head, err))
			continue
		}
		loaded, err := loadValidatedRulePack(cache, dir, "guardrail.custom_packs."+name)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", head, err))
			continue
		}
		if got := "sha256:" + loaded.FilesDigest(); !strings.EqualFold(strings.TrimSpace(pack.Digest), got) {
			problems = append(problems, fmt.Sprintf("%s: the files at %s have digest %s, which does not match guardrail.custom_packs.%s.digest; "+
				"review the pack, then pin that digest in the key", head, dir, got, name))
		}
	}
	return problems
}

// CheckRulePacks builds every rule pack cfg selects (globally, per connector
// and per guardrail profile) as the generation build at gateway start does,
// custom_packs digest pins included. The Windows standalone lifecycle runs it
// on the config an upgrade keeps before it stops the services, so a pin the
// new gateway refuses fails the upgrade at once, not after the readiness
// wait (GAP-0188).
func CheckRulePacks(cfg *config.Config) error {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	configs, err := rulePackConfigs(cfg)
	if err != nil {
		return err
	}
	cache := guardrail.NewRulePackCache()
	tuned := profileConnectorNames(cfg)
	for _, c := range configs {
		for _, scope := range profileRulePackScopes(c.cfg, tuned) {
			// The gateway opens a rule_pack_dir as written: ~ is not expanded
			// and a relative path follows its working directory (GAP-0363).
			if scope.ref.Name == "" && scope.dir != "" && !filepath.IsAbs(scope.dir) {
				return fmt.Errorf("%s rule pack directory %q is not an absolute path; the gateway does not expand ~ "+
					"or a relative path, so write the full path", c.label, scope.dir)
			}
			if err := scope.customEntryError(c.cfg, c.label); err != nil {
				return err
			}
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

// scopedConfig is a configuration the rule packs are built for: the base
// configuration and each derived guardrail profile.
type scopedConfig struct {
	cfg   *config.Config
	label string
}

func rulePackConfigs(cfg *config.Config) ([]scopedConfig, error) {
	configs := []scopedConfig{{cfg, "config"}}
	if cfg.Guardrail.HasProfiles() {
		derived, err := cfg.DeriveGuardrailProfiles()
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(derived))
		for name := range derived {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			configs = append(configs, scopedConfig{derived[name].Config, "guardrail profile " + name})
		}
	}
	return configs, nil
}

// customEntryError is the config error of the custom_packs entry the scope
// selects. The gateway runs a broken entry's built-in fallback; a writer or an
// install check refuses the entry itself.
func (s rulePackScope) customEntryError(cfg *config.Config, label string) error {
	if err := cfg.CustomRulePackError(s.ref.Name); err != nil {
		return fmt.Errorf("%s rule pack %q: %w", label, s.ref.Name, err)
	}
	return nil
}

// CheckSelectedCustomRulePacks is the part of CheckRulePacks that refuses a
// custom_packs entry some scope selects when it has a config error (a stale
// pin, an empty or unreadable folder, a pack that does not load), before any
// pack is read. An entry nothing selects is not checked.
func CheckSelectedCustomRulePacks(cfg *config.Config) error {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil
	}
	configs, err := rulePackConfigs(cfg)
	if err != nil {
		return err
	}
	tuned := profileConnectorNames(cfg)
	for _, c := range configs {
		for _, scope := range profileRulePackScopes(c.cfg, tuned) {
			if err := scope.customEntryError(c.cfg, c.label); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkCandidateWebhooks refuses an enabled webhook whose URL the dispatcher
// would drop when it builds its endpoints (a malformed URL, a scheme other
// than http or https, a loopback, private or link-local address). Without it
// a bad webhook is accepted and then silently never delivers. Host names are
// not resolved here; the dispatcher still checks what they resolve to.
func checkCandidateWebhooks(cfg *config.Config) error {
	check := func(path string, hooks []config.WebhookConfig) error {
		for i, hook := range hooks {
			if !hook.Enabled || hook.URL == "" {
				continue
			}
			if err := validateWebhookURLWith(hook.URL, nil); err != nil {
				label := fmt.Sprintf("webhook %d", i)
				if hook.Name != "" {
					label = fmt.Sprintf("webhook %q", hook.Name)
				}
				return &config.V8SemanticError{
					Path:     fmt.Sprintf("$.%s[%d].url", path, i),
					Summary:  fmt.Sprintf("%s: %s", label, scrubWebhookErr(err, hook.URL)),
					Expected: "an http or https URL the gateway can deliver to (not loopback, private or link-local)",
					Action:   "fix the url, or remove the webhook",
				}
			}
		}
		return nil
	}
	if err := check("webhooks", cfg.Webhooks); err != nil {
		return err
	}
	names := cfg.Observability.ConnectorNames()
	for _, name := range names {
		if override := cfg.Observability.Connectors[name].Webhooks; override != nil {
			if err := check(fmt.Sprintf("observability.connectors[%q].webhooks", name), *override); err != nil {
				return err
			}
		}
	}
	return nil
}

// builtinPackNotSeeded reports a built-in pack (or a rule_pack_dir naming
// a built-in pack's guardrail/<name> folder, under policy_dir or a managed
// layout's vendor policy folder) that is not on disk yet. That is
// installation state the policy seeding fixes, not a reference a config
// change made, so the writer does not refuse it. Any other missing directory
// is refused: the gateway's reload refuses it too, and the writer accepted it
// while the running gateway kept the previous policy (GAP-0363).
func builtinPackNotSeeded(s rulePackScope) bool {
	if s.dir == "" {
		return false
	}
	name := s.ref.Name
	if name == "" {
		dir := filepath.Clean(s.dir)
		if filepath.Base(filepath.Dir(dir)) != "guardrail" {
			return false
		}
		name = filepath.Base(dir)
	}
	if !config.IsBuiltinRulePack(name) {
		return false
	}
	_, err := os.Stat(s.dir)
	return errors.Is(err, fs.ErrNotExist)
}
