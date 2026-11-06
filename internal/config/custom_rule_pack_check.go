// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
)

// EmptyRulePackFilesDigest is the guardrail.custom_packs pin of a pack with
// no files of its own: the digest of an empty file set, which the embedded
// pack also has (guardrail RulePack.FilesDigest). It proves no content.
const EmptyRulePackFilesDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// CustomRulePackError is the one check of guardrail.custom_packs.<name>
// that the gateway, the standalone hook, the candidate check and status
// share: its path is non-empty after trimming and names a readable folder,
// and its digest does not pin an empty file set. nil for a name that is not
// a custom_packs key. The gateway still compares the pin with the files it
// loads; a valid entry is one that can be loaded, not one that matches.
func (g *GuardrailConfig) CustomRulePackError(name string) error {
	if g == nil {
		return nil
	}
	pack, ok := g.CustomPacks[name]
	if !ok {
		return nil
	}
	return checkCustomRulePack(name, pack, strings.TrimSpace(pack.Path))
}

// checkCustomRulePack is CustomRulePackError of one entry whose folder is
// dir: its configured path, or the offline copy a bundle signer reads it from
// (UseOfflineVendorPolicies).
func checkCustomRulePack(name string, pack CustomRulePack, dir string) error {
	key := "guardrail.custom_packs." + name
	if strings.TrimSpace(pack.Path) == "" || dir == "" {
		return fmt.Errorf("%s.path is empty", key)
	}
	if strings.EqualFold(strings.TrimSpace(pack.Digest), EmptyRulePackFilesDigest) {
		return fmt.Errorf("%s.digest pins an empty file set; pin the digest `defenseclaw-gateway rulepack validate --dir %s` prints", key, dir)
	}
	folder, err := os.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s.path %q is not a folder", key, dir)
	} else if err != nil {
		return fmt.Errorf("%s.path cannot be read: %w", key, err)
	}
	defer folder.Close()
	if info, err := folder.Stat(); err != nil {
		return fmt.Errorf("%s.path cannot be read: %w", key, err)
	} else if !info.IsDir() {
		return fmt.Errorf("%s.path %q is not a folder", key, dir)
	}
	if _, err := folder.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s.path cannot be read: %w", key, err)
	}
	return nil
}

// customRulePackCheck is one entry as the loader checked it.
type customRulePackCheck struct {
	pack CustomRulePack
	dir  string
	err  error
}

// checkCustomRulePacks records every custom_packs entry's CustomRulePackError
// once, when the config is loaded, so each reader of this configuration sees
// the same entries as usable for its whole life.
func (c *Config) checkCustomRulePacks() {
	c.customRulePackChecks = make(map[string]customRulePackCheck, len(c.Guardrail.CustomPacks))
	for name, pack := range c.Guardrail.CustomPacks {
		dir := c.customRulePackDir(pack)
		c.customRulePackChecks[name] = customRulePackCheck{pack: pack, dir: dir, err: checkCustomRulePack(name, pack, dir)}
	}
}

// customRulePackDir is the folder pack loads from (ResolveRulePackDir).
func (c *Config) customRulePackDir(pack CustomRulePack) string {
	return c.offlineVendorPath(strings.TrimSpace(pack.Path))
}

// CustomRulePackError is the config-load CustomRulePackError of name; an
// entry the loader did not see as it is now (a configuration it did not
// build, an entry added or edited since) is checked now. Secure Client keeps
// its loader's own refusals: nil there.
func (c *Config) CustomRulePackError(name string) error {
	if c == nil || c.SecureClientIntegration() {
		return nil
	}
	pack, ok := c.Guardrail.CustomPacks[name]
	if !ok {
		return nil
	}
	dir := c.customRulePackDir(pack)
	if checked, ok := c.customRulePackChecks[name]; ok && checked.pack == pack && checked.dir == dir {
		return checked.err
	}
	return checkCustomRulePack(name, pack, dir)
}

// CustomRulePackErrors lists the config error of every broken custom_packs
// entry by name, for status and the gateway's start warning.
func (c *Config) CustomRulePackErrors() []error {
	if c == nil {
		return nil
	}
	var out []error
	for _, name := range slices.Sorted(maps.Keys(c.Guardrail.CustomPacks)) {
		if err := c.CustomRulePackError(name); err != nil {
			out = append(out, err)
		}
	}
	return out
}

// UsableCustomRulePack is the custom_packs entry name selects when it passes
// CustomRulePackError. A broken entry is not a pack: the selection loads its
// built-in fallback (BuiltinRulePackFor).
func (c *Config) UsableCustomRulePack(name string) (CustomRulePack, bool) {
	if c == nil {
		return CustomRulePack{}, false
	}
	pack, ok := c.Guardrail.CustomPacks[name]
	if !ok || c.CustomRulePackError(name) != nil {
		return CustomRulePack{}, false
	}
	return pack, true
}

// BuiltinRulePackFor is the built-in pack a selected name loads when no
// usable custom pack takes it: the name itself when built in (a broken
// custom pack never shadows a built-in one), the default pack for a broken
// entry of any other name, "" for a usable custom pack or an unknown name.
func (c *Config) BuiltinRulePackFor(name string) string {
	if c == nil || name == "" {
		return ""
	}
	if _, usable := c.UsableCustomRulePack(name); usable {
		return ""
	}
	if IsBuiltinRulePack(name) {
		return name
	}
	if _, registered := c.Guardrail.CustomPacks[name]; registered {
		return "default"
	}
	return ""
}

// brokenCustomRulePackSelected reports that ref selects a custom_packs entry
// that fails CustomRulePackError.
func (c *Config) brokenCustomRulePackSelected(ref RulePackRef) bool {
	if c == nil || ref.Name == "" {
		return false
	}
	_, registered := c.Guardrail.CustomPacks[ref.Name]
	return registered && c.CustomRulePackError(ref.Name) != nil
}
