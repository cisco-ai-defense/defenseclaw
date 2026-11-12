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
	"path/filepath"
	"slices"
	"strings"
)

// EmptyRulePackFilesDigest is the guardrail.custom_packs pin of a pack with
// no files of its own: the digest of an empty file set, which the embedded
// pack also has (guardrail RulePack.FilesDigest). It proves no content.
const EmptyRulePackFilesDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// RulePackValidator is the rule loader's verdict on one pack folder: the
// FilesDigest pin ("sha256:...") of the files it loaded and the posture its
// manifest names, or why the folder is not a loadable pack. The guardrail
// package registers it (config cannot import it), so the gateway, the
// standalone hook, the candidate check and status read one verdict made by
// the loader the gateway itself uses.
type RulePackValidator func(dir string) (digest, posture string, err error)

var customRulePackValidator RulePackValidator

// RegisterCustomRulePackValidator supplies the rule loader's validator. A
// binary without it checks an entry's path and pin shape only, and keeps a
// standalone pinned selection strict (HookPolicyTierForConnector).
func RegisterCustomRulePackValidator(validate RulePackValidator) {
	customRulePackValidator = validate
}

// StalePinError is the config error of a custom_packs entry whose folder is a
// valid rule pack but whose files no longer hash to the pin of the entry. It
// is an integrity refusal, not a fallback: the pack the administrator pinned
// is not the pack on disk, so nothing is enforced in its place silently. The
// gateway refuses to load it until the pin is reviewed and corrected, and
// status and doctor name the error (IsStalePinError).
type StalePinError struct{ message string }

func (e *StalePinError) Error() string { return e.message }

// IsStalePinError reports that err is the stale pin of a custom_packs entry.
func IsStalePinError(err error) bool {
	var stale *StalePinError
	return errors.As(err, &stale)
}

// customRulePackCheck is one guardrail.custom_packs entry as it was checked:
// the entry and folder that were read, and the verdict. posture is the
// manifest posture of a pack the loader accepted (validated).
type customRulePackCheck struct {
	pack      CustomRulePack
	dir       string
	posture   string
	validated bool
	err       error
}

// checkCustomRulePack is the one check of a guardrail.custom_packs entry whose
// folder is dir (its path resolved against the config directory, or the
// offline copy a bundle signer reads it from: UseOfflineVendorPolicies). The
// path is non-empty after trimming and names a readable folder, the pin is
// not the empty file set's, and, where the rule loader is linked, the folder
// loads as a valid pack whose files hash to the pin (a missing pin matches
// nothing). The gateway
// still compares the pin with the files it loads for a generation.
func checkCustomRulePack(name string, pack CustomRulePack, dir string) customRulePackCheck {
	out := customRulePackCheck{pack: pack, dir: dir}
	key := "guardrail.custom_packs." + name
	pin := strings.TrimSpace(pack.Digest)
	switch {
	case strings.TrimSpace(pack.Path) == "" || dir == "":
		out.err = fmt.Errorf("%s.path is empty", key)
		return out
	case strings.EqualFold(pin, EmptyRulePackFilesDigest):
		out.err = fmt.Errorf("%s.digest pins an empty file set; pin the digest `defenseclaw-gateway rulepack validate --dir %s` prints", key, dir)
		return out
	}
	folder, err := os.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		out.err = fmt.Errorf("%s.path %q is not a folder", key, dir)
		return out
	} else if err != nil {
		out.err = fmt.Errorf("%s.path cannot be read: %w", key, err)
		return out
	}
	defer folder.Close()
	if info, err := folder.Stat(); err != nil {
		out.err = fmt.Errorf("%s.path cannot be read: %w", key, err)
		return out
	} else if !info.IsDir() {
		out.err = fmt.Errorf("%s.path %q is not a folder", key, dir)
		return out
	}
	if _, err := folder.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		out.err = fmt.Errorf("%s.path cannot be read: %w", key, err)
		return out
	}
	if customRulePackValidator == nil {
		return out
	}
	digest, posture, err := customRulePackValidator(dir)
	if err != nil {
		out.err = fmt.Errorf("%s.path %q is not a valid rule pack: %w", key, dir, err)
		return out
	}
	if !strings.EqualFold(pin, digest) {
		out.err = &StalePinError{fmt.Sprintf("the files in %q hash to %s, which does not match %s.digest; review the pack, then pin that digest "+
			"(`defenseclaw config set %s.digest %s` on a per-user install; `defenseclaw-gateway rulepack validate --dir %s` "+
			"prints it on the \"custom_packs pin\" line)", dir, digest, key, key, digest, dir)}
		return out
	}
	out.validated, out.posture = true, posture
	return out
}

// customPackPathIn is the folder a custom_packs path names: an absolute path
// as written, a relative one against base, the directory of the config file
// that declares it (never the process working directory).
func customPackPathIn(base string, pack CustomRulePack) string {
	path := strings.TrimSpace(pack.Path)
	if path == "" || base == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// CustomRulePackPath is the folder custom_packs entry name loads from, ""
// when it is not an entry.
func (g *GuardrailConfig) CustomRulePackPath(name string) string {
	if g == nil {
		return ""
	}
	pack, ok := g.CustomPacks[name]
	if !ok {
		return ""
	}
	return customPackPathIn(g.customPackBase, pack)
}

// customRulePackCheck is the check of entry name. A configuration the loader
// built answers from what it checked then, so every reader, and every copy of
// the configuration, sees one verdict for the life of the load; an entry the
// loader did not see as it is now (a configuration it did not build, an entry
// added or edited since, a folder moved by offline) is checked now. offline
// maps the folder to the one actually read (nil: as resolved); base is the
// directory its relative path resolves against.
func (g *GuardrailConfig) customRulePackCheck(name, base string, offline func(string) string) (customRulePackCheck, bool) {
	if g == nil {
		return customRulePackCheck{}, false
	}
	pack, ok := g.CustomPacks[name]
	if !ok {
		return customRulePackCheck{}, false
	}
	dir := customPackPathIn(base, pack)
	if offline != nil {
		dir = offline(dir)
	}
	if checked, ok := g.customRulePackChecks[name]; ok && checked.pack == pack && checked.dir == dir {
		return checked, true
	}
	return checkCustomRulePack(name, pack, dir), true
}

// CustomRulePackError is the config error of custom_packs entry name, nil for
// a usable entry and for a name that is not an entry. It is the verdict of
// the configuration the entry was loaded with; Config.CustomRulePackError is
// the same verdict where the Secure Client integration keeps its loader's own
// refusals.
func (g *GuardrailConfig) CustomRulePackError(name string) error {
	if g == nil {
		return nil
	}
	checked, _ := g.customRulePackCheck(name, g.customPackBase, nil)
	return checked.err
}

// BuiltinRulePackFor is Config.BuiltinRulePackFor for a caller that holds
// only the guardrail block.
func (g *GuardrailConfig) BuiltinRulePackFor(name string) string {
	if g == nil {
		return ""
	}
	_, registered := g.CustomPacks[name]
	return builtinRulePackFallback(name, registered, g.CustomRulePackFallsBack(name))
}

// CustomRulePackFallsBack reports that custom_packs entry name has a config
// error whose selection loads its built-in pack (BuiltinRulePackFor). A stale
// pin does not: the entry stays the selected pack and the gateway refuses it.
func (g *GuardrailConfig) CustomRulePackFallsBack(name string) bool {
	err := g.CustomRulePackError(name)
	return err != nil && !IsStalePinError(err)
}

// builtinRulePackFallback is the built-in pack a selected name loads when no
// usable custom pack takes it: the name itself when built in (a broken custom
// pack never shadows a built-in one), the default pack for a broken entry of
// any other name, "" for a usable custom pack or an unknown name.
func builtinRulePackFallback(name string, registered, broken bool) string {
	switch {
	case name == "" || (registered && !broken):
		return ""
	case IsBuiltinRulePack(name):
		return name
	case registered:
		return "default"
	}
	return ""
}

// CheckCustomRulePacks records every custom_packs entry's check once, with the
// config directory its relative paths resolve against. The loader runs it as
// the configuration is read, so each reader, and each copy of the
// configuration (DeepCopy), sees one verdict for the life of the load; a
// configuration built in code runs it to the same end. An entry that was not
// recorded, or that has since been edited, is checked again at each read.
func (c *Config) CheckCustomRulePacks() {
	g := &c.Guardrail
	g.customPackBase = configDirectory(c.ConfigFilePath)
	g.customRulePackChecks = make(map[string]customRulePackCheck, len(g.CustomPacks))
	for name, pack := range g.CustomPacks {
		g.customRulePackChecks[name] = checkCustomRulePack(name, pack, c.customRulePackDir(pack))
	}
}

// customRulePackDir is the folder pack loads from (ResolveRulePackDir).
func (c *Config) customRulePackDir(pack CustomRulePack) string {
	return c.offlineVendorPath(customPackPathIn(c.customPackBase(), pack))
}

// customPackBase is the directory relative custom_packs paths resolve
// against: the one recorded at load, else this configuration's file.
func (c *Config) customPackBase() string {
	if c.Guardrail.customPackBase != "" {
		return c.Guardrail.customPackBase
	}
	return configDirectory(c.ConfigFilePath)
}

// configDirectory is the absolute directory of the config file at path, "" for
// no path. LoadFromFile accepts a relative path, so the directory is made
// absolute when it is recorded: a later change of working directory must not
// move the folder a relative custom_packs path names.
func configDirectory(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	dir := filepath.Dir(path)
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// customRulePackCheck is the check of entry name, whatever the integration.
func (c *Config) customRulePackCheck(name string) (customRulePackCheck, bool) {
	if c == nil {
		return customRulePackCheck{}, false
	}
	return c.Guardrail.customRulePackCheck(name, c.customPackBase(), c.offlineVendorPath)
}

// CustomRulePackError is the config-load CustomRulePackError of name. Secure
// Client keeps its loader's own refusals: nil there.
func (c *Config) CustomRulePackError(name string) error {
	if c == nil || c.SecureClientIntegration() {
		return nil
	}
	checked, _ := c.customRulePackCheck(name)
	return checked.err
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

// UsableCustomRulePack is the custom_packs entry name selects unless its
// config error makes the selection load its built-in fallback
// (CustomRulePackFallsBack, BuiltinRulePackFor). A stale pin keeps the entry:
// the gateway then refuses its files.
func (c *Config) UsableCustomRulePack(name string) (CustomRulePack, bool) {
	if c == nil {
		return CustomRulePack{}, false
	}
	pack, ok := c.Guardrail.CustomPacks[name]
	if !ok || c.CustomRulePackFallsBack(name) {
		return CustomRulePack{}, false
	}
	return pack, true
}

// CustomRulePackFallsBack is GuardrailConfig.CustomRulePackFallsBack with the
// Secure Client exemption of CustomRulePackError.
func (c *Config) CustomRulePackFallsBack(name string) bool {
	err := c.CustomRulePackError(name)
	return err != nil && !IsStalePinError(err)
}

// BuiltinRulePackFor is the built-in pack a selected name loads when no
// usable custom pack takes it (builtinRulePackFallback).
func (c *Config) BuiltinRulePackFor(name string) string {
	if c == nil {
		return ""
	}
	_, registered := c.Guardrail.CustomPacks[name]
	return builtinRulePackFallback(name, registered, c.CustomRulePackFallsBack(name))
}

// brokenCustomRulePackSelected reports that ref selects a custom_packs entry
// that fails CustomRulePackError, a stale pin included: no posture such a
// pack claims sets a hook outage tier.
func (c *Config) brokenCustomRulePackSelected(ref RulePackRef) bool {
	if c == nil || ref.Name == "" {
		return false
	}
	_, registered := c.Guardrail.CustomPacks[ref.Name]
	return registered && c.CustomRulePackError(ref.Name) != nil
}
