// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package configwrite

import (
	"bytes"
	"net"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// MaxRestartSettingPatterns bounds the settings RestartSettingPatterns
// returns.
const MaxRestartSettingPatterns = 32

// restartSettingPatternShape is what a reported setting may look like:
// schema key names, "*" and dots.
var restartSettingPatternShape = lazyregexp.New(`^[a-z_*.]{1,96}$`)

// RestartSettingPatterns names the settings behind restart-required change
// paths (ManagedRestartRequired), never the paths: a change path can carry
// an administrator's map key, such as a profile, a group or a connector
// name. A path is reported as the restartKeys entry it matched, cut at the
// path's depth when the whole block above it changed ("guardrail"); a
// connector set change as guardrail.connectors.*.enabled; the rest of the
// enterprise block as enterprise.<section>. The result is sorted, without
// duplicates, and at most MaxRestartSettingPatterns long.
func RestartSettingPatterns(paths []string) []string {
	var out []string
	for _, path := range paths {
		pattern := restartSettingPattern(restartSegments(path))
		if restartSettingPatternShape.MatchString(pattern) && !slices.Contains(out, pattern) {
			out = append(out, pattern)
		}
	}
	slices.Sort(out)
	if len(out) > MaxRestartSettingPatterns {
		out = out[:MaxRestartSettingPatterns]
	}
	return out
}

// restartSettingPattern is the setting a restart-required path belongs to,
// in the order ManagedRestartRequired classifies it; "" for a path it does
// not classify.
func restartSettingPattern(segs []string) string {
	if len(segs) == 0 {
		return ""
	}
	cut := func(key []string) string { return strings.Join(key[:min(len(segs), len(key))], ".") }
	for _, key := range restartKeys {
		if parts := strings.Split(key, "."); restartKeyMatches(segs, parts) {
			return cut(parts)
		}
	}
	if connector := []string{"guardrail", "connectors", "*", "enabled"}; restartKeyMatches(segs, connector) {
		return cut(connector)
	}
	if segs[0] == "enterprise" {
		return strings.Join(segs[:min(len(segs), 2)], ".")
	}
	return ""
}

// ManagedDefaults are the values a managed standalone device resolves an
// omitted data_dir, gateway.api_bind and gateway.api_port to: its layout's
// data directory and API listener. Ensure and bundle validation accept no
// other value for the three (config.ValidateManagedStandaloneConfig), and
// the gateway loads an omitted one as this value, so a config that spells
// one out and a config that omits it run the same gateway. The zero value
// resolves nothing, and then every difference counts.
type ManagedDefaults struct {
	GOOS    string
	DataDir string
	APIBind string
	APIPort int
}

// ManagedDefaultsFor is the ManagedDefaults of a standalone layout.
func ManagedDefaultsFor(layout managed.StandaloneLayout) ManagedDefaults {
	defaults := ManagedDefaults{GOOS: layout.GOOS, DataDir: layout.DataDir}
	if host, port, err := net.SplitHostPort(layout.APIAddr); err == nil {
		if n, err := strconv.Atoi(port); err == nil && n > 0 {
			defaults.APIBind, defaults.APIPort = host, n
		}
	}
	return defaults
}

// dropUnchanged removes from changed the defaulted settings whose effective
// value is the same in both configs. An installed config that does not
// parse is replaced wholesale, so every change stays.
func (d ManagedDefaults) dropUnchanged(before, after []byte, changed []string) []string {
	if !slices.ContainsFunc(changed, d.defaulted) {
		return changed
	}
	var left, right map[string]any
	if len(bytes.TrimSpace(before)) == 0 || yaml.Unmarshal(before, &left) != nil || yaml.Unmarshal(after, &right) != nil {
		return changed
	}
	return slices.DeleteFunc(slices.Clone(changed), func(path string) bool {
		l, lok := d.resolve(path, left)
		r, rok := d.resolve(path, right)
		return lok && rok && l == r
	})
}

// defaulted reports a setting whose omission d resolves.
func (d ManagedDefaults) defaulted(path string) bool {
	switch path {
	case "data_dir":
		return d.DataDir != ""
	case "gateway.api_bind":
		return d.APIBind != ""
	case "gateway.api_port":
		return d.APIPort != 0
	}
	return false
}

// resolve is the effective value of a defaulted setting in a parsed
// document: its default when omitted (an empty api_bind is the default
// listener too), its spelled-out value otherwise. ok is false for any other
// setting and for a value of another type.
func (d ManagedDefaults) resolve(path string, document map[string]any) (string, bool) {
	if !d.defaulted(path) {
		return "", false
	}
	value, present := lookupSetting(document, path)
	switch path {
	case "data_dir":
		dir := d.DataDir
		if present {
			s, isString := value.(string)
			if !isString || strings.TrimSpace(s) == "" {
				return "", false
			}
			dir = s
		}
		if d.GOOS == "windows" {
			return strings.ToLower(strings.TrimRight(strings.ReplaceAll(dir, "/", `\`), `\`)), true
		}
		return strings.TrimRight(dir, "/"), true
	case "gateway.api_bind":
		if !present {
			return d.APIBind, true
		}
		s, isString := value.(string)
		if !isString {
			return "", false
		}
		if s = strings.TrimSpace(s); s == "" {
			return d.APIBind, true
		}
		return s, true
	default: // gateway.api_port
		if !present {
			return strconv.Itoa(d.APIPort), true
		}
		n, isInt := value.(int)
		return strconv.Itoa(n), isInt
	}
}

// lookupSetting reads the value at a dotted path of a parsed document.
func lookupSetting(document map[string]any, path string) (any, bool) {
	var value any = document
	for _, key := range strings.Split(path, ".") {
		block, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		if value, ok = block[key]; !ok {
			return nil, false
		}
	}
	return value, true
}
