// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"maps"
	"runtime"
	"strings"
	"sync"
	"weak"
)

// pinnedRulePackPostures keeps a generation's loaded posture with its
// configuration. Weak keys let a retired configuration and its snapshot go
// away together.
var pinnedRulePackPostures sync.Map // weak.Pointer[Config] -> map[directory]posture

// BindRulePackPostures pins the postures read while building this
// configuration's rule generation. An empty posture means the loaded pack
// had no posture manifest and uses its legacy folder name.
func (c *Config) BindRulePackPostures(postures map[string]string) {
	if c == nil || postures == nil {
		return
	}
	key := weak.Make(c)
	if _, loaded := pinnedRulePackPostures.Swap(key, maps.Clone(postures)); !loaded {
		runtime.AddCleanup(c, func(key weak.Pointer[Config]) { pinnedRulePackPostures.Delete(key) }, key)
	}
}

// PinnedRulePackPosture returns the loaded posture for dir when a generation
// bound it to this configuration. A missing entry leaves older config-only
// callers to resolve their pack as before.
func (c *Config) PinnedRulePackPosture(dir string) (string, bool) {
	if c == nil {
		return "", false
	}
	if snapshot, ok := pinnedRulePackPostures.Load(weak.Make(c)); ok {
		posture, found := snapshot.(map[string]string)[strings.TrimSpace(dir)]
		return posture, found
	}
	return "", false
}
