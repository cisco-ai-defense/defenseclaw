// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"strings"
)

func pluginLaunchConnector(name string) bool {
	switch name {
	case "opencode", "amp", "kiro-cli", "devin", "hermes", "agy":
		return true
	}
	return false
}

// pluginLaunchEnvironment retains only the variables whose values can move
// an enrolled agent away from its managed hooks. It never stores the rest of
// the process environment, which can contain credentials.
func pluginLaunchEnvironment(raw []byte) map[string]string {
	out := map[string]string{}
	for _, entry := range bytes.Split(raw, []byte{0}) {
		key, value, ok := strings.Cut(string(entry), "=")
		if !ok {
			continue
		}
		switch key {
		case "OPENCODE_PURE", "OPENCODE_TEST_MANAGED_CONFIG_DIR",
			"XDG_CONFIG_HOME", "HOME", "KIRO_HOME", "KIRO_AGENT_CONFIG_DIR", "KIRO_TEST_AGENTS_DIR",
			"HERMES_HOME", "HERMES_MANAGED_DIR", "HERMES_SAFE_MODE":
			out[key] = value
		}
	}
	return out
}
