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
	case "opencode", "amp", "kiro-cli", "devin", "hermes", "agy", "codex", "copilot":
		return true
	}
	return false
}

// pluginLaunchEnvironment retains only selectors relevant to managed hook or
// plugin loading. Shell startup values are reduced to fixed markers; it never
// stores those paths or the rest of the environment, which can hold credentials.
func pluginLaunchEnvironment(raw []byte) map[string]string {
	out := map[string]string{}
	for _, entry := range bytes.Split(raw, []byte{0}) {
		key, value, ok := strings.Cut(string(entry), "=")
		if !ok {
			continue
		}
		switch key {
		case "BASH_ENV":
			if value != "" {
				out[key] = "set" // Never retain the startup file path.
			}
		case "SHELLOPTS":
			for _, option := range strings.Split(value, ":") {
				if option == "noexec" {
					out[key] = "noexec"
					break
				}
			}
		case "OPENCODE_PURE", "OPENCODE_TEST_MANAGED_CONFIG_DIR",
			"XDG_CONFIG_HOME", "HOME", "KIRO_HOME", "KIRO_AGENT_CONFIG_DIR", "KIRO_TEST_AGENTS_DIR",
			"HERMES_HOME", "HERMES_MANAGED_DIR", "HERMES_SAFE_MODE":
			out[key] = value
		}
	}
	return out
}
