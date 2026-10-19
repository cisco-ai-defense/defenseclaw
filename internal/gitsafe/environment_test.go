// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gitsafe

import (
	"slices"
	"strings"
	"testing"
)

func TestScrubbedEnvironmentWindowsFoldsOnlyComparisonKeys(t *testing.T) {
	entries := []string{
		"gIt_CONFIG_PARAMETERS='test.canary=fixed-public'", "gIt_CONFIG_COUNT=1",
		"gIt_CONFIG_KEY_0=test.canary", "gIt_CONFIG_VALUE_0=fixed-public",
		"gIt_DIR=fixed-other-repo", "gIt_WORK_TREE=fixed-other-tree", "gIt_SSH_COMMAND=fixed-unused-command",
		"xDg_CONFIG_HOME=fixed-other-home", "HoMe=fixed-other-home", "UsErPrOfIlE=fixed-other-profile",
		"Path=Fixed-Preserved-Path", "SYSTEMROOT=Fixed-Preserved-SystemRoot", "UNRELATED=Literal=Case-Sensitive-Value",
	}
	for _, insensitive := range []bool{false, true} {
		name := "Unix"
		if insensitive {
			name = "Windows"
		}
		t.Run(name, func(t *testing.T) {
			env := scrubbedEnvEntries(entries, "fixed-private-home", insensitive)
			for _, original := range entries {
				key, _, _ := strings.Cut(original, "=")
				unsafe := strings.HasPrefix(strings.ToUpper(key), "GIT_") || strings.HasPrefix(strings.ToUpper(key), "XDG_") ||
					strings.EqualFold(key, "HOME") || strings.EqualFold(key, "USERPROFILE")
				if got, want := slices.Contains(env, original), !insensitive || !unsafe; got != want {
					t.Fatalf("preserved key %q = %t, want %t", key, got, want)
				}
			}
			for key, want := range map[string]string{"GIT_CONFIG_COUNT": "0", "GIT_CONFIG_NOSYSTEM": "1",
				"GIT_CONFIG_GLOBAL": "/dev/null", "HOME": "fixed-private-home", "XDG_CONFIG_HOME": "fixed-private-home"} {
				if got, ok := envValue(env, key); !ok || got != want {
					t.Fatalf("canonical private environment key %s changed", key)
				}
			}
		})
	}
}
