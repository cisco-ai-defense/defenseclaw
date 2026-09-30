// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const testHookBinary = "/opt/defenseclaw/bin/defenseclaw-hook"

// testOpenCodePlugin is the canonical Linux path of the managed OpenCode
// plugin, the path OpenCode's managed config names.
const testOpenCodePlugin = "/opt/defenseclaw/share/opencode/defenseclaw.js"

// installTestOpenCodePlugin installs this release's managed OpenCode plugin
// at its canonical path inside the rooted test tree and returns the file.
func installTestOpenCodePlugin(t *testing.T, opts *Options) string {
	t.Helper()
	opts.OpenCodePluginPath = testOpenCodePlugin
	file := rooted(*opts, testOpenCodePlugin)
	writeFile(t, file, string(openCodeManagedPlugin))
	return file
}

// publishTestOptions are testOptions whose summary directory already exists.
// Publish writes the summary under the host path PublicPolicyPath; a Windows
// host joins it with backslashes, which the linux-rooted writer cannot split
// into the parent directory it would create.
func publishTestOptions(t *testing.T) Options {
	t.Helper()
	opts := testOptions(t)
	if err := os.MkdirAll(filepath.Dir(opts.PublicPolicyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	return opts
}

func testOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	return Options{
		GOOS:             "linux",
		Root:             root,
		HookBinary:       testHookBinary,
		StateDir:         filepath.Join(root, "var/lib/defenseclaw-enterprise/machine-policy"),
		PublicPolicyPath: filepath.Join(root, "etc/defenseclaw/machine-policy.json"),
		Now:              func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) },
		SkipTrustChecks:  true,
	}
}

func withPolicy(opts Options, connector string, mutate func(*config.EnterpriseConnectorPolicy)) Options {
	cfg := config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{}}
	policy := config.EnterpriseConnectorPolicy{}
	mutate(&policy)
	cfg.Connectors[connector] = policy
	if opts.Policies == nil {
		opts.Policies = map[string]config.ResolvedConnectorPolicy{}
	}
	opts.Policies[connector] = cfg.PolicyFor(connector)
	return opts
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustNoConflicts(t *testing.T, state State) {
	t.Helper()
	if len(state.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %s", strings.Join(state.Conflicts, " | "))
	}
}

func hasConflict(state State, substring string) bool {
	for _, conflict := range state.Conflicts {
		if strings.Contains(conflict, substring) {
			return true
		}
	}
	return false
}
