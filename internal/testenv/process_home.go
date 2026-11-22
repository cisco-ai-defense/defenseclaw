// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"fmt"
	"os"
)

// accountHomeEnv are the variables through which the real account's home
// reaches a test process: HOME itself and the agents' own config roots
// (CLAUDE_CONFIG_DIR, CODEX_HOME).
var accountHomeEnv = []string{"HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME"}

// IsolateProcessHome gives the whole test process an empty home of its own:
// HOME is a new temporary folder and the agents' config roots are unset, so a
// test that reads the instruction files, the config or the agent folders of
// the account (a developer's, a shared host's, a CI runner's) finds none
// (rel-1-0-10 GAP-0293 environment sweep: two gateway tests read the host's
// ~/.claude and ~/.codex). TestMain calls it once; the returned function
// restores the environment and removes the folder.
func IsolateProcessHome() (func(), error) {
	dir, err := os.MkdirTemp("", "defenseclaw-test-home-")
	if err != nil {
		return nil, fmt.Errorf("create the process home: %w", err)
	}
	previous := map[string]*string{}
	for _, name := range accountHomeEnv {
		if value, ok := os.LookupEnv(name); ok {
			previous[name] = &value
		} else {
			previous[name] = nil
		}
	}
	restore := func() {
		for name, value := range previous {
			if value == nil {
				_ = os.Unsetenv(name)
			} else {
				_ = os.Setenv(name, *value)
			}
		}
		_ = os.RemoveAll(dir)
	}
	for _, name := range accountHomeEnv[1:] {
		_ = os.Unsetenv(name)
	}
	if err := os.Setenv("HOME", dir); err != nil {
		restore()
		return nil, fmt.Errorf("set HOME: %w", err)
	}
	return restore, nil
}
