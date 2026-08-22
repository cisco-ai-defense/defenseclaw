// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os/exec"
	"sync"
)

func codexSystemRequirementsPath() (string, error) {
	return "/etc/codex/requirements.toml", nil
}

func startCodexAppServerTree(cmd *exec.Cmd, expectedDigest ...string) (func(), error) {
	digest := ""
	if len(expectedDigest) > 0 {
		digest = expectedDigest[0]
	}
	if err := startCodexAppServerProcess(cmd, digest); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = terminateCodexAppServerProcess(cmd)
			}
			_ = cmd.Wait()
		})
	}, nil
}
