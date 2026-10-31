// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0576: an earlier failed hook install (rc.1 under allowManagedHooksOnly)
// left ~/.defenseclaw/hooks, a hook token and config and connector_backups
// with no manifest row. A managed purge removes those orphans with the rest
// of the account's managed data; a folder that also holds the account's own
// per-user install (config.yaml) is kept whole (GAP-0727).
func TestPurgeUserStateRemovesOrphansOfAnEarlierFailedInstall(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	for name, content := range map[string]string{
		"hooks/claude-code-hook.sh":                      "#!/bin/sh\n",
		".hook-claudecode.token":                         "tok\n",
		".hookcfg-claudecode.json":                       "{}\n",
		"connector_backups/claudecode/settings.json.bak": "{}\n",
	} {
		writePurgeTestFile(t, filepath.Join(dataDir, name), content)
	}
	summary, err := PurgeUserState(context.Background(), InstallOptions{
		UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(), Registry: connector.NewDefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("PurgeUserState: %v", err)
	}
	if !summary.Data {
		t.Fatalf("summary = %+v, want the data purged", summary)
	}
	if left, _ := filepath.Glob(filepath.Join(dataDir, "*")); len(left) != 0 {
		t.Fatalf("orphans stayed: %v", left)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("~/.defenseclaw stayed: %v", err)
	}
}
