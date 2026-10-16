// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0588: Hermes and Devin keep the last known good copy of the agent
// config and its restore notice in connector_backups\<connector>; the
// rollback of a failed first install removes only the names it knows there
// and refuses the whole root for any other, so it must know theirs.
func TestManagedRuntimeCleanupKnowsTheAgentConfigCopies(t *testing.T) {
	for _, name := range []string{"hermes", "devin"} {
		leaves := connector.AgentConfigBackupLeaves(name)
		if len(leaves) != 2 {
			t.Fatalf("%s: leaves = %v", name, leaves)
		}
		files := windowsManagedRuntimeCleanupConnectors[name]
		for _, leaf := range leaves {
			if !slices.Contains(files.backups, leaf) {
				t.Errorf("%s: the cleanup contract does not know %s (backups %v)", name, leaf, files.backups)
			}
			if _, ok := windowsManagedRuntimeCleanupLeaves[leaf]; !ok {
				t.Errorf("%s: %s is not a cleanup leaf", name, leaf)
			}
		}
	}
}
