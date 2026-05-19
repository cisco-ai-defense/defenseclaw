// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestDiscoveredAuditActionsRegistered(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "discovered_unregistered_audit_actions.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read discovered audit actions: %v", err)
	}

	var missing []string
	for _, line := range strings.Split(string(raw), "\n") {
		action := strings.TrimSpace(line)
		if action == "" || strings.HasPrefix(action, "#") {
			continue
		}
		if !IsKnownAction(action) {
			missing = append(missing, action)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("discovered audit actions not registered in AllActions: %s", strings.Join(missing, ", "))
	}
}
