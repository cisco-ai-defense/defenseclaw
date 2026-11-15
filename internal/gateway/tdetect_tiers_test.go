// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// tdetectVerdict is the action the tool-inspect route answers for one shell
// command in one pack (rel-1-0-10 S7 train T-DETECT: the five tiers are the
// packs of gap0437Packs).
func tdetectVerdict(t *testing.T, a *APIServer, command string) (action string, raw map[string]any) {
	t.Helper()
	out := gap0437Inspect(t, a, t.TempDir(), command)
	action, _ = out["action"].(string)
	return action, out
}
