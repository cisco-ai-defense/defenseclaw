// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import "testing"

// GAP-0055: after an operator moved the controls policy to monitor, or
// deleted it, a ready user read "the controls policy is not in enforce mode
// yet", or "no agent installed" once no anchor was left. Both now name the
// operator's change, and neither is enforcing.
func TestOperatorOverrideNamesTheUsersItHolds(t *testing.T) {
	for name, act := range map[string]func(h *harness, policy string){
		"set-mode monitor": func(h *harness, policy string) { h.tg.setMode(policy, LoadedMonitor) },
		"delete":           func(h *harness, policy string) { h.tg.remove(policy) },
	} {
		t.Run(name, func(t *testing.T) {
			h := enforcing(t)
			controls, _ := h.tg.find(FamilyControls)
			act(h, controls.Name)
			h.pass()
			if state := userState(h, 1001); state.State != UIDMonitor || state.Reason != WarnOperatorOverride {
				t.Fatalf("alice after %s = %+v", name, state)
			}
		})
	}
}
