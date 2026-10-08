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

package enterpriseunix

import (
	"strings"
	"testing"
)

// GAP-0772: SELinux-confined users (user_u, staff_u) could not stat the
// var_run_t hook socket, so every hook they ran was refused while status and
// verify were green. On an SELinux host the install loads the DefenseClaw
// module once and relabels the hook socket; status names a host whose policy
// store does not hold the module.
func TestSELinuxHostLoadsTheHookSocketModule(t *testing.T) {
	h := newTestHost(t, "linux")
	writeHostFile(t, h, "/sys/fs/selinux/enforce", "1\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	var loads, relabels int
	for _, call := range h.runner.calls {
		if strings.HasPrefix(call, "semodule -i ") && strings.HasSuffix(call, "/defenseclaw.cil") {
			loads++
		}
		if strings.HasPrefix(call, "restorecon -R ") && strings.HasSuffix(call, h.env.P(h.env.Layout.HookSocketDir)) {
			relabels++
		}
	}
	if loads != 1 || relabels != 1 {
		t.Fatalf("the install must load the SELinux module and relabel the hook socket: loads %d relabels %d in %v", loads, relabels, h.runner.calls)
	}
	// The fake semodule stores nothing, so the policy store lacks the module.
	if r := h.run(Options{Action: ActionStatus}); !hasWarning(r, codeSELinuxModuleMissing) {
		t.Fatalf("status must name the missing SELinux module: %+v", r.Warnings)
	}
}
