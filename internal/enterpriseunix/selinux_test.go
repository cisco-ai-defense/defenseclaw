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
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	selinuxpolicy "github.com/defenseclaw/defenseclaw/packaging/selinux"
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

	// GAP-1143: the module let confined users connect to every
	// unconfined_service_t socket. It now labels the gateway binary, from
	// which systemd starts the gateway, and gives its listening sockets, a
	// domain of its own; user domains may connect only to that domain.
	module := string(selinuxpolicy.Module())
	gateway := filepath.Join(h.env.Layout.BinDir, binGateway)
	if !strings.Contains(module, `(filecon "`+gateway+`" file (system_u object_r `+selinuxpolicy.GatewayExecType+` `) ||
		!strings.Contains(module, "(typetransition init_t "+selinuxpolicy.GatewayExecType+" process defenseclaw_gateway_t)") {
		t.Fatalf("the module must start %s in the gateway domain:\n%s", gateway, module)
	}
	for _, grant := range regexp.MustCompile(`\(allow userdomain (\S+) \(unix_stream_socket \(connectto\)\)\)`).FindAllStringSubmatch(module, -1) {
		if grant[1] != "defenseclaw_gateway_t" {
			t.Fatalf("user domains may connect only to the gateway domain, not %s", grant[1])
		}
	}
	// An upgrade that loads a changed module replaces the hook socket: its
	// label is the domain the gateway ran in when systemd created it.
	writeHostFile(t, h, "/var/lib/selinux/targeted/active/modules/400/defenseclaw/cil", "x")
	writeHostFile(t, h, filepath.Join(h.env.Layout.LifecycleDir, selinuxModuleStamp), strings.Repeat("0", 64)+"\n")
	before := len(h.services.calls)
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}))
	if calls := socketCalls(h, before); strings.Join(calls, ",") != "restart "+unitHookSocket {
		t.Fatalf("loading a changed module must replace the hook socket, and only it: %v", calls)
	}
}
