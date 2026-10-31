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
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// GAP-1323: an entry that denies the gateway's service account reading the
// administrator policy folder (policy_dir) was not removed by repair, so the
// gateway refused the folder and repair failed activation_failed whenever the
// folder also had an unrelated entry. Repair removes the denying entry (and
// one in a rule pack below it) and keeps the unrelated ones: a deny for
// another account, or a deny the service account's earlier allow overrides.
func TestRepairRemovesOnlyThePolicyDirEntriesThatDenyTheGateway(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	dir := h.env.P(h.env.Layout.PolicyDir)
	pack := filepath.Join(dir, "guardrail", "lane")
	if err := os.MkdirAll(pack, 0o750); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(pack, "rules.yaml")
	if err := os.WriteFile(rule, []byte("rules: []\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	service := "user:" + h.env.Layout.ServiceUser
	h.runner.acls = map[string][]string{
		dir:  {service + " deny list,search", "user:dcm-qv deny delete,writeattr", "user:dcm-qv deny list"},
		rule: {service + " allow read", service + " deny read", "group:everyone deny read"},
		pack: {"group:" + h.env.Layout.ServiceGroup + " deny search"},
	}
	status := h.run(Options{Action: ActionStatus})
	if status.OK {
		t.Fatal("status passed a policy_dir entry that denies the gateway reading it")
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if got := h.runner.acls[dir]; !slices.Equal(got, []string{"user:dcm-qv deny delete,writeattr", "user:dcm-qv deny list"}) {
		t.Fatalf("after repair the ACL of policy_dir is %v, want only the entries for another account", got)
	}
	if got := h.runner.acls[rule]; !slices.Equal(got, []string{service + " allow read", service + " deny read", "group:everyone deny read"}) {
		t.Fatalf("after repair the ACL of the rule file is %v, want it unchanged (the allow decides)", got)
	}
	if got, ok := h.runner.acls[pack]; ok {
		t.Fatalf("after repair the rule pack folder keeps %v, want the service group deny removed", got)
	}
	requireOK(t, h.run(Options{Action: ActionStatus}))
}
