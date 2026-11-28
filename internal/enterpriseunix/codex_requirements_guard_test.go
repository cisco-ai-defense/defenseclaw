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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// deploymentJSON is the committed deployment record: a lifecycle
// transaction rewrites it.
func (c *codexHealHost) deploymentJSON(t *testing.T) string {
	t.Helper()
	record, err := c.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatalf("deployment record: %v %v", record, err)
	}
	out, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Guards of the Codex requirements heal that no test needed (review
// RV1928b, GAP-1989): each test fails when its guard line is removed.

// Repair checks the policy view once more after it committed: a
// requirements.toml another writer changed after repair published and
// pinned it fails the repair instead of returning ok.
func TestGAP1989RepairFailsWhenCodexRequirementsChangeAfterItsPublish(t *testing.T) {
	c := newCodexHealHost(t, "linux")
	c.write(t, c.want+"# tampered\n")
	health, raced := c.env.HealthGet, false
	c.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
		raced = true
		c.write(t, c.want+"# raced\n")
		return health(ctx)
	}
	repair := c.run(Options{Action: ActionRepair})
	if !raced {
		t.Fatal("repair never checked the gateway health, so nothing raced it")
	}
	if repair.OK || !strings.Contains(fmt.Sprint(repair.Errors), "repair did not put back") {
		t.Fatalf("repair returned %v with errors %+v while requirements.toml stayed changed", repair.OK, repair.Errors)
	}
}

// The guardian's config-apply puts back a tampered Codex requirements file
// on the restore path, with no transaction: no gateway restart.
func TestGAP1989GuardianRestoreOfCodexRequirementsTakesNoTransaction(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			c := newCodexHealHost(t, goos)
			c.write(t, codexTampers(c.want)["appended comment"])
			before, beforeRecord := len(c.runner.calls), c.deploymentJSON(t)
			ensure := c.run(Options{Action: ActionEnsure, Reason: "path"})
			requireOK(t, ensure)
			if after := c.deploymentJSON(t); after != beforeRecord {
				t.Fatalf("the restore ran a transaction: the deployment record changed\nbefore %s\nafter  %s", beforeRecord, after)
			}
			// The same file text and an identical deployment record land
			// either way. What differs is what the run reports: the
			// transaction also restores the guardian's protected-target
			// owner and restarts the gateway, which the restore path never
			// does. This fails when the Codex branch of
			// restoreTamperedMachinePolicy is removed (the apply then heals
			// the file).
			if len(ensure.Changes) != 1 || !strings.HasPrefix(ensure.Changes[0], "restored the published codex machine policy") {
				t.Fatalf("ensure reported more than the restore of the Codex requirements file (a transaction ran); changes %q", ensure.Changes)
			}
			if strings.Contains(strings.Join(ensure.Changes, "\n"), "restarted") {
				t.Fatalf("the restore restarted the gateway: %q", ensure.Changes)
			}
			for _, call := range c.runner.calls[before:] {
				if strings.Contains(call, "restart") || strings.Contains(call, "kickstart") || strings.Contains(call, "bootstrap") {
					t.Fatalf("the restore ran a transaction (%q); calls %v", call, c.runner.calls[before:])
				}
			}
			c.requireHealed(t, "ensure")
		})
	}
}
