// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// openCodePortGuardian is a standalone guardian with the given eligible
// accounts (fake uids, their homes under the test's temp dir), OpenCode on
// the machine policy when governed, an in-memory OpenCode ports record, and
// a worker that runs the as-the-user step in this process.
func openCodePortGuardian(t *testing.T, governed bool, uids ...int) (map[int]string, *map[int]int) {
	t.Helper()
	previousManifest, previousMachinePolicy := enterpriseHookManifest, enterpriseHookStandaloneMachinePolicySet
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	previousLoadPorts, previousWritePorts := enterpriseHookLoadOpenCodePorts, enterpriseHookWriteOpenCodePorts
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookStandaloneMachinePolicySet = previousManifest, previousMachinePolicy
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookLoadOpenCodePorts, enterpriseHookWriteOpenCodePorts = previousLoadPorts, previousWritePorts
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.leftoversClean = false
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	useForeignHookGuardian(t, map[string]config.EnterpriseConnectorPolicy{})
	published := map[string]struct{}{enterprisepolicy.ConnectorClaudeCode: {}}
	if governed {
		published[enterprisepolicy.ConnectorOpenCode] = struct{}{}
	}
	enterpriseHookStandaloneMachinePolicySet = func() map[string]struct{} { return published }
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	root := t.TempDir()
	homes := map[int]string{}
	accounts := []enterprisehooks.UnixEligibleAccount{}
	for _, uid := range uids {
		home := filepath.Join(root, fmt.Sprintf("ent%d", uid))
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		homes[uid] = home
		accounts = append(accounts, enterprisehooks.UnixEligibleAccount{User: filepath.Base(home), UID: uid, GID: uid, Home: home})
	}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return accounts, nil }
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	record := map[int]int{}
	enterpriseHookLoadOpenCodePorts = func(string) (map[int]int, error) {
		out := map[int]int{}
		for uid, port := range record {
			out[uid] = port
		}
		return out, nil
	}
	enterpriseHookWriteOpenCodePorts = func(_ string, ports map[int]int, _ map[int]string) error {
		record = map[int]int{}
		for uid, port := range ports {
			record[uid] = port
		}
		return nil
	}
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		request.Home = account.Home
		response := enterpriseHookWorkerResponse{}
		if request.OpenCodeServicePort > 0 {
			response.OpenCodeServicePort = runEnterpriseHookWorkerOpenCodePort(request)
		}
		return response, nil
	}
	return homes, &record
}

func openCodePortIn(t *testing.T, home string) int {
	t.Helper()
	data, err := os.ReadFile(enterprisepolicy.OpenCodeServiceConfigPath(home))
	if err != nil {
		return 0
	}
	var doc struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Port
}

func runOpenCodePortPass(t *testing.T) string {
	t.Helper()
	enterpriseHookForeignCleanupState.fingerprint = ""
	var log strings.Builder
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
	return log.String()
}

// gas-ux-r1 GAP-0053: on a managed host (dc-fc-gas-ent1, ent1 and ent2)
// nobody runs per-user setup; the guardian gives every eligible account its
// own OpenCode service port, keeps ports across passes and upgrades, keeps
// a port the user set, and gives a new account a port nobody holds.
func TestManagedGuardianGivesEveryAccountItsOwnOpenCodePort(t *testing.T) {
	homes, record := openCodePortGuardian(t, true, 1001, 1002, 1003)
	// ent3 set its own port before DefenseClaw ran.
	userSet := enterprisepolicy.OpenCodeServiceConfigPath(homes[1003])
	if err := os.MkdirAll(filepath.Dir(userSet), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userSet, []byte(`{"port":25001,"password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	log := runOpenCodePortPass(t)
	got := map[int]int{}
	seen := map[int]int{}
	for uid, home := range homes {
		port := openCodePortIn(t, home)
		if port == 0 || port == enterprisepolicy.OpenCodeDefaultServicePort {
			t.Fatalf("uid %d has no own port (%d)\n%s", uid, port, log)
		}
		if other, dup := seen[port]; dup {
			t.Fatalf("uids %d and %d share port %d\n%s", other, uid, port, log)
		}
		seen[port], got[uid] = uid, port
	}
	if got[1003] != 25001 {
		t.Fatalf("the user's own port was replaced: %d", got[1003])
	}
	if (*record)[1001] != got[1001] || (*record)[1002] != got[1002] || (*record)[1003] != 25001 {
		t.Fatalf("record %v does not hold the ports %v", *record, got)
	}
	if !strings.Contains(log, "gave ") || !strings.Contains(log, "OpenCode background server port") {
		t.Fatalf("the write is not logged:\n%s", log)
	}
	// Stable: the next pass, and one after an upgrade (the record and the
	// files stay), changes nothing.
	for pass := 0; pass < 2; pass++ {
		log = runOpenCodePortPass(t)
		for uid, home := range homes {
			if port := openCodePortIn(t, home); port != got[uid] {
				t.Fatalf("pass %d moved uid %d from %d to %d\n%s", pass, uid, got[uid], port, log)
			}
		}
		if strings.Contains(log, "gave ") {
			t.Fatalf("pass %d wrote again:\n%s", pass, log)
		}
	}
}

// Two accounts whose uids give the same first port (mod 8000) still get two
// ports: the lower uid keeps its own, the other takes the next free one.
func TestManagedGuardianOpenCodePortsForUIDsThatShareAStart(t *testing.T) {
	homes, record := openCodePortGuardian(t, true, 1001, 9001)
	log := runOpenCodePortPass(t)
	a, b := openCodePortIn(t, homes[1001]), openCodePortIn(t, homes[9001])
	if a != enterprisepolicy.OpenCodeAccountPort(1001) || b != a+1 || (*record)[9001] != b {
		t.Fatalf("ports %d %d record %v\n%s", a, b, *record, log)
	}
}

// Without OpenCode on the machine policy (or a per-user enrollment) no
// account's OpenCode file is touched.
func TestManagedGuardianLeavesOpenCodeAloneWhenNotGoverned(t *testing.T) {
	homes, record := openCodePortGuardian(t, false, 1001, 1002)
	runOpenCodePortPass(t)
	for uid, home := range homes {
		if _, err := os.Lstat(enterprisepolicy.OpenCodeServiceConfigPath(home)); !os.IsNotExist(err) {
			t.Fatalf("uid %d got an OpenCode service file: %v", uid, err)
		}
	}
	if len(*record) != 0 {
		t.Fatalf("record written: %v", *record)
	}
}
