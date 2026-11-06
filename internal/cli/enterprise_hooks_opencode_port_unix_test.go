// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	homes, record, _ := openCodePortGuardianWith(t, governed, uids...)
	return homes, record
}

// openCodePortGuardianWith also returns a setter for the eligible uids (an
// exclusion, a new account) and the accounts whose home is not available this
// pass; every uid keeps its home.
func openCodePortGuardianWith(t *testing.T, governed bool, uids ...int) (map[int]string, *map[int]int, func(pending map[int]bool, eligible ...int)) {
	t.Helper()
	previousManifest, previousMachinePolicy := enterpriseHookManifest, enterpriseHookStandaloneMachinePolicySet
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	previousLoadPorts, previousWritePorts := enterpriseHookLoadOpenCodePorts, enterpriseHookWriteOpenCodePorts
	previousRootRead := enterpriseHookReadOpenCodePort
	openCodeRootCannotRead, openCodeUserCannotRead = map[int]bool{}, map[int]bool{}
	t.Cleanup(func() {
		enterpriseHookReadOpenCodePort = previousRootRead
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
	byUID := map[int]enterprisehooks.UnixEligibleAccount{}
	for _, account := range accounts {
		byUID[account.UID] = account
	}
	unavailable := map[int]bool{}
	enterpriseHookCheckHome = func(_ string, uid int) enterprisehooks.HomeCheck {
		if unavailable[uid] {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	setEligible := func(pending map[int]bool, eligible ...int) {
		unavailable = map[int]bool{}
		for uid := range pending {
			unavailable[uid] = true
		}
		accounts = nil
		for _, uid := range eligible {
			// homes[uid], when set before the call, is the account's home
			// (a reused or new folder); otherwise it keeps the one it had.
			account, ok := byUID[uid]
			home := homes[uid]
			if !ok || (home != "" && home != account.Home) {
				if home == "" {
					home = filepath.Join(root, fmt.Sprintf("ent%d", uid))
				}
				if err := os.MkdirAll(home, 0o700); err != nil {
					t.Fatal(err)
				}
				homes[uid] = home
				account = enterprisehooks.UnixEligibleAccount{User: filepath.Base(home), UID: uid, GID: uid, Home: home}
				byUID[uid] = account
			}
			accounts = append(accounts, account)
		}
	}
	record := map[int]int{}
	openCodeRecordUnreadable = nil
	t.Cleanup(func() { openCodeRecordUnreadable = nil })
	enterpriseHookLoadOpenCodePorts = func(string) (map[int]int, error) {
		if openCodeRecordUnreadable != nil {
			return nil, openCodeRecordUnreadable
		}
		out := map[int]int{}
		for uid, port := range record {
			out[uid] = port
		}
		return out, nil
	}
	enterpriseHookWriteOpenCodePorts = func(_ string, ports map[int]int, _ map[int]string) error {
		openCodeRecordWrites++
		record = map[int]int{}
		for uid, port := range ports {
			record[uid] = port
		}
		return nil
	}
	// Root's view: homes in openCodeRootCannotRead (root_squash NFS, a
	// confined guardian) read as nothing, the way a refused read does.
	uidOfHome := func(home string) int {
		for uid, h := range homes {
			if h == home {
				return uid
			}
		}
		return 0
	}
	enterpriseHookReadOpenCodePort = func(home string) int {
		if openCodeRootCannotRead[uidOfHome(home)] {
			return 0
		}
		return enterprisepolicy.ReadOpenCodeServicePort(home)
	}
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		request.Home = account.Home
		response := enterpriseHookWorkerResponse{}
		if request.Operation == enterpriseHookWorkerOpOpenCodePortRead {
			// The as-the-user read: links resolve; a file the user cannot
			// read either is an error.
			if openCodeUserCannotRead[account.UID] {
				response.OpenCodeServicePort = &enterpriseHookWorkerOpenCodePortReport{Error: "permission denied"}
				return response, nil
			}
			port, err := enterprisepolicy.ReadOpenCodeServicePortAsUser(account.Home)
			response.OpenCodeServicePort = &enterpriseHookWorkerOpenCodePortReport{Port: port}
			if err != nil {
				response.OpenCodeServicePort.Error = err.Error()
			}
			return response, nil
		}
		if request.OpenCodeServicePort > 0 && openCodeUserCannotRead[account.UID] {
			response.OpenCodeServicePort = &enterpriseHookWorkerOpenCodePortReport{Error: "permission denied"}
			return response, nil
		}
		if request.OpenCodeServicePort > 0 {
			response.OpenCodeServicePort = runEnterpriseHookWorkerOpenCodePort(request)
		}
		return response, nil
	}
	return homes, &record, setEligible
}

// openCodeRecordUnreadable makes the record load fail (corrupt, partial,
// wrong owner, symlink, permission); openCodeRecordWrites counts writes.
var (
	openCodeRecordUnreadable error
	openCodeRecordWrites     int
	// openCodeRootCannotRead and openCodeUserCannotRead are the uids whose
	// service.json root, or the account itself, cannot read.
	openCodeRootCannotRead, openCodeUserCannotRead map[int]bool
)

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

// REVIEW-gx053-2 MF1: an account that leaves the eligible set (manifest
// exclusion, group removal) keeps its port: its service.json and its OpenCode
// still use it. A new account must not be given that port, and the account
// enrolled again keeps it. The entry goes only when the uid no longer
// resolves.
func TestManagedGuardianKeepsTheOpenCodePortOfAnExcludedAccount(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001, 1002)
	runOpenCodePortPass(t)
	first := map[int]int{1001: openCodePortIn(t, homes[1001]), 1002: openCodePortIn(t, homes[1002])}
	if first[1001] != 25001 || first[1002] != 25002 {
		t.Fatalf("first pass ports %v", first)
	}
	// 1001 is excluded; 9001 (same first port as 1001) is enrolled.
	setEligible(nil, 1002, 9001)
	log := runOpenCodePortPass(t)
	if got := openCodePortIn(t, homes[9001]); got == first[1001] || got == first[1002] || got == 0 {
		t.Fatalf("new account 9001 got %d, a port another account holds (%v)\n%s", got, first, log)
	}
	if (*record)[1001] != first[1001] {
		t.Fatalf("the excluded account's port left the record: %v", *record)
	}
	// 1001 is enrolled again: it keeps its port; nobody shares.
	setEligible(nil, 1001, 1002, 9001)
	log = runOpenCodePortPass(t)
	seen := map[int]int{}
	for _, uid := range []int{1001, 1002, 9001} {
		port := openCodePortIn(t, homes[uid])
		if other, dup := seen[port]; dup {
			t.Fatalf("uids %d and %d share port %d\n%s", other, uid, port, log)
		}
		seen[port] = uid
	}
	if openCodePortIn(t, homes[1001]) != first[1001] {
		t.Fatalf("re-enrolled 1001 moved off %d\n%s", first[1001], log)
	}
	// 1001 is deleted: its entry stays (REVIEW-gx053-3 MF2, below).
	setEligible(nil, 1002, 9001)
	runOpenCodePortPass(t)
	if (*record)[1001] != first[1001] {
		t.Fatalf("a departed account lost its record entry: %v", *record)
	}
}

// REVIEW-gx053-3 MF1: a directory (AD, SSSD, LDAP) account the guardian's
// static lookup cannot see, and an eligible account whose home is not
// available this pass, keep their ports: no entry is ever dropped.
func TestManagedGuardianNeverDropsAnOpenCodePortEntry(t *testing.T) {
	const directory = 94401103 // dcad-alice on dc-ent-rhel: not in /etc/passwd
	homes, record, setEligible := openCodePortGuardianWith(t, true, directory, 1002)
	runOpenCodePortPass(t)
	held := map[int]int{directory: openCodePortIn(t, homes[directory]), 1002: openCodePortIn(t, homes[1002])}
	// The directory account is excluded; a new account starting on its port
	// (same uid mod 8000) is enrolled.
	newcomer := directory + 8000
	setEligible(nil, 1002, newcomer)
	runOpenCodePortPass(t)
	if got := openCodePortIn(t, homes[newcomer]); got == held[directory] || got == held[1002] || got == 0 {
		t.Fatalf("the newcomer got %d, held by another account (%v, record %v)", got, held, *record)
	}
	// 1002's home is not available (automount, homed): no worker answers
	// for it; its entry stays and nobody else is given its port.
	other := 1002 + 8000
	setEligible(map[int]bool{1002: true}, 1002, newcomer, other)
	runOpenCodePortPass(t)
	if (*record)[1002] != held[1002] || (*record)[directory] != held[directory] {
		t.Fatalf("an entry was dropped: %v (held %v)", *record, held)
	}
	if got := openCodePortIn(t, homes[other]); got == held[1002] || got == held[directory] {
		t.Fatalf("account %d got %d, held by another account (%v)", other, got, held)
	}
}

// REVIEW-gx053-3 MF2: an account deleted (userdel without -r) and created
// again with its old home keeps its port; the account added in between got
// another one.
func TestManagedGuardianOpenCodePortForAnAccountThatComesBack(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	runOpenCodePortPass(t)
	before := openCodePortIn(t, homes[1001])
	setEligible(nil) // deleted: nobody eligible
	runOpenCodePortPass(t)
	setEligible(nil, 17001) // a new account whose first port is 1001's
	runOpenCodePortPass(t)
	setEligible(nil, 1001, 17001) // 1001 comes back with its old home
	log := runOpenCodePortPass(t)
	a, b := openCodePortIn(t, homes[1001]), openCodePortIn(t, homes[17001])
	if a != before || a == b || b == 0 {
		t.Fatalf("returning 1001 %d (was %d), 17001 %d, record %v\n%s", a, before, b, *record, log)
	}
}

// With every port of the range taken an eligible account gets none: the
// guardian writes nothing for it, says so, and no account shares a port.
func TestManagedGuardianOpenCodePortRangeExhausted(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001)
	full := map[int]int{}
	for i := 0; i < enterprisepolicy.OpenCodeAccountPortSpan; i++ {
		full[100000+i] = enterprisepolicy.OpenCodeAccountPortBase + i
	}
	*record = full
	log := runOpenCodePortPass(t)
	if port := openCodePortIn(t, homes[1001]); port != 0 {
		t.Fatalf("1001 was given %d although every port is taken", port)
	}
	if !strings.Contains(log, "no free OpenCode background server port for ent1001") {
		t.Fatalf("exhaustion is not logged:\n%s", log)
	}
	if len(*record) != enterprisepolicy.OpenCodeAccountPortSpan {
		t.Fatalf("record changed size: %d", len(*record))
	}
}

func writeOpenCodePortFile(t *testing.T, home string, port int) {
	t.Helper()
	path := enterprisepolicy.OpenCodeServiceConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"port":%d,"password":"p"}`, port)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertNoSharedOpenCodePort(t *testing.T, homes map[int]string, uids []int, log string) map[int]int {
	t.Helper()
	got, seen := map[int]int{}, map[int]int{}
	for _, uid := range uids {
		port := openCodePortIn(t, homes[uid])
		if other, dup := seen[port]; dup && port != 0 {
			t.Fatalf("uids %d and %d share port %d\n%s", other, uid, port, log)
		}
		seen[port], got[uid] = uid, port
	}
	return got
}

// REVIEW-gx053-4 MF1 repro 1: alice (1001) gets 25001 and is deleted with
// her home kept; bob is created as uid 1001 with a fresh home, and alice comes
// back as uid 1002 with her old home (its service.json still names 25001).
// The earlier holder (uid 1001, in the record) keeps 25001; alice is moved,
// and the conflict is logged naming both.
func TestManagedGuardianOpenCodeHomeReusedByAReturningAccount(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	runOpenCodePortPass(t)
	aliceHome := homes[1001]
	homes[1001] = filepath.Join(filepath.Dir(aliceHome), "bob")
	homes[1002] = aliceHome
	setEligible(nil, 1001, 1002)
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
	if got[1001] != 25001 || got[1002] == 0 {
		t.Fatalf("ports %v record %v\n%s", got, *record, log)
	}
	if !strings.Contains(log, "port 25001 of ") || !strings.Contains(log, "(uid 1002) is held by") || !strings.Contains(log, "(uid 1001)") {
		t.Fatalf("the conflict is not logged with both uids:\n%s", log)
	}
	// Stable: the next pass moves nothing and logs no conflict.
	log = runOpenCodePortPass(t)
	if again := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log); again[1001] != got[1001] || again[1002] != got[1002] || strings.Contains(log, "is held by") {
		t.Fatalf("second pass moved %v -> %v\n%s", got, again, log)
	}
}

// REVIEW-gx053-4 MF1 repro 2: two files name the same port (an admin's
// /etc/skel service.json, a copied dotfiles repo). The lower uid keeps it;
// the other is moved and the conflict is logged.
func TestManagedGuardianOpenCodeTwoFilesNameOnePort(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001, 1002)
	writeOpenCodePortFile(t, homes[1001], 26000)
	writeOpenCodePortFile(t, homes[1002], 26000)
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
	if got[1001] != 26000 || got[1002] == 26000 || (*record)[1002] != got[1002] {
		t.Fatalf("ports %v record %v\n%s", got, *record, log)
	}
	if !strings.Contains(log, "port 26000 of ent1002 (uid 1002) is held by ent1001 (uid 1001)") {
		t.Fatalf("the conflict is not logged:\n%s", log)
	}
}

// REVIEW-gx053-4 MF2: while the record cannot be read no account gets a new
// port and nobody is moved; ports already in files are kept, the record is
// not rewritten, and the reason is logged.
func TestManagedGuardianOpenCodeUnreadableRecordGivesNoNewPorts(t *testing.T) {
	for _, reason := range []string{"corrupt", "partial", "wrong owner", "symlink", "permission"} {
		t.Run(reason, func(t *testing.T) {
			homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
			runOpenCodePortPass(t)
			held := openCodePortIn(t, homes[1001])
			before := map[int]int{}
			for uid, port := range *record {
				before[uid] = port
			}
			openCodeRecordUnreadable = errors.New("enterprise hooks: OpenCode service ports record: " + reason)
			openCodeRecordWrites = 0
			setEligible(nil, 1002, 9001) // 1001 excluded; 9001 starts on 1001's port
			writeOpenCodePortFile(t, homes[1002], 27000)
			log := runOpenCodePortPass(t)
			if port := openCodePortIn(t, homes[9001]); port != 0 {
				t.Fatalf("9001 got port %d while the record could not be read (1001 holds %d)\n%s", port, held, log)
			}
			if openCodePortIn(t, homes[1002]) != 27000 {
				t.Fatalf("a port already in a file was changed\n%s", log)
			}
			if openCodeRecordWrites != 0 || len(*record) != len(before) || (*record)[1001] != before[1001] {
				t.Fatalf("the unreadable record was rewritten: %v -> %v", before, *record)
			}
			if !strings.Contains(log, "cannot be read") || !strings.Contains(log, "no account gets a new OpenCode port") || !strings.Contains(log, "sudo rm ") {
				t.Fatalf("the reason is not logged:\n%s", log)
			}
		})
	}
}

// REVIEW-gx053-5 MF1: alice keeps her OpenCode config in dotfiles
// (~/.config/opencode -> ~/dotfiles/opencode, the stow layout), where root's
// no-link read sees nothing, and set port 25002 by hand; bob's first port is
// 25002. The as-the-user read sees her port: bob gets another, nobody shares,
// over passes, and no line promises a move that does not happen.
func TestManagedGuardianOpenCodeSymlinkedConfigFolder(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	alice := homes[1001]
	if err := os.MkdirAll(filepath.Join(alice, "dotfiles", "opencode"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(alice, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(alice, "dotfiles", "opencode"), filepath.Join(alice, ".config", "opencode")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alice, "dotfiles", "opencode", "service.json"), []byte(`{"port":25002,"password":"p"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if port := enterprisepolicy.ReadOpenCodeServicePort(alice); port != 0 {
		t.Fatalf("root's read should not follow the link (got %d)", port)
	}
	setEligible(nil, 1001, 1002)
	for pass := 0; pass < 3; pass++ {
		log := runOpenCodePortPass(t)
		got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
		if got[1001] != 25002 || got[1002] == 0 || (*record)[1001] != 25002 {
			t.Fatalf("pass %d: ports %v record %v\n%s", pass, got, *record, log)
		}
		if strings.Contains(log, "next pass") {
			t.Fatalf("pass %d promises a later move:\n%s", pass, log)
		}
	}
}

// REVIEW-gx053-5 MF1: a home root cannot read (root_squash NFS) is read by
// the account's own worker; its port is held and nobody else is given it.
func TestManagedGuardianOpenCodeRootUnreadableHome(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	writeOpenCodePortFile(t, homes[1001], 25002)
	openCodeRootCannotRead[1001] = true
	setEligible(nil, 1001, 1002)
	for pass := 0; pass < 2; pass++ {
		log := runOpenCodePortPass(t)
		got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
		if got[1001] != 25002 || got[1002] == 25002 || (*record)[1001] != 25002 {
			t.Fatalf("pass %d: ports %v record %v\n%s", pass, got, *record, log)
		}
	}
}

// A file the account cannot read either keeps its recorded port held: no
// other account is given it, and the warning names the account.
func TestManagedGuardianOpenCodeFileUnreadableEvenAsTheUser(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	runOpenCodePortPass(t)
	held := (*record)[1001]
	openCodeUserCannotRead[1001] = true
	setEligible(nil, 1001, 9001) // 9001 starts on 1001's port
	log := runOpenCodePortPass(t)
	if got := openCodePortIn(t, homes[9001]); got == held || got == 0 {
		t.Fatalf("9001 got %d; 1001 holds %d\n%s", got, held, log)
	}
	if (*record)[1001] != held {
		t.Fatalf("the unreadable account lost its port: %v", *record)
	}
	if !strings.Contains(log, "ent1001's OpenCode service.json cannot be read as ent1001") {
		t.Fatalf("no warning names the account:\n%s", log)
	}
}

// When the read phase could not run (the plan did not know alice's port),
// alice's own write worker sees her file name a port another account holds
// and moves her: still no share, and the move is logged as done.
func TestManagedGuardianOpenCodeWriteWorkerMovesAPortTheReadMissed(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	writeOpenCodePortFile(t, homes[1001], 25002)
	openCodeRootCannotRead[1001] = true
	previousRead := enterpriseHookReadOpenCodePortsAsUsers
	t.Cleanup(func() { enterpriseHookReadOpenCodePortsAsUsers = previousRead })
	enterpriseHookReadOpenCodePortsAsUsers = func(context.Context, io.Writer, []enterprisehooks.UnixEligibleAccount) map[int]int {
		return map[int]int{} // the read workers did not answer, root saw nothing
	}
	setEligible(nil, 1001, 1002)
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
	if got[1002] != 25002 || got[1001] == 25002 || (*record)[1001] != got[1001] {
		t.Fatalf("ports %v record %v\n%s", got, *record, log)
	}
	if !strings.Contains(log, "moved ent1001's OpenCode background server from port 25002") {
		t.Fatalf("the move is not logged:\n%s", log)
	}
}
