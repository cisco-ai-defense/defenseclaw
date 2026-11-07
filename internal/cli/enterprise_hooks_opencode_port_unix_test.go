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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
	previousReadTimeout := enterpriseHookOpenCodeReadTimeout
	openCodeOnCommit, openCodeAfterRewrite = nil, nil
	openCodeCrashed.Store(false)
	openCodeFaultMu.Lock()
	openCodeUserCannotRead, openCodeReadFails, openCodeReadHangs = map[int]bool{}, map[int]bool{}, map[int]chan struct{}{}
	openCodeFaultMu.Unlock()
	t.Cleanup(func() {
		enterpriseHookOpenCodeReadTimeout = previousReadTimeout
		openCodeOnCommit, openCodeAfterRewrite = nil, nil
		openCodeCrashed.Store(false)
		openCodeFaultMu.Lock()
		for _, release := range openCodeReadHangs {
			close(release)
		}
		openCodeFaultMu.Unlock()
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
	openCodeRecordUnreadable, openCodeRecordUnknown, openCodeRecordContested, openCodeRecordExists = nil, nil, nil, false
	openCodeRecordImportPending = false
	t.Cleanup(func() {
		openCodeRecordUnreadable, openCodeRecordUnknown, openCodeRecordContested, openCodeRecordExists = nil, nil, nil, false
		openCodeRecordImportPending = false
	})
	enterpriseHookLoadOpenCodePorts = func(string) (enterprisehooks.UnixOpenCodeServicePortsState, error) {
		state := enterprisehooks.UnixOpenCodeServicePortsState{Ports: map[int]int{}, Users: map[int]string{}}
		if openCodeRecordUnreadable != nil {
			state.Exists = true
			return state, openCodeRecordUnreadable
		}
		for uid, port := range record {
			state.Ports[uid] = port
		}
		state.Exists = openCodeRecordExists || len(record) > 0
		state.ImportDone = state.Exists && !openCodeRecordImportPending
		state.Unknown, state.Contested = openCodeRecordUnknown, openCodeRecordContested
		return state, nil
	}
	enterpriseHookWriteOpenCodePorts = func(_ string, state enterprisehooks.UnixOpenCodeServicePortsState) error {
		if openCodeCrashed.Load() {
			return nil // the guardian is gone: nothing more reaches the disk
		}
		if openCodeOnCommit != nil {
			if err := openCodeOnCommit(state); err != nil {
				return err
			}
		}
		openCodeRecordUnknown, openCodeRecordContested = state.Unknown, state.Contested
		openCodeRecordImportPending = !state.ImportDone
		openCodeRecordWrites++
		openCodeRecordExists = true
		record = map[int]int{}
		for uid, port := range state.Ports {
			record[uid] = port
		}
		return nil
	}
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		request.Home = account.Home
		response := enterpriseHookWorkerResponse{}
		if request.Operation == enterpriseHookWorkerOpOpenCodePortRead {
			// A read the pass abandons keeps running after the test moves on:
			// it takes its fault settings once, under the lock, and touches no
			// shared state after it wakes.
			openCodeFaultMu.Lock()
			release, hangs := openCodeReadHangs[account.UID]
			readFails, cannotRead := openCodeReadFails[account.UID], openCodeUserCannotRead[account.UID]
			openCodeFaultMu.Unlock()
			if hangs {
				<-release // a hung home: the read never answers
				return response, context.DeadlineExceeded
			}
			if readFails {
				return response, errors.New("worker for uid " + fmt.Sprint(account.UID) + " exited 1")
			}
			// The as-the-user read: links resolve; a file the user cannot
			// read either is an error.
			if cannotRead {
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
		if request.OpenCodeServicePort > 0 {
			// One rewrite at a time, so a crash lands between two of them.
			openCodeRewriteMu.Lock()
			defer openCodeRewriteMu.Unlock()
		}
		if request.OpenCodeServicePort > 0 && openCodeCrashed.Load() {
			return response, errors.New("the guardian crashed")
		}
		if request.OpenCodeServicePort > 0 && openCodeUserCannotReadNow(account.UID) {
			response.OpenCodeServicePort = &enterpriseHookWorkerOpenCodePortReport{Error: "permission denied"}
			return response, nil
		}
		if request.OpenCodeServicePort > 0 {
			response.OpenCodeServicePort = runEnterpriseHookWorkerOpenCodePort(request)
			if openCodeAfterRewrite != nil {
				openCodeAfterRewrite(account.UID)
			}
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
	openCodeRecordUnknown    []enterprisehooks.UnixOpenCodeServicePortUnknown
	openCodeRecordContested  []enterprisehooks.UnixOpenCodeContestedPort
	openCodeRecordExists     bool
	// openCodeRecordImportPending: the record exists but was committed with
	// import_done false, so the next pass is still the import pass.
	openCodeRecordImportPending bool
	// Fault injection (REVIEW-gx053-12 MF1): openCodeOnCommit runs at each
	// record commit and can fail it; openCodeAfterRewrite runs after each
	// user-file rewrite; once openCodeCrashed is set no rewrite and no
	// commit happens any more (the guardian died).
	openCodeOnCommit     func(enterprisehooks.UnixOpenCodeServicePortsState) error
	openCodeAfterRewrite func(uid int)
	openCodeCrashed      atomic.Bool
	openCodeRewriteMu    sync.Mutex
	// openCodeFaultMu guards the three fault maps below against a read
	// worker the pass abandoned at its deadline.
	openCodeFaultMu sync.Mutex
	// openCodeUserCannotRead are the uids whose service.json the account
	// itself cannot read; openCodeReadFails the uids whose read worker fails;
	// openCodeReadHangs the uids whose read never answers (until released).
	openCodeUserCannotRead, openCodeReadFails map[int]bool
	openCodeReadHangs                         map[int]chan struct{}
)

// The fault maps are shared with read workers the pass abandoned at their
// deadline, so every change and every read of an entry goes through these
// functions and takes openCodeFaultMu.
func setOpenCodeReadHang(uid int) {
	openCodeFaultMu.Lock()
	defer openCodeFaultMu.Unlock()
	openCodeReadHangs[uid] = make(chan struct{})
}

func setOpenCodeReadFails(uid int, fails bool) {
	openCodeFaultMu.Lock()
	defer openCodeFaultMu.Unlock()
	openCodeReadFails[uid] = fails
}

func setOpenCodeUserCannotRead(uid int, cannot bool) {
	openCodeFaultMu.Lock()
	defer openCodeFaultMu.Unlock()
	openCodeUserCannotRead[uid] = cannot
}

func openCodeUserCannotReadNow(uid int) bool {
	openCodeFaultMu.Lock()
	defer openCodeFaultMu.Unlock()
	return openCodeUserCannotRead[uid]
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
	// The record exists, so the import window is closed: alice's old file is
	// not input; she gets a fresh port and her file is rewritten.
	if got[1002] == 25001 || (*record)[1002] != got[1002] {
		t.Fatalf("alice was given bob's port: %v record %v\n%s", got, *record, log)
	}
	// Stable: the next pass moves nothing and logs no conflict.
	log = runOpenCodePortPass(t)
	if again := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log); again[1001] != got[1001] || again[1002] != got[1002] || strings.Contains(log, "is recorded for") {
		t.Fatalf("second pass moved %v -> %v\n%s", got, again, log)
	}
}

// Two files name the same port (an admin's /etc/skel service.json, a copied
// dotfiles repo) and neither account is recorded: the port is contested, so
// it is given to nobody (REVIEW-gx053-10); both get fresh ports.
func TestManagedGuardianOpenCodeTwoFilesNameOnePort(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001, 1002)
	writeOpenCodePortFile(t, homes[1001], 26000)
	writeOpenCodePortFile(t, homes[1002], 26000)
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
	if got[1001] == 26000 || got[1002] == 26000 || got[1001] == 0 || got[1002] == 0 || (*record)[1002] != got[1002] {
		t.Fatalf("ports %v record %v\n%s", got, *record, log)
	}
	if !strings.Contains(log, "port 26000 is named by the files of several accounts") {
		t.Fatalf("the contest is not logged:\n%s", log)
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
	writeOpenCodePortFile(t, homes[1001], 25002) // readable by the account only (root_squash)
	setEligible(nil, 1001, 1002)
	for pass := 0; pass < 2; pass++ {
		log := runOpenCodePortPass(t)
		got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
		if got[1001] != 25002 || got[1002] == 25002 || (*record)[1001] != 25002 {
			t.Fatalf("pass %d: ports %v record %v\n%s", pass, got, *record, log)
		}
	}
}

// A file the account cannot read either: its port is unknown, its recorded
// port stays reserved and nothing changes for it; a new account still gets a
// port, not that one (REVIEW-gx053-7), and the warning names the account.
func TestManagedGuardianOpenCodeFileUnreadableEvenAsTheUser(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	runOpenCodePortPass(t)
	held := (*record)[1001]
	setOpenCodeUserCannotRead(1001, true)
	setEligible(nil, 1001, 9001) // 9001 starts on 1001's port
	log := runOpenCodePortPass(t)
	if got := openCodePortIn(t, homes[9001]); got == 0 || got == held {
		t.Fatalf("9001 got %d; 1001's recorded port is %d\n%s", got, held, log)
	}
	if (*record)[1001] != held {
		t.Fatalf("the unreadable account lost its port: %v", *record)
	}
	if !strings.Contains(log, "ent1001's OpenCode service port file") || !strings.Contains(log, "the record keeps port") {
		t.Fatalf("no warning names the account:\n%s", log)
	}
}

// When the read phase could not run (the plan did not know alice's port),
// alice's own write worker sees her file name a port another account holds
// and moves her: still no share, and the move is logged as done.
func TestManagedGuardianOpenCodeWriteWorkerMovesAPortTheReadMissed(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	writeOpenCodePortFile(t, homes[1001], 25002)
	previousRead := enterpriseHookReadOpenCodePortsAsUsers
	t.Cleanup(func() { enterpriseHookReadOpenCodePortsAsUsers = previousRead })
	enterpriseHookReadOpenCodePortsAsUsers = func(context.Context, io.Writer, []enterprisehooks.UnixEligibleAccount) (map[int]int, []enterprisehooks.UnixOpenCodeServicePortUnknown) {
		return map[int]int{}, nil // the file changed after the read (it named no port then)
	}
	setEligible(nil, 1001, 1002)
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
	if got[1002] != 25002 || got[1001] == 25002 || (*record)[1001] != got[1001] {
		t.Fatalf("ports %v record %v\n%s", got, *record, log)
	}
	if !strings.Contains(log, "ent1001's OpenCode service.json named port 25002; wrote its recorded port") {
		t.Fatalf("the move is not logged:\n%s", log)
	}
}

// linkOpenCodeConfig gives home the stow layout: ~/.config/opencode is a
// link to ~/dotfiles/opencode, whose service.json names port.
func linkOpenCodeConfig(t *testing.T, home string, port int) {
	t.Helper()
	real := filepath.Join(home, "dotfiles", "opencode")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".config", "opencode")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "service.json"), []byte(fmt.Sprintf(`{"port":%d}`, port)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// REVIEW-gx053-6..9: alice keeps OpenCode's config in dotfiles (a linked
// ~/.config/opencode the guardian cannot write) naming 25002, and her read
// worker fails once, at enrolment. Bob is bound 25002 that pass. From then on
// the record is the only authority: bob keeps 25002 on every pass, alice's
// import of 25002 is refused (recorded for bob), her fresh binding cannot be
// written through the link, so none is recorded, and she is warned with the
// admin step. Nobody's binding changes; the record never pairs two uids.
func TestManagedGuardianOpenCodeReadWorkerFails(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	linkOpenCodeConfig(t, homes[1001], 25002)
	setOpenCodeReadFails(1001, true)
	setEligible(nil, 1001, 1002)
	log := runOpenCodePortPass(t)
	bob := openCodePortIn(t, homes[1002])
	if bob == 0 || !strings.Contains(log, "ent1001's OpenCode service port is unknown this pass") || !strings.Contains(log, "To clear it:") {
		t.Fatalf("pass 1: bob %d\n%s", bob, log)
	}
	setOpenCodeReadFails(1001, false)
	for pass := 2; pass <= 4; pass++ {
		log = runOpenCodePortPass(t)
		if got := openCodePortIn(t, homes[1002]); got != bob || (*record)[1002] != bob {
			t.Fatalf("pass %d: bob's binding changed %d -> %d (record %v)\n%s", pass, bob, got, *record, log)
		}
		if _, ok := (*record)[1001]; ok && (*record)[1001] == bob {
			t.Fatalf("pass %d: the record pairs alice with bob's port: %v", pass, *record)
		}
		if len(openCodeRecordUnknown) != 1 || openCodeRecordUnknown[0].UID != 1001 || !strings.Contains(openCodeRecordUnknown[0].Fix, "opencode service set port") {
			t.Fatalf("pass %d: alice is not warned with the admin step: %+v\n%s", pass, openCodeRecordUnknown, log)
		}
	}
}

// REVIEW-gx053-8 repro (TestZZRV8LinkedBlindThenRecover) under the record
// model: bob, bound first, keeps 25002 for good; alice's linked file is never
// rewritten (the guardian cannot) and she is warned.
func TestManagedGuardianOpenCodeLinkedBlindThenRecover(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	linkOpenCodeConfig(t, homes[1001], 25002)
	setOpenCodeReadFails(1001, true)
	setEligible(nil, 1001, 1002)
	runOpenCodePortPass(t)
	setOpenCodeReadFails(1001, false)
	bob := (*record)[1002]
	for pass := 2; pass <= 4; pass++ {
		log := runOpenCodePortPass(t)
		if (*record)[1002] != bob || openCodePortIn(t, homes[1002]) != bob {
			t.Fatalf("pass %d: bob moved from %d (record %v)\n%s", pass, bob, *record, log)
		}
		if openCodePortIn(t, homes[1001]) != 25002 {
			t.Fatalf("pass %d: alice's linked file changed", pass)
		}
	}
}

// Two linked files name the same port: contested, so neither import is
// granted. Each claimant gets a fresh binding that is committed before the
// writes (write-ahead); the writes through the links fail, so both bindings
// stay recorded for the next pass and both accounts are warned with the admin
// step.
func TestManagedGuardianOpenCodeImportCollisionCannotBeWritten(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	linkOpenCodeConfig(t, homes[1001], 26000)
	setEligible(nil, 1001, 1002)
	linkOpenCodeConfig(t, homes[1002], 26000)
	log := runOpenCodePortPass(t)
	// Write-ahead (REVIEW-gx053-12): the fresh bindings are committed before
	// the writes; a write that fails keeps them and the next pass retries.
	if len(*record) != 2 || (*record)[1001] == 26000 || (*record)[1002] == 26000 || (*record)[1001] == (*record)[1002] {
		t.Fatalf("the contested port was recorded, or the fresh bindings were not: %v\n%s", *record, log)
	}
	if len(openCodeRecordUnknown) != 2 || !strings.Contains(openCodeRecordUnknown[0].Fix, "opencode service set port") {
		t.Fatalf("not warned with the admin step: %+v\n%s", openCodeRecordUnknown, log)
	}
}

// A read that hangs (a hard NFS mount) is cut at its deadline: the pass
// finishes, the account's port is unknown and nobody gets a new port.
func TestManagedGuardianOpenCodeReadWorkerTimesOut(t *testing.T) {
	homes, _, setEligible := openCodePortGuardianWith(t, true, 1001)
	writeOpenCodePortFile(t, homes[1001], 25002)
	enterpriseHookOpenCodeReadTimeout = 200 * time.Millisecond
	setOpenCodeReadHang(1001)
	setEligible(nil, 1001, 1002)
	done := make(chan string, 1)
	go func() { done <- runOpenCodePortPass(t) }()
	var log string
	select {
	case log = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the pass hangs on a read that does not answer")
	}
	if got := openCodePortIn(t, homes[1002]); got == 0 {
		t.Fatalf("bob got no port while alice's read hung: one account stopped the rest\n%s", log)
	}
	if !strings.Contains(log, "did not answer within") {
		t.Fatalf("the timeout is not logged:\n%s", log)
	}
}

// REVIEW-11 MF1: a read worker that only starts after the pass gave up on it
// reads its fault settings while the test already changes them for the next
// step; the two share nothing unguarded, so go test -race stays quiet.
func TestManagedGuardianOpenCodeLateReadWorkerSharesNoFaultState(t *testing.T) {
	homes, _, setEligible := openCodePortGuardianWith(t, true, 1001)
	writeOpenCodePortFile(t, homes[1001], 25002)
	enterpriseHookOpenCodeReadTimeout = 200 * time.Millisecond
	inner := enterpriseHookWorkerRunner
	gate, finished := make(chan struct{}), make(chan struct{})
	var once sync.Once
	enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if request.Operation == enterpriseHookWorkerOpOpenCodePortRead && account.UID == 1001 {
			<-gate // the worker starts late, after the pass returned
			defer once.Do(func() { close(finished) })
		}
		return inner(ctx, account, request)
	}
	setEligible(nil, 1001, 1002)
	log := runOpenCodePortPass(t)
	if got := openCodePortIn(t, homes[1002]); got == 0 {
		t.Fatalf("bob got no port while alices read had not started\n%s", log)
	}
	// The late worker starts reading its fault settings while the next step
	// of the test changes them, with nothing ordering the two.
	close(gate)
	setOpenCodeReadFails(1001, true)
	setOpenCodeUserCannotRead(1002, true)
	setOpenCodeReadFails(1002, false)
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the late read worker never finished")
	}
}

// A hung account does not stop the next one: carol (healthy) is read and
// recorded in the same pass; nobody shares a port.
func TestManagedGuardianOpenCodeHungAccountThenHealthyOne(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	enterpriseHookOpenCodeReadTimeout = 200 * time.Millisecond
	setOpenCodeReadHang(1001)
	setEligible(nil, 1001, 1003)
	writeOpenCodePortFile(t, homes[1003], 25010)
	done := make(chan string, 1)
	go func() { done <- runOpenCodePortPass(t) }()
	var log string
	select {
	case log = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a hung account blocked the pass")
	}
	assertNoSharedOpenCodePort(t, homes, []int{1001, 1003}, log)
	if (*record)[1003] != 25010 {
		t.Fatalf("the healthy account was not processed: record %v\n%s", *record, log)
	}
}

// REVIEW-gx053-7 MF1: a user's bad file (here, not JSON) affects nobody else:
// with mallory unknown, a new account gets a port that is not mallory's
// recorded one, and a clash between two readable accounts is still resolved.
func TestManagedGuardianOpenCodeOneBadFileAffectsNobodyElse(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001)
	runOpenCodePortPass(t)
	malloryPort := (*record)[1001]
	path := enterprisepolicy.OpenCodeServiceConfigPath(homes[1001])
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	setEligible(nil, 1001, 9001, 1003, 1004) // 9001 starts on mallory's port
	writeOpenCodePortFile(t, homes[1003], 26000)
	writeOpenCodePortFile(t, homes[1004], 26000) // a clash between readable accounts
	log := runOpenCodePortPass(t)
	if got := openCodePortIn(t, homes[9001]); got == 0 || got == malloryPort {
		t.Fatalf("the new account got %d (mallory holds %d)\n%s", got, malloryPort, log)
	}
	got := assertNoSharedOpenCodePort(t, homes, []int{9001, 1003, 1004}, log)
	if got[1003] == 26000 || got[1004] == 26000 || got[1003] == 0 || got[1004] == 0 {
		t.Fatalf("the readable clash was not resolved: %v\n%s", got, log)
	}
	if (*record)[1001] != malloryPort {
		t.Fatalf("mallory's reserved port changed: %v", *record)
	}
	if !strings.Contains(log, path) || !strings.Contains(log, "is not a JSON object") || !strings.Contains(log, "sudo -u ent1001 rm "+path) || !strings.Contains(log, "the record keeps port") {
		t.Fatalf("the warning does not name the path, the reason and the fix:\n%s", log)
	}
}

// REVIEW-gx053-9 MF1 repro (TestZZRV9LinkedTakesExcludedPort): 1001 and 1002
// are bound 25001 and 25002; 1001 is excluded; 1002 links its folder and
// names 25001. The record does not change: 1001 keeps 25001, 1002 keeps
// 25002 (the guardian cannot write through the link, so it warns).
func TestManagedGuardianOpenCodeLinkCannotTakeAnExcludedPort(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001, 1002)
	runOpenCodePortPass(t)
	before := map[int]int{1001: (*record)[1001], 1002: (*record)[1002]}
	setEligible(nil, 1002)
	if err := os.Remove(enterprisepolicy.OpenCodeServiceConfigPath(homes[1002])); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(enterprisepolicy.OpenCodeServiceConfigPath(homes[1002]))); err != nil {
		t.Fatal(err)
	}
	linkOpenCodeConfig(t, homes[1002], before[1001])
	for pass := 1; pass <= 2; pass++ {
		log := runOpenCodePortPass(t)
		if (*record)[1001] != before[1001] || (*record)[1002] != before[1002] {
			t.Fatalf("pass %d: the record changed %v -> %v\n%s", pass, before, *record, log)
		}
		if len(openCodeRecordUnknown) != 1 || openCodeRecordUnknown[0].UID != 1002 {
			t.Fatalf("pass %d: 1002 is not warned: %+v\n%s", pass, openCodeRecordUnknown, log)
		}
	}
}

// REVIEW-gx053-9 MF2 repros (TestZZRV9LinkedEvictsRecordedHolder,
// TestZZRV9ReadOnlyFolderEvicts): mallory links, or chmods 500, her own
// folder and names bob's port, then the next one. Bob's binding and file
// never change; mallory keeps her own recorded port and is warned.
func TestManagedGuardianOpenCodeUserCannotEvictAnother(t *testing.T) {
	for _, how := range []string{"link", "chmod 500"} {
		t.Run(how, func(t *testing.T) {
			homes, record, setEligible := openCodePortGuardianWith(t, true, 1002)
			runOpenCodePortPass(t)
			bob := (*record)[1002]
			setEligible(nil, 1002, 1009)
			runOpenCodePortPass(t)
			mallory := (*record)[1009]
			folder := filepath.Dir(enterprisepolicy.OpenCodeServiceConfigPath(homes[1009]))
			name := func(port int) {
				switch how {
				case "link":
					_ = os.RemoveAll(folder)
					_ = os.RemoveAll(filepath.Join(homes[1009], "dotfiles"))
					linkOpenCodeConfig(t, homes[1009], port)
				default:
					_ = os.Chmod(folder, 0o700)
					writeOpenCodePortFile(t, homes[1009], port)
					_ = os.Chmod(folder, 0o500)
					t.Cleanup(func() { _ = os.Chmod(folder, 0o700) })
				}
			}
			for _, target := range []int{bob, bob + 1, bob} {
				name(target)
				log := runOpenCodePortPass(t)
				if (*record)[1002] != bob || openCodePortIn(t, homes[1002]) != bob {
					t.Fatalf("mallory naming %d moved bob from %d (record %v)\n%s", target, bob, *record, log)
				}
				if (*record)[1009] != mallory {
					t.Fatalf("mallory's own binding changed %d -> %d", mallory, (*record)[1009])
				}
			}
		})
	}
}

// listenOn opens a listener on 127.0.0.1:port for the test (an OpenCode
// server, or an attacker's): the guardian must not care.
func listenOn(t *testing.T, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("cannot listen on %d here: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
}

// REVIEW-gx053-10 MF1 repro (TestZZRV10RebuildAfterRemoval): 1001 copies
// bob's 25002 into her own file and the administrator removes the record (the
// documented rebuild). Both files name 25002 and neither account is recorded:
// nobody gets 25002, both get fresh ports, one warning names both.
func TestManagedGuardianOpenCodeRebuildContestGivesThePortToNobody(t *testing.T) {
	for _, listening := range []string{"nobody", "bob", "attacker"} {
		t.Run("listener "+listening, func(t *testing.T) {
			homes, record, _ := openCodePortGuardianWith(t, true, 1001, 1002)
			runOpenCodePortPass(t)
			bob := (*record)[1002]
			writeOpenCodePortFile(t, homes[1001], bob) // the copy
			for uid := range *record {
				delete(*record, uid) // sudo rm opencode-service-ports.json
			}
			openCodeRecordExists, openCodeRecordContested = false, nil
			if listening != "nobody" {
				listenOn(t, bob) // bob's OpenCode, or an attacker's listener on the copied port
			}
			log := runOpenCodePortPass(t)
			got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
			if got[1001] == bob || got[1002] == bob || got[1001] == 0 || got[1002] == 0 {
				t.Fatalf("a contested port was granted: %v (contested %d)\n%s", got, bob, log)
			}
			if (*record)[1001] == bob || (*record)[1002] == bob {
				t.Fatalf("the record binds the contested port: %v", *record)
			}
			if !strings.Contains(log, fmt.Sprintf("port %d is named by the files of several accounts", bob)) ||
				!strings.Contains(log, "ent1001 (uid 1001)") || !strings.Contains(log, "ent1002 (uid 1002)") {
				t.Fatalf("the warning does not name both claimants:\n%s", log)
			}
		})
	}
}

// The first pass after an upgrade from 1.0.8 (no record yet): bob's own
// file names 25002 and a lower uid copied it. Neither gets it.
func TestManagedGuardianOpenCodeUpgradeContestGivesThePortToNobody(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001, 1002)
	writeOpenCodePortFile(t, homes[1002], 25002)
	writeOpenCodePortFile(t, homes[1001], 25002)
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002}, log)
	if got[1001] == 25002 || got[1002] == 25002 || (*record)[1001] == 25002 || (*record)[1002] == 25002 {
		t.Fatalf("a contested port was granted: %v record %v\n%s", got, *record, log)
	}
}

// REVIEW-gx053-10 TestZZRV10PreImportRace: two new accounts enrol in one
// pass; mallory's file names carol's 25003. Neither gets 25003.
func TestManagedGuardianOpenCodeTwoNewAccountsContest(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1002)
	setEligible(nil, 1002, 1003)
	writeOpenCodePortFile(t, homes[1002], 25003)
	writeOpenCodePortFile(t, homes[1003], 25003)
	listenOn(t, 25003) // carol's OpenCode: it still decides nothing
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1002, 1003}, log)
	if got[1002] == 25003 || got[1003] == 25003 || len(*record) != 2 {
		t.Fatalf("ports %v record %v\n%s", got, *record, log)
	}
}

// An existing DefenseClaw record, also one an earlier round wrote (no
// "unknown" list), decides over every user file: bob keeps 25002 whatever
// any file names, and with the record there no file is imported at all
// (REVIEW-gx053-11: the import window is the pass that builds the record).
func TestManagedGuardianOpenCodeEarlierRecordDecides(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1002)
	(*record)[1002] = 25002
	setEligible(nil, 1001, 1002, 1003)
	writeOpenCodePortFile(t, homes[1001], 25002) // a copy of bob's
	writeOpenCodePortFile(t, homes[1002], 26111) // bob's own file disagrees
	writeOpenCodePortFile(t, homes[1003], 26500) // free, but the window is closed: not imported
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002, 1003}, log)
	if got[1002] != 25002 || (*record)[1002] != 25002 || got[1001] == 25002 || got[1003] == 26500 || got[1003] == 0 {
		t.Fatalf("ports %v record %v\n%s", got, *record, log)
	}
}

// REVIEW-gx053-13 S2: the import-done flag decides, not the existence of the
// record. A record committed with import_done false (an older format) is not
// past its import pass: the next pass imports for the uids with no entry (the
// recorded uid keeps its port), commits the flag done, and after that pass no
// file is input again.
func TestManagedGuardianOpenCodeRecordWithoutImportDoneIsTheImportPass(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1002)
	(*record)[1002] = 25002
	openCodeRecordImportPending = true
	setEligible(nil, 1001, 1002, 1003)
	writeOpenCodePortFile(t, homes[1001], 26500) // no entry, free: imported in the import pass
	writeOpenCodePortFile(t, homes[1002], 26111) // recorded: the record wins
	log := runOpenCodePortPass(t)
	got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002, 1003}, log)
	if got[1001] != 26500 || (*record)[1001] != 26500 || got[1002] != 25002 || got[1003] == 0 || openCodeRecordImportPending {
		t.Fatalf("ports %v record %v pending %v\n%s", got, *record, openCodeRecordImportPending, log)
	}
	// The window is closed now: a new account's file is not imported.
	setEligible(nil, 1001, 1002, 1003, 1004)
	writeOpenCodePortFile(t, homes[1004], 26700)
	log = runOpenCodePortPass(t)
	if got := assertNoSharedOpenCodePort(t, homes, []int{1001, 1002, 1003, 1004}, log); got[1004] == 26700 || got[1004] == 0 {
		t.Fatalf("a file was input after the import pass: %v\n%s", got, log)
	}
}

// REVIEW-gx053-13 S2: a pass sweeps the temp files a killed record write left
// in the record's folder: the old orphan goes, a file newer than the pass
// start (a writer at work) and files that are not the record's temp files
// stay.
func TestManagedGuardianOpenCodeSweepsOrphanRecordTempFiles(t *testing.T) {
	openCodePortGuardianWith(t, true, 1001)
	dir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, dir) // after the guardian helper, which sets its own
	cfg.DataDir = filepath.Join(t.TempDir(), "data")       // the record lives in the authorization folder (the env above)
	plant := func(name string, offset time.Duration) string {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(offset)
		if err := os.Chtimes(full, when, when); err != nil {
			t.Fatal(err)
		}
		return full
	}
	orphan := plant(".defenseclaw-opencode-ports-123456.new", -time.Hour)
	live := plant(".defenseclaw-opencode-ports-777.new", time.Hour) // created after the pass started
	other := plant(".defenseclaw-copilot-vscode-accounts-5.new", -time.Hour)
	log := runOpenCodePortPass(t)
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) || !strings.Contains(log, "removed 1 leftover temp file") {
		t.Fatalf("the orphan is still there (%v)\n%s", err, log)
	}
	for _, kept := range []string{live, other} {
		if _, err := os.Lstat(kept); err != nil {
			t.Fatalf("%s must stay: %v", kept, err)
		}
	}
}

// OpenCode's own defaults are never imported (REVIEW-gx053-10 S1).
func TestManagedGuardianOpenCodeDefaultPortIsNotImported(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001)
	writeOpenCodePortFile(t, homes[1001], enterprisepolicy.OpenCodeDefaultServicePort)
	runOpenCodePortPass(t)
	if got := (*record)[1001]; got == enterprisepolicy.OpenCodeDefaultServicePort || got == 0 {
		t.Fatalf("the shared default was imported: %v", *record)
	}
}

// REVIEW-gx053-11 MF1 repros: with no record, the victim's port is named by
// two accounts' files (a contest), and mallory, who copied it too, makes her
// own file unreadable for that pass, so she is not a claimant. On the next
// pass her file is readable and she would be the only claimant. She never
// gets the port: no file is input after the pass that built the record, and
// the contested port stays marked.
func TestManagedGuardianOpenCodeAttackerSkipsTheImportPass(t *testing.T) {
	for _, victim := range []struct {
		name string
		port int
	}{{"bob", 25002}, {"carol", 25003}} {
		t.Run(victim.name, func(t *testing.T) {
			homes, record, _ := openCodePortGuardianWith(t, true, 1001, 1002, 1003)
			writeOpenCodePortFile(t, homes[1002], victim.port) // the victim's file
			writeOpenCodePortFile(t, homes[1003], victim.port) // another account names it too: a contest
			writeOpenCodePortFile(t, homes[1001], victim.port) // mallory's copy
			setOpenCodeReadFails(1001, true)                   // linked, chmod 000, or a hung read
			runOpenCodePortPass(t)
			setOpenCodeReadFails(1001, false)
			for pass := 2; pass <= 4; pass++ {
				log := runOpenCodePortPass(t)
				for uid, port := range *record {
					if port == victim.port {
						t.Fatalf("pass %d: uid %d was given the contested port %d\n%s", pass, uid, port, log)
					}
				}
				if (*record)[1001] == 0 {
					t.Fatalf("pass %d: mallory got no port at all: %v", pass, *record)
				}
			}
		})
	}
}

// A uid unreadable in the import pass and readable later gets a fresh port,
// not the one its file names.
func TestManagedGuardianOpenCodeUnreadableInTheImportPassGetsAFreshPort(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001)
	writeOpenCodePortFile(t, homes[1001], 26600)
	setOpenCodeReadFails(1001, true)
	runOpenCodePortPass(t)
	setOpenCodeReadFails(1001, false)
	runOpenCodePortPass(t)
	if got := (*record)[1001]; got == 26600 || got == 0 || openCodePortIn(t, homes[1001]) != got {
		t.Fatalf("record %v, file %d", *record, openCodePortIn(t, homes[1001]))
	}
}

// A contested port stays contested over later passes and new accounts:
// nobody is given it until an administrator clears the mark.
func TestManagedGuardianOpenCodeContestedPortStaysContested(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001, 1002)
	writeOpenCodePortFile(t, homes[1001], 25003)
	writeOpenCodePortFile(t, homes[1002], 25003)
	log := runOpenCodePortPass(t)
	if len(openCodeRecordContested) != 1 || openCodeRecordContested[0].Port != 25003 || len(openCodeRecordContested[0].UIDs) != 2 {
		t.Fatalf("the contest is not marked: %+v\n%s", openCodeRecordContested, log)
	}
	if !strings.Contains(log, "opencode-port-clear 25003 --yes") {
		t.Fatalf("the clear command is not named:\n%s", log)
	}
	setEligible(nil, 1001, 1002, 1003) // uid 1003's first port is 25003
	for pass := 2; pass <= 3; pass++ {
		runOpenCodePortPass(t)
		for uid, port := range *record {
			if port == 25003 {
				t.Fatalf("pass %d: uid %d was given the contested port: %v", pass, uid, *record)
			}
		}
		if len(openCodeRecordContested) != 1 {
			t.Fatalf("pass %d: the mark was lost: %+v", pass, openCodeRecordContested)
		}
	}
}

// assertOpenCodeContestKept: the mark on port stays, no account is recorded
// with it, no two share a port, and every file names its recorded port.
func assertOpenCodeContestKept(t *testing.T, homes map[int]string, record map[int]int, port int, log string) {
	t.Helper()
	marked := false
	for _, entry := range openCodeRecordContested {
		marked = marked || entry.Port == port
	}
	if !marked {
		t.Fatalf("the contested mark on %d was lost: %+v\n%s", port, openCodeRecordContested, log)
	}
	seen := map[int]int{}
	for uid, home := range homes {
		got := record[uid]
		if got == 0 || got == port {
			t.Fatalf("uid %d is recorded with %d (the contested port is %d): %v\n%s", uid, got, port, record, log)
		}
		if other, shared := seen[got]; shared {
			t.Fatalf("uids %d and %d share port %d: %v\n%s", other, uid, got, record, log)
		}
		seen[got] = uid
		if file := openCodePortIn(t, home); file != got {
			t.Fatalf("uid %d's service.json names %d, the record %d\n%s", uid, file, got, log)
		}
	}
}

// A linked service file is read in the import pass. Its recorded binding
// remains reserved when the account-side replacement refuses the link.
func TestReviewLinkedServiceFileNeverGivesItsPortToNewcomer(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001, 1002)
	target := filepath.Join(homes[1001], "actual-service.json")
	if err := os.WriteFile(target, []byte(`{"port":25002}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := enterprisepolicy.OpenCodeServiceConfigPath(homes[1001])
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 3; pass++ {
		log := runOpenCodePortPass(t)
		if (*record)[1001] != 25002 || (*record)[1002] == 25002 || openCodePortIn(t, homes[1002]) == 25002 {
			t.Fatalf("pass %d lost a recorded port: record=%v log=%s", pass, *record, log)
		}
	}
	setEligible(nil, 1001, 1002, 9002)
	log := runOpenCodePortPass(t)
	if (*record)[9002] == 25002 || openCodePortIn(t, homes[9002]) == 25002 {
		t.Fatalf("later newcomer received a recorded port: record=%v log=%s", *record, log)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte(`{"port":25002}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runOpenCodePortPass(t)
	if (*record)[1001] != 25002 || openCodePortIn(t, homes[1001]) != 25002 {
		t.Fatalf("ordinary file recovery lost its binding: %v", *record)
	}
}

// REVIEW-gx053-12 MF1: the record is committed before any user file is
// rewritten. A commit that fails rewrites no file, and the next pass is the
// same import pass over the same files, with the same result.
func TestManagedGuardianOpenCodeCommitFailureRewritesNoFile(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001, 1002, 1003)
	writeOpenCodePortFile(t, homes[1001], 25003)
	writeOpenCodePortFile(t, homes[1002], 25003)
	openCodeOnCommit = func(enterprisehooks.UnixOpenCodeServicePortsState) error {
		return errors.New("no space left on device")
	}
	log := runOpenCodePortPass(t)
	for uid, want := range map[int]int{1001: 25003, 1002: 25003, 1003: 0} {
		if got := openCodePortIn(t, homes[uid]); got != want {
			t.Fatalf("uid %d's file was rewritten to %d although the record was not committed\n%s", uid, got, log)
		}
	}
	if len(*record) != 0 || openCodeRecordExists || !strings.Contains(log, "no account's OpenCode service.json is rewritten this pass") {
		t.Fatalf("the failed commit is not reported, or something was recorded: %v\n%s", *record, log)
	}
	openCodeOnCommit = nil
	log = runOpenCodePortPass(t)
	assertOpenCodeContestKept(t, homes, *record, 25003, log)
}

// A crash right after the commit, before any file is rewritten: the next
// pass is a normal pass, the record wins and the files are rewritten.
func TestManagedGuardianOpenCodeCrashBetweenCommitAndRewrites(t *testing.T) {
	homes, record, _ := openCodePortGuardianWith(t, true, 1001, 1002, 1003)
	writeOpenCodePortFile(t, homes[1001], 25003)
	writeOpenCodePortFile(t, homes[1002], 25003)
	var early []string
	openCodeOnCommit = func(enterprisehooks.UnixOpenCodeServicePortsState) error {
		for uid, want := range map[int]int{1001: 25003, 1002: 25003, 1003: 0} {
			if got := openCodePortIn(t, homes[uid]); got != want {
				early = append(early, fmt.Sprintf("uid %d's file names %d", uid, got))
			}
		}
		openCodeCrashed.Store(true) // the guardian dies right after this commit
		return nil
	}
	log := runOpenCodePortPass(t)
	if len(early) > 0 {
		t.Fatalf("user files were rewritten before the record was committed: %v\n%s", early, log)
	}
	if len(*record) != 3 || !openCodeRecordExists || len(openCodeRecordContested) != 1 {
		t.Fatalf("the commit is not whole: %v %+v\n%s", *record, openCodeRecordContested, log)
	}
	openCodeOnCommit = nil
	openCodeCrashed.Store(false)
	for pass := 2; pass <= 3; pass++ {
		log = runOpenCodePortPass(t)
		assertOpenCodeContestKept(t, homes, *record, 25003, log)
	}
}

// A crash in the middle of the rewrites (one file written, the other not):
// the committed marks and bindings decide the next passes, so the account
// whose file still names the contested port does not get it, nor does a new
// account whose first port it is.
func TestManagedGuardianOpenCodeCrashMidRewrites(t *testing.T) {
	homes, record, setEligible := openCodePortGuardianWith(t, true, 1001, 1002)
	writeOpenCodePortFile(t, homes[1001], 25003)
	writeOpenCodePortFile(t, homes[1002], 25003)
	openCodeAfterRewrite = func(int) { openCodeCrashed.Store(true) } // dies after the first file
	log := runOpenCodePortPass(t)
	if a, b := openCodePortIn(t, homes[1001]), openCodePortIn(t, homes[1002]); (a == 25003) == (b == 25003) {
		t.Fatalf("not a crash between two rewrites: files name %d and %d\n%s", a, b, log)
	}
	openCodeAfterRewrite = nil
	openCodeCrashed.Store(false)
	setEligible(nil, 1001, 1002, 1003) // uid 1003's first port is 25003
	for pass := 2; pass <= 3; pass++ {
		log = runOpenCodePortPass(t)
		assertOpenCodeContestKept(t, homes, *record, 25003, log)
	}
}

// REVIEW-gx053-12 MF2: opencode-port-clear takes the guardian's reconcile
// lock, so it waits while a guardian pass holds it (the pass's read, plan,
// commit and rewrites) and never interleaves with one.
func TestOpenCodePortClearWaitsForTheGuardianPass(t *testing.T) {
	_ = newStandaloneFixture(t, standaloneTestResolver{})
	unlock, err := lockEnterpriseHookReconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(managed.HookGuardianAuthorizationDir(cfg.DataDir), enterprisehooks.UnixOpenCodeServicePortsFileName)
	done := make(chan error, 1)
	go func() {
		_, err := openCodePortClear(path, 25003, "admin", time.Now())
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("the clear ran while a guardian pass held the reconcile lock: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the clear did not run after the guardian pass released the lock")
	}
}
