// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0422 (FC-BLK-167-ER): on a host whose gateway accepts every account (a
// machine-policy connector), a local account the gateway served gets an
// identity record keyed on its home inode, so the gateway can tell it from
// an account created again under the same name and uid; the key changes
// with the home, so the record is rewritten at the next tick. A host that
// accepts only its targets lists no such account.
func TestMachinePolicyHostRecordsTheLocalAccountsTheGatewayServed(t *testing.T) {
	identityCallerTestConfig(t)
	const uid = 52100
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
	previousMachine, previousPeers := enterpriseHookLoadMachinePolicyConnectors, enterpriseHookGatewayPeerAccounts
	t.Cleanup(func() {
		enterpriseHookLoadMachinePolicyConnectors, enterpriseHookGatewayPeerAccounts = previousMachine, previousPeers
	})
	inode := uint64(201442906)
	enterpriseHookGatewayPeerAccounts = func(string) []enterpriseHookPeerAccount {
		return []enterpriseHookPeerAccount{{UID: uid, User: "fcuid1", HomeInode: inode}}
	}
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return []string{"claudecode"}, nil }
	dir := t.TempDir()
	accounts, keys, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); !slices.Contains(listed, uid) {
		t.Fatalf("machine-policy host: accounts %+v; want the served local account listed", accounts)
	}
	if !slices.Contains(keys, "52100:fcuid1:201442906") {
		t.Fatalf("keys %v; want the account keyed on its home inode", keys)
	}
	// userdel -r; useradd -u 52100 fcuid1: another home.
	inode = 327434342
	if _, again, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{}); slices.Equal(again, keys) {
		t.Fatalf("keys %v did not change with the home", again)
	}
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return nil, nil }
	accounts, _, _ = enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	if listed, _ := listedUIDs(accounts); slices.Contains(listed, uid) {
		t.Fatalf("targets-only host: accounts %+v; want no served account listed", accounts)
	}
}

// enterpriseHookGatewayPeerAccounts reads the uids of the gateway's homes
// file, skips the format entry and every key that is not a uid, and gives
// each account the account database resolves with the inode of its home.
func TestGatewayPeerAccountsReadTheGatewayHomesFile(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current account:", err)
	}
	uid, err := strconv.Atoi(me.Uid)
	if err != nil || uid <= 0 {
		t.Skip("not run as a non-root account")
	}
	dataDir := t.TempDir()
	body := `{"0":{"name":"root"},"format":{"format":1},"x1":{},"` + me.Uid + `":{"name":"` + me.Username + `"}}`
	if err := os.WriteFile(filepath.Join(dataDir, "managed_peer_homes.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	peers := enterpriseHookGatewayPeerAccounts(dataDir)
	if len(peers) == 0 {
		t.Skip("the account database gives the current account no non-SID incarnation here")
	}
	if len(peers) != 1 || peers[0].UID != uid || !strings.EqualFold(peers[0].User, me.Username) {
		t.Fatalf("peers %+v; want only the current account", peers)
	}
	if want := enterpriseHookHomeInode(me.HomeDir); peers[0].HomeInode != want {
		t.Fatalf("home inode %d, want %d", peers[0].HomeInode, want)
	}
	if enterpriseHookGatewayPeerAccounts(t.TempDir()) != nil {
		t.Fatal("peers without a homes file")
	}
}

// GAP-1864: on a machine-policy host the guardian refreshed every record it
// already held, also the record of a local account deleted since, so the
// record never went and status and verify warned identity_records_stale for
// good. A local record whose uid no account holds any more is not listed,
// and the pass's cleanup removes it; a local record of an account that
// exists is still refreshed.
func TestDeletedLocalAccountRecordIsNotRefreshed(t *testing.T) {
	identityCallerTestConfig(t)
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
	previousMachine, previousPeers := enterpriseHookLoadMachinePolicyConnectors, enterpriseHookGatewayPeerAccounts
	t.Cleanup(func() {
		enterpriseHookLoadMachinePolicyConnectors, enterpriseHookGatewayPeerAccounts = previousMachine, previousPeers
	})
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return []string{"claudecode"}, nil }
	enterpriseHookGatewayPeerAccounts = func(string) []enterpriseHookPeerAccount { return nil }
	me, err := user.Current()
	if err != nil {
		t.Skip("no current account:", err)
	}
	const deleted = 2147400123
	if _, err := user.LookupId(strconv.Itoa(deleted)); err == nil {
		t.Skipf("uid %d exists here", deleted)
	}
	dir := t.TempDir()
	for _, record := range []enterprisehooks.IdentitySpoolRecord{
		{Key: strconv.Itoa(deleted), User: "fcuid1"},
		{Key: me.Uid, User: me.Username},
	} {
		record.Version, record.UpdatedAt = enterprisehooks.IdentitySpoolRecordVersion, time.Now().UTC()
		record.Facts = useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}
		data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	accounts, _, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
	listed, _ := listedUIDs(accounts)
	if slices.Contains(listed, deleted) {
		t.Fatalf("accounts %+v; the deleted local account's record is still refreshed", accounts)
	}
	if uid, _ := strconv.Atoi(me.Uid); !slices.Contains(listed, uid) {
		t.Fatalf("accounts %+v; want the existing local account's record refreshed", accounts)
	}
	_ = enterprisehooks.WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil)
	if _, err := os.Stat(filepath.Join(dir, strconv.Itoa(deleted)+".json")); !os.IsNotExist(err) {
		t.Fatalf("the deleted local account's record is still there after a pass (%v)", err)
	}
}

// GAP-1866: the account lookups of the served accounts run again only when
// the gateway's homes file changes (or after the spool interval), not at
// every one-minute tick, and a home whose stat fails this tick keeps the
// inode of its last answer, so the spool key does not flap.
func TestGatewayPeerListingIsCachedAndKeepsTheLastInode(t *testing.T) {
	previous := enterpriseHookResolveGatewayPeers
	t.Cleanup(func() { enterpriseHookResolveGatewayPeers = previous; enterpriseHookPeerListing.reset() })
	enterpriseHookPeerListing.reset()
	home := t.TempDir()
	resolves := 0
	enterpriseHookResolveGatewayPeers = func(string, map[int]enterpriseHookCachedPeer) map[int]enterpriseHookCachedPeer {
		resolves++
		return map[int]enterpriseHookCachedPeer{52100: {enterpriseHookPeerAccount{UID: 52100, User: "fcuid1", HomeInode: enterpriseHookHomeInode(home)}, home}}
	}
	dataDir := t.TempDir()
	homes := filepath.Join(dataDir, "managed_peer_homes.json")
	if err := os.WriteFile(homes, []byte(`{"52100":{"name":"fcuid1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	first := enterpriseHookGatewayPeerAccounts(dataDir)
	if len(first) != 1 || first[0].HomeInode == 0 {
		t.Fatalf("first listing %+v", first)
	}
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	again := enterpriseHookGatewayPeerAccounts(dataDir)
	if resolves != 1 || len(again) != 1 || again[0].HomeInode != first[0].HomeInode {
		t.Fatalf("second tick: %d lookups, listing %+v; want the cached account with its last inode %d", resolves, again, first[0].HomeInode)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(homes, later, later); err != nil {
		t.Fatal(err)
	}
	_ = enterpriseHookGatewayPeerAccounts(dataDir)
	if resolves != 2 {
		t.Fatalf("a changed homes file gave %d lookups; want the accounts resolved again", resolves)
	}
}

// GAP-1865 refix (RV4-1): a machine-policy host with targets 0 that comes
// from published 1.0.3 directly has only served accounts. If none of them
// could write the first migration map, the pre-upgrade agents entries of its
// local accounts were refused for good. The homes file shows whether a 1.0.4
// gateway served the uids: 1.0.3 writes no format entry, 1.0.4 writes format
// 1, and this release keeps pre_token_holder on each uid it took over from 1.0.3.
// Only the 1.0.4 shape keeps the account from writing the first map.
func TestServedAccountWritesTheFirstMigrationMapWithoutA104Window(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current account:", err)
	}
	uid, err := strconv.Atoi(me.Uid)
	if err != nil || uid <= 0 {
		t.Skip("not run as a non-root account")
	}
	identityCallerTestConfig(t)
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledInspect
	cfg.DataDir = t.TempDir()
	previousMachine := enterpriseHookLoadMachinePolicyConnectors
	t.Cleanup(func() { enterpriseHookLoadMachinePolicyConnectors = previousMachine; enterpriseHookPeerListing.reset() })
	enterpriseHookLoadMachinePolicyConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	entry := `"` + me.Uid + `":{"home":"` + me.HomeDir + `","name":"` + me.Username + `"}`
	for _, tc := range []struct {
		name, body string
		peer       bool
	}{
		{"1.0.3 homes file", `{` + entry + `}`, false},
		{"1.0.4 homes file", `{"format":{"format":1},` + entry + `}`, true},
		{"homes file this release marked for the uid", `{"format":{"format":1},` + strings.TrimSuffix(entry, "}") + `,"pre_token_holder":true}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enterpriseHookPeerListing.reset()
			if err := os.WriteFile(filepath.Join(cfg.DataDir, "managed_peer_homes.json"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			accounts, _, _ := enterpriseHookIdentitySpoolAccounts(context.Background(), io.Discard, dir, enterpriseHookReconcileRun{})
			i := slices.IndexFunc(accounts, func(a enterprisehooks.IdentitySpoolAccount) bool { return a.UID == uid })
			if i < 0 {
				t.Skip("the account database gives the current account no non-SID incarnation here")
			}
			if accounts[i].Peer != tc.peer {
				t.Fatalf("account %+v: Peer=%v, want %v", accounts[i], accounts[i].Peer, tc.peer)
			}
			_ = enterprisehooks.WriteIdentitySpool(context.Background(), dir, accounts[i:i+1], nil, nil, nil)
			record, err := enterprisehooks.ReadIdentitySpoolRecord(dir, me.Uid, nil)
			if err != nil || record.LegacyOwnerToken == "" {
				t.Logf("no record with an owner token for the current account here (%v); the map half rests on enterprisehooks", err)
				return
			}
			if recorded := enterprisehooks.LegacyAgentOwnersRecorded(dir); recorded == tc.peer {
				t.Fatalf("first pass wrote the migration map=%v, want %v", recorded, !tc.peer)
			}
		})
	}
}
