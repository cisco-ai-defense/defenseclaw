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

	"github.com/defenseclaw/defenseclaw/internal/config"
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
