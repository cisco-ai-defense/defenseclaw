// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// bothDamagedFixture installs Hermes for a fixture account with the real
// installer and returns the options the worker repairs it with, the hook script
// and the agent config, and what the install left in them.
type bothDamagedFixture struct {
	account                    enterpriseHookWorkerAccount
	target                     enterpriseHookWorkerTarget
	script, config             string
	installedScript, installed []byte
}

func newBothDamagedFixture(t *testing.T) bothDamagedFixture {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("the installer refuses uid 0 targets")
	}
	previous := enterprisehooks.StandaloneUnix()
	enterprisehooks.SetStandaloneUnix(true)
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previous) })
	account := selfWorkerAccount(t)
	if err := os.Chmod(account.Home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", account.Home)
	config := filepath.Join(account.Home, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterprisehooks.InstallOptions{
		ConnectorName: "hermes", UserHome: account.Home, OwnerUID: account.UID, OwnerGID: account.GID,
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "observe", HookFailMode: "open", AgentVersion: "0.21.5",
	}
	if _, err := enterprisehooks.Install(context.Background(), opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	f := bothDamagedFixture{account: account, config: config, script: filepath.Join(account.Home, ".defenseclaw", "hooks", "hermes-hook.sh")}
	var err error
	if f.installed, err = os.ReadFile(config); err != nil {
		t.Fatal(err)
	}
	if f.installedScript, err = os.ReadFile(f.script); err != nil {
		t.Fatal(err)
	}
	f.target = enterpriseHookWorkerTarget{Index: 1, Mode: enterpriseHookWorkerModeVerifyOrRepair, PreviouslyProtected: true,
		Options: enterpriseHookWorkerOptionsFrom(opts)}
	return f
}

// apply runs the worker the way the guardian does for a protected target: with
// progress on, so it names what it put back.
func (f bothDamagedFixture) apply(t *testing.T, recheck time.Duration) enterpriseHookWorkerTargetResult {
	t.Helper()
	request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true,
		UID: f.account.UID, GID: f.account.GID, User: f.account.User, Home: f.account.Home,
		RecheckMillis: int(recheck / time.Millisecond), Targets: []enterpriseHookWorkerTarget{f.target}}
	response := runEnterpriseHookWorkerApply(withEnterpriseHookWorkerProgress(context.Background(), io.Discard), request)
	if len(response.Targets) != 1 {
		t.Fatalf("answers = %+v, want one", response.Targets)
	}
	return response.Targets[0]
}

func (f bothDamagedFixture) requireIntact(t *testing.T, step string) {
	t.Helper()
	if body, err := os.ReadFile(f.config); err != nil || string(body) != string(f.installed) {
		t.Fatalf("%s: the config entry was not put back exactly (err %v)", step, err)
	}
	if body, err := os.ReadFile(f.script); err != nil || string(body) != string(f.installedScript) {
		t.Fatalf("%s: the hook script was not put back exactly (err %v)", step, err)
	}
}

// GAP-0754: two elements damaged in one change (the hook script and the hook
// entry in the agent config) are both put back by one repair, both counted, each
// with what happened to it, and the config holds exactly what the install wrote
// when it is sampled after 1 s and after 5 s.
func TestWorkerRestoresTheScriptAndTheEntryDamagedInOneChange(t *testing.T) {
	scriptElement := "hook runtime file hermes-hook.sh"
	for _, tc := range []struct {
		name         string
		sample       bool // sample the files 1 s and 5 s after the repair
		tamper       func(f bothDamagedFixture) error
		wantElements []string
		wantChanges  []string
	}{
		{"script appended to, entry removed", true, func(f bothDamagedFixture) error {
			if err := os.WriteFile(f.script, append(slices.Clone(f.installedScript), "#"...), 0o700); err != nil {
				return err
			}
			return os.WriteFile(f.config, []byte("{}\n"), 0o600)
		}, []string{enterprisehooks.HookElementEntry, scriptElement}, []string{enterprisehooks.HookChangeDeleted, enterprisehooks.HookChangeAppended}},
		{"script deleted, entry edited", true, func(f bothDamagedFixture) error {
			if err := os.Remove(f.script); err != nil {
				return err
			}
			return os.WriteFile(f.config, []byte(strings.ReplaceAll(string(f.installed), "hermes-hook.sh", "hermes-hook.sh.bak")), 0o600)
		}, []string{enterprisehooks.HookElementEntry, scriptElement}, []string{enterprisehooks.HookChangeEdited, enterprisehooks.HookChangeDeleted}},
		// The twins: one element damaged is one restore, and an intact target none.
		{"script appended to only", false, func(f bothDamagedFixture) error {
			return os.WriteFile(f.script, append(slices.Clone(f.installedScript), "#"...), 0o700)
		}, []string{scriptElement}, []string{enterprisehooks.HookChangeAppended}},
		{"entry edited only", false, func(f bothDamagedFixture) error {
			return os.WriteFile(f.config, []byte(strings.ReplaceAll(string(f.installed), "hermes-hook.sh", "hermes-hook.sh.bak")), 0o600)
		}, []string{enterprisehooks.HookElementEntry}, []string{enterprisehooks.HookChangeEdited}},
		{"nothing damaged", false, func(bothDamagedFixture) error { return nil }, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBothDamagedFixture(t)
			if err := tc.tamper(f); err != nil {
				t.Fatal(err)
			}
			got := f.apply(t, 0)
			if !got.OK || !slices.Equal(got.RestoredElements, tc.wantElements) || !slices.Equal(got.RestoredChanges, tc.wantChanges) {
				t.Fatalf("answer = %+v, want a healthy target with %v restored (%v)", got, tc.wantElements, tc.wantChanges)
			}
			f.requireIntact(t, "after the repair")
			if !tc.sample {
				return
			}
			time.Sleep(time.Second)
			f.requireIntact(t, "1 s after")
			time.Sleep(4 * time.Second)
			f.requireIntact(t, "5 s after")
		})
	}
}

// A second element damaged a moment after the install read its file is put back
// by the same pass: the target that was repaired is checked again over the
// window, and the restores of both checks are kept.
func TestWorkerRechecksARepairedTargetAndKeepsBothRestores(t *testing.T) {
	f := newBothDamagedFixture(t)
	if err := os.WriteFile(f.script, append(slices.Clone(f.installedScript), "#"...), 0o700); err != nil {
		t.Fatal(err)
	}
	real := enterpriseHookWorkerInstaller
	var installs atomic.Int32
	t.Cleanup(func() { enterpriseHookWorkerInstaller = real })
	enterpriseHookWorkerInstaller = func(ctx context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		result, err := real(ctx, opts)
		if installs.Add(1) == 1 {
			// The entry is damaged after the install is done with the config.
			if writeErr := os.WriteFile(f.config, []byte("{}\n"), 0o600); writeErr != nil {
				t.Error(writeErr)
			}
		}
		return result, err
	}
	got := f.apply(t, 500*time.Millisecond)
	want := []string{"hook runtime file hermes-hook.sh", enterprisehooks.HookElementEntry}
	if !got.OK || !slices.Equal(got.RestoredElements, want) ||
		!slices.Equal(got.RestoredChanges, []string{enterprisehooks.HookChangeAppended, enterprisehooks.HookChangeDeleted}) {
		t.Fatalf("answer = %+v, want a healthy target with %v restored", got, want)
	}
	f.requireIntact(t, "after the recheck")

	// The twin: no damage after the install, so one install and one restore.
	g := newBothDamagedFixture(t)
	if err := os.WriteFile(g.script, append(slices.Clone(g.installedScript), "#"...), 0o700); err != nil {
		t.Fatal(err)
	}
	installs.Store(100)
	enterpriseHookWorkerInstaller = real
	if got := g.apply(t, 500*time.Millisecond); !got.OK || !slices.Equal(got.RestoredElements, want[:1]) {
		t.Fatalf("twin answer = %+v, want the script alone restored", got)
	}
}
