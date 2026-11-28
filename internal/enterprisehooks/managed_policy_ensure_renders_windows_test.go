//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-1742: an unchanged guardian ensure pass searched the
// recorded forms of the Claude drop-in from the version-less contract up,
// so a drop-in rendered for a later contract was found only after every
// earlier contract, lock and form was rendered, each rendering checking the
// hook executables again: about 12 s of CPU every pass, about one core at
// idle on the managed host. The contract and lock the pass renders are
// searched first, so the current drop-in is rendered once.
func TestStandaloneClaudeEnsureOfTheCurrentDropInRendersItOnce(t *testing.T) {
	requireGAP633Elevated(t) // a standard user is refused the managed policy folder (rel-1-0-10 GAP-1519)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	stateBody, err := os.ReadFile(filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile))
	if err != nil {
		t.Fatal(err)
	}
	var record windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(stateBody, &record); err != nil {
		t.Fatal(err)
	}
	// The contract and lock the published drop-in was rendered under, as the
	// guardian names them (enterpriseHookMachinePolicyContract).
	ensure := withWindowsClaudeManagedHooksOnly(connector.SetupOpts{APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe})
	type contractLock struct {
		contract string
		lock     bool
	}
	published := contractLock{}
	searched := 0
	found := false
	for _, contract := range windowsClaudeRecordedPolicyContracts() {
		for _, lock := range []bool{true, false} {
			if found {
				continue
			}
			searched++
			body, renderErr := renderWindowsClaudeRecordedPolicy(record, contract, lock)
			if renderErr != nil {
				t.Fatal(renderErr)
			}
			if bytes.Equal(body, current) {
				published = contractLock{contract: contract, lock: lock}
				found = true
			}
		}
	}
	if !found || published.lock != ensure.ClaudeAllowManagedHooksOnly || searched < 2 {
		t.Fatalf("fixture precondition: the installed drop-in is contract %q lock %v (found=%v, %d contract/lock pairs searched); want a later contract with the lock the ensure pass renders (%v)",
			published.contract, published.lock, found, searched, ensure.ClaudeAllowManagedHooksOnly)
	}
	ensure.HookContractID = published.contract

	render := windowsClaudeRecordedPolicyRender
	t.Cleanup(func() { windowsClaudeRecordedPolicyRender = render })
	renders := 0
	windowsClaudeRecordedPolicyRender = func(
		record windowsClaudeManagedPolicyState,
		contract string,
		lock bool,
		form windowsClaudeRecordedForm,
	) ([]byte, error) {
		renders++
		return render(record, contract, lock, form)
	}
	for pass := 1; pass <= 2; pass++ {
		renders = 0
		if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
			t.Fatalf("pass %d: ensure: %v", pass, err)
		}
		if renders != 1 {
			t.Fatalf("pass %d: an unchanged ensure pass made %d recorded Claude policy renderings; want 1 (the contract %q and lock it writes)", pass, renders, published.contract)
		}
		got, err := os.ReadFile(fixture.policyPath)
		if err != nil || !bytes.Equal(got, current) {
			t.Fatalf("pass %d: ensure changed the current drop-in: err=%v", pass, err)
		}
	}
}

// rel-1-0-10 GAP-1742 (deferred staging, after GAP-1713): staging a pending
// account with no known Claude version asks keep whether the published
// drop-in is a rendering of a known contract, every contract, lock and form,
// and asked it under the managed policy transaction lock (about 5 s on the
// managed host). keep is asked before the lock; under it the answer is used
// for the same bytes only, and a drop-in that changed is asked again.
func TestDeferredClaudeKeepIsDecidedOutsideTransactionLock(t *testing.T) {
	requireGAP633Elevated(t) // a standard user is refused the managed policy folder (rel-1-0-10 GAP-1519)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	opts.AgentVersion = "2.1.230 (Claude Code)"
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	stateBody, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var record windowsClaudeManagedPolicyState
	if err := decodeWindowsClaudeManagedPolicyState(stateBody, &record); err != nil {
		t.Fatal(err)
	}
	// The version-less rendering staging would publish if keep said no.
	versionless, err := renderWindowsClaudeRecordedPolicy(record, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(versionless, current) {
		t.Fatal("fixture precondition: the version-less rendering is the published drop-in")
	}
	// Another recorded form of the drop-in, published before the lock is
	// taken in the second case below.
	direct, err := renderWindowsClaudeRecordedPolicy(record, "", true, windowsClaudeFormDirect)
	if err != nil {
		t.Fatal(err)
	}
	directRecord := record
	directRecord.PolicySHA256 = windowsManagedPolicyDigest(direct)
	directState, err := json.MarshalIndent(directRecord, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	directState = append(directState, byte(10))

	transaction := windowsClaudeManagedPolicyTransaction
	t.Cleanup(func() { windowsClaudeManagedPolicyTransaction = transaction })
	locked := false
	var onLock func()
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error {
		return transaction(func() error {
			locked = true
			defer func() { locked = false }()
			if onLock != nil {
				hook := onLock
				onLock = nil
				hook()
			}
			return fn()
		})
	}
	var asked [][]byte
	underLock := 0
	keep := func(published []byte) bool {
		asked = append(asked, append([]byte(nil), published...))
		if locked {
			underLock++
		}
		return bytes.Equal(published, current) || bytes.Equal(published, direct)
	}
	setup := connector.SetupOpts{
		APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe,
		HookFailMode: "closed", ManagedEnterprise: true,
	}

	// The published drop-in does not change: keep is asked once, before
	// the lock, and the drop-in is kept byte for byte.
	if _, _, err := installWindowsClaudeManagedPolicyKeepingPublished(versionless, keep, setup, fixture.targetSID); err != nil {
		t.Fatalf("staging: %v", err)
	}
	if len(asked) != 1 || underLock != 0 || !bytes.Equal(asked[0], current) {
		t.Fatalf("staging asked keep %d times, %d under the managed policy transaction lock; want once, outside it, about the published drop-in", len(asked), underLock)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(got, current) {
		t.Fatalf("staging replaced the kept drop-in: err=%v", err)
	}

	// The drop-in changes between the unlocked read and the lock: the
	// answer for the earlier read is not used, keep is asked about the
	// bytes authenticated under the lock.
	asked, underLock = nil, 0
	onLock = func() {
		if err := windowsManagedPolicyWriter(fixture.policyPath, direct, true); err != nil {
			t.Fatal(err)
		}
		if err := windowsManagedPolicyWriter(statePath, directState, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := installWindowsClaudeManagedPolicyKeepingPublished(versionless, keep, setup, fixture.targetSID); err != nil {
		t.Fatalf("staging after a concurrent change: %v", err)
	}
	if underLock != 1 || len(asked) != 2 || !bytes.Equal(asked[1], direct) {
		t.Fatalf("after a concurrent change keep was asked %d times, %d under the lock; want the changed drop-in asked under the lock", len(asked), underLock)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(got, direct) {
		t.Fatalf("staging did not keep the drop-in authenticated under the lock: err=%v", err)
	}

	// The drop-in changes, between the unlocked read and the lock, to bytes
	// keep refuses: the yes for the earlier read is not used for them, and
	// staging publishes its own rendering (GAP-1885, review note P4-3).
	asked, underLock = nil, 0
	keepOnly := direct
	keep = func(published []byte) bool {
		asked = append(asked, append([]byte(nil), published...))
		if locked {
			underLock++
		}
		return bytes.Equal(published, keepOnly)
	}
	onLock = func() {
		if err := windowsManagedPolicyWriter(fixture.policyPath, current, true); err != nil {
			t.Fatal(err)
		}
		if err := windowsManagedPolicyWriter(statePath, stateBody, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := installWindowsClaudeManagedPolicyKeepingPublished(versionless, keep, setup, fixture.targetSID); err != nil {
		t.Fatalf("staging after a change to a refused drop-in: %v", err)
	}
	if underLock != 1 || len(asked) != 2 || !bytes.Equal(asked[0], direct) || !bytes.Equal(asked[1], current) {
		t.Fatalf("after a change to a refused drop-in keep was asked %d times, %d under the lock; want the changed drop-in asked under the lock", len(asked), underLock)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || !bytes.Equal(got, versionless) {
		t.Fatalf("staging kept a changed drop-in on the answer for the earlier read: err=%v", err)
	}
}
