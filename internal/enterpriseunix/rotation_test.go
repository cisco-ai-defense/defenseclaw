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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// guardianServices runs a simulated hook guardian reconcile whenever the
// reconcile oneshot starts.
type guardianServices struct {
	*fakeServices
	reconcile func()
}

func (g *guardianServices) Start(ctx context.Context, u Unit) error {
	if u.Name == unitGuardianOneshot {
		g.reconcile()
	}
	return g.fakeServices.Start(ctx, u)
}

// rotationHost is an installed test host whose gateway accepts the keys on
// disk and whose guardian renders two users from the staged key when there
// is one, else from the committed key. events records, in order, each key
// the gateway proved and each key the guardian rendered a user from.
type rotationHost struct {
	*testHost
	serviceUID int
	keyA       string
	rendered   map[string]string // user -> key fingerprint of their hooks
	failStaged bool              // bob fails whenever a key is staged
	// holdBack keeps a user on the key their hooks carry while no key is
	// staged (a guardian that cannot move them back yet).
	holdBack bool
	// failed are targets every reconcile reports failed, beside the users.
	failed     []enterprisehooks.CredentialAttestationTarget
	reconciles int
	events     []string
	onProof    func() // runs on every listener proof
}

func newRotationHost(t *testing.T) *rotationHost {
	t.Helper()
	h := &rotationHost{testHost: newTestHost(t, "linux"), keyA: strings.Repeat("a1", 32), rendered: map[string]string{}}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.serviceUID = h.accounts.accounts[h.env.Layout.ServiceUser].UID
	if err := os.MkdirAll(filepath.Dir(h.env.committedUserKeyPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.committedUserKeyPath(), []byte(h.keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.owners[h.env.committedUserKeyPath()] = [2]int{h.serviceUID, h.serviceUID}
	idA := connector.UserScopedTokenKeyFingerprint(h.keyA)
	h.rendered["alice"], h.rendered["bob"] = idA, idA

	h.env.Services = &guardianServices{fakeServices: h.services, reconcile: h.reconcile}
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		body, _ := json.Marshal(map[string]any{
			"api":                     map[string]any{"state": "running"},
			"user_scoped_credentials": map[string]any{"key_ids": h.liveKeyIDs()},
		})
		return 200, body, nil
	}
	h.env.ListenerProof = func(_ context.Context, name, keyID, nonce string) (string, error) {
		if h.onProof != nil {
			h.onProof()
		}
		for _, key := range h.liveKeys() {
			for _, uid := range []string{"1001", "1002"} {
				credential, _ := connector.UserScopedHookAPIToken(key, name, uid)
				if connector.UserScopedCredentialKeyID(credential) == keyID {
					event := "proved " + connector.UserScopedTokenKeyFingerprint(key)
					if h.reconcileLockHeld() {
						event += " (reconcile lock held)"
					}
					h.events = append(h.events, event)
					return connector.UserScopedListenerProof(credential, name, nonce)
				}
			}
		}
		return "", errors.New("HTTP 401")
	}
	return h
}

// reconcileLockHeld reports whether a guardian reconcile would have to wait
// for the reconcile lock right now.
func (h *rotationHost) reconcileLockHeld() bool {
	file, err := os.OpenFile(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianReconcileLockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		h.t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return false
}

// liveKeys are the keys the gateway accepts: the committed, staged and
// retiring keys on disk.
func (h *rotationHost) liveKeys() []string {
	var keys []string
	for _, path := range []string{h.env.committedUserKeyPath(), h.env.stagedUserKeyPath(), h.env.retiringUserKeyPath()} {
		if data, err := os.ReadFile(path); err == nil {
			keys = append(keys, strings.TrimSpace(string(data)))
		}
	}
	return keys
}

func (h *rotationHost) liveKeyIDs() []string {
	ids := []string{}
	for _, key := range h.liveKeys() {
		ids = append(ids, connector.UserScopedTokenKeyFingerprint(key))
	}
	return ids
}

// reconcile renders both users from the staged key while the guardian's
// prepare record names it, else from the committed one, as the guardian
// does: a user already on it is verified, anyone else is repaired. A user
// whose key the gateway no longer accepts is recorded as refused.
func (h *rotationHost) reconcile() {
	key := h.committedKey()
	var transaction enterprisehooks.CredentialTransaction
	if data, err := os.ReadFile(h.env.transactionPath()); err == nil {
		if transaction, err = enterprisehooks.ParseCredentialTransaction(data); err != nil {
			h.t.Fatal(err)
		}
		if staged, err := os.ReadFile(h.env.stagedUserKeyPath()); err == nil &&
			transaction.RendersNext(connector.UserScopedTokenKeyFingerprint(key), connector.UserScopedTokenKeyFingerprint(strings.TrimSpace(string(staged)))) {
			key = strings.TrimSpace(string(staged))
		}
	}
	keyID := connector.UserScopedTokenKeyFingerprint(key)
	for _, user := range []string{"alice", "bob"} {
		if !slices.Contains(h.liveKeyIDs(), h.rendered[user]) {
			h.events = append(h.events, "refused "+user)
		}
	}
	h.reconciles++
	attestation := enterprisehooks.CredentialAttestation{
		Version: enterprisehooks.CredentialAttestationVersion, ID: fmt.Sprintf("%032x", h.reconciles),
		UpdatedAt: "2026-09-29T00:00:00Z", ManifestSHA256: strings.Repeat("d", 64), KeyID: keyID,
		OperationID: transaction.OperationID, Phase: transaction.Phase,
		Targets: []enterprisehooks.CredentialAttestationTarget{},
	}
	for index, user := range []string{"alice", "bob"} {
		target := enterprisehooks.CredentialAttestationTarget{Connector: "codex", User: user, UID: 1001 + index, State: enterprisehooks.CredentialTargetCurrent}
		credential, _ := connector.UserScopedHookAPIToken(key, "codex", fmt.Sprint(target.UID))
		target.CredentialID = connector.UserScopedCredentialKeyID(credential)
		switch {
		case user == "bob" && h.failStaged && exists(h.env.stagedUserKeyPath()):
			target.State, target.UID, target.CredentialID = enterprisehooks.CredentialTargetFailed, -1, ""
		case h.rendered[user] == keyID:
			target.Credentials, target.Verified = true, true
		case h.holdBack && !exists(h.env.stagedUserKeyPath()):
			target.Credentials = true
		default:
			h.rendered[user] = keyID
			target.Credentials = true
			h.events = append(h.events, "rendered "+keyID)
		}
		attestation.Targets = append(attestation.Targets, target)
	}
	attestation.Targets = append(attestation.Targets, h.failed...)
	if ledger, err := os.ReadFile(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianAuthorizationFile)); err == nil {
		sum := sha256.Sum256(ledger)
		attestation.AuthorizationSHA256 = hex.EncodeToString(sum[:])
	}
	data, _ := json.Marshal(attestation)
	if err := os.WriteFile(h.env.attestationPath(), data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rotationHost) committedKey() string {
	data, err := os.ReadFile(h.env.committedUserKeyPath())
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func (h *rotationHost) requireNoRotationLeft() {
	h.t.Helper()
	for _, path := range []string{h.env.stagedUserKeyPath(), h.env.retiringUserKeyPath(), h.env.transactionPath(), h.env.rotationIntentPath()} {
		if exists(path) {
			h.t.Fatalf("%s is left behind", path)
		}
	}
}

// rotate-credentials commits the new key only after the gateway accepts
// it for every user and the guardian has moved and verified every user on
// it; the old key is retired after the commit. When one user cannot be
// moved, nothing commits: the new key is removed and every user is moved
// back to the previous key, whose bytes are untouched.
func TestRotateCredentialsMovesEveryUserBeforeTheKeyCommits(t *testing.T) {
	h := newRotationHost(t)
	idA := connector.UserScopedTokenKeyFingerprint(h.keyA)
	result := h.run(Options{Action: ActionRotateCredentials})
	requireOK(t, result)
	keyB := h.committedKey()
	idB := connector.UserScopedTokenKeyFingerprint(keyB)
	h.requireNoRotationLeft()
	// The result says which key replaced which, whom it moved, and that
	// running agents need a restart.
	if changes := strings.Join(result.Changes, "\n"); !strings.Contains(changes, shortKeyID(idB)+" in place of key "+shortKeyID(idA)) ||
		!strings.Contains(changes, "2 per-user target(s) of 2 user(s)") || !strings.Contains(changes, "restart their agents") {
		t.Fatalf("the result does not describe the rotation: %q", result.Changes)
	}
	if keyB == h.keyA || !lowerHexKey(keyB) || h.rendered["alice"] != idB || h.rendered["bob"] != idB {
		t.Fatalf("rotation left key %s and users on %v", shortKeyID(idB), h.rendered)
	}
	if !slices.Equal(h.liveKeyIDs(), []string{idB}) {
		t.Fatalf("the previous key is still accepted: %v", h.liveKeyIDs())
	}
	// The first proofs run under the reconcile lock, so the guardian's own
	// watch and interval passes cannot move a user before them either.
	firstProof, firstRender := slices.Index(h.events, "proved "+idB+" (reconcile lock held)"), slices.Index(h.events, "rendered "+idB)
	if firstProof < 0 || firstRender < 0 || firstProof > firstRender {
		t.Fatalf("a user could be moved before the gateway accepted the new key: %v", h.events)
	}

	// A stopped gateway is refused at once instead of after ReadyTimeout.
	h = newRotationHost(t)
	h.services.active[unitGateway] = false
	result = h.run(Options{Action: ActionRotateCredentials})
	requireError(t, result, codeRotation)
	if h.committedKey() != h.keyA || !strings.Contains(result.Errors[0].Message, unitGateway+" is not running") {
		t.Fatalf("a rotation with the gateway stopped was not refused: %+v", result.Errors)
	}

	h = newRotationHost(t)
	h.failStaged = true
	result = h.run(Options{Action: ActionRotateCredentials})
	requireError(t, result, codeRotation)
	for _, e := range result.Errors {
		if e.Code == codeRollbackFailed {
			t.Fatalf("the rollback did not restore every user: %+v", result.Errors)
		}
	}
	h.requireNoRotationLeft()
	if h.committedKey() != h.keyA || h.rendered["alice"] != idA || h.rendered["bob"] != idA {
		t.Fatalf("a failed rotation did not restore key A for every user: %v", h.rendered)
	}
	if !strings.Contains(result.Errors[0].Message, "codex for user bob") {
		t.Fatalf("the failure does not name the user: %+v", result.Errors)
	}
	// Alice was already on the new key; the rollback kept accepting it
	// until the guardian had moved her back.
	if slices.Contains(h.events, "refused alice") {
		t.Fatalf("the rollback refused a user who had moved: %v", h.events)
	}

	// A rollback that cannot move alice back keeps accepting the new key
	// and keeps the rotation record; the next run finishes the rollback
	// once the guardian has moved her.
	h = newRotationHost(t)
	h.failStaged, h.holdBack = true, true
	requireError(t, h.run(Options{Action: ActionRotateCredentials}), codeRollbackFailed)
	if len(h.liveKeyIDs()) != 2 || !exists(h.env.rotationIntentPath()) {
		t.Fatalf("an unfinished rollback stopped accepting the new key: keys=%v", h.liveKeyIDs())
	}
	if result := h.run(Options{Action: ActionReconcile}); !hasWarning(result, codeRotationRecovered) || len(h.liveKeyIDs()) != 2 {
		t.Fatalf("recovery retired the new key before alice was back: %+v keys=%v", result.Warnings, h.liveKeyIDs())
	}
	h.holdBack = false
	requireOK(t, h.run(Options{Action: ActionReconcile}))
	h.requireNoRotationLeft()
	if h.committedKey() != h.keyA || h.rendered["alice"] != idA || slices.Contains(h.events, "refused alice") {
		t.Fatalf("the rollback did not finish on key A: users=%v events=%v", h.rendered, h.events)
	}
}

// One account's agent that the guardian could not protect (an agent
// version without a verified hook contract) blocked the rotation for the
// whole host. It holds no per-user credential, so the rotation now moves
// every other user and names it; so does an account that no longer exists.
// A failed target the authorization ledger still protects holds the
// current key's credentials, and the rotation still refuses it.
func TestRotateCredentialsSkipsTargetsWithoutACredential(t *testing.T) {
	h := newRotationHost(t)
	h.accounts.accounts["carol"] = Account{Name: "carol", UID: 1003, GID: 1003}
	h.failed = []enterprisehooks.CredentialAttestationTarget{{Connector: "devin", User: "carol", UID: 1003, State: enterprisehooks.CredentialTargetFailed}}
	protect := func(carol bool) {
		targets := []map[string]any{{"user": "alice", "connector": "codex", "ok": true}, {"user": "bob", "connector": "codex", "ok": true}}
		if carol {
			targets = append(targets, map[string]any{"user": "carol", "connector": "devin", "ok": true})
		}
		data, _ := json.Marshal(map[string]any{"version": 1, "protected_targets": targets})
		if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianAuthorizationFile), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	protect(false)
	result := h.run(Options{Action: ActionRotateCredentials})
	requireOK(t, result)
	keyB := h.committedKey()
	if keyB == h.keyA || !strings.Contains(strings.Join(result.Changes, "\n"), "skipped 1 target(s) that hold no per-user credential: devin for user carol") {
		t.Fatalf("the rotation did not skip and name the unprotected target: %q", result.Changes)
	}

	protect(true)
	result = h.run(Options{Action: ActionRotateCredentials})
	requireError(t, result, codeRotation)
	if h.committedKey() != keyB || !strings.Contains(result.Errors[0].Message, "hold a per-user credential failed their reconcile: devin for user carol") {
		t.Fatalf("a failed target that holds a credential did not stop the rotation: %+v", result.Errors)
	}

	// The lookup no longer finds carol, but the guardian still resolves
	// her (a directory account the lookup does not see), so she still
	// holds a credential; once the guardian cannot resolve her either,
	// her account is gone.
	delete(h.accounts.accounts, "carol")
	requireError(t, h.run(Options{Action: ActionRotateCredentials}), codeRotation)
	h.failed[0].UID = -1
	requireOK(t, h.run(Options{Action: ActionRotateCredentials}))
	if h.committedKey() == keyB {
		t.Fatal("the target of an account that no longer exists blocked the rotation")
	}
}

// An interrupt (Ctrl+C) rolls the rotation back before the run ends, so one
// key stays accepted. status reports a rotation that was killed instead.
// The next lifecycle run rolls back one killed before its commit and
// completes one killed after the rename, and an uninstall removes the
// staged key.
func TestInterruptedRotationIsSettledByTheNextRun(t *testing.T) {
	h := newRotationHost(t)
	idA := connector.UserScopedTokenKeyFingerprint(h.keyA)
	ctx, cancel := context.WithCancel(context.Background())
	h.onProof = cancel
	result := Run(ctx, h.env, Options{Action: ActionRotateCredentials})
	h.onProof = nil
	requireError(t, result, codeRotation)
	// GAP-0513: the interrupt is the cause, and the rollback is named.
	if got := messagesOf(result.Errors, codeRotation); !strings.Contains(got, "the run was interrupted; it was rolled back and key ") || strings.Contains(got, "exit -1") {
		t.Fatalf("interrupted rotation error = %q", got)
	}
	h.requireNoRotationLeft()
	if h.committedKey() != h.keyA || h.rendered["alice"] != idA || !slices.Equal(h.liveKeyIDs(), []string{idA}) || slices.Contains(h.events, "refused alice") {
		t.Fatalf("an interrupted rotation did not settle on key A: users=%v events=%v", h.rendered, h.events)
	}

	keyB := strings.Repeat("b2", 32)
	idB := connector.UserScopedTokenKeyFingerprint(keyB)
	interrupt := func() {
		intent := rotationIntent{SchemaVersion: rotationSchemaVersion, OperationID: strings.Repeat("0", 32), PreviousKeyID: idA, NextKeyID: idB}
		if err := h.env.saveRotationIntent(intent); err != nil {
			t.Fatal(err)
		}
		if err := h.env.saveTransaction(intent, enterprisehooks.CredentialPhasePrepare, strings.Repeat("d", 64)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.stagedUserKeyPath(), []byte(keyB+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		h.reconcile() // the guardian had moved both users
	}
	interrupt()
	if status := h.run(Options{Action: ActionStatus}); !hasWarning(status, codeRotationIncomplete) {
		t.Fatalf("status does not report the unfinished rotation: %+v", status.Warnings)
	}
	result = h.run(Options{Action: ActionReconcile})
	requireOK(t, result)
	h.requireNoRotationLeft()
	if !hasWarning(result, codeRotationRecovered) || h.committedKey() != h.keyA || h.rendered["alice"] != idA || slices.Contains(h.events, "refused alice") {
		t.Fatalf("an uncommitted rotation was not rolled back: warnings=%+v users=%v", result.Warnings, h.rendered)
	}

	interrupt()
	if err := os.Rename(h.env.stagedUserKeyPath(), h.env.committedUserKeyPath()); err != nil {
		t.Fatal(err)
	}
	result = h.run(Options{Action: ActionReconcile})
	requireOK(t, result)
	h.requireNoRotationLeft()
	if !hasWarning(result, codeRotationRecovered) || h.committedKey() != keyB {
		t.Fatalf("a committed rotation was not completed: warnings=%+v", result.Warnings)
	}

	interrupt()
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	h.requireNoRotationLeft()
}

// A rotation takes a reconcile as proof only when it ran under the
// rotation's own operation and phase, attests each credential the key
// derives for that account, and names the account the rotation began with.
func TestOnKeyTakesOnlyThisPhasesBoundProof(t *testing.T) {
	key, manifest := strings.Repeat("a1", 32), strings.Repeat("d", 64)
	attest := func(uid, credentialUID int) enterprisehooks.CredentialAttestation {
		credential, err := connector.UserScopedHookAPIToken(key, "codex", fmt.Sprint(credentialUID))
		if err != nil {
			t.Fatal(err)
		}
		return enterprisehooks.CredentialAttestation{
			Version: enterprisehooks.CredentialAttestationVersion, ManifestSHA256: manifest,
			KeyID: connector.UserScopedTokenKeyFingerprint(key), OperationID: "op1", Phase: enterprisehooks.CredentialPhaseRollback,
			Targets: []enterprisehooks.CredentialAttestationTarget{{
				Connector: "codex", User: "alice", UID: uid, State: enterprisehooks.CredentialTargetCurrent,
				Credentials: true, Verified: true, CredentialID: connector.UserScopedCredentialKeyID(credential),
			}},
		}
	}
	want := credentialTargets(attest(1001, 1001))
	if done, fatal := onKey(attest(1001, 1001), key, "op1", enterprisehooks.CredentialPhaseRollback, manifest, want); !done || fatal != "" {
		t.Fatalf("bound proof refused: done=%v fatal=%q", done, fatal)
	}
	prepare, other := attest(1001, 1001), attest(1001, 1001)
	prepare.Phase, other.OperationID = enterprisehooks.CredentialPhasePrepare, "op2"
	for name, attestation := range map[string]enterprisehooks.CredentialAttestation{
		"prepare phase":        prepare,
		"other operation":      other,
		"unbound credential":   attest(1001, 1002),
		"moved to another uid": attest(1002, 1002),
	} {
		if done, fatal := onKey(attestation, key, "op1", enterprisehooks.CredentialPhaseRollback, manifest, want); done || fatal == "" {
			t.Errorf("%s: accepted as proof (done=%v)", name, done)
		}
	}
}

// On a healthy macOS host whose users run only hook-based agents no user
// holds a credential, and rotate-credentials failed rotation_failed (GAP-0541).
func TestRotateCredentialsWithoutAKeyIsANoop(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	r := h.run(Options{Action: ActionRotateCredentials})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != NoopNoCredentials {
		t.Fatalf("rotation without a key: noop=%v reason=%q", r.Noop, r.NoopReason)
	}
}
