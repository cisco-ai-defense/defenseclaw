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
	events     []string
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

func (h *rotationHost) liveKeys() []string {
	var keys []string
	for _, path := range []string{h.env.committedUserKeyPath(), h.env.stagedUserKeyPath()} {
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

// reconcile renders both users from the current key, as the guardian does:
// a user already on it is verified, anyone else is repaired.
func (h *rotationHost) reconcile() {
	keys := h.liveKeys()
	keyID := connector.UserScopedTokenKeyFingerprint(keys[len(keys)-1])
	attestation := enterprisehooks.CredentialAttestation{
		Version: enterprisehooks.CredentialAttestationVersion, ID: fmt.Sprintf("%032x", len(h.events)+1),
		UpdatedAt: "2026-09-29T00:00:00Z", ManifestSHA256: strings.Repeat("d", 64), KeyID: keyID,
		Targets: []enterprisehooks.CredentialAttestationTarget{},
	}
	for index, user := range []string{"alice", "bob"} {
		target := enterprisehooks.CredentialAttestationTarget{Connector: "codex", User: user, UID: 1001 + index, State: enterprisehooks.CredentialTargetCurrent}
		switch {
		case user == "bob" && h.failStaged && len(keys) == 2:
			target.State, target.UID = enterprisehooks.CredentialTargetFailed, -1
		case h.rendered[user] == keyID:
			target.Credentials, target.Verified = true, true
		default:
			h.rendered[user] = keyID
			target.Credentials = true
			h.events = append(h.events, "rendered "+keyID)
		}
		attestation.Targets = append(attestation.Targets, target)
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
	for _, path := range []string{h.env.stagedUserKeyPath(), h.env.rotationIntentPath()} {
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
	requireOK(t, h.run(Options{Action: ActionRotateCredentials}))
	keyB := h.committedKey()
	idB := connector.UserScopedTokenKeyFingerprint(keyB)
	h.requireNoRotationLeft()
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

	h = newRotationHost(t)
	h.failStaged = true
	result := h.run(Options{Action: ActionRotateCredentials})
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
}

// status reports a rotation that did not finish. The next lifecycle run
// rolls back one interrupted before its commit and completes one
// interrupted after the rename.
func TestInterruptedRotationIsSettledByTheNextRun(t *testing.T) {
	h := newRotationHost(t)
	idA := connector.UserScopedTokenKeyFingerprint(h.keyA)
	keyB := strings.Repeat("b2", 32)
	idB := connector.UserScopedTokenKeyFingerprint(keyB)
	interrupt := func() {
		if err := h.env.saveRotationIntent(rotationIntent{SchemaVersion: rotationSchemaVersion, OperationID: strings.Repeat("0", 32), PreviousKeyID: idA, NextKeyID: idB}); err != nil {
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
	result := h.run(Options{Action: ActionReconcile})
	requireOK(t, result)
	h.requireNoRotationLeft()
	if !hasWarning(result, codeRotationRecovered) || h.committedKey() != h.keyA || h.rendered["alice"] != idA {
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
}
