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
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Credential rotation (rotate-credentials).
//
// Each enrolled user's agent telemetry and in-agent plugins authenticate
// with credentials derived from one per-machine key and bound to the user's
// uid (connector.UserScopedHookAPIToken); hooks use the peer-authorized hook
// socket and hold no credential. Rotating the key is one transaction over
// two participants, the gateway and the hook guardian, with one commit
// point:
//
//  1. Preflight, before anything changes: the deployment is installed, the
//     committed key A is present and trusted, the gateway reports exactly A
//     live, and a fresh guardian reconcile attests every enabled target
//     current on A with no failed target.
//  2. Stage: record the intent in the root-only lifecycle directory, then
//     write key B beside A (connector.PendingUserScopedTokenKeyPath) under
//     the guardian's reconcile lock. The gateway now accepts the credentials
//     of both keys. The rotation waits until /health names A and B and has
//     the gateway prove, for every user, that it accepts that user's B
//     credential, before any user is moved.
//  3. Prepare: the guardian renders every target from B, and a further
//     reconcile verifies the installed hooks. Every target must be attested
//     current, verified and on B in the same roster (manifest digest), and
//     the gateway must prove B again for each user.
//  4. Commit: rename B over A under the reconcile lock, wait until /health
//     names only B (A's credentials are refused from then on), clear the
//     intent.
//
// A failure before the commit removes B, waits until only A is live and
// reconciles every user back to A. Credentials derive from the key, so
// restoring A restores each user's A credentials exactly. A run that is
// interrupted is settled by the next lifecycle run
// (recoverInterruptedRotation): the rename is the commit point, so a
// committed key equal to B completes the rotation and anything else restores
// A. Keys leave this process only as files with the committed key's custody,
// and results name them only by fingerprint.

// ActionRotateCredentials rotates the per-user credential key.
const ActionRotateCredentials = "rotate-credentials"

const (
	codeRotation           = "rotation_failed"
	codeRotationRecovered  = "rotation_recovered"
	codeRotationIncomplete = "rotation_incomplete"

	rotationFileName      = "credential-rotation.json"
	rotationSchemaVersion = 1
	// rotationAttempts bounds the reconciles that render and then verify a
	// key (and that move users back to A on a rollback).
	rotationAttempts = 3
	// rotationRollbackTimeout bounds a rollback that runs after the run's
	// own context was cancelled.
	rotationRollbackTimeout = 5 * time.Minute
	userKeyMaxBytes         = 4096
)

// rotationIntent is the root-only record of an uncommitted rotation.
type rotationIntent struct {
	SchemaVersion int    `json:"schema_version"`
	OperationID   string `json:"operation_id"`
	StartedAt     string `json:"started_at"`
	PreviousKeyID string `json:"previous_key_id"`
	NextKeyID     string `json:"next_key_id"`
}

func shortKeyID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func (e *Env) rotationIntentPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), rotationFileName)
}

func (e *Env) committedUserKeyPath() string {
	path, _ := connector.UserScopedTokenKeyPath(e.P(e.Layout.DataDir))
	return path
}

func (e *Env) stagedUserKeyPath() string {
	path, _ := connector.PendingUserScopedTokenKeyPath(e.P(e.Layout.DataDir))
	return path
}

func (e *Env) attestationPath() string {
	return filepath.Join(e.P(e.Layout.GuardianAuthDir), managed.HookGuardianCredentialAttestationFile)
}

func (e *Env) loadRotationIntent() (*rotationIntent, error) {
	data, err := readBounded(e.rotationIntentPath(), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var intent rotationIntent
	if err := json.Unmarshal(data, &intent); err != nil || intent.SchemaVersion != rotationSchemaVersion {
		return nil, fmt.Errorf("the credential rotation record %s is not valid", e.rotationIntentPath())
	}
	return &intent, nil
}

func (e *Env) saveRotationIntent(intent rotationIntent) error {
	data, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.rotationIntentPath(), append(data, '\n'), 0o600, rootOwner())
}

func (e *Env) clearRotationIntent() error {
	err := removeFile(e.rotationIntentPath())
	syncDir(e.P(e.Layout.LifecycleDir))
	return err
}

// readUserKey reads a per-user credential key file with the custody the
// gateway requires: a regular 0600 file of the service account (or root)
// holding 64 lowercase hex characters. present is false when it is absent.
func (e *Env) readUserKey(path string, serviceUID int) (key string, present bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", true, fmt.Errorf("%s is not a regular 0600 file", path)
	}
	if uid, _, err := e.OwnerOf(path); err != nil || (uid != serviceUID && uid != 0) {
		return "", true, fmt.Errorf("%s is not owned by the %s service account", path, e.Layout.ServiceUser)
	}
	data, err := readBounded(path, userKeyMaxBytes)
	if err != nil {
		return "", true, err
	}
	key = strings.TrimSpace(string(data))
	if !lowerHexKey(key) {
		return "", true, fmt.Errorf("%s does not hold a 64-character lowercase hex key", path)
	}
	return key, true, nil
}

func lowerHexKey(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// withReconcileLock runs fn holding the hook guardian's reconcile lock, so
// no reconcile renders targets while a key is staged, committed or removed.
func (e *Env) withReconcileLock(ctx context.Context, fn func() error) error {
	path := filepath.Join(e.P(e.Layout.GuardianAuthDir), managed.HookGuardianReconcileLockFile)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open the hook guardian reconcile lock: %w", err)
	}
	defer file.Close()
	deadline := e.Now().Add(e.ReadyTimeout)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("lock the hook guardian reconcile lock: %w", err)
		}
		if !e.Now().Before(deadline) {
			return fmt.Errorf("a hook guardian reconcile held its lock for more than %s", e.ReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.PollInterval):
		}
	}
	defer func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// removeStagedKey removes a staged key (a no-op when there is none).
func (e *Env) removeStagedKey() error {
	err := removeFile(e.stagedUserKeyPath())
	syncDir(filepath.Dir(e.stagedUserKeyPath()))
	return err
}

// readAttestation reads the guardian's last credential attestation.
func (e *Env) readAttestation() (enterprisehooks.CredentialAttestation, error) {
	path := e.attestationPath()
	if err := e.Trust(path, TrustAdminFile); err != nil {
		return enterprisehooks.CredentialAttestation{}, err
	}
	data, err := readBounded(path, enterprisehooks.CredentialAttestationMaxBytes)
	if err != nil {
		return enterprisehooks.CredentialAttestation{}, err
	}
	return enterprisehooks.ParseCredentialAttestation(data)
}

func (e *Env) attestationID() string {
	attestation, err := e.readAttestation()
	if err != nil {
		return ""
	}
	return attestation.ID
}

// triggerGuardianReconcile runs one guardian reconcile to completion. Its
// exit status is not the answer (it exits 1 for a failed target); the
// attestation it publishes is.
func (l *lifecycle) triggerGuardianReconcile(ctx context.Context) error {
	env := l.env
	if env.GOOS == "linux" {
		err := env.Services.Start(ctx, Unit{Name: unitGuardianOneshot})
		if err != nil {
			_, _ = env.Runner.Run(ctx, "systemctl", "reset-failed", unitGuardianOneshot)
		}
		return err
	}
	_, err := env.runGatewayCLI(ctx, "enterprise", "hooks", "reconcile", "--manifest", env.Layout.ManifestPath, "--json")
	return err
}

// freshAttestation runs a reconcile and returns the attestation it
// published, refusing the one read before (previousID).
func (l *lifecycle) freshAttestation(ctx context.Context, previousID string) (enterprisehooks.CredentialAttestation, error) {
	runErr := l.triggerGuardianReconcile(ctx)
	attestation, err := l.env.readAttestation()
	if err == nil && attestation.ID != previousID {
		return attestation, nil
	}
	reason := "the hook guardian did not publish a new credential attestation"
	if err != nil {
		reason += " (" + err.Error() + ")"
	}
	if runErr != nil {
		reason += "; its reconcile failed: " + runErr.Error()
	}
	return enterprisehooks.CredentialAttestation{}, errors.New(reason)
}

// credentialTargets are the targets whose hooks carry per-user
// credentials, keyed by CredentialAttestationTarget.Key.
func credentialTargets(attestation enterprisehooks.CredentialAttestation) map[string]enterprisehooks.CredentialAttestationTarget {
	out := map[string]enterprisehooks.CredentialAttestationTarget{}
	for _, target := range attestation.Targets {
		if target.Credentials {
			out[target.Key()] = target
		}
	}
	return out
}

func failedTargets(attestation enterprisehooks.CredentialAttestation) []string {
	var labels []string
	for _, target := range attestation.Targets {
		if target.State == enterprisehooks.CredentialTargetFailed {
			labels = append(labels, target.Label())
		}
	}
	return labels
}

func listLabels(labels []string) string {
	const shown = 5
	if len(labels) > shown {
		return strings.Join(labels[:shown], ", ") + fmt.Sprintf(" and %d more", len(labels)-shown)
	}
	return strings.Join(labels, ", ")
}

// onKey reports whether attestation shows every target of want current and
// verified on keyID, and every other credential-bearing target verified
// too. fatal is set for a state no further reconcile fixes.
func onKey(attestation enterprisehooks.CredentialAttestation, keyID, manifestSHA256 string, want map[string]enterprisehooks.CredentialAttestationTarget) (done bool, fatal string) {
	switch {
	case attestation.ManifestSHA256 != manifestSHA256:
		return false, "the guardian's target roster changed during the rotation (targets.yaml was rewritten)"
	case attestation.KeyID != keyID:
		return false, fmt.Sprintf("the guardian rendered from key %s, not %s", shortKeyID(attestation.KeyID), shortKeyID(keyID))
	}
	if failed := failedTargets(attestation); len(failed) > 0 {
		return false, fmt.Sprintf("%d guardian target(s) failed: %s", len(failed), listLabels(failed))
	}
	have := credentialTargets(attestation)
	var missing []string
	for key, target := range want {
		if _, ok := have[key]; !ok {
			missing = append(missing, target.Label())
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return false, fmt.Sprintf("%d target(s) no longer carry credentials: %s", len(missing), listLabels(missing))
	}
	for _, target := range have {
		if !target.Verified {
			return false, ""
		}
	}
	return true, ""
}

// gatewayKeyIDs reads the key fingerprints the gateway accepts right now.
func (l *lifecycle) gatewayKeyIDs(ctx context.Context, gateway Unit, serviceUID int) ([]string, error) {
	body, err := l.gatewayHealth(ctx, gateway, serviceUID)
	if err != nil {
		return nil, err
	}
	var document struct {
		UserScoped *struct {
			KeyIDs []string `json:"key_ids"`
		} `json:"user_scoped_credentials"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("gateway health: %w", err)
	}
	if document.UserScoped == nil {
		return nil, errors.New("the running gateway does not report its per-user credential keys; it predates credential rotation, so run repair first")
	}
	return document.UserScoped.KeyIDs, nil
}

// waitGatewayKeys waits until the gateway accepts exactly want.
func (l *lifecycle) waitGatewayKeys(ctx context.Context, gateway Unit, serviceUID int, want []string) error {
	env := l.env
	deadline := env.Now().Add(env.ReadyTimeout)
	for {
		ids, err := l.gatewayKeyIDs(ctx, gateway, serviceUID)
		if err == nil && slices.Equal(ids, want) {
			return nil
		}
		if !env.Now().Before(deadline) {
			if err != nil {
				return err
			}
			short := make([]string, 0, len(ids))
			for _, id := range ids {
				short = append(short, shortKeyID(id))
			}
			return fmt.Errorf("the gateway accepts keys [%s] after %s", strings.Join(short, " "), env.ReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(env.PollInterval):
		}
	}
}

// proveKey has the gateway prove, for every target, that it accepts the
// target's hook credential derived from key: the listener proof the
// standalone plugins use, which names the credential only by its SHA-256.
func (l *lifecycle) proveKey(ctx context.Context, key string, targets map[string]enterprisehooks.CredentialAttestationTarget) error {
	var refused []string
	for _, target := range targets {
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		credential, err := connector.UserScopedHookAPIToken(key, name, strconv.Itoa(target.UID))
		if err != nil {
			return err
		}
		nonce, err := randomHex(32)
		if err != nil {
			return err
		}
		want, err := connector.UserScopedListenerProof(credential, name, nonce)
		if err != nil {
			return err
		}
		got, err := l.env.ListenerProof(ctx, name, connector.UserScopedCredentialKeyID(credential), nonce)
		if err != nil || !hmac.Equal([]byte(got), []byte(want)) {
			refused = append(refused, target.Label())
		}
	}
	if len(refused) > 0 {
		slices.Sort(refused)
		return fmt.Errorf("the gateway does not accept the credentials of %d target(s): %s", len(refused), listLabels(refused))
	}
	return nil
}

// listenerProof asks the gateway's loopback API for a listener proof.
func listenerProof(ctx context.Context, addr, connectorName, keyID, nonce string) (string, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+connector.UserScopedListenerProofPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-DefenseClaw-Connector", connectorName)
	req.Header.Set(connector.UserScopedListenerKeyIDHeader, keyID)
	req.Header.Set(connector.UserScopedListenerNonceHeader, nonce)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("listener proof answered HTTP %d", resp.StatusCode)
	}
	return resp.Header.Get(connector.UserScopedListenerProofHeader), nil
}

func (l *lifecycle) gatewayUnit() (Unit, bool) {
	for _, unit := range l.env.Services.Units() {
		if unit.Kind == "gateway" {
			return unit, true
		}
	}
	return Unit{}, false
}

// rotateCredentials is the rotate-credentials action.
func (l *lifecycle) rotateCredentials(ctx context.Context, record *Deployment) int {
	env, r := l.env, l.result
	if record == nil {
		r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed")
		return 0
	}
	defer l.describe(ctx, record, false)
	refuse := func(format string, args ...any) int {
		r.AddError(codeRotation, fmt.Sprintf(format, args...)+"; nothing was changed")
		return 0
	}
	gateway, ok := l.gatewayUnit()
	if !ok {
		return refuse("the deployment has no gateway service")
	}
	keyA, present, err := env.readUserKey(env.committedUserKeyPath(), record.ServiceUID)
	switch {
	case err != nil:
		return refuse("the per-user credential key is not trusted: %v", err)
	case !present:
		return refuse("there is no per-user credential key to rotate yet; the hook guardian creates it when it enrolls the first user")
	}
	if exists(env.stagedUserKeyPath()) {
		// No rotation owns it (recoverInterruptedRotation settled any
		// recorded one), so nothing authorized it: remove it.
		if err := env.withReconcileLock(ctx, env.removeStagedKey); err != nil {
			return refuse("an unrecorded staged key could not be removed: %v", err)
		}
		r.AddWarning(codeRotationRecovered, "removed a staged per-user credential key that no rotation recorded")
	}
	idA := connector.UserScopedTokenKeyFingerprint(keyA)
	if err := l.waitGatewayKeys(ctx, gateway, record.ServiceUID, []string{idA}); err != nil {
		return refuse("the gateway is not serving the committed per-user credential key alone: %v", err)
	}
	preflight, err := l.freshAttestation(ctx, env.attestationID())
	if err != nil {
		return refuse("%v", err)
	}
	if preflight.KeyID != idA {
		return refuse("the hook guardian rendered from key %s, not the committed key %s", shortKeyID(preflight.KeyID), shortKeyID(idA))
	}
	if failed := failedTargets(preflight); len(failed) > 0 {
		return refuse("%d guardian target(s) failed their reconcile: %s. Fix or disable them (see `enterprise %s status`), then rotate again",
			len(failed), listLabels(failed), platformName(env.GOOS))
	}
	selected := credentialTargets(preflight)

	keyB, err := randomHex(32)
	if err != nil || keyB == keyA {
		return refuse("could not generate a new key")
	}
	idB := connector.UserScopedTokenKeyFingerprint(keyB)
	operation, err := randomHex(16)
	if err != nil {
		return refuse("could not generate an operation ID")
	}
	intent := rotationIntent{
		SchemaVersion: rotationSchemaVersion,
		OperationID:   operation,
		StartedAt:     env.Now().UTC().Format(time.RFC3339),
		PreviousKeyID: idA,
		NextKeyID:     idB,
	}
	if err := env.saveRotationIntent(intent); err != nil {
		return refuse("record the rotation: %v", err)
	}

	prepareErr := func() error {
		lastID := ""
		if err := env.withReconcileLock(ctx, func() error {
			owner := fileOwner{UID: record.ServiceUID, GID: record.ServiceGID}
			if err := env.writeFileAtomic(env.stagedUserKeyPath(), []byte(keyB+"\n"), 0o600, owner); err != nil {
				return err
			}
			lastID = env.attestationID()
			return nil
		}); err != nil {
			return fmt.Errorf("stage the new key: %w", err)
		}
		if err := l.waitGatewayKeys(ctx, gateway, record.ServiceUID, []string{idA, idB}); err != nil {
			return fmt.Errorf("the gateway did not start accepting the new key: %w", err)
		}
		if err := l.proveKey(ctx, keyB, selected); err != nil {
			return err
		}
		for attempt := 1; ; attempt++ {
			attestation, err := l.freshAttestation(ctx, lastID)
			if err != nil {
				return err
			}
			lastID = attestation.ID
			done, fatal := onKey(attestation, idB, preflight.ManifestSHA256, selected)
			switch {
			case fatal != "":
				return errors.New(fatal)
			case done:
				return l.proveKey(ctx, keyB, credentialTargets(attestation))
			case attempt == rotationAttempts:
				return fmt.Errorf("the hook guardian did not verify every target on the new key after %d reconciles", attempt)
			}
		}
	}()
	if prepareErr != nil {
		r.AddError(codeRotation, fmt.Sprintf("rotation %s did not commit: %v; key %s stays in use", operation, prepareErr, shortKeyID(idA)))
		if err := l.abortRotation(ctx, gateway, record, keyA, selected, preflight.ManifestSHA256); err != nil {
			r.AddError(codeRollbackFailed, err.Error())
		}
		return 0
	}

	if err := env.withReconcileLock(ctx, func() error {
		staged, present, err := env.readUserKey(env.stagedUserKeyPath(), record.ServiceUID)
		if err != nil || !present || staged != keyB {
			return errors.New("the staged key changed before the commit")
		}
		committed := env.committedUserKeyPath()
		if err := os.Rename(env.stagedUserKeyPath(), committed); err != nil {
			return err
		}
		syncDir(filepath.Dir(committed))
		return nil
	}); err != nil {
		r.AddError(codeRotation, fmt.Sprintf("rotation %s did not commit: %v; key %s stays in use", operation, err, shortKeyID(idA)))
		if err := l.abortRotation(ctx, gateway, record, keyA, selected, preflight.ManifestSHA256); err != nil {
			r.AddError(codeRollbackFailed, err.Error())
		}
		return 0
	}
	// Committed: from here on the only way forward is B.
	if err := l.waitGatewayKeys(ctx, gateway, record.ServiceUID, []string{idB}); err != nil {
		r.AddError(codeRotation, fmt.Sprintf("rotation %s committed key %s, but the gateway has not retired key %s: %v; run verify", operation, shortKeyID(idB), shortKeyID(idA), err))
	}
	if err := env.clearRotationIntent(); err != nil {
		r.AddWarning(codeRotationIncomplete, "the completed rotation's record could not be removed: "+err.Error())
	}
	return 0
}

// abortRotation restores key A: it removes the staged key, waits until the
// gateway accepts only A and reconciles every user back to A.
func (l *lifecycle) abortRotation(ctx context.Context, gateway Unit, record *Deployment, keyA string, selected map[string]enterprisehooks.CredentialAttestationTarget, manifestSHA256 string) error {
	env := l.env
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rotationRollbackTimeout)
	defer cancel()
	if err := env.withReconcileLock(ctx, env.removeStagedKey); err != nil {
		return fmt.Errorf("the new key could not be removed (%v); the next lifecycle run retries the rollback", err)
	}
	var problems []string
	idA := connector.UserScopedTokenKeyFingerprint(keyA)
	if err := l.waitGatewayKeys(ctx, gateway, record.ServiceUID, []string{idA}); err != nil {
		problems = append(problems, err.Error())
	}
	restored := false
	lastID := env.attestationID()
	for attempt := 0; attempt < rotationAttempts && !restored; attempt++ {
		attestation, err := l.freshAttestation(ctx, lastID)
		if err != nil {
			problems = append(problems, err.Error())
			break
		}
		lastID = attestation.ID
		done, fatal := onKey(attestation, idA, manifestSHA256, selected)
		if fatal != "" {
			problems = append(problems, fatal)
			break
		}
		restored = done
	}
	if err := env.clearRotationIntent(); err != nil {
		problems = append(problems, "the rotation record could not be removed: "+err.Error())
	}
	if !restored {
		problems = append(problems, "not every user is back on the previous key yet; the hook guardian re-renders them on its next reconcile")
	}
	if len(problems) > 0 {
		return errors.New("rollback: " + strings.Join(problems, "; "))
	}
	return nil
}

// recoverInterruptedRotation settles a rotation an earlier run did not
// finish: completed when the committed key is the rotation's new key,
// otherwise rolled back to the previous key.
func (l *lifecycle) recoverInterruptedRotation(ctx context.Context, record *Deployment) {
	env, r := l.env, l.result
	intent, err := env.loadRotationIntent()
	if err == nil && intent == nil {
		return
	}
	committedID := ""
	if key, present, keyErr := env.readUserKey(env.committedUserKeyPath(), record.ServiceUID); keyErr == nil && present {
		committedID = connector.UserScopedTokenKeyFingerprint(key)
	}
	if err == nil && committedID != "" && committedID == intent.NextKeyID {
		if err := env.clearRotationIntent(); err != nil {
			r.AddWarning(codeRotationRecovered, "the completed rotation's record could not be removed: "+err.Error())
			return
		}
		r.AddWarning(codeRotationRecovered, fmt.Sprintf("completed an interrupted credential rotation that had committed key %s", shortKeyID(committedID)))
		return
	}
	if err := env.withReconcileLock(ctx, env.removeStagedKey); err != nil {
		r.AddWarning(codeRotationRecovered, fmt.Sprintf("an interrupted credential rotation could not be rolled back yet: %v", err))
		return
	}
	if err := env.clearRotationIntent(); err != nil {
		r.AddWarning(codeRotationRecovered, "the interrupted rotation's record could not be removed: "+err.Error())
		return
	}
	// Users the interrupted run had already moved go back to the committed
	// key on this reconcile.
	_ = l.triggerGuardianReconcile(ctx)
	kept := "the committed key"
	if committedID != "" {
		kept = "key " + shortKeyID(committedID)
	}
	r.AddWarning(codeRotationRecovered, "rolled back an interrupted credential rotation; "+kept+" stays in use")
}

func platformName(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return goos
}
