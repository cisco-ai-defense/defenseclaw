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
	"cmp"
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
//     live, and a fresh guardian reconcile attests every target that holds
//     a credential current on A. A target that is not current holds one
//     while the guardian's authorization ledger carries its last success
//     forward (the gateway accepts credentials for every target the ledger
//     protects), and then the rotation refuses. One that holds none (never
//     protected, for example an agent version without a verified hook
//     contract, or an account that no longer exists) is skipped and named:
//     the guardian renders it from whichever key is committed once it can
//     protect it.
//  2. Stage: record the intent in the root-only lifecycle directory, then,
//     under the guardian's reconcile lock, write the guardian's prepare
//     record (enterprisehooks.CredentialTransaction: operation, roster, A
//     and B by fingerprint) and key B beside A
//     (connector.PendingUserScopedTokenKeyPath). The guardian renders from
//     a staged key only while a prepare record names it. The gateway now
//     accepts the credentials of both keys. Still holding the lock, so no reconcile moves a user
//     yet, the rotation waits until /health names A and B and has the
//     gateway prove, for every user, that it accepts that user's B
//     credential.
//  3. Prepare: the guardian renders every target from B, and a further
//     reconcile verifies the installed hooks. Every target must be attested
//     current, verified and on B in the same roster (manifest digest), by a
//     reconcile that names this operation's prepare phase, each with the
//     credential B derives for its connector and uid; and the gateway must
//     prove B again for each user.
//  4. Commit: rename B over A under the reconcile lock and remove the
//     guardian's record, wait until /health names only B (A's credentials
//     are refused from then on), clear the intent.
//
// A failure before the commit turns the guardian's record to rollback and
// moves B aside as the retiring key (connector.RetiringUserScopedTokenKeyPath),
// which the gateway still accepts but the guardian no longer renders from,
// reconciles every user back to A (proved by rollback-phase attestations
// whose credentials A derives), then removes B and the record and waits
// until only A is live. Users already on
// B are therefore not refused while they move back. Credentials derive from
// the key, so restoring A restores each user's A credentials exactly. An
// interrupt (Ctrl+C, SIGTERM) cancels the run's context, which takes the
// same rollback. A run that is killed is settled by the next lifecycle run
// (recoverInterruptedRotation): the rename is the commit point, so a
// committed key equal to B completes the rotation and anything else restores
// A. Until then the gateway and the guardian honor a staged or retiring key
// only for connector.RotationKeyMaxAge, so a killed rotation stops widening
// the accepted keys on its own. Keys leave this process only as files with
// the committed key's custody, and results name them only by fingerprint.

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

func (e *Env) retiringUserKeyPath() string {
	path, _ := connector.RetiringUserScopedTokenKeyPath(e.P(e.Layout.DataDir))
	return path
}

func (e *Env) attestationPath() string {
	return filepath.Join(e.P(e.Layout.GuardianAuthDir), managed.HookGuardianCredentialAttestationFile)
}

func (e *Env) transactionPath() string {
	return filepath.Join(e.P(e.Layout.GuardianAuthDir), managed.HookGuardianCredentialTransactionFile)
}

// saveTransaction writes the guardian's root-only record of the rotation
// (enterprisehooks.CredentialTransaction). Call it under the reconcile lock.
func (e *Env) saveTransaction(intent rotationIntent, phase, manifestSHA256 string) error {
	data, err := json.MarshalIndent(enterprisehooks.CredentialTransaction{
		Version:        enterprisehooks.CredentialTransactionVersion,
		OperationID:    intent.OperationID,
		Phase:          phase,
		StartedAt:      intent.StartedAt,
		ManifestSHA256: manifestSHA256,
		PreviousKeyID:  intent.PreviousKeyID,
		NextKeyID:      intent.NextKeyID,
	}, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.transactionPath(), append(data, '\n'), 0o600, rootOwner())
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

// removeRotationKeys removes a staged and a retiring key and the
// guardian's transaction record (a no-op when there are none).
func (e *Env) removeRotationKeys() error {
	err := errors.Join(removeFile(e.stagedUserKeyPath()), removeFile(e.retiringUserKeyPath()))
	syncDir(filepath.Dir(e.stagedUserKeyPath()))
	if txErr := removeFile(e.transactionPath()); txErr != nil {
		err = errors.Join(err, txErr)
	}
	syncDir(filepath.Dir(e.transactionPath()))
	return err
}

// retireStagedKey moves a staged key aside as the retiring key: the gateway
// keeps accepting its credentials while the guardian renders from the
// committed key again. Without a staged key it is a no-op.
func (e *Env) retireStagedKey() error {
	err := os.Rename(e.stagedUserKeyPath(), e.retiringUserKeyPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
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

// attestationProblem checks the guardian's credential attestation against
// ledger, the authorization ledger bytes just read: it must be in the
// current format, from the reconcile that published them, for the current
// targets.yaml, list each target it enables exactly once, and bind every
// credential-bearing target to the credential a key the gateway holds
// derives for it. torn is set when it is from another reconcile or another
// roster, which a read between the guardian's writes (or between the
// enumerator's rewrite and the guardian's next reconcile) also sees.
func (e *Env) attestationProblem(ledger []byte) (problem string, torn bool) {
	if _, err := os.Lstat(e.attestationPath()); errors.Is(err, os.ErrNotExist) {
		return "the hook guardian has not published its credential attestation yet", false
	}
	attestation, err := e.readAttestation()
	if err != nil {
		return "guardian credential attestation: " + err.Error(), false
	}
	if !attestation.Current() {
		return fmt.Sprintf("the hook guardian's credential attestation is in the older format %d, which does not bind each target; the next guardian reconcile rewrites it", attestation.Version), false
	}
	if !attestation.BoundTo(ledger) {
		return "the hook guardian's authorization ledger does not match its last credential attestation; the next guardian reconcile publishes both", true
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(e.P(e.Layout.ManifestPath))
	if err != nil {
		return "guardian targets: " + err.Error(), false
	}
	if attestation.ManifestSHA256 != manifestSHA256 {
		return "the hook guardian has not reconciled the current targets.yaml yet; its next reconcile does", true
	}
	if problem := rosterProblem(manifest, attestation); problem != "" {
		return problem, false
	}
	if attestation.KeyID == "" {
		return "", false
	}
	for _, path := range []string{e.committedUserKeyPath(), e.stagedUserKeyPath()} {
		data, err := readBounded(path, userKeyMaxBytes)
		if key := strings.TrimSpace(string(data)); err == nil && connector.UserScopedTokenKeyFingerprint(key) == attestation.KeyID {
			if unbound := unboundCredentials(attestation, key); len(unbound) > 0 {
				return fmt.Sprintf("the hook guardian attested %d target(s) whose credentials are not the ones key %s derives for their account: %s; the next guardian reconcile renders them again",
					len(unbound), shortKeyID(attestation.KeyID), listLabels(unbound)), false
			}
			return "", false
		}
	}
	return fmt.Sprintf("the hook guardian's last reconcile rendered per-user credentials from key %s, which the gateway no longer holds; the next guardian reconcile renders them again", shortKeyID(attestation.KeyID)), false
}

// rosterProblem checks that attestation has exactly one row per target
// manifest enables, in manifest order (the guardian writes one row per
// enabled target), each naming that target's connector and account.
func rosterProblem(manifest enterprisehooks.Manifest, attestation enterprisehooks.CredentialAttestation) string {
	var enabled []enterprisehooks.ManifestTarget
	for _, target := range manifest.Targets {
		if target.IsEnabled() {
			enabled = append(enabled, target)
		}
	}
	if len(enabled) != len(attestation.Targets) {
		return fmt.Sprintf("the hook guardian's credential attestation lists %d target(s), but targets.yaml enables %d; the next guardian reconcile publishes it again", len(attestation.Targets), len(enabled))
	}
	for index, want := range enabled {
		got := attestation.Targets[index]
		sameHome := strings.TrimSpace(want.UserHome) == "" || filepath.Clean(strings.TrimSpace(want.UserHome)) == filepath.Clean(got.UserHome)
		sameUID := want.UID == nil || got.UID < 0 || *want.UID == got.UID
		if !strings.EqualFold(strings.TrimSpace(want.Connector), strings.TrimSpace(got.Connector)) ||
			strings.TrimSpace(want.User) != got.User || !sameHome || !sameUID {
			return fmt.Sprintf("the hook guardian's credential attestation names %s where targets.yaml enables another target; the next guardian reconcile publishes it again", got.Label())
		}
	}
	return ""
}

// unboundCredentials lists the credential-bearing targets of attestation
// whose credential fingerprint is not that of the hook credential key
// derives for the target's connector and uid.
func unboundCredentials(attestation enterprisehooks.CredentialAttestation, key string) []string {
	var unbound []string
	for _, target := range attestation.Targets {
		if !target.Credentials {
			continue
		}
		credential, err := connector.UserScopedHookAPIToken(key, strings.ToLower(strings.TrimSpace(target.Connector)), strconv.Itoa(target.UID))
		if err != nil || connector.UserScopedCredentialKeyID(credential) != target.CredentialID {
			unbound = append(unbound, target.Label())
		}
	}
	slices.Sort(unbound)
	return unbound
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

// targetsNotMoved sorts the targets of attestation that are not current
// (failed or pending), which the rotation cannot move, into those that
// still hold a per-user credential and those that hold none. A target holds
// one while the guardian's authorization ledger carries its last success
// forward: the gateway accepts the credentials of every target the ledger
// protects, and the target's files keep the ones an earlier reconcile
// rendered. One whose account no longer exists (the guardian resolved no
// account, and the account lookup answers that there is none) holds none
// that anyone can use; the commit retires them with the old key. err is set
// when the ledger cannot be read, so which of them hold a credential is
// unknown.
func (l *lifecycle) targetsNotMoved(ctx context.Context, attestation enterprisehooks.CredentialAttestation) (held, skipped []string, err error) {
	var protected map[string]bool
	for _, target := range attestation.Targets {
		if target.State == enterprisehooks.CredentialTargetCurrent {
			continue
		}
		if protected == nil {
			if protected, err = l.env.ledgerProtectedTargets(); err != nil {
				return nil, nil, err
			}
		}
		// The lookup alone does not prove an account gone: it does not see
		// every directory account the guardian resolves (dscl reads only
		// the local node on macOS), so the guardian must have resolved none.
		if protected[protectedTargetKey(target.Connector, target.User, target.UserHome)] && (target.UID >= 0 || !l.accountAbsent(ctx, target.User)) {
			held = append(held, target.Label())
		} else {
			skipped = append(skipped, target.Label())
		}
	}
	slices.Sort(held)
	slices.Sort(skipped)
	return held, skipped, nil
}

// ledgerProtectedTargets reads the protected targets of the guardian's
// authorization ledger, keyed by protectedTargetKey.
func (e *Env) ledgerProtectedTargets() (map[string]bool, error) {
	path := filepath.Join(e.P(e.Layout.GuardianAuthDir), managed.HookGuardianAuthorizationFile)
	if err := e.Trust(path, TrustAdminFile); err != nil {
		return nil, err
	}
	data, err := readBounded(path, 4<<20)
	if err != nil {
		return nil, err
	}
	type identity struct {
		Connector string `json:"connector"`
		User      string `json:"user"`
		UserHome  string `json:"user_home"`
	}
	var ledger struct {
		Targets []struct {
			identity
			OK     bool      `json:"ok"`
			Result *identity `json:"result"`
		} `json:"protected_targets"`
	}
	if err := json.Unmarshal(data, &ledger); err != nil {
		return nil, fmt.Errorf("the hook guardian authorization ledger %s is not valid: %w", path, err)
	}
	protected := map[string]bool{}
	for _, target := range ledger.Targets {
		if !target.OK {
			continue
		}
		// The guardian keys a row by these, falling back to its result.
		name, home := strings.TrimSpace(target.Connector), strings.TrimSpace(target.UserHome)
		if target.Result != nil {
			name = cmp.Or(name, target.Result.Connector)
			home = cmp.Or(home, target.Result.UserHome)
		}
		protected[protectedTargetKey(name, target.User, home)] = true
	}
	return protected, nil
}

// protectedTargetKey is the guardian's key for a protected target: the
// connector and the account name, or the home for a target named by home.
func protectedTargetKey(connectorName, user, home string) string {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if user = strings.TrimSpace(user); user != "" {
		return name + "\x00user\x00" + user
	}
	return name + "\x00home\x00" + filepath.Clean(strings.TrimSpace(home))
}

func listLabels(labels []string) string {
	const shown = 5
	if len(labels) > shown {
		return strings.Join(labels[:shown], ", ") + fmt.Sprintf(" and %d more", len(labels)-shown)
	}
	return strings.Join(labels, ", ")
}

// onKey reports whether attestation, from a reconcile that acted under
// phase of operation, shows every target of want current and verified on
// key, each with the credential key derives for its connector and uid, and
// every other credential-bearing target verified too. fatal is set for a
// state no further reconcile fixes. A target outside want that is not
// current held no credential when the rotation began (targetsNotMoved), so
// it does not stop the rotation.
func onKey(attestation enterprisehooks.CredentialAttestation, key, operation, phase, manifestSHA256 string, want map[string]enterprisehooks.CredentialAttestationTarget) (done bool, fatal string) {
	keyID := connector.UserScopedTokenKeyFingerprint(key)
	switch {
	case !attestation.Current():
		return false, fmt.Sprintf("the hook guardian published a format %d credential attestation, which does not bind each target", attestation.Version)
	case attestation.OperationID != operation || attestation.Phase != phase:
		return false, fmt.Sprintf("the hook guardian's reconcile did not act under the %s phase of rotation %s", phase, operation)
	case attestation.ManifestSHA256 != manifestSHA256:
		return false, "the guardian's target roster changed during the rotation (targets.yaml was rewritten)"
	case attestation.KeyID != keyID:
		return false, fmt.Sprintf("the guardian rendered from key %s, not %s", shortKeyID(attestation.KeyID), shortKeyID(keyID))
	}
	if unbound := unboundCredentials(attestation, key); len(unbound) > 0 {
		return false, fmt.Sprintf("the guardian attested %d target(s) whose credentials key %s does not derive for their account: %s", len(unbound), shortKeyID(keyID), listLabels(unbound))
	}
	have := credentialTargets(attestation)
	var moved []string
	for key, target := range want {
		if got, ok := have[key]; ok && got.UID != target.UID {
			moved = append(moved, target.Label())
		}
	}
	if len(moved) > 0 {
		slices.Sort(moved)
		return false, fmt.Sprintf("%d target(s) resolved to another account during the rotation: %s", len(moved), listLabels(moved))
	}
	failed := map[string]bool{}
	for _, target := range attestation.Targets {
		failed[target.Key()] = target.State == enterprisehooks.CredentialTargetFailed
	}
	var lost, missing []string
	for key, target := range want {
		if _, ok := have[key]; ok {
			continue
		}
		if failed[key] {
			lost = append(lost, target.Label())
		} else {
			missing = append(missing, target.Label())
		}
	}
	if len(lost) > 0 {
		slices.Sort(lost)
		return false, fmt.Sprintf("%d guardian target(s) that hold a per-user credential failed: %s", len(lost), listLabels(lost))
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
	// An interrupt cancels ctx; the result still describes the host.
	defer l.describe(context.WithoutCancel(ctx), record, false)
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
	if exists(env.stagedUserKeyPath()) || exists(env.retiringUserKeyPath()) || exists(env.transactionPath()) {
		// No rotation owns it (recoverInterruptedRotation settled any
		// recorded one), so nothing authorized it: remove it.
		if err := env.withReconcileLock(ctx, env.removeRotationKeys); err != nil {
			return refuse("an unrecorded staged key could not be removed: %v", err)
		}
		r.AddWarning(codeRotationRecovered, "removed a staged per-user credential key that no rotation recorded")
	}
	idA := connector.UserScopedTokenKeyFingerprint(keyA)
	if !env.Services.Active(ctx, gateway) && !l.backFromRestart(ctx, gateway) {
		// Waiting out ReadyTimeout for its keys would only delay the answer.
		return refuse("%s is not running; run `enterprise %s repair`, then rotate again", gateway.Name, platformName(env.GOOS))
	}
	if err := l.waitGatewayKeys(ctx, gateway, record.ServiceUID, []string{idA}); err != nil {
		return refuse("the gateway is not serving the committed per-user credential key alone: %v", err)
	}
	preflight, err := l.freshAttestation(ctx, env.attestationID())
	if err != nil {
		return refuse("%v", err)
	}
	switch {
	case !preflight.Current():
		return refuse("the hook guardian published a format %d credential attestation, which does not bind each target; run `enterprise %s repair`, then rotate again", preflight.Version, platformName(env.GOOS))
	case preflight.OperationID != "":
		return refuse("the hook guardian is acting under another credential rotation (%s)", preflight.OperationID)
	case preflight.KeyID != idA:
		return refuse("the hook guardian rendered from key %s, not the committed key %s", shortKeyID(preflight.KeyID), shortKeyID(idA))
	}
	if unbound := unboundCredentials(preflight, keyA); len(unbound) > 0 {
		return refuse("the hook guardian attested %d target(s) whose credentials the committed key does not derive for their account: %s", len(unbound), listLabels(unbound))
	}
	held, skipped, err := l.targetsNotMoved(ctx, preflight)
	switch {
	case err != nil:
		return refuse("the hook guardian could not protect every target, and whether they hold a per-user credential is unknown: %v", err)
	case len(held) > 0:
		return refuse("%d guardian target(s) that hold a per-user credential failed their reconcile: %s. Fix or disable them (see `enterprise %s status`), then rotate again",
			len(held), listLabels(held), platformName(env.GOOS))
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
		// The reconcile lock stays held until the gateway has proved B for
		// every user, so neither this rotation nor the guardian's own watch
		// and interval passes move a user to B before then.
		if err := env.withReconcileLock(ctx, func() error {
			if err := env.saveTransaction(intent, enterprisehooks.CredentialPhasePrepare, preflight.ManifestSHA256); err != nil {
				return fmt.Errorf("record the rotation for the hook guardian: %w", err)
			}
			owner := fileOwner{UID: record.ServiceUID, GID: record.ServiceGID}
			if err := env.writeFileAtomic(env.stagedUserKeyPath(), []byte(keyB+"\n"), 0o600, owner); err != nil {
				return fmt.Errorf("stage the new key: %w", err)
			}
			lastID = env.attestationID()
			if err := l.waitGatewayKeys(ctx, gateway, record.ServiceUID, []string{idA, idB}); err != nil {
				return fmt.Errorf("the gateway did not start accepting the new key: %w", err)
			}
			return l.proveKey(ctx, keyB, selected)
		}); err != nil {
			return err
		}
		for attempt := 1; ; attempt++ {
			attestation, err := l.freshAttestation(ctx, lastID)
			if err != nil {
				return err
			}
			lastID = attestation.ID
			done, fatal := onKey(attestation, keyB, operation, enterprisehooks.CredentialPhasePrepare, preflight.ManifestSHA256, selected)
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
	if prepareErr == nil && ctx.Err() != nil {
		// An interrupt rolls back even when every user is ready to commit.
		prepareErr = errors.New("the run was interrupted")
	}
	if prepareErr != nil {
		r.AddError(codeRotation, fmt.Sprintf("rotation %s did not commit: %v; key %s stays in use", operation, prepareErr, shortKeyID(idA)))
		if err := l.abortRotation(ctx, gateway, record, keyA, intent, selected, preflight.ManifestSHA256); err != nil {
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
		// Committed: the guardian's record retires with the old key. A
		// record left behind names a staged key that no longer exists, so
		// the guardian renders from the committed key either way, and the
		// next lifecycle run removes it.
		if err := removeFile(env.transactionPath()); err != nil {
			r.AddWarning(codeRotationIncomplete, "the hook guardian's record of the completed rotation could not be removed: "+err.Error())
		}
		syncDir(filepath.Dir(env.transactionPath()))
		return nil
	}); err != nil {
		r.AddError(codeRotation, fmt.Sprintf("rotation %s did not commit: %v; key %s stays in use", operation, err, shortKeyID(idA)))
		if err := l.abortRotation(ctx, gateway, record, keyA, intent, selected, preflight.ManifestSHA256); err != nil {
			r.AddError(codeRollbackFailed, err.Error())
		}
		return 0
	}
	// Committed: from here on the only way forward is B.
	users := map[string]bool{}
	for _, target := range selected {
		users[target.User] = true
	}
	r.Changes = append(r.Changes,
		fmt.Sprintf("rotation %s committed key %s in place of key %s", operation, shortKeyID(idB), shortKeyID(idA)),
		fmt.Sprintf("moved %d per-user target(s) of %d user(s) to the new key", len(selected), len(users)))
	if len(skipped) > 0 {
		r.Changes = append(r.Changes, fmt.Sprintf("skipped %d target(s) that hold no per-user credential: %s; the guardian renders them from the new key once it can protect them", len(skipped), listLabels(skipped)))
	}
	r.Changes = append(r.Changes,
		"agents that were already running send telemetry with the old key's credentials, which the gateway now refuses; ask users to restart their agents")
	// An interrupt after the commit does not cut this wait short: the
	// rotation is done, and the result should say whether A is retired.
	if err := l.waitGatewayKeys(context.WithoutCancel(ctx), gateway, record.ServiceUID, []string{idB}); err != nil {
		r.AddError(codeRotation, fmt.Sprintf("rotation %s committed key %s, but the gateway has not retired key %s: %v; run verify", operation, shortKeyID(idB), shortKeyID(idA), err))
	}
	if err := env.clearRotationIntent(); err != nil {
		r.AddWarning(codeRotationIncomplete, "the completed rotation's record could not be removed: "+err.Error())
	}
	return 0
}

// abortRotation restores key A: it retires the staged key, reconciles every
// user back to A while the gateway still accepts both keys, then removes the
// new key and waits until the gateway accepts only A.
func (l *lifecycle) abortRotation(ctx context.Context, gateway Unit, record *Deployment, keyA string, intent rotationIntent, selected map[string]enterprisehooks.CredentialAttestationTarget, manifestSHA256 string) error {
	env := l.env
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rotationRollbackTimeout)
	defer cancel()
	var problems []string
	if err := env.withReconcileLock(ctx, func() error {
		if err := env.saveTransaction(intent, enterprisehooks.CredentialPhaseRollback, manifestSHA256); err != nil {
			// The guardian then renders from A without naming the
			// rollback, which the checks below report.
			problems = append(problems, "the hook guardian's record could not be turned to rollback: "+err.Error())
		}
		return env.retireStagedKey()
	}); err != nil {
		if err := env.withReconcileLock(ctx, env.removeRotationKeys); err != nil {
			return fmt.Errorf("the new key could not be removed (%v); the next lifecycle run retries the rollback", err)
		}
	}
	idA := connector.UserScopedTokenKeyFingerprint(keyA)
	restored := false
	lastID := env.attestationID()
	for attempt := 0; attempt < rotationAttempts && !restored; attempt++ {
		attestation, err := l.freshAttestation(ctx, lastID)
		if err != nil {
			problems = append(problems, err.Error())
			break
		}
		lastID = attestation.ID
		done, fatal := onKey(attestation, keyA, intent.OperationID, enterprisehooks.CredentialPhaseRollback, manifestSHA256, selected)
		if fatal != "" {
			problems = append(problems, fatal)
			break
		}
		restored = done
	}
	// Every user is back on A, or the attempts ran out: the new key goes
	// either way, so the rollback never leaves both keys accepted.
	if err := env.withReconcileLock(ctx, env.removeRotationKeys); err != nil {
		return fmt.Errorf("rollback: the new key could not be removed (%v); the next lifecycle run retries the rollback", err)
	}
	if err := l.waitGatewayKeys(ctx, gateway, record.ServiceUID, []string{idA}); err != nil {
		problems = append(problems, err.Error())
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
		if err := env.withReconcileLock(ctx, env.removeRotationKeys); err != nil {
			r.AddWarning(codeRotationRecovered, "the completed rotation's guardian record could not be removed: "+err.Error())
			return
		}
		if err := env.clearRotationIntent(); err != nil {
			r.AddWarning(codeRotationRecovered, "the completed rotation's record could not be removed: "+err.Error())
			return
		}
		r.AddWarning(codeRotationRecovered, fmt.Sprintf("completed an interrupted credential rotation that had committed key %s", shortKeyID(committedID)))
		return
	}
	// Users the interrupted run had already moved go back to the committed
	// key on this reconcile, while the gateway still accepts the retired
	// key; it goes once they are back.
	if err := env.withReconcileLock(ctx, env.retireStagedKey); err == nil {
		_ = l.triggerGuardianReconcile(ctx)
	}
	if err := env.withReconcileLock(ctx, env.removeRotationKeys); err != nil {
		r.AddWarning(codeRotationRecovered, fmt.Sprintf("an interrupted credential rotation could not be rolled back yet: %v", err))
		return
	}
	if err := env.clearRotationIntent(); err != nil {
		r.AddWarning(codeRotationRecovered, "the interrupted rotation's record could not be removed: "+err.Error())
		return
	}
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
