// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// checkSecretBinding refuses (secret_ref_mismatch, secret_ref_unbound)
// storing value as credential name when the signed policy bundle that uses
// the credential does not bind that value. The confirmed bundle decides;
// when it refuses, the bundle at rotationPath (secret set --bundle) may bind
// the new value instead, once it verifies on this device as an apply would,
// apart from the stored credentials. The MDM wrappers pass the bundle they
// deliver, which needs no trust anchors yet when nothing is confirmed.
// replacing is true when a value is stored now: a rotation from a confirmed
// bundle that signs only the name (secret_ref_unbound, signed before 1.0.4)
// is refused then, because a failed apply could not put that value back
// (secret set refuses every value such a bundle names). secret set calls it
// under the lock bundle apply takes, so the confirmed bundle cannot change in
// between. A state or manifest it cannot read refuses.
func checkSecretBinding(ctx context.Context, name string, value []byte, rotationPath string, replacing bool) error {
	store, err := bundleStore()
	if err != nil {
		return err
	}
	confirmed, err := store.ConfirmedManifest()
	if err != nil {
		if enterprisebundle.CodeOf(err) == "" {
			err = &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
		}
		return err
	}
	err = enterprisebundle.CheckCredentialChange(confirmed, nil, name, value)
	if err == nil || rotationPath == "" {
		return err
	}
	if replacing && enterprisebundle.CodeOf(err) == enterprisebundle.CodeSecretRefUnbound {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeSecretRefUnbound, Path: "secret_refs", Detail: fmt.Sprintf(
			"the confirmed policy bundle signs the name of credential %s but not its value, so a failed apply could not put the stored value back; "+
				"first apply a bundle signed with --secret-file %s=<file> for the value stored now, then rotate it with a newer bundle", name, name)}
	}
	res := &bundleVerifyResult{Warnings: []enterprisebundle.Warning{}, Errors: []bundleError{}}
	if err := bundleVerify(ctx, &bundleVerifyOptions{bundle: rotationPath, platform: runtime.GOOS, skipSecretStore: true}, res); err != nil {
		// A bundle this device does not accept binds no value; the
		// message keeps its own refusal.
		return &enterprisebundle.Error{Code: enterprisebundle.CodeSecretRefMismatch, Path: "--bundle",
			Detail: "the --bundle policy bundle does not verify on this device, so it signs no value: " + err.Error()}
	}
	return enterprisebundle.CheckCredentialChange(confirmed, res.manifest, name, value)
}

const (
	// codeConfirmedBundleChanged refuses a rotation (set --bundle
	// --if-confirmed) once another bundle is confirmed: nothing is written.
	codeConfirmedBundleChanged enterprisebundle.Code = "confirmed_bundle_changed"
	// codeRotationConfirmed refuses a put-back (--undo-rotation) the
	// confirmed bundle no longer needs: a bundle confirmed since the
	// rotation, or the confirmed bundle itself, uses the value stored now,
	// so it stays.
	codeRotationConfirmed enterprisebundle.Code = "rotation_confirmed"
)

var lowerSHA256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// secretTransactionArguments refuses a malformed --if-confirmed,
// --undo-rotation or --undo-config and a combination with no meaning:
// --if-confirmed guards a rotation, so it needs --bundle; --undo-rotation
// puts a value back, so it takes neither; --undo-config belongs to that
// put-back.
func secretTransactionArguments(opts *enterpriseSecretOptions) error {
	for _, flag := range []struct{ name, value string }{{"--if-confirmed", opts.ifConfirmed}, {"--undo-rotation", opts.undoRotation}} {
		if flag.value != "" && flag.value != "none" && !lowerSHA256Hex.MatchString(flag.value) {
			return fmt.Errorf("%s takes the confirmed policy bundle's manifest SHA-256 (64 lowercase hex digits) or none, not %q", flag.name, flag.value)
		}
	}
	if opts.undoConfig != "" {
		if opts.undoConfig != "none" && !lowerSHA256Hex.MatchString(opts.undoConfig) {
			return fmt.Errorf("--undo-config takes the SHA-256 of the config installed before the rotation (64 lowercase hex digits) or none, not %q", opts.undoConfig)
		}
		if opts.undoRotation == "" {
			return errors.New("--undo-config belongs to a put-back: pass it with --undo-rotation")
		}
	}
	if opts.ifStored != "" && !lowerSHA256Hex.MatchString(opts.ifStored) {
		return fmt.Errorf("--if-stored takes the SHA-256 of the expected stored value (64 lowercase hex digits), not %q", opts.ifStored)
	}
	if opts.undoRotation != "" && opts.ifStored == "" {
		return errors.New("--undo-rotation requires --if-stored to protect a credential changed after the rotation")
	}
	if opts.ifConfirmed != "" && opts.bundle == "" {
		return errors.New("--if-confirmed guards a rotation: pass it with --bundle")
	}
	if opts.undoRotation != "" && (opts.bundle != "" || opts.ifConfirmed != "") {
		return errors.New("--undo-rotation puts a credential back: pass it without --bundle and --if-confirmed")
	}
	return nil
}

// checkSecretTransaction is the guard of a credential rotation the MDM
// wrapper runs as one transaction with a bundle apply. A rotation (set
// --bundle --if-confirmed) runs only while the bundle the wrapper journaled
// is still confirmed (confirmed_bundle_changed). A put-back
// (--undo-rotation) runs only while that bundle is still confirmed and does
// not sign the value stored now (stored, when storedOK); otherwise the
// confirmed bundle uses the stored value and rotation_confirmed tells the
// wrapper to keep it. Only this refusal proves the rotation committed: a
// put-back refused for any other reason (credential_in_use,
// secret_ref_mismatch) says nothing about it. The caller holds the lock
// bundle apply takes, so the confirmed bundle cannot change in between.
func checkSecretTransaction(name string, opts *enterpriseSecretOptions, stored []byte, storedOK bool) error {
	if opts.ifStored != "" {
		sum := sha256.Sum256(stored)
		if !storedOK || hex.EncodeToString(sum[:]) != opts.ifStored {
			return &enterprisebundle.Error{Code: "credential_changed", Detail: fmt.Sprintf(
				"credential %s no longer holds the expected stored value; it was not changed", name)}
		}
	}
	want, code := opts.ifConfirmed, codeConfirmedBundleChanged
	if opts.undoRotation != "" {
		want, code = opts.undoRotation, codeRotationConfirmed
	}
	if want == "" {
		return nil
	}
	stateInvalid := func(err error) error {
		if enterprisebundle.CodeOf(err) == "" {
			err = &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
		}
		return err
	}
	store, err := bundleStore()
	if err != nil {
		return err
	}
	state, err := store.LoadState()
	if err != nil {
		return stateInvalid(err)
	}
	current := "none"
	if state.Current != nil {
		current = state.Current.ManifestSHA256
	}
	if current != want {
		return &enterprisebundle.Error{Code: code, Detail: fmt.Sprintf(
			"the confirmed policy bundle (manifest %s) is not the one confirmed before the rotation (%s); credential %s was not changed", current, want, name)}
	}
	if opts.undoRotation == "" || !storedOK || state.Current == nil {
		return nil
	}
	confirmed, err := store.ConfirmedManifest()
	if err != nil {
		return stateInvalid(err)
	}
	for _, ref := range confirmed.SecretRefs {
		if ref.Name() == name && ref.Binds(confirmed.TenantID, stored) {
			return &enterprisebundle.Error{Code: code, Detail: fmt.Sprintf(
				"the confirmed policy bundle signs the value credential %s holds now, so it was not changed", name)}
		}
	}
	return nil
}

// undoRotationOnConfig reports whether a put-back (remove --undo-rotation)
// runs on the very config that was installed before its rotation: the
// wrapper journals the SHA-256 of the installed config bytes before it
// stores the new value and passes it as --undo-config, and installed is the
// config read now, under the lifecycle lock. Only then may the put-back take
// a credential that config references: the config already referenced it
// with no value stored, so removing it restores the state from before the
// rotation. A config installed since (another ensure, or this run's own
// lifecycle) may use the value the rotation stored, so the reference stands
// (credential_in_use) and the wrapper keeps the credential and its journal
// entry. "none" (no config was installed) never matches.
func undoRotationOnConfig(opts *enterpriseSecretOptions, installed []byte) bool {
	if opts.undoRotation == "" || !lowerSHA256Hex.MatchString(opts.undoConfig) {
		return false
	}
	sum := sha256.Sum256(installed)
	return hex.EncodeToString(sum[:]) == opts.undoConfig
}

// secretBindingCode is the errors[].code of a checkSecretBinding refusal.
func secretBindingCode(err error) string {
	if code := enterprisebundle.CodeOf(err); code != "" {
		return string(code)
	}
	return codeSecretChangeFailed
}
