// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
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

// secretBindingCode is the errors[].code of a checkSecretBinding refusal.
func secretBindingCode(err error) string {
	if code := enterprisebundle.CodeOf(err); code != "" {
		return string(code)
	}
	return codeSecretChangeFailed
}
