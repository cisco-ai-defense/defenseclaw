// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// resolveBundleSecret reads a credential as the gateway service would;
// tests replace it.
var resolveBundleSecret = managed.ResolveServiceCredentialAs

// managedBundleSecretValue reads a credential from the standalone
// enterprise secret store with the checks the gateway reads it with, as the
// Windows bundle apply does (it passes this function), so verify and apply
// agree. The caller is an administrator or plain SYSTEM shell without the
// service's environment pins, so the gateway service account comes from the
// layout the installer pins it from (GAP-0009). Verify compares the value
// with the signed value_sha256 and clears it; it is never printed. A
// credential that is not stored, or that is stored but fails a check the
// gateway's read applies (path trust, an extra reader ACE, empty, too
// large), is missing (nil), so a required reference refuses. Only a store
// the caller cannot read (a standard account, a failed security descriptor
// read) is an error, so verify warns secret_presence_unchecked
// (managed.ServiceCredentialValue).
func managedBundleSecretValue(name string) ([]byte, error) {
	layout, err := enterprisebundle.Layout(runtime.GOOS)
	if err != nil {
		return nil, err
	}
	value, _, err := resolveBundleSecret(name, layout.SecretsDir, layout.ServiceUser)
	return managed.ServiceCredentialValue(value, err)
}
