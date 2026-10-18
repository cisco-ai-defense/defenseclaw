// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// resolveBundleSecret reads a credential as the gateway service would;
// tests replace it.
var resolveBundleSecret = managed.ResolveServiceCredentialAs

// managedBundleSecretPresent looks a credential up in the standalone
// enterprise secret store with the checks the gateway reads it with, as the
// Windows bundle apply does (it passes this function), so verify and apply
// agree. The caller is an administrator or plain SYSTEM shell without the
// service's environment pins, so the gateway service account comes from the
// layout the installer pins it from (GAP-0009). The value is dropped at once
// and never printed. A credential that is not stored is missing; any other
// failure (a standard account, a store or ACL the checks refuse) is an
// error, so verify warns secret_presence_unchecked instead of refusing.
func managedBundleSecretPresent(name string) (bool, error) {
	layout, err := enterprisebundle.Layout(runtime.GOOS)
	if err != nil {
		return false, err
	}
	value, _, err := resolveBundleSecret(name, layout.SecretsDir, layout.ServiceUser)
	for i := range value {
		value[i] = 0
	}
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, managed.ErrNoServiceCredential):
		return false, nil
	}
	return false, err
}
