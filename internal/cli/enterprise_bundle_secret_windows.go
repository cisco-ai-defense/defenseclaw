// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"io/fs"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedBundleSecretPresent looks a credential up in the standalone
// enterprise secret store with the checks the gateway reads it with, as the
// Windows bundle apply does (it passes this function), so verify and apply
// agree. The value is dropped at once and never printed. An unreadable
// store (a standard account) is reported as an error, so verify warns
// instead of refusing.
func managedBundleSecretPresent(name string) (bool, error) {
	layout, err := enterprisebundle.Layout(runtime.GOOS)
	if err != nil {
		return false, err
	}
	value, _, err := managed.ResolveServiceCredential(name, layout.SecretsDir)
	for i := range value {
		value[i] = 0
	}
	if errors.Is(err, fs.ErrPermission) {
		return false, err
	}
	return err == nil, nil
}
