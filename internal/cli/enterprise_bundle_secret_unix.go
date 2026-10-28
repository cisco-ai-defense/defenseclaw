// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterpriseunix"

// managedBundleSecretValue reads a credential from the standalone
// enterprise secret store with the checks the Linux and macOS bundle apply
// runs (enterpriseunix Env.SecretValue), so verify and apply agree. A
// stored file the gateway would refuse is missing (nil). An unreadable store
// (a standard account) is reported as an error, so verify warns instead of
// refusing.
func managedBundleSecretValue(name string) ([]byte, error) {
	env, err := newUnixLifecycleEnv(enterpriseunix.CurrentGOOS())
	if err != nil {
		return nil, err
	}
	return env.SecretValue(name)
}
