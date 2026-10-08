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
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rulePackTrust is the TrustRulePack check: the pack folder and the folders
// above it pass the gateway's own check of a managed rule pack (no symlink,
// not writable by group or others, no ACL write entry, owned by root or the
// service account), so ensure refuses a pack before the gateway is
// restarted into a failed start (GAP-0546).
func rulePackTrust(dir string) error {
	return managed.ValidateTrustedRuntimeDir(dir, "rule pack")
}

// rulePackTrustAdvice is the fix named with a refused pack.
const rulePackTrustAdvice = "keep the pack folder and the folders above it owned by root and not writable by group or others, without symlinks or ACL entries that grant write"
