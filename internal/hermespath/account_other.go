// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hermespath

import "runtime"

// accountHomeDir is the account's ~/.hermes: Linux and macOS keep no
// persistent per-account environment a service can read.
func accountHomeDir(userHome string) (string, error) {
	return ResolveHomeDir(runtime.GOOS, "", "", userHome), nil
}
