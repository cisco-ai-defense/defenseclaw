// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "context"

// enterpriseHookAccountDatabaseChanges is nil on Windows: the Unix guardian
// follows the local account database to spool a new account's identity
// record before its first hook (GAP-2108).
func enterpriseHookAccountDatabaseChanges(context.Context) <-chan struct{} { return nil }
