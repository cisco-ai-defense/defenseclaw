// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package cli

import "context"

// enterpriseHookGatewayPeerAccounts lists none on macOS: the gateway tells a
// local account deleted and created again from the one before it by its
// listed record (GAP-0669). Tests replace it.
var enterpriseHookGatewayPeerAccounts = func(string) []enterpriseHookPeerAccount { return nil }

// enterpriseHookLocalAccountsStamp is "" on macOS: the gateway compares no
// record with the account database there (guardianHomeProofCurrent).
var enterpriseHookLocalAccountsStamp = func() string { return "" }

// enterpriseHookNoteHomeRoots records nothing on macOS, which keeps no
// account database stamp (enterpriseHookLocalAccountsStamp).
func enterpriseHookNoteHomeRoots([]enterpriseHookReconcileRow) {}

// enterpriseHookHomeRootsStamp is "" on macOS. Tests replace it.
var enterpriseHookHomeRootsStamp = func() string { return "" }

// enterpriseHookAccountIncarnationLookup is nil on macOS: Open Directory
// names no SID the guardian keys records on. Tests replace it.
var enterpriseHookAccountIncarnationLookup = func(context.Context) func(uid int, user string) (string, bool) { return nil }
