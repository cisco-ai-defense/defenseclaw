// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

// profileExplainAccountID resolves an explain --user spelling to its SID
// for the per-user owner check (perUserExplainRefusal); the LSA name
// translation reads no directory facts.
var profileExplainAccountID = func(name, _ string) (string, error) {
	id, _, err := LookupWindowsAccount(name)
	return id, err
}
