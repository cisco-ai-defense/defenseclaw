//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// enterpriseHookGuardianLedgerStandaloneRefusalPlatform is nil here: the
// standalone content-drift rule is Windows-only
// (managed.StandaloneRefusesContentDrift).
func enterpriseHookGuardianLedgerStandaloneRefusalPlatform(string, bool) error { return nil }
