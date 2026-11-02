//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// manifestIsolatesBadRows: on macOS a malformed, incomplete or duplicate
// manifest row is left out and reported (Manifest.Skipped) instead of
// stopping the reconcile for every user.
const manifestIsolatesBadRows = true
