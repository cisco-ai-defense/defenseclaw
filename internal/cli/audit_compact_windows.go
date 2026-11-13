// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/spf13/cobra"

// auditCompactAsStoreOwner: on Windows the store's custody checks accept an
// elevated administrator for the managed store (the pinned gateway service
// SID and the administrator principals), and the claim refuses a store the
// service has open, so the caller compacts it itself.
func auditCompactAsStoreOwner(*cobra.Command, string) (bool, error) { return false, nil }
