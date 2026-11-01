// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

// guardianRecordReplaceBusy is Windows-only: a rename never leaves a
// guardian record unopenable here.
func guardianRecordReplaceBusy(error) bool { return false }
