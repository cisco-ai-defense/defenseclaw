//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

func ownerFootprintRepairedAsRoot() bool { return false }

func platformRepairAfterOwnerInstall(string, string, int, int) {}
