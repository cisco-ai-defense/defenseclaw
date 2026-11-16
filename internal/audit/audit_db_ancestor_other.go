//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

// auditDBAncestorOwnerAdvisory keeps every owner verdict on the store's path
// fatal on this platform.
func auditDBAncestorOwnerAdvisory(string, bool, bool) bool { return false }
