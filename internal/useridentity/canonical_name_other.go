// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

// A Windows SID names no account here (CanonicalNameForID).
func platformSAMNameForUPN(string) string     { return "" }
func platformSIDForAccountName(string) string { return "" }
func platformDomainForSID(string) string      { return "" }
