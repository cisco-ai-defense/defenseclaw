//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

// osRootAncestor is Windows and macOS only; on other Unix systems only
// PlatformInstallerOwnedRoots make an ancestor advisory.
func osRootAncestor(string) bool { return false }

// trustedRootAlias is macOS only: other Unix systems have no fixed root
// aliases a managed path crosses.
func trustedRootAlias(string) bool { return false }
