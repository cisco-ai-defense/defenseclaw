// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package actionfacts

// osWindowsLongPath: only a Windows host can name the long form of a
// Windows path, so elsewhere the shape of a short name decides.
func osWindowsLongPath(string) (string, bool) { return "", false }

// osDNSHostName: only a Windows host has a domain-qualified name that
// os.Hostname does not return.
func osDNSHostName() []string { return nil }
