// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookguard

// coworkMarkerTrusted has no Windows security to read: the account plugin
// runs this guard on Windows only. On Linux and macOS the plugin's hook is a
// shell command with its own marker check, and the CLI refuses a group- or
// world-writable folder for the marker.
func coworkMarkerTrusted(string) bool { return true }
