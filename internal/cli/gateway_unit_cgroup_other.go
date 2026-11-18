// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cli

// systemdServiceCgroup: only Linux runs the gateway from a systemd unit.
func systemdServiceCgroup() (string, bool) { return "", false }

// processOutsideCgroup: no cgroups, so never outside one.
func processOutsideCgroup(int, string) bool { return false }
