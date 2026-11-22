// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cli

// Only Linux runs the gateway from a systemd unit (GAP-0205): no unit binds
// the gateway, so start and stop act as a shell's.

func boundSystemdUnitCgroup(string) (string, bool) { return "", false }

func recordGatewayLaunchUnit(string) {}

func adoptGatewayUnitOf(string, int) {}

func processOutsideCgroup(int, string) bool { return false }
