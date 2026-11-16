// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procidentity

func recorded(pid int) (string, bool) { return startTicks(pid) }
