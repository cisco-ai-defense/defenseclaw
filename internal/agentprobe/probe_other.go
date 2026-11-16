// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package agentprobe

import "time"

// WaitManagedHermesVersion has no process lineage proof on this platform.
func WaitManagedHermesVersion(string, int, string, time.Duration) bool { return false }
