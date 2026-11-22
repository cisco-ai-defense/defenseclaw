// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import "os"

// readMountinfo is the relay's own mount table (kitMountRefusal).
func readMountinfo() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }
