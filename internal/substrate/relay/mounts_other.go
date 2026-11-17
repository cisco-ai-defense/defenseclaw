// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

// readMountinfo has no mount table to read: actors are Linux. Off Linux
// (the relay's tests) there is no mount over the kit, so the table is the
// root mount alone; the GAP-0443 check that a table names it stays strict
// on Linux.
func readMountinfo() ([]byte, error) { return []byte("0 0 0:0 / / rw - none none rw\n"), nil }
