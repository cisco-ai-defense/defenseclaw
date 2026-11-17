// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

// readMountinfo has no mount table to read: actors are Linux.
func readMountinfo() ([]byte, error) { return nil, nil }
