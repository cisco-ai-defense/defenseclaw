// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package systemd

// launchdListener: Linux services get their sockets from systemd only.
func launchdListener(string) (*sharedListener, bool, error) { return nil, false, nil }
