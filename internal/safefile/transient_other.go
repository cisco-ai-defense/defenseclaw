// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

// RetryTransientRead runs read once: a rename never drops a name here.
func RetryTransientRead(read func() error) error { return read() }
