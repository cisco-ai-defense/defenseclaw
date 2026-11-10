// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package testenv

// readThreadTimes is nil off Linux: the host reports no time a thread was
// ready and without a CPU, so a Meter reads 0 and every bound stays the
// product value. The shared build box that makes these tests miss their
// bounds is Linux; a hosted runner is not shared between jobs.
func readThreadTimes() map[int]threadTimes { return nil }
