// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookcli

// isolateHookTestHost has nothing to isolate off Windows: the Unix managed
// readers take their paths from the tests themselves.
func isolateHookTestHost() func() { return func() {} }
