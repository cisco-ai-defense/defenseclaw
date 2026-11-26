// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

// ReadGzB opens a gzipped fixture for the external test package: perf_test.go
// times the port against internal/psparse, which imports this package, so it
// cannot be an internal test (import cycle).
var ReadGzB = readGzB
