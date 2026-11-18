// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package scanner

// raceDetector reports a test binary built with -race, whose instrumented
// code runs the CodeGuard proof about 20 times slower than the product
// build: timing bounds hold for the plain build only.
const raceDetector = false
