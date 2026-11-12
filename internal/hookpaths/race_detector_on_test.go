// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build race

package hookpaths

// raceDetector reports a test binary built with -race, whose instrumented
// readers allocate a few percent more than the product build.
const raceDetector = true
