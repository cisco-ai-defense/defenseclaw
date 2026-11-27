// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build race

package pwshparse

// raceDetector is true in a -race build, where wall-clock bounds do not hold
// (the CI Go suites run -race with a cover profile, 10-15x slower).
const raceDetector = true
