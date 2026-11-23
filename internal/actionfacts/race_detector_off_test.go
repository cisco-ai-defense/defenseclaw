// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package actionfacts

// raceDetector is true in a -race build, where timing bounds do not hold.
const raceDetector = false
