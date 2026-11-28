// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package pwshparse

// raceDetector is false outside a -race build: the wall-clock bounds apply.
const raceDetector = false
