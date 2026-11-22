// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build race

package chainstate

// raceEnabled: the race detector's shadow memory grows with every address
// the program touches and is never given back, so resident memory is not a
// measure of the leader's own memory under -race.
const raceEnabled = true
