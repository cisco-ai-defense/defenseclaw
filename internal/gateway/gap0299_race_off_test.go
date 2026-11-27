// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package gateway

// gap0299RaceTimeScale is 1 in a plain build (see the race file).
const gap0299RaceTimeScale = 1.0
