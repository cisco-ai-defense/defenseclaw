// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build race

package gateway

// gap0299RaceTimeScale: under -race the 1 MiB call costs about 1.6x more
// against the reference call than in a plain build (ratio 19.4-20.0 vs
// 11.3-14.8), so the race pin scales the measured ratio by 2 to keep the
// same headroom as the plain pin (rel-1-0-10:GAP-0299).
const gap0299RaceTimeScale = 2.0
