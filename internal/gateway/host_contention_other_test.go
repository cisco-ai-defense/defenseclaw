// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package gateway

// startContention has no scheduler statistics here: the factor is 1.
func startContention() func() float64 { return func() float64 { return 1 } }
