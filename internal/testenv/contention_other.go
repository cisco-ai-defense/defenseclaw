// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package testenv

import "time"

// Contention has no scheduler statistics here: no wait, factor 1.
type Contention struct{}

// StartContention starts measuring (nothing to measure here).
func StartContention() *Contention { return &Contention{} }

// Wait is zero without scheduler statistics.
func (*Contention) Wait() time.Duration { return 0 }

// Factor is 1 without scheduler statistics.
func (*Contention) Factor() float64 { return 1 }
