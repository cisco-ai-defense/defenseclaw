// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package refusalpipe

import "context"

// Send is a no-op off Windows: the Unix standalone gateway authenticates the
// hook socket caller itself and audits its refusals.
func Send(context.Context, Report) error { return nil }
