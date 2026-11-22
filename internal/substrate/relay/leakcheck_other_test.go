// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

// The leak check reads /proc; elsewhere it is off.
func markLeaks() {}

func checkLeaks(code int) int { return code }
