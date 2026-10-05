// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package winsession carries Windows Service Control Manager session-change
// notifications from the service host to the long-running enterprise
// service commands (the hook guardian and the hook enumerator), so a user who
// signs in is enrolled promptly instead of on the next periodic tick.
//
// Only the standalone profile's services subscribe (see cmd/defenseclaw's
// service host); for every other process Logons never fires.
package winsession

var logons = make(chan struct{}, 1)

// NotifyLogon records that an interactive session started or reconnected.
// It never blocks: a burst of notifications coalesces into one pending
// signal.
func NotifyLogon() {
	select {
	case logons <- struct{}{}:
	default:
	}
}

// Logons delivers one value per coalesced burst of NotifyLogon calls.
func Logons() <-chan struct{} {
	return logons
}
