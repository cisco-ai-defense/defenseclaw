// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package relay

func processAlive(int) bool    { return false }
func signalRecreateSocket(int) {}
