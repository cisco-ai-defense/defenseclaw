// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

func hardenProcess() error    { return nil }
func dumpable() (bool, error) { return true, nil }
func holdSignals() bool       { return false }
