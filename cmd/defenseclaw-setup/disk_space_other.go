// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

func platformFreeDiskBytes(string) (uint64, bool, error) { return 0, false, nil }
