// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package gateway

// disableTransparentHugePages: only Linux collapses released heap pages back
// into huge pages behind the process (see the Linux file).
func disableTransparentHugePages() error { return nil }
