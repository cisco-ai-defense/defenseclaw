// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

// listenerProcessLabel is used only by the Windows start-up listener check;
// Linux and macOS name the holder through foreignGatewayListener.
func listenerProcessLabel(int) string { return "" }
