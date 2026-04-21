// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

// refreshTestHook runs at the start of (*Model).refresh in tests (e.g. SLO latency).
var refreshTestHook func()
