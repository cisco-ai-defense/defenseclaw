// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package winmutex holds a Windows named mutex from Go. A Windows mutex is
// owned by the OS thread that acquired it, while Go moves goroutines between
// threads, so the hold lives on one goroutine locked to its thread.
package winmutex
