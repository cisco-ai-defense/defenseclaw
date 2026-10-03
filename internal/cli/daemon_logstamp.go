// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/defenseclaw/defenseclaw/internal/daemon"

// daemonLogStampStop ends the detached gateway's gateway.log time stamper.
// The root pre-run starts it before the config load and the audit store
// open, whose "[audit] ..." lines (the corrupt-store notice, the migration
// lines) were written without a time (GAP-2109). runSidecar keeps it running
// and stops it on return.
var daemonLogStampStop func()

// startDaemonLogStamp starts the stamper once. It does nothing outside a
// daemon child (see daemon.StampChildLog).
func startDaemonLogStamp() {
	if daemonLogStampStop == nil {
		daemonLogStampStop = daemon.StampChildLog()
	}
}

// stopDaemonLogStamp puts the log file back and drains the stamper. It is
// safe to call when the stamper is not running.
func stopDaemonLogStamp() {
	if daemonLogStampStop != nil {
		stop := daemonLogStampStop
		daemonLogStampStop = nil
		stop()
	}
}
