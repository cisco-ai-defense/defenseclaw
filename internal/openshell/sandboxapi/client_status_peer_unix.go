//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

func (e *statusPeerEvidence) record(pid, uid int) {
	if pid <= 0 || uid < 0 || e.seen && (e.pid != pid || e.uid != uid) {
		e.invalid = true
		return
	}
	e.pid, e.uid, e.seen = pid, uid, true
}
