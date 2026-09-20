// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

// readStability records metadata that changes for an in-place content
// mutation. Identity checks alone are insufficient: a writer that already
// holds the same object can truncate or overwrite it while a reader is
// consuming credentials or process-control state.
type readStability struct {
	size       int64
	modified   int64
	changed    int64
	attributes uint32
}
