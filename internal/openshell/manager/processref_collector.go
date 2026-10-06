// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// integration keeps one copy: the sandbox-visibility round's telemetry lane
// (destinations) defines ProcessLookup and ProcessRef too; when the lanes
// merge, keep one definition of each and delete the other file's.

package manager

// ProcessRef is one process of a sandbox's lineage. Every field is the
// sandbox's, and agent-chosen display text.
type ProcessRef struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid,omitempty"`
	Comm string `json:"comm,omitempty"`
	Exe  string `json:"exe,omitempty"`
}

// ProcessLookup names the process behind a sandbox observation and its
// ancestors, nearest first; nil when it does not know the process (the
// sandbox's process tree is off, or the process was never seen). A nil
// ProcessLookup knows none.
type ProcessLookup interface {
	Lineage(sandboxName string, pid int) []ProcessRef
}
