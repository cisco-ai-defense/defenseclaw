// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

//go:build linux

package procprobe

// clockTicksPerSecond is the kernel's USER_HZ, the unit /proc/<pid>/stat
// reports CPU time in.
//
// It is 100 on every Linux ABI Go supports, and unlike sysconf(_SC_CLK_TCK) it
// cannot be read without cgo. Hard-coding it is correct rather than a
// shortcut: USER_HZ is a fixed part of the kernel's userspace ABI, distinct
// from CONFIG_HZ, precisely so that /proc consumers do not have to discover it.
func clockTicksPerSecond() int64 { return 100 }
