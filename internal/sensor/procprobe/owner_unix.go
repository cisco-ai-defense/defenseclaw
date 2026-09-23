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

//go:build unix

package procprobe

import (
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
)

// userCache avoids one getpwuid per process per poll. A busy host has hundreds
// of processes owned by a handful of users, and the lookup can touch a
// directory service.
var userCache sync.Map // uid string -> username string

// ownerOf resolves the owning username of a /proc entry or process directory.
// It returns "" rather than a uid string when the name cannot be resolved,
// because a bare number is not what an operator reads in a finding.
func ownerOf(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	if cached, ok := userCache.Load(uid); ok {
		return cached.(string)
	}
	name := ""
	if resolved, err := user.LookupId(uid); err == nil {
		name = resolved.Username
	}
	userCache.Store(uid, name)
	return name
}
