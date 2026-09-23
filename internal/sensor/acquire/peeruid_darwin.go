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

package acquire

import (
	"errors"

	"golang.org/x/sys/unix"
)

// peerUIDOf reads the kernel-supplied peer uid via LOCAL_PEERCRED.
//
// macOS has no SO_PEERCRED; LOCAL_PEERCRED carries the same fact, filled in
// by the kernel from the peer's real credentials at connect time.
func peerUIDOf(fd uintptr) (int, error) {
	credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	if credentials == nil {
		return 0, errors.New("acquire: LOCAL_PEERCRED returned no credentials")
	}
	return int(credentials.Uid), nil
}
