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

import "net"

// authorize is a no-op on Windows because the decision was already made,
// earlier and by the kernel, from the socket's DACL.
//
// The transport is an AF_UNIX socket on all three platforms, but the access
// boundary differs. POSIX socket modes are advisory enough to be worth
// re-checking in userspace, so the unix build reads the kernel-supplied peer
// uid at accept. Windows has no SO_PEERCRED or LOCAL_PEERCRED to read, and
// its DACL is a real refusal applied at open time -- a process outside the
// ACE set never reaches Accept.
//
// This matches the product's existing posture for its other local socket:
// see internal/ipc/peerauth_windows.go, where the socket DACL is likewise
// the sole boundary and richer peer authentication is explicitly deferred
// under spec 004. When that lands, this is the second place to adopt it.
func (s *Server) authorize(net.Conn) error { return nil }
