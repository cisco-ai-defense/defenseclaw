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

// Package sandboxauth authenticates and scopes traffic from OpenShell
// sandboxes to the DefenseClaw hook ingress.
//
// Every sandbox gets its own Binding: a random bearer credential (stored
// only as a SHA-256 hash), the one connector whose hook routes it may call,
// the reviewed hook contract baked into its image, the host user who
// launched it, and the container-to-host path map for its project mount.
// The credential reaches the sandbox as an OpenShell provider credential,
// so the workload only ever sees a placeholder that OpenShell substitutes
// on the way to host.openshell.internal.
//
// Sandbox requests arrive from host loopback through the host-networked
// OpenShell supervisor. Nothing in this package treats loopback as proof
// of anything: a request is a sandbox request only when its credential
// matches a live binding, and it may then touch only what the binding
// names. FSView enforces the filesystem half of that rule for handlers
// that inspect paths named in hook payloads: mount-mode paths resolve to
// host paths that stay inside the mounted project, and copy-mode paths
// never reach the host filesystem at all.
//
// The FileStore is owner-only JSON (0600 in a 0700 directory), updated
// under an advisory lock with atomic replacement, so a crashed writer can
// never leave a half-written credential table behind.
package sandboxauth
