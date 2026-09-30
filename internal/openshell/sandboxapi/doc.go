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

// Package sandboxapi is the wire contract of the DefenseClaw daemon's
// sandbox REST API (/api/v1/sandbox/...) and a typed client for it.
//
// The daemon is the single writer of sandbox bindings, OpenShell providers,
// sandboxes, approvals and egress rules; the `defenseclaw sandbox` CLI owns
// the terminal, the copy-mode workspace and the installer, and reaches the
// daemon only through this API on the main loopback port, authenticated with
// the gateway master token and the CSRF client header.
//
// The package holds no behaviour beyond request encoding: the gateway
// serves these types (internal/gateway/api_sandbox.go) and the sandbox
// manager (internal/openshell/manager) produces them.
package sandboxapi
