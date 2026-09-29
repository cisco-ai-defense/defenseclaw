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

// Package openshell integrates DefenseClaw with NVIDIA OpenShell 0.1.x, the
// sandbox runtime that runs coding harnesses inside a kernel-enforced
// boundary (network-less workload container, Landlock, seccomp, non-root,
// endpoint-bound credential placeholders).
//
// OpenShell owns isolation; DefenseClaw owns judgment. The control plane
// talks to the local OpenShell gateway through the Go SDK, and uses the
// upstream `openshell` CLI only where the SDK has no transport (terminal
// attach, file transfer, port forwarding, gateway registration, install).
//
// A gateway runs one compute driver: docker, or vm, OpenShell's MicroVM
// driver, which a Mac runs sandboxes with. What DefenseClaw does
// differently per driver lives in one table (Driver, GatewayDriver).
//
// Sandboxed harnesses reach DefenseClaw at host.openshell.internal, which
// either driver maps to host loopback: hooks land on a dedicated sandbox
// ingress listener, and web egress leaves through the DefenseClaw egress
// proxy. Neither path is ever the main API port.
package openshell
