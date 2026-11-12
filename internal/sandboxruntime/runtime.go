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

// Package sandboxruntime names the sandbox runtimes DefenseClaw protects and
// the one host name a runtime gives its sandboxes for DefenseClaw's hook
// ingress. Every package that renders, relays or words a sandbox address
// takes the name from here, so no copy of it drifts.
package sandboxruntime

import "strings"

// Runtimes, as defenseclaw.sandbox.runtime records them.
const (
	// OpenShell is NVIDIA OpenShell on the user's machine.
	OpenShell = "openshell"
	// Substrate is Agent Substrate: the agent runs as an actor in a
	// Kubernetes cluster.
	Substrate = "substrate"
)

// OpenShellHostAlias is how an OpenShell sandbox names the user's machine.
// The docker driver resolves it to a synthetic address inside the workload
// and relays it to host loopback, and MicroVM guests reach the gateway by
// it. DefenseClaw's hook ingress, a --host-port service and an asked host
// port are all behind it, so a decision about it is a decision about a port
// on the user's machine.
const OpenShellHostAlias = "host.openshell.internal"

// Normalize returns the runtime runtime names, with "" meaning OpenShell
// (every sandbox before Agent Substrate support was one), or "" for a name
// DefenseClaw does not know.
func Normalize(runtime string) string {
	switch strings.ToLower(strings.TrimSpace(runtime)) {
	case "", OpenShell:
		return OpenShell
	case Substrate:
		return Substrate
	}
	return ""
}

// DefaultIngressHost is the hook ingress host of a runtime's sandboxes when
// the render target names none: OpenShellHostAlias for OpenShell. A
// Substrate actor reaches the gateway's actor Service, which the cluster's
// configuration names, so Substrate has no default ("").
func DefaultIngressHost(runtime string) string {
	if Normalize(runtime) == OpenShell {
		return OpenShellHostAlias
	}
	return ""
}

// IsOpenShellHostAlias reports whether host is OpenShellHostAlias, compared
// as DNS compares names (ASCII case, one trailing dot).
func IsOpenShellHostAlias(host string) bool {
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(host), "."), OpenShellHostAlias)
}
