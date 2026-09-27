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

package openshell

// Environment variable names DefenseClaw sets inside every OpenShell sandbox
// it launches (registered in internal/envvars/registry.json).
const (
	// EnvSandboxToken carries the per-sandbox ingress binding token. By
	// default (openshell.token_delivery=provider), it is delivered as an
	// OpenShell provider credential, so the workload only sees a
	// revision-scoped placeholder that the OpenShell supervisor substitutes
	// at the ingress endpoint; hooks must read it at request time.
	EnvSandboxToken = "DEFENSECLAW_SANDBOX_TOKEN"
	// EnvSandboxID is the OpenShell sandbox id. Its presence also tells a
	// nested `defenseclaw sandbox run` (or the shell wrapper) that it
	// already runs sandboxed.
	EnvSandboxID = "DEFENSECLAW_SANDBOX_ID"
	// EnvSandboxName is the DefenseClaw sandbox name.
	EnvSandboxName = "DEFENSECLAW_SANDBOX_NAME"
)
