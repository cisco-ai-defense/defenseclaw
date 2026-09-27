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

// Package workspace gives a sandboxed harness the project folder and nothing
// else, and lets the operator take back what the agent did with it.
//
// Two modes exist:
//
//   - Mount (default). PlanMount validates the launch folder and turns it into
//     OpenShell docker-driver bind mounts: the project read-write at
//     /work/<repo>, secret files masked by read-only empty files, and every
//     piece of git state that would run code on the host (hooks, config,
//     include files, the git directory itself, commondir, submodule git
//     directories) pinned read-only or against replacement. Snapshot records
//     the working tree before the session; Review lists what changed and which
//     of those changes can execute on the host; Undo puts the folder back.
//   - Copy (--copy). Stage builds a sanitized shallow clone plus the working
//     tree with secrets held back; Upload and EstablishBaseline put it in the
//     sandbox; Pull brings the agent's result back as a verified git bundle and
//     Apply lands it as a 3-way merge, a dc/<name> branch, or a patch file.
//
// # Threat model
//
// The agent runs as the operator's uid inside the sandbox and can write
// anything under the project mount, including most of .git. Every git
// command DefenseClaw runs on the host therefore goes through
// internal/gitsafe, and every post-session git operation that touches the
// working tree runs against a DefenseClaw-owned "shadow" git directory rather
// than the project's own .git, so a planted config, attributes file, commondir
// or hook in the project is never consulted. The shadow also keeps its own
// copy (hard links where possible) of the project's objects, so the snapshot
// survives an agent deleting .git/objects.
//
// OpenShell is reached only through the Execer, Uploader, Downloader and
// SandboxLister interfaces. CLI implements the transfers and exec with the
// upstream openshell binary, pinned to one gateway; GatewayClient
// implements exec and sandbox listing on an openshell.Client. Both follow
// the openshell package's exec rules: the sandbox stops a command at its
// timeout, and only commands marked Idempotent are ever retried.
package workspace
