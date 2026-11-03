// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package agentprobe

import "time"

// EnvName marks the short-lived version command started by the per-user
// enumerator worker. A marker alone does not establish process provenance.
const EnvName = "DC_AGENT_VERSION_PROBE"

const Hermes = "hermes"

// VersionProbeWait bounds a verify pass that finds an in-flight version
// command. Its process must exit before verification can succeed.
const VersionProbeWait = 7 * time.Second
