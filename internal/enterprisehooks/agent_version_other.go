// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// The Windows per-connector agent-version probe
// (`discoverWindowsAgentVersion`, `windowsAgentVersionExplain`) is
// defined in `agent_version_windows.go` under a `//go:build windows`
// tag and is only referenced by the equally-Windows-tagged
// `enumerator_windows.go`. There is no non-Windows caller of those
// symbols and therefore no stub is needed here — `golangci-lint`'s
// `unused` analyzer flagged the prior stubs (returning empty
// unconditionally) as dead code across the non-Windows build. This
// file is intentionally empty apart from the package clause so the
// file layout mirrors the Windows sibling without smuggling dead
// symbols into the darwin / linux build.

package enterprisehooks
