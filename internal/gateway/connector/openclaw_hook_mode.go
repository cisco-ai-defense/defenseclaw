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

package connector

import (
	"flag"
	"runtime"
	"strings"
)

// OpenClawNativeHooksSince is the first OpenClaw release whose plugin hooks
// DefenseClaw uses natively: before_agent_run, after_tool_call, llm_input
// and llm_output with per-hook budgets. Older releases keep the guardrail
// proxy with before_tool_call (the 1.0.9 behaviour).
const OpenClawNativeHooksSince = "2026.8.35"

// OpenClaw plugin hook modes, written to plugins.entries.defenseclaw.config.hookMode.
const (
	// OpenClawHookModeProxy: guardrail proxy, fetch interceptor and
	// before_tool_call (1.0.9).
	OpenClawHookModeProxy = "proxy"
	// OpenClawHookModeHybrid: proxy plus the native hooks (Linux, macOS).
	OpenClawHookModeHybrid = "hybrid"
	// OpenClawHookModeNative: native hooks only, no proxy (Windows).
	OpenClawHookModeNative = "native"
)

// OpenClawManagedWindowsRefusal is why managed (enterprise) Windows refuses
// OpenClaw in this release: the enterprise refusal list and Setup show it.
const OpenClawManagedWindowsRefusal = "native OpenClaw plugin hooks for managed Windows are not in this release; OpenClaw is supported on per-user (OSS) Windows installs"

// openClawHooksGOOS is runtime.GOOS; tests replace it.
var openClawHooksGOOS = runtime.GOOS

// PinOpenClawHooksGOOSForTest makes the OpenClaw hook mode resolve as on goos
// and returns a restore function, so tests in other packages can exercise the
// native Windows topology on any host. It panics outside a test binary.
func PinOpenClawHooksGOOSForTest(goos string) func() {
	if flag.Lookup("test.v") == nil {
		panic("connector: PinOpenClawHooksGOOSForTest is test-only")
	}
	previous := openClawHooksGOOS
	openClawHooksGOOS = goos
	return func() { openClawHooksGOOS = previous }
}

// ResolveOpenClawHookMode picks the plugin hook mode from the configured
// connectors.openclaw.hooks.mode (auto or proxy), the observed OpenClaw
// version and the OS. An unknown version on Linux and macOS keeps the proxy:
// a hook OpenClaw does not know is a registration error there. On Windows
// there is no proxy, so the mode is native and Setup refuses an OpenClaw
// that is known to be older than OpenClawNativeHooksSince.
func ResolveOpenClawHookMode(configured, rawVersion string) string {
	return resolveOpenClawHookModeOn(openClawHooksGOOS, configured, rawVersion)
}

func resolveOpenClawHookModeOn(goos, configured, rawVersion string) string {
	if goos == "windows" {
		return OpenClawHookModeNative
	}
	if strings.EqualFold(strings.TrimSpace(configured), "proxy") || !openClawNativeHooksSupported(rawVersion) {
		return OpenClawHookModeProxy
	}
	return OpenClawHookModeHybrid
}

// OpenClawHookModeUsesProxy reports whether mode routes OpenClaw model
// traffic through the guardrail proxy: proxy and hybrid do, native does not.
// Only Windows resolves to native (hooks.mode takes auto or proxy), so on
// Linux and macOS every mode uses the proxy whatever the OpenClaw version.
func OpenClawHookModeUsesProxy(mode string) bool {
	return mode != OpenClawHookModeNative
}

// openClawNativeOnly reports a host where OpenClaw runs in native mode only.
func openClawNativeOnly() bool {
	return !OpenClawHookModeUsesProxy(resolveOpenClawHookModeOn(openClawHooksGOOS, "", ""))
}

func openClawNativeHooksSupported(rawVersion string) bool {
	version := NormalizeAgentVersion("openclaw", rawVersion)
	return version != "" && CompareAgentVersions(version, OpenClawNativeHooksSince) >= 0
}

// openClawLacksNativeHooks reports an observed OpenClaw version that is
// older than OpenClawNativeHooksSince. An unknown version is not refused.
func openClawLacksNativeHooks(rawVersion string) bool {
	version := NormalizeAgentVersion("openclaw", rawVersion)
	return version != "" && CompareAgentVersions(version, OpenClawNativeHooksSince) < 0
}
