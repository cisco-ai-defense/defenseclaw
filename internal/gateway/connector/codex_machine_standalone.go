// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsCodexStandaloneHookContractFor returns the default Codex hook
// contract when hookBinary is layout's hook launcher. A machine-wide
// requirements file serves every Codex release on the host, so it binds
// the default contract, which registers every event of the published
// group matrix.
func windowsCodexStandaloneHookContractFor(layout managed.StandaloneLayout, hookBinary string) string {
	if layout.GOOS != "windows" || strings.TrimSpace(layout.BinDir) == "" {
		return ""
	}
	if !sameWindowsCodexMachinePath(hookBinary, strings.TrimRight(layout.BinDir, `\`)+`\defenseclaw-hook.exe`) {
		return ""
	}
	return ResolveHookContract("codex", "").Contract.ContractID
}
