// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsCodexStandaloneHookContractFor returns the default Codex hook
// contract when hookBinary is layout's hook launcher: the transition image
// in BinDir or a launch image under BinDir\hooks\<16 hex> (GAP-0751). A
// machine-wide
// requirements file serves every Codex release on the host, so it binds
// the default contract, which registers every event of the published
// group matrix.
func windowsCodexStandaloneHookContractFor(layout managed.StandaloneLayout, hookBinary string) string {
	if layout.GOOS != "windows" || strings.TrimSpace(layout.BinDir) == "" {
		return ""
	}
	transition := strings.TrimRight(layout.BinDir, `\`) + `\defenseclaw-hook.exe`
	if !sameWindowsCodexMachinePath(hookBinary, transition) &&
		!winpath.SameEnterpriseHookImageFamily(hookBinary, transition) {
		return ""
	}
	return ResolveHookContract("codex", "").Contract.ContractID
}
