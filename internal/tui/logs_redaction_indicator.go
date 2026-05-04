// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// redactionDisabledForLogsBadge reports whether the Logs panel
// header should render the "RAW" badge. We delegate to
// “redaction.DisableAll“ so the badge reflects the SAME source
// of truth the writer side uses (config flag OR env override).
//
// Pulled into a tiny indirection so tests can override the lookup
// without monkey-patching package state.
var redactionDisabledForLogsBadge = func() bool {
	return redaction.DisableAll()
}

// applyTUIRedactionOverride mirrors the operator's intent into
// this TUI process's redaction package state. Used by the [R]
// confirm path to make the "RAW" badge react immediately rather
// than lagging until the sidecar has finished restarting and the
// next config.Load() picks up the persisted flag.
//
// Defined as a var (not a func) so unit tests can replace it with
// a recording shim.
var applyTUIRedactionOverride = func(disable bool) {
	redaction.SetDisableAll(disable)
}
