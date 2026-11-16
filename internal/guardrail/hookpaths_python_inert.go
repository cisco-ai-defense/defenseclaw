// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import "github.com/defenseclaw/defenseclaw/internal/hookpaths"

func init() {
	hookpaths.PythonInertTextMasked = pythonInertTextMasked
}

// pythonInertTextMasked is hookpaths' view of Python source: string text
// blanked when no string can run from cwd (PythonStringsMayRun), else the
// source whole.
func pythonInertTextMasked(code, cwd string) string {
	calls := MaskPythonStrings(code)
	if PythonStringsMayRun(calls, cwd) {
		return code
	}
	return calls
}
