// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP2271InlineWriteReadsTheCallOnce: a copy-mode call that runs a
// command the split cannot read ($CMD) is read whole by the laptop writer
// (sandboxAgentHookConfigInlineWrite, substrate-1 GAP-0888). That reader
// narrows the hook files by halves, and each half parsed and placed every
// statement of the call again: 1,500 statements after a cd and a write to
// the guest home settings cost about four times the rel actor's hook
// (rel-1-0-10:GAP-2271). The set-free part of the reading (the write
// operands of the call and of each placed statement) is now read once, and
// the guard, which names one hook file, stops narrowing at the first one.
// The named file is the first one the full reading names.
func TestGAP2271InlineWriteReadsTheCallOnce(t *testing.T) {
	const home = "/home/alice"
	var b strings.Builder
	b.WriteString("cd .cache\n$CMD\n")
	for i := range 1500 {
		fmt.Fprintf(&b, ":%d\n", i)
	}
	b.WriteString("echo x > ../.claude/settings.json")
	command := b.String()
	names := sandboxAgentHookConfigNames(home, home)
	full := hookpaths.RegistrationWriteReached(command, home, home, names)
	if len(full) == 0 {
		t.Fatal("the full reading names no hook file")
	}
	if got := sandboxAgentHookConfigInlineWrite(command, home, home); got != full[0] {
		t.Fatalf("the guard names %q, the full reading %q first", got, full[0])
	}
	one := testing.AllocsPerRun(2, func() { hookpaths.LiteralWriteOperands(command, home, home) })
	guard := testing.AllocsPerRun(2, func() { sandboxAgentHookConfigInlineWrite(command, home, home) })
	// At 2b475e7f12 the guard allocated about 38 times one reading of the
	// call (every half it narrowed placed all 1,500 statements again); now
	// about 2.7.
	if guard > 6*one {
		t.Fatalf("the guard allocates %.0f times, one reading of the call %.0f (%.1fx): it reads the call again for each half", guard, one, guard/one)
	}
}
