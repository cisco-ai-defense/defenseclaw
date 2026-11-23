// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// Seen live on detach from Claude Code: the shell came back in the agent
// alternate screen with bracketed paste on. The end of a connection turns
// the agent modes off.
func TestDetachGivesTheShellAPlainTerminal(t *testing.T) {
	out := &writes{}
	scr := newScreen(out, func() relay.Resize { return relay.Resize{Cols: 80, Rows: 24} })
	scr.begin()
	_, _ = scr.Write([]byte("\x1b[?1049h\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[?25lagent"))
	scr.end()
	w := out.list()
	last := w[len(w)-1]
	for _, off := range []string{"\x1b[?1049l", "\x1b[?2004l", "\x1b[?1000l", "\x1b[?1006l", "\x1b[?25h"} {
		if !strings.Contains(last, off) {
			t.Errorf("end does not send %q: %q", off, last)
		}
	}
}
