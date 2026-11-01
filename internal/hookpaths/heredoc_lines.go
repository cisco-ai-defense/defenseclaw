// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"
)

// HeredocLines finds here-document delimiter lines in one command in time
// linear in the command (GAP-2557): the searches scan line by line until
// they have read about twice the command, then an index of its lines is
// built once. Without it, many bodies whose delimiter line never comes (the
// redefinition read blanks the bodies, an unterminated <<A per line) each
// scanned the rest of the command: 1 MiB took ~60 s. The zero value is
// ready; one finder serves one command.
type HeredocLines struct {
	scanned int
	// plain maps a line (CR dropped) and tabs the same line with its
	// leading tabs dropped (<<-) to the ascending offsets where it starts.
	plain, tabs map[string][]int
}

// Next returns the first line at or after from (a line start) that is
// delim, read as bash reads a delimiter line.
func (x *HeredocLines) Next(command, delim string, stripTabs bool, from int) (lineStart, lineEnd int, ok bool) {
	if x == nil || x.plain == nil && x.scanned <= 2*len(command)+1<<16 {
		for pos := from; pos < len(command); {
			lineEnd := len(command)
			if k := strings.IndexByte(command[pos:], '\n'); k >= 0 {
				lineEnd = pos + k
			}
			if x != nil {
				x.scanned += lineEnd - pos + 1
			}
			line := strings.TrimSuffix(command[pos:lineEnd], "\r")
			if stripTabs {
				line = strings.TrimLeft(line, "\t")
			}
			if line == delim {
				return pos, lineEnd, true
			}
			pos = lineEnd + 1
		}
		return 0, 0, false
	}
	if x.plain == nil {
		x.plain, x.tabs = map[string][]int{}, map[string][]int{}
		for pos := 0; pos < len(command); {
			lineEnd := len(command)
			if k := strings.IndexByte(command[pos:], '\n'); k >= 0 {
				lineEnd = pos + k
			}
			line := strings.TrimSuffix(command[pos:lineEnd], "\r")
			x.plain[line] = append(x.plain[line], pos)
			stripped := strings.TrimLeft(line, "\t")
			x.tabs[stripped] = append(x.tabs[stripped], pos)
			pos = lineEnd + 1
		}
	}
	starts := x.plain[delim]
	if stripTabs {
		starts = x.tabs[delim]
	}
	k, _ := slices.BinarySearch(starts, from)
	if k == len(starts) {
		return 0, 0, false
	}
	lineStart = starts[k]
	lineEnd = len(command)
	if e := strings.IndexByte(command[lineStart:], '\n'); e >= 0 {
		lineEnd = lineStart + e
	}
	return lineStart, lineEnd, true
}
