// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0646. A path list joined in one string ("paths": "/a,/b")
// names each part and the value read whole, and the whole value counted
// against the 64 path twins (maxNonShellPathTwins): a list of 64 paths lost
// the whole value's twin and was TRUNCATED, where the same 64 paths as an
// array were judged item by item. The whole value is another reading of the
// parts and is counted on its own now; 65 parts still reach the cap.
func TestGAP0646PathListWholeValueIsNotCountedAsATwin(t *testing.T) {
	list := func(parts int, last string) string {
		var paths []string
		for i := 0; i < parts; i++ {
			paths = append(paths, fmt.Sprintf("/repo/docs/f%02d.md", i))
		}
		if last != "" {
			paths[len(paths)-1] = last
		}
		return strings.Join(paths, ",")
	}
	for _, row := range []struct {
		name, paths  string
		limit, block bool
	}{
		{"64 benign parts", list(64, ""), false, false},
		{"64 parts, the protected one last", list(64, "/home/u/.ssh/id_rsa"), false, true},
		{"65 benign parts", list(65, ""), true, false},
	} {
		args, _ := json.Marshal(map[string]any{"paths": row.paths})
		got := nonShellToolFindings(context.Background(), nonShellReq("mcp__filesystem__read_multiple_files", string(args), false), nil, "")
		if _, limited := findingByID(got, "ACTION-COMPOUND-LIMIT"); limited != row.limit {
			t.Errorf("%s: limit finding=%v, want %v (%v)", row.name, limited, row.limit, findingIDs(got))
		}
		if _, key := findingByID(got, "PATH-SSH-KEY"); key != row.block {
			t.Errorf("%s: PATH-SSH-KEY=%v, want %v (%v)", row.name, key, row.block, findingIDs(got))
		}
	}
}
