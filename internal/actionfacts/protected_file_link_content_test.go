// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

// TestAccountDatabaseWriteThroughALinkTheClientPlacedOnItIsProven: a write of
// a UID-0 account record to a project link is proven like the direct name when
// the hook client (or the gateway's own walk) placed the link on /etc/passwd,
// resolved or, for a closed directory, as the file the link text leads to.
func TestAccountDatabaseWriteThroughALinkTheClientPlacedOnItIsProven(t *testing.T) {
	linksEtcForTest(t, true)
	record := "root:x:0:0:root:/root:/bin/bash\nr109:x:0:0::/root:/bin/sh\n"
	ordinary := "root:x:0:0:root:/root:/bin/bash\nr109:x:1001:1001::/home/r109:/bin/sh\n"
	for _, row := range []struct {
		name, content, physical string
		proves                  bool
	}{
		{"link to the account database", record, "/etc/passwd", true},
		{"link to the macOS physical spelling", record, "/private/etc/passwd", true},
		{"ordinary account through the link", ordinary, "/etc/passwd", false},
		{"link to another file", record, "/srv/passwd.copy", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]any{"path": "grant-link", "content": row.content})
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{
				Tool: "write_file", Args: args, CWD: "/work/proj",
				ClientResolvedTargets: map[string]string{"/work/proj/grant-link": row.physical},
			})
			if got := ExactPOSIXNonRootUIDZeroAccountWrite(facts); got != row.proves {
				t.Fatalf("proof = %t, want %t", got, row.proves)
			}
		})
	}
}
