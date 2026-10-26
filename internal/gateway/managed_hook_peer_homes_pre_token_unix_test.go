// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1865 refix (RV4-1): the guardian lets a served account write the first
// migration map only when no 1.0.4 gateway served its uid. The gateway keeps
// that fact on the format entry of the homes file it rewrites: a file a
// build before 1.0.4 wrote (no format entry) gets pre_token_file, the mark
// survives this release's own rewrites, and a file 1.0.4 wrote (format 1,
// no mark) gets none. 1.0.4 drops the mark when it writes the file again.
func TestHomesFileKeepsThatNo104GatewayServedItsUIDs(t *testing.T) {
	const entry = `"52100":{"home":"/home/fcuid1","name":"fcuid1"}`
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"written by 1.0.3", `{` + entry + `}`, true},
		{"written by 1.0.4", `{"format":{"format":1},` + entry + `}`, false},
		{"taken over from 1.0.3 by this release", `{"format":{"format":1,"pre_token_file":true},` + entry + `}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "managed_peer_homes.json")
			if err := os.WriteFile(store, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			c := &managedHookPeerHomeCache{now: time.Now}
			c.setStore(store)
			c.mu.Lock()
			c.loadHomesLocked()
			c.saveHomesLocked()
			c.mu.Unlock()
			data, err := os.ReadFile(store)
			if err != nil {
				t.Fatal(err)
			}
			var stored map[string]managedHookPeerLast
			if err := json.Unmarshal(data, &stored); err != nil {
				t.Fatal(err)
			}
			format := stored[managedHookPeerHomesFormatKey]
			if format.Format != 1 || format.PreTokenFile != tc.want {
				t.Fatalf("format entry %+v after the rewrite; want format 1, pre_token_file %v", format, tc.want)
			}
			if stored["52100"].Name != "fcuid1" {
				t.Fatalf("rewrite lost the entry: %s", data)
			}
		})
	}
}
