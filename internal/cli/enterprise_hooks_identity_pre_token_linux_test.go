// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1976 and GAP-1977: the guardian lets a served account write the first
// migration map only for a uid no 1.0.4 gateway served (no format entry, a
// legacy holder without a base token, or pre_token_holder), held by an
// account whose home is not younger than the entry's last sighting.
func TestServedAccountIsAPreTokenHolderPerUID(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current account:", err)
	}
	uid, err := strconv.Atoi(me.Uid)
	if err != nil || uid <= 0 {
		t.Skip("not run as a non-root account")
	}
	birth, known := enterprisehooks.HomeBirth(me.HomeDir)
	head := `"` + me.Uid + `":{"home":"` + me.HomeDir + `","name":"` + me.Username + `"`
	for _, tc := range []struct {
		name, body string
		mtime      time.Time
		pre        bool
		needBirth  bool
	}{
		{"1.0.4: legacy holder 1.0.4 never served", `{"format":{"format":1},` + head + `,"legacy_holder":true}}`, time.Now(), true, false},
		{"1.0.4: served by 1.0.4", `{"format":{"format":1},` + head + `,"base_incarnation":"files"}}`, time.Now(), false, false},
		{"this release: marked", `{"format":{"format":1},` + head + `,"base_incarnation":"files","pre_token_holder":true}}`, time.Now(), true, false},
		{"this release: marked, home created after the sighting",
			`{"format":{"format":1},` + head + `,"base_incarnation":"files","pre_token_holder":true,"first_seen":` +
				strconv.FormatInt(birth-int64(time.Hour), 10) + `}}`, time.Now(), false, true},
		{"1.0.3: home created after the file was written", `{` + head + `}}`, time.Unix(0, birth).Add(-time.Hour), false, true},
		{"1.0.3", `{` + head + `}}`, time.Now(), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needBirth && (!known || birth <= int64(2*time.Hour)) {
				t.Skip("the file system keeps no creation time for the home here")
			}
			path := filepath.Join(t.TempDir(), "managed_peer_homes.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, tc.mtime, tc.mtime); err != nil {
				t.Fatal(err)
			}
			peers := enterpriseHookResolveGatewayPeers(path, nil)
			peer, ok := peers[uid]
			if !ok {
				t.Skip("the account database gives the current account no non-SID incarnation here")
			}
			if peer.PreToken != tc.pre {
				t.Fatalf("PreToken %v, want %v", peer.PreToken, tc.pre)
			}
		})
	}
}
