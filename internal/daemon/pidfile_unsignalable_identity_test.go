// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// rel-1-0-10:GAP-1473 (GAP-1314): IsRunning's decision for the record of a
// live process this account may not signal, over a fake process table. The
// table gives the live start identity the way holderStartIdentity does for
// a Windows gateway whose handle is denied (the kernel's process list); the
// PID is above every pid_max, so no process handle or /proc entry opens for
// it, as on Windows, and verifyStartIdentity's re-read fails. A matching
// identity keeps gateway.pid, an unreadable one keeps it and reports
// unknown, and only a contradicting one removes it.
func TestUnsignalableRecordKeptUnlessItsStartIdentityContradicts(t *testing.T) {
	const pid = 1<<22 + 7
	const created = "1763491200123456700"
	table := map[int]string{}
	prev := unsignalableStartIdentity
	unsignalableStartIdentity = func(p int) (string, error) {
		if identity, ok := table[p]; ok {
			return identity, nil
		}
		return "", errors.New("fake process table: no start identity")
	}
	t.Cleanup(func() { unsignalableStartIdentity = prev })

	for _, tc := range []struct {
		name     string
		live     string // "" = the table has no identity for the PID
		recorded string
		want     unsignalableIdentity
		kept     bool
	}{
		{"live identity is the recorded one", created, created, unsignalableIdentitySame, true},
		{"live identity cannot be read", "", created, unsignalableIdentityUnknown, true},
		{"live identity contradicts the record", created, "1", unsignalableIdentityReused, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delete(table, pid)
			if tc.live != "" {
				table[pid] = tc.live
			}
			d := New(t.TempDir())
			info := pidInfo{PID: pid, Executable: os.Args[0], DataDir: d.dataDir, StartIdentity: tc.recorded}
			data, err := json.Marshal(info)
			if err != nil {
				t.Fatal(err)
			}
			if err := safefile.WritePrivate(d.pidFile, data); err != nil {
				t.Fatal(err)
			}
			got := d.settleUnsignalableRecord(info)
			after, readErr := os.ReadFile(d.pidFile)
			kept := readErr == nil && string(after) == string(data)
			if kept != tc.kept {
				t.Fatalf("gateway.pid kept = %v (read %v), want %v", kept, readErr, tc.kept)
			}
			if got != tc.want {
				t.Fatalf("settleUnsignalableRecord = %d, want %d", got, tc.want)
			}
		})
	}
}
