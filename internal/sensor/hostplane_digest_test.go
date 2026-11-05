// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// The counters name the digest state of the client execs a live run saw,
// and of the ones it recorded.
func TestClientExecCountsByDigestState(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	host := newHost(newFake(fullCoverage()))
	host.coldHold = 0
	host.clientChecksums = func(string) ([][32]byte, bool) { return [][32]byte{release}, true }
	uid := os.Getuid() + 1000
	at := time.Unix(1_760_000_000, 0)
	const prompt = `claude -p use @modelcontextprotocol/server-filesystem`
	for i, state := range []plane.DigestState{plane.DigestRead, plane.DigestFailed, "", plane.DigestPending} {
		sum := ""
		if state == plane.DigestRead {
			sum = hex.EncodeToString(release[:])
		}
		host.handle(plane.Event{Kind: plane.KindExec, PID: 500 + i, PPID: 1, Name: "claude", Cmdline: prompt,
			UID: &uid, At: at, ImageVersion: "2.1.317", ImageSHA256: sum, ImageDigestState: state})
	}
	want := map[string]int64{"read": 1, "failed": 1, "failed_reported": 1, "unstated": 1, "unstated_reported": 1,
		"pending": 1, "pending_reported": 1}
	got := host.clientExecs.counts()
	if len(got) != len(want) {
		t.Fatalf("counts %v, want %v", got, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("counts %v, want %v", got, want)
		}
	}
}
