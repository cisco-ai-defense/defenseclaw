// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// stableReadDelays are the waits between the reads of readStable: about a
// quarter of a second in all.
var stableReadDelays = []time.Duration{
	time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond, 8 * time.Millisecond,
	16 * time.Millisecond, 32 * time.Millisecond, 64 * time.Millisecond, 128 * time.Millisecond,
}

var (
	stableReadSleep = time.Sleep
	readBounded     = safefile.ReadRegularFileBounded
)

// readStable reads the vault or its pin, which some readers do without the
// writer lock. (A pending exposure is written once, under a new name, and
// is never replaced, so it is read once.) Its writers replace it whole, by an
// atomic rename, so a read that overlaps a write sees the file change under
// it and safefile returns none of its bytes. The file at the path is then a
// whole new one, so the read is repeated. A file that keeps changing for
// longer than stableReadDelays is still an error.
func readStable(path string, maxBytes int64) ([]byte, error) {
	b, err := readBounded(path, maxBytes)
	for _, d := range stableReadDelays {
		if !errors.Is(err, safefile.ErrFileChanged) {
			break
		}
		stableReadSleep(d)
		b, err = readBounded(path, maxBytes)
	}
	return b, err
}
