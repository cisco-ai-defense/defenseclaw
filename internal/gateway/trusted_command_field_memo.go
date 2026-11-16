// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"sync"
	"time"
)

const (
	// commandFieldMemoMin is the size of tool arguments from which the
	// answer of trustedTopLevelCommandField is remembered. About twenty
	// proofs of one call each read the command field of the same arguments;
	// for an 889 KB patch every read was a full JSON decode (GAP-1040).
	// Smaller arguments are decoded each time, as before.
	commandFieldMemoMin = 64 << 10
	// commandFieldMemoMax bounds the arguments remembered.
	commandFieldMemoMax = 4 << 20
	// commandFieldMemoEntries bounds how many arguments are remembered.
	commandFieldMemoEntries = 4
	// commandFieldMemoLife is how long an answer is kept: one hook call, with
	// room for a retry.
	commandFieldMemoLife = 30 * time.Second
)

type commandFieldMemoEntry struct {
	raw          []byte // a private copy, so a later edit of the caller bytes never matches
	command      string
	found, valid bool
	at           time.Time
}

var commandFieldMemo struct {
	sync.Mutex
	entries []commandFieldMemoEntry
}

// trustedTopLevelCommandField is decodeTrustedTopLevelCommandField with the
// answer for large arguments remembered for a short time. The answer is a
// pure function of the bytes, which are compared in full.
func trustedTopLevelCommandField(raw json.RawMessage) (string, bool, bool) {
	if len(raw) < commandFieldMemoMin || len(raw) > commandFieldMemoMax {
		return decodeTrustedTopLevelCommandField(raw)
	}
	now := time.Now()
	commandFieldMemo.Lock()
	kept := commandFieldMemo.entries[:0]
	for _, entry := range commandFieldMemo.entries {
		if now.Sub(entry.at) < commandFieldMemoLife {
			kept = append(kept, entry)
		}
	}
	commandFieldMemo.entries = kept
	for _, entry := range kept {
		if bytes.Equal(entry.raw, raw) {
			commandFieldMemo.Unlock()
			return entry.command, entry.found, entry.valid
		}
	}
	commandFieldMemo.Unlock()
	command, found, valid := decodeTrustedTopLevelCommandField(raw)
	entry := commandFieldMemoEntry{raw: bytes.Clone(raw), command: command, found: found, valid: valid, at: time.Now()}
	commandFieldMemo.Lock()
	if len(commandFieldMemo.entries) >= commandFieldMemoEntries {
		commandFieldMemo.entries = append(commandFieldMemo.entries[:0], commandFieldMemo.entries[1:]...)
	}
	commandFieldMemo.entries = append(commandFieldMemo.entries, entry)
	commandFieldMemo.Unlock()
	return command, found, valid
}
