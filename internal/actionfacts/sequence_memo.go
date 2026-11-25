// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"sync"
	"time"
)

// The split of a call into its statements (sequenceStatementDetails) is a
// function of the text and the four reading flags only, and one hook asks
// for the same split of the same large call many times: the semantic
// splitter, the statement budget and, for a sandbox call, the guest
// placement plan each split the whole call again (substrate-1 GAP-1028: two
// of the guest plan's splits were a third of its CPU). A source of
// sequenceMemoMinSource bytes or more keeps its split for a short time, and
// every caller gets its own copy of the statements.
const (
	// sequenceMemoMinSource is the size from which a split is kept; a short
	// source is split again, as before.
	sequenceMemoMinSource = 1 << 10
	// sequenceMemoEntries bounds how many splits are kept.
	sequenceMemoEntries = 8
	// sequenceMemoLife is how long a kept split stays: one hook call, with
	// room for a retry.
	sequenceMemoLife = 30 * time.Second
)

type sequenceMemoKey struct {
	source                                      string
	compound, allSimple, straight, walkUncalled bool
}

type sequenceMemoEntry struct {
	key         sequenceMemoKey
	statements  []sequenceStatement // as split, never handed out
	reduced, ok bool
	at          time.Time
}

var sequenceMemo struct {
	sync.Mutex
	entries []sequenceMemoEntry
}

// sequenceStatementDetails is sequenceStatementDetailsWalk, kept for a
// large source (sequenceMemoMinSource).
func sequenceStatementDetails(source string, compound, allSimple, straight, walkUncalled bool) (statements []sequenceStatement, reduced, ok bool) {
	if len(source) < sequenceMemoMinSource {
		return sequenceStatementDetailsWalk(source, compound, allSimple, straight, walkUncalled)
	}
	key := sequenceMemoKey{source, compound, allSimple, straight, walkUncalled}
	now := time.Now()
	sequenceMemo.Lock()
	kept := sequenceMemo.entries[:0]
	for _, entry := range sequenceMemo.entries {
		if now.Sub(entry.at) < sequenceMemoLife {
			kept = append(kept, entry)
		}
	}
	clear(sequenceMemo.entries[len(kept):])
	sequenceMemo.entries = kept
	for _, entry := range kept {
		if entry.key == key {
			sequenceMemo.Unlock()
			return cloneSequenceStatements(entry.statements), entry.reduced, entry.ok
		}
	}
	sequenceMemo.Unlock()
	statements, reduced, ok = sequenceStatementDetailsWalk(source, compound, allSimple, straight, walkUncalled)
	entry := sequenceMemoEntry{key: key, statements: cloneSequenceStatements(statements), reduced: reduced, ok: ok, at: now}
	sequenceMemo.Lock()
	if len(sequenceMemo.entries) >= sequenceMemoEntries {
		sequenceMemo.entries = slices.Delete(sequenceMemo.entries, 0, 1)
	}
	sequenceMemo.entries = append(sequenceMemo.entries, entry)
	sequenceMemo.Unlock()
	return statements, reduced, ok
}

// cloneSequenceStatements copies statements and every list they hold, so a
// caller that appends to or changes one changes no other caller's copy. The
// syntax nodes the loop bindings point at are shared: no reader changes them.
func cloneSequenceStatements(statements []sequenceStatement) []sequenceStatement {
	if statements == nil {
		return nil
	}
	out := slices.Clip(slices.Clone(statements))
	for at := range out {
		statement := &out[at]
		statement.callStarts = slices.Clip(slices.Clone(statement.callStarts))
		if statement.read != nil {
			read := *statement.read
			statement.read = &read
		}
		if statement.binds != nil {
			statement.binds = slices.Clip(slices.Clone(statement.binds))
			for index := range statement.binds {
				bind := &statement.binds[index]
				bind.items = slices.Clip(slices.Clone(bind.items))
				bind.ifs = slices.Clip(slices.Clone(bind.ifs))
				bind.outerIFS = slices.Clip(slices.Clone(bind.outerIFS))
				bind.rebound = slices.Clip(slices.Clone(bind.rebound))
			}
		}
	}
	return out
}
