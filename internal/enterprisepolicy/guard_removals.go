// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Foreign-hook removals.
//
// An agent keeps the hooks its process loaded at start, and some agents send
// their session-start event only with the first prompt (Hermes), so the
// session-start snapshot can miss a hook the guardian removed in between.
// The guardian therefore records each removal (account, connector, file and
// time) in its protected authorization directory, and the gateway denies the
// calls of that account's agent processes of that connector (and of any
// other that loads the file) that started before the removal: they may
// still run the hook. A process that started afterwards loaded the cleaned
// files, and other accounts and connectors are not affected. A process
// DefenseClaw cannot name has no start time to compare, so only its
// session-start snapshot applies.

// ForeignHookRemovalsFile is the removal ledger in the hook guardian's
// authorization directory. The guardian writes it; the gateway reads it.
const ForeignHookRemovalsFile = "foreign-hook-removals.json"

const (
	foreignHookRemovalsVersion = 1
	// ForeignHookRemovalsMaxBytes bounds the ledger file.
	ForeignHookRemovalsMaxBytes = 1 << 20
	// foreignHookRemovalsLimit bounds the entries; the newest are kept.
	foreignHookRemovalsLimit = 1024
)

// ForeignHookRemovalInProgressSuffix ends the path of the first record of a
// removal (made before the file changes, with a mark ahead): the removal's
// commit drops that exact entry when it records the change
// (EncodeForeignHookRemovalsDropping). One a guardian left when it ended
// mid-removal stays, and denies, for its TTL.
const ForeignHookRemovalInProgressSuffix = " (removal in progress)"

// ForeignHookRemoval is one hook file the guardian cleaned for an account.
type ForeignHookRemoval struct {
	// Identity is the account as the gateway names a verified caller: a
	// decimal uid or an upper-case SID.
	Identity  string `json:"identity"`
	Connector string `json:"connector"`
	Path      string `json:"path"`
	// At is when the removal was recorded, and Mark an instant as an agent
	// process start time (agentprocess.Now): processes that started no later
	// than Mark are denied. The guardian records each removal twice under
	// the account's removal lock: before the file changes, with Mark a
	// bounded time ahead (agentprocess.NowAfter), so a guardian that ends
	// in between leaves every process that may have loaded the file denied,
	// and once the change is done, with Mark now, which replaces the first.
	At   string `json:"at"`
	Mark string `json:"mark"`
}

type foreignHookRemovalLedger struct {
	Version  int                  `json:"version"`
	Removals []ForeignHookRemoval `json:"removals"`
}

// ParseForeignHookRemovals decodes the ledger. Anything but a complete
// version 1 ledger is an error.
func ParseForeignHookRemovals(data []byte) ([]ForeignHookRemoval, error) {
	if len(data) > ForeignHookRemovalsMaxBytes {
		return nil, errors.New("foreign-hook removal ledger exceeds the size limit")
	}
	var ledger foreignHookRemovalLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		return nil, fmt.Errorf("parse foreign-hook removal ledger: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse foreign-hook removal ledger: trailing content")
	}
	if ledger.Version != foreignHookRemovalsVersion || len(ledger.Removals) > foreignHookRemovalsLimit {
		return nil, errors.New("foreign-hook removal ledger has an invalid schema")
	}
	for _, removal := range ledger.Removals {
		if _, err := time.Parse(time.RFC3339Nano, removal.At); err != nil || !removal.complete() {
			return nil, errors.New("foreign-hook removal ledger contains an incomplete entry")
		}
	}
	return ledger.Removals, nil
}

func (r ForeignHookRemoval) complete() bool {
	return r.Identity != "" && r.Connector != "" && r.Path != "" && r.Mark != ""
}

// foreignHookRemovalIndent bounds what indentation adds to one encoded
// entry, and to the ledger around them.
const foreignHookRemovalIndent = 64

// EncodeForeignHookRemovals adds added to existing, keeping the latest entry
// per account, connector and file, drops incomplete entries and those older
// than sessionRecordTTL (a session block lasts as long), and encodes the
// ledger within foreignHookRemovalsLimit and ForeignHookRemovalsMaxBytes.
// The gateway denies every account's calls while the ledger does not parse,
// so one account's removals (paths the user names) must never make it
// unreadable.
//
// What a full ledger drops must not end a denial (GAP-0352 review loop
// round 4): one account's many removals evicted another account's only
// one, and that account's agent, still running the removed hook, was
// allowed again. So the ledger first keeps each account's and connector's
// horizon (foreignHookRemovalHorizon), the one entry that denies every agent
// process any other entry of the pair denies, newest pair first, and then
// the other entries, newest first, while they fit. An account can only
// crowd out its own entries. When the horizons alone do not fit (more
// account and connector pairs within the TTL than the ledger holds), the
// encoding fails, and the guardian removes nothing: the hook stays in
// place, so the scan keeps blocking (ErrForeignHookRemovalLedgerFull).
func EncodeForeignHookRemovals(existing, added []ForeignHookRemoval, now time.Time) ([]byte, error) {
	return EncodeForeignHookRemovalsDropping(existing, added, nil, now)
}

// EncodeForeignHookRemovalsDropping is EncodeForeignHookRemovals that first
// drops the entries of existing equal to one of dropped: a removal commit
// drops its own first record. Per account, connector and file the entry
// with the later mark wins (removalMarkedAfter), whatever order the
// guardian processes published in, so an older cleanup published last never
// replaces a newer removal.
func EncodeForeignHookRemovalsDropping(existing, added, dropped []ForeignHookRemoval, now time.Time) ([]byte, error) {
	if len(dropped) != 0 {
		kept := make([]ForeignHookRemoval, 0, len(existing))
		for _, removal := range existing {
			// The time is not compared: the horizon may have moved it.
			if !slices.ContainsFunc(dropped, func(drop ForeignHookRemoval) bool {
				return drop.Identity == removal.Identity && drop.Connector == removal.Connector && drop.Path == removal.Path && drop.Mark == removal.Mark
			}) {
				kept = append(kept, removal)
			}
		}
		existing = kept
	}
	type dated struct {
		removal ForeignHookRemoval
		at      time.Time
		key     string
		size    int
		horizon bool
	}
	latest := map[string]dated{}
	for _, removal := range append(append([]ForeignHookRemoval{}, existing...), added...) {
		at, err := time.Parse(time.RFC3339Nano, removal.At)
		if err != nil || now.Sub(at) > sessionRecordTTL || !removal.complete() {
			continue
		}
		key := removal.Identity + "\x00" + removal.Connector + "\x00" + removal.Path
		if previous, ok := latest[key]; !ok || removalMarkedAfter(removal, at, previous.removal, previous.at) {
			latest[key] = dated{removal: removal, at: at, key: key}
		}
	}
	entries := make([]dated, 0, len(latest))
	for _, entry := range latest {
		entries = append(entries, entry)
	}
	newestFirst := func(entries []dated) {
		sort.Slice(entries, func(i, j int) bool {
			if !entries[i].at.Equal(entries[j].at) {
				return entries[i].at.After(entries[j].at)
			}
			return entries[i].key < entries[j].key
		})
	}
	newestFirst(entries)
	// The horizon of each pair: the latest mark of each boot, kept as long
	// as the pair's newest entry lives.
	type horizon struct {
		index int
		clock int64
		at    time.Time
	}
	horizons := map[string]horizon{}
	for i, entry := range entries {
		key, clock := foreignHookRemovalHorizon(entry.removal)
		current, ok := horizons[key]
		switch {
		case !ok:
			horizons[key] = horizon{index: i, clock: clock, at: entry.at}
		case clock > current.clock:
			current.index, current.clock = i, clock
			horizons[key] = current
		}
	}
	for _, h := range horizons {
		entry := &entries[h.index]
		entry.horizon = true
		if entry.at.Before(h.at) {
			entry.at = h.at
			entry.removal.At = h.at.Format(time.RFC3339Nano)
		}
	}
	for i := range entries {
		encoded, err := json.Marshal(entries[i].removal)
		if err != nil {
			return nil, err
		}
		entries[i].size = len(encoded) + foreignHookRemovalIndent
	}
	newestFirst(entries)
	kept := make([]dated, 0, min(len(entries), foreignHookRemovalsLimit))
	size := foreignHookRemovalIndent
	fits := func(entry dated) bool {
		if len(kept) == foreignHookRemovalsLimit || size+entry.size > ForeignHookRemovalsMaxBytes {
			return false
		}
		kept, size = append(kept, entry), size+entry.size
		return true
	}
	for _, entry := range entries {
		if entry.horizon && !fits(entry) {
			return nil, ErrForeignHookRemovalLedgerFull
		}
	}
	for _, entry := range entries {
		if !entry.horizon {
			fits(entry)
		}
	}
	newestFirst(kept)
	ledger := foreignHookRemovalLedger{Version: foreignHookRemovalsVersion, Removals: make([]ForeignHookRemoval, 0, len(kept))}
	for _, entry := range kept {
		ledger.Removals = append(ledger.Removals, entry.removal)
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return nil, err
	}
	if data = append(data, '\n'); len(data) > ForeignHookRemovalsMaxBytes {
		return nil, errors.New("foreign-hook removal ledger exceeds the size limit")
	}
	return data, nil
}

// ErrForeignHookRemovalLedgerFull is a ledger that cannot keep the denial of
// every account and connector together with the new removals.
var ErrForeignHookRemovalLedgerFull = errors.New("the foreign-hook removal ledger cannot keep every account's denial")

// removalMarkedAfter reports whether removal (dated at) denies no fewer
// agent processes than previous (dated previousAt): its mark is later in
// the same boot, or, when the marks cannot be ordered or are equal, it was
// recorded no earlier.
func removalMarkedAfter(removal ForeignHookRemoval, at time.Time, previous ForeignHookRemoval, previousAt time.Time) bool {
	if order, ok := agentprocess.CompareMarks(removal.Mark, previous.Mark); ok && order != 0 {
		return order > 0
	}
	return !at.Before(previousAt)
}

// foreignHookRemovalHorizon names the pair (account, connector and the boot
// of the mark) a removal denies agent processes for, and the mark's clock.
// Within one boot, the entry with the latest mark denies every agent
// process an earlier mark of the pair denies (agentprocess.StartedBefore);
// a mark of another boot denies none of this boot's processes. A mark that
// does not parse (clock -1) is its own pair.
func foreignHookRemovalHorizon(removal ForeignHookRemoval) (string, int64) {
	identity := removal.Identity
	if canonical, ok := connector.CanonicalUserScopedIdentity(identity); ok {
		identity = canonical
	}
	boot, clock := removal.Mark, int64(-1)
	if i := strings.LastIndexByte(removal.Mark, ':'); i >= 0 {
		if parsed, err := strconv.ParseInt(removal.Mark[i+1:], 10, 64); err == nil {
			boot, clock = removal.Mark[:i], parsed
		}
	}
	return identity + "\x00" + strings.ToLower(removal.Connector) + "\x00" + boot, clock
}

// ForeignHookRemovalConnectors returns connector and each of candidates
// whose agent loads the user file path from its default location under
// home: Cursor and Devin also load Claude Code's ~/.claude/settings.json. A
// pass removes an entry once, for the first connector it cleans, so the
// removal is recorded for every agent that may have loaded it.
func ForeignHookRemovalConnectors(home, path, connector string, candidates []string) []string {
	out := []string{connector}
	for _, name := range candidates {
		if slices.Contains(out, name) {
			continue
		}
		for _, source := range guardSources(GuardRequest{Connector: name, Home: home, AccountHome: home}) {
			if source.scope == ScopeUser && samePath(filepath.Clean(source.path), filepath.Clean(path)) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// removalAfterProcessStart returns the earliest live removal of the key's
// connector that the guardian recorded after the key's agent process
// started.
func removalAfterProcessStart(removals []ForeignHookRemoval, key SessionKey, now time.Time) (ForeignHookRemoval, bool) {
	var found ForeignHookRemoval
	var foundAt time.Time
	for _, removal := range removals {
		if !strings.EqualFold(removal.Connector, key.Connector) || !agentprocess.StartedBefore(key.Process, removal.Mark) {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, removal.At)
		if err != nil || now.Sub(at) > sessionRecordTTL {
			continue
		}
		if foundAt.IsZero() || at.Before(foundAt) {
			found, foundAt = removal, at
		}
	}
	return found, !foundAt.IsZero()
}

// sessionRemovedNote ends a denial for an agent process that started before
// the guardian removed a hook.
const sessionRemovedNote = "The agent can keep running a hook it loaded when it started, even after the file changes, so DefenseClaw blocks this agent's tool calls until it restarts: restart the agent."

// removedSessionReason is the reason of a block for an agent process that
// started before the guardian removed one of its connector's hooks.
const removedSessionReason = "removed after this agent process started"

// removedHookDecision denies a call of an agent process that started before
// the guardian removed an unapproved hook of its connector for this account.
func removedHookDecision(decision GuardDecision, connector string, removal ForeignHookRemoval) GuardDecision {
	decision.Deny = true
	decision.Reason = fmt.Sprintf(
		"enterprise_foreign_hook_blocked: your organization blocks %s hooks it has not approved, because they can change a tool call after DefenseClaw checks it. This agent started before DefenseClaw removed an unapproved hook from %s at %s. %s",
		connector, removal.Path, removal.At, sessionRemovedNote,
	)
	decision.Findings = append([]Finding{{
		Connector: connector,
		Path:      removal.Path,
		Reason:    removedSessionReason,
	}}, decision.Findings...)
	return decision
}
