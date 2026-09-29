// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
)

// Foreign-hook removals.
//
// An agent keeps the hooks its process loaded at start, and some agents send
// their session-start event only with the first prompt (Hermes), so the
// session-start snapshot can miss a hook the guardian removed in between.
// The guardian therefore records each removal (account, connector, file and
// time) in its protected authorization directory, and the gateway denies the
// calls of that account's agent processes of that connector that started
// before the removal: they may still run the hook. A process that started
// afterwards loaded the cleaned files, and other accounts and connectors are
// not affected. A process DefenseClaw cannot name has no start time to
// compare, so only its session-start snapshot applies.

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

// ForeignHookRemoval is one hook file the guardian cleaned for an account.
type ForeignHookRemoval struct {
	// Identity is the account as the gateway names a verified caller: a
	// decimal uid or an upper-case SID.
	Identity  string `json:"identity"`
	Connector string `json:"connector"`
	Path      string `json:"path"`
	// At is when the removal was recorded, after the file was cleaned, and
	// Mark is the same instant as an agent process start time
	// (agentprocess.Now).
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
		if _, err := time.Parse(time.RFC3339Nano, removal.At); err != nil || removal.Identity == "" ||
			removal.Connector == "" || removal.Path == "" || removal.Mark == "" {
			return nil, errors.New("foreign-hook removal ledger contains an incomplete entry")
		}
	}
	return ledger.Removals, nil
}

// EncodeForeignHookRemovals adds added to existing, keeping the latest entry
// per account, connector and file, drops the entries older than
// sessionRecordTTL (a session block lasts as long) and keeps the newest
// foreignHookRemovalsLimit, and encodes the ledger.
func EncodeForeignHookRemovals(existing, added []ForeignHookRemoval, now time.Time) ([]byte, error) {
	type dated struct {
		removal ForeignHookRemoval
		at      time.Time
	}
	latest := map[string]dated{}
	for _, removal := range append(append([]ForeignHookRemoval{}, existing...), added...) {
		at, err := time.Parse(time.RFC3339Nano, removal.At)
		if err != nil || now.Sub(at) > sessionRecordTTL {
			continue
		}
		key := removal.Identity + "\x00" + removal.Connector + "\x00" + removal.Path
		if previous, ok := latest[key]; !ok || !at.Before(previous.at) {
			latest[key] = dated{removal, at}
		}
	}
	entries := make([]dated, 0, len(latest))
	for _, entry := range latest {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].at.Equal(entries[j].at) {
			return entries[i].at.After(entries[j].at)
		}
		return entries[i].removal.Path < entries[j].removal.Path
	})
	if len(entries) > foreignHookRemovalsLimit {
		entries = entries[:foreignHookRemovalsLimit]
	}
	ledger := foreignHookRemovalLedger{Version: foreignHookRemovalsVersion, Removals: []ForeignHookRemoval{}}
	for _, entry := range entries {
		ledger.Removals = append(ledger.Removals, entry.removal)
	}
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
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
		Reason:    "removed after this agent process started",
	}}, decision.Findings...)
	return decision
}
