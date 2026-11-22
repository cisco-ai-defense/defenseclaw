// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"sync"
	"time"
)

// OpenClaw names a session two ways: the session key (agent:<id>:<name>),
// which its gateway stream and the event router use, and the transcript's
// session id. The router keeps the user's task under the session key
// (scanInboundPrompt), and the OpenClaw plugin sends that key on every
// request. The plugin of 1.0.9 and earlier sent the session id first on
// /api/v1/inspect/tool, so the tool judge looked for the task under a key it
// was never stored under (rel-1-0-10:GAP-0148). After an upgrade OpenClaw
// keeps running the plugin it loaded until it restarts, so the router learns
// which key each session id belongs to from the stream's agent events, and
// the tool check of such a plugin is judged under the key. Kept while an
// upgrade can start from a 1.0.9 or earlier plugin.

const (
	openClawSessionAliasTTL = time.Hour
	openClawSessionAliasCap = 1024
)

type openClawSessionAlias struct {
	key string
	at  time.Time
}

var openClawSessionAliases struct {
	mu   sync.Mutex
	byID map[string]openClawSessionAlias
	now  func() time.Time
}

func openClawSessionAliasNow() time.Time {
	if openClawSessionAliases.now != nil {
		return openClawSessionAliases.now()
	}
	return time.Now()
}

// learnOpenClawSessionAlias records that the stream named sessionID as the
// session id of sessionKey.
func learnOpenClawSessionAlias(sessionID, sessionKey string) {
	sessionID, sessionKey = strings.TrimSpace(sessionID), strings.TrimSpace(sessionKey)
	if sessionID == "" || sessionKey == "" || sessionID == sessionKey {
		return
	}
	openClawSessionAliases.mu.Lock()
	defer openClawSessionAliases.mu.Unlock()
	now := openClawSessionAliasNow()
	if openClawSessionAliases.byID == nil {
		openClawSessionAliases.byID = make(map[string]openClawSessionAlias)
	}
	if _, known := openClawSessionAliases.byID[sessionID]; !known && len(openClawSessionAliases.byID) >= openClawSessionAliasCap {
		// Drop the expired entries, then the oldest one, to stay in the cap.
		oldestID, oldest := "", now
		for id, alias := range openClawSessionAliases.byID {
			if now.Sub(alias.at) >= openClawSessionAliasTTL {
				delete(openClawSessionAliases.byID, id)
			} else if !alias.at.After(oldest) {
				oldestID, oldest = id, alias.at
			}
		}
		if len(openClawSessionAliases.byID) >= openClawSessionAliasCap {
			delete(openClawSessionAliases.byID, oldestID)
		}
	}
	openClawSessionAliases.byID[sessionID] = openClawSessionAlias{key: sessionKey, at: now}
}

// openClawSessionKeyFor is the session key the stream named for sessionID,
// or "" when it named none in the last hour.
func openClawSessionKeyFor(sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ""
	}
	openClawSessionAliases.mu.Lock()
	defer openClawSessionAliases.mu.Unlock()
	alias, ok := openClawSessionAliases.byID[sessionID]
	if !ok || openClawSessionAliasNow().Sub(alias.at) >= openClawSessionAliasTTL {
		return ""
	}
	return alias.key
}

// withOpenClawSessionKey puts the session key on ctx in place of a session id
// the stream named for it, so the judge reads the session's task and calls.
func withOpenClawSessionKey(ctx context.Context) context.Context {
	if key := openClawSessionKeyFor(SessionIDFromContext(ctx)); key != "" {
		return ContextWithSessionID(ctx, key)
	}
	return ctx
}
