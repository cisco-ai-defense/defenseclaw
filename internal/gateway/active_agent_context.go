// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxActiveAgentContextFiles    = 32
	maxActiveAgentContextSessions = 256
	maxActiveAgentContextPathSize = 4 << 10
	maxActiveAgentSessionIDSize   = 512
	activeAgentContextTTL         = 30 * time.Minute
)

type authenticatedHookConnectorContextKey struct{}

func withAuthenticatedHookConnector(ctx context.Context, connectorName string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	connectorName = canonicalConnectorRulePackKey(connectorName)
	if connectorName == "" {
		return ctx
	}
	return context.WithValue(ctx, authenticatedHookConnectorContextKey{}, connectorName)
}

func authenticatedHookConnector(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	connectorName, _ := ctx.Value(authenticatedHookConnectorContextKey{}).(string)
	return canonicalConnectorRulePackKey(connectorName)
}

type activeAgentContextKey struct {
	connector string
	sessionID string
}

type activeAgentContextSession struct {
	files     []string
	updatedAt time.Time
}

// activeAgentContextCache is an APIServer-owned, process-local authority
// cache. Its zero value is ready for use so tests and small server fixtures
// that construct APIServer directly retain the production behavior.
type activeAgentContextCache struct {
	mu       sync.Mutex
	sessions map[activeAgentContextKey]activeAgentContextSession
	now      func() time.Time
}

func (cache *activeAgentContextCache) currentTime() time.Time {
	if cache.now != nil {
		return cache.now()
	}
	return time.Now()
}

func exactActiveAgentFile(filePath string) (string, bool) {
	if filePath == "" || len(filePath) > maxActiveAgentContextPathSize ||
		strings.TrimSpace(filePath) != filePath || !filepath.IsAbs(filePath) ||
		filepath.Clean(filePath) != filePath {
		return "", false
	}
	switch filepath.Base(filePath) {
	case "AGENTS.md", "MEMORY.md":
	default:
		return "", false
	}
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(filePath)
	if err != nil || resolved != filePath {
		return "", false
	}
	return filePath, true
}

func validActiveAgentContextKey(connectorName, sessionID string) (activeAgentContextKey, bool) {
	connectorName = canonicalConnectorRulePackKey(connectorName)
	if connectorName == "" || sessionID == "" ||
		len(sessionID) > maxActiveAgentSessionIDSize || strings.TrimSpace(sessionID) != sessionID {
		return activeAgentContextKey{}, false
	}
	return activeAgentContextKey{connector: connectorName, sessionID: sessionID}, true
}

func (cache *activeAgentContextCache) pruneLocked(now time.Time) {
	for key, session := range cache.sessions {
		if now.Sub(session.updatedAt) >= activeAgentContextTTL {
			delete(cache.sessions, key)
		}
	}
}

func (cache *activeAgentContextCache) makeRoomLocked() {
	if len(cache.sessions) < maxActiveAgentContextSessions {
		return
	}
	var oldestKey activeAgentContextKey
	var oldestTime time.Time
	found := false
	for key, session := range cache.sessions {
		if !found || session.updatedAt.Before(oldestTime) ||
			session.updatedAt.Equal(oldestTime) && activeAgentContextKeyLess(key, oldestKey) {
			oldestKey = key
			oldestTime = session.updatedAt
			found = true
		}
	}
	if found {
		delete(cache.sessions, oldestKey)
	}
}

func activeAgentContextKeyLess(left, right activeAgentContextKey) bool {
	if left.connector != right.connector {
		return left.connector < right.connector
	}
	return left.sessionID < right.sessionID
}

func (cache *activeAgentContextCache) seed(connectorName, sessionID, filePath string) {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return
	}
	canonicalPath, valid := exactActiveAgentFile(filePath)
	if !valid {
		return
	}
	now := cache.currentTime()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.sessions == nil {
		cache.sessions = make(map[activeAgentContextKey]activeAgentContextSession)
	}
	cache.pruneLocked(now)
	session, exists := cache.sessions[key]
	if !exists {
		cache.makeRoomLocked()
		session = activeAgentContextSession{updatedAt: now}
	}
	for _, existing := range session.files {
		if existing == canonicalPath {
			session.updatedAt = now
			cache.sessions[key] = session
			return
		}
	}
	if len(session.files) >= maxActiveAgentContextFiles {
		return
	}
	session.files = append(session.files, canonicalPath)
	session.updatedAt = now
	cache.sessions[key] = session
}

func (cache *activeAgentContextCache) reset(connectorName, sessionID string) {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return
	}
	cache.mu.Lock()
	delete(cache.sessions, key)
	cache.mu.Unlock()
}

func (cache *activeAgentContextCache) snapshot(connectorName, sessionID string) []string {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return nil
	}
	now := cache.currentTime()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.pruneLocked(now)
	session, ok := cache.sessions[key]
	if !ok || len(session.files) == 0 {
		return nil
	}
	session.updatedAt = now
	cache.sessions[key] = session
	return append([]string(nil), session.files...)
}

// applyClaudeCodeActiveAgentContext consumes only authenticated, typed Claude
// Code lifecycle fields. It never reads req.Payload or ToolInput, preventing a
// generic payload, command mention, or tool argument from manufacturing trusted
// instruction-file context.
func (a *APIServer) applyClaudeCodeActiveAgentContext(ctx context.Context, req claudeCodeHookRequest) []string {
	const connectorName = "claudecode"
	if a == nil || authenticatedHookConnector(ctx) != connectorName {
		return nil
	}
	switch req.HookEventName {
	case "SessionStart", "CwdChanged":
		a.activeAgentContext.reset(connectorName, req.SessionID)
	case "SessionEnd":
		a.activeAgentContext.reset(connectorName, req.SessionID)
	case "InstructionsLoaded":
		a.activeAgentContext.seed(connectorName, req.SessionID, req.FilePath)
	case "PreToolUse":
		return a.activeAgentContext.snapshot(connectorName, req.SessionID)
	}
	return nil
}
