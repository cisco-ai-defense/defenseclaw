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
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	maxActiveAgentContextFiles    = 32
	maxActiveAgentContextSessions = 256
	maxActiveAgentContextPathSize = 4 << 10
	maxActiveAgentSessionIDSize   = 512
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
	files                []string
	caseInsensitiveFiles []string
	uncertain            bool
	updatedAt            time.Time
}

type activeAgentContextSnapshot struct {
	files                []string
	caseInsensitiveFiles []string
	uncertain            bool
}

// activeAgentContextCache is an APIServer-owned, process-local authority
// cache. Its zero value is ready for use so tests and small server fixtures
// that construct APIServer directly retain the production behavior.
type activeAgentContextCache struct {
	mu        sync.Mutex
	sessions  map[activeAgentContextKey]activeAgentContextSession
	uncertain bool
	now       func() time.Time
}

func (cache *activeAgentContextCache) currentTime() time.Time {
	if cache.now != nil {
		return cache.now()
	}
	return time.Now()
}

func exactActiveAgentFile(filePath string) (string, bool, bool) {
	if filePath == "" || len(filePath) > maxActiveAgentContextPathSize ||
		strings.TrimSpace(filePath) != filePath || !filepath.IsAbs(filePath) ||
		filepath.Clean(filePath) != filePath {
		return "", false, false
	}
	canonicalName, ok := canonicalActiveAgentFileName(filepath.Base(filePath))
	if !ok {
		return "", false, false
	}
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", false, false
	}
	canonicalPath := filepath.Join(filepath.Dir(filePath), canonicalName)
	canonicalInfo, err := os.Lstat(canonicalPath)
	if err != nil || !canonicalInfo.Mode().IsRegular() ||
		canonicalInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(info, canonicalInfo) {
		return "", false, false
	}
	resolved, err := filepath.EvalSymlinks(canonicalPath)
	if err != nil || resolved != canonicalPath {
		return "", false, false
	}
	caseInsensitive := nativePOSIXFilenameCaseInsensitive(
		canonicalPath,
		canonicalInfo,
	)
	if filepath.Separator == '/' && filepath.Base(filePath) != canonicalName &&
		!caseInsensitive {
		// On POSIX, a non-canonical spelling is authoritative only when native
		// lookup proves that one directory entry serves both spellings. This
		// rejects a distinct lowercase file and a casing hard-link alias on a
		// case-sensitive filesystem.
		return "", false, false
	}
	return canonicalPath, caseInsensitive, true
}

func canonicalActiveAgentFileName(value string) (string, bool) {
	for _, canonical := range []string{"AGENTS.md", "MEMORY.md"} {
		if activeAgentASCIIEqualFold(value, canonical) {
			return canonical, true
		}
	}
	return "", false
}

// nativePOSIXFilenameCaseInsensitive runs only while an authenticated
// InstructionsLoaded event is being recorded. The later synchronous tool
// policy path consumes the cached result and never touches the filesystem.
func nativePOSIXFilenameCaseInsensitive(filePath string, info os.FileInfo) bool {
	if filepath.Separator != '/' {
		return false
	}
	base := filepath.Base(filePath)
	aliasPath := filepath.Join(filepath.Dir(filePath), strings.ToLower(base))
	if aliasPath == filePath {
		return false
	}
	aliasInfo, err := os.Lstat(aliasPath)
	if err != nil || !aliasInfo.Mode().IsRegular() ||
		aliasInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, aliasInfo) {
		return false
	}
	directory, err := os.Open(filepath.Dir(filePath))
	if err != nil {
		return false
	}
	defer directory.Close()

	matches := 0
	for {
		entries, readErr := directory.ReadDir(64)
		for _, entry := range entries {
			if activeAgentASCIIEqualFold(entry.Name(), base) {
				matches++
				if matches > 1 {
					return false
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return false
		}
	}
	// A case-sensitive directory can contain a differently cased hard link.
	// Accept folding only when one directory entry serves both spellings.
	return matches == 1
}

func activeAgentASCIIEqualFold(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		leftByte := left[index]
		rightByte := right[index]
		if leftByte >= 'A' && leftByte <= 'Z' {
			leftByte += 'a' - 'A'
		}
		if rightByte >= 'A' && rightByte <= 'Z' {
			rightByte += 'a' - 'A'
		}
		if leftByte != rightByte {
			return false
		}
	}
	return true
}

func validActiveAgentContextKey(connectorName, sessionID string) (activeAgentContextKey, bool) {
	connectorName = canonicalConnectorRulePackKey(connectorName)
	if connectorName == "" || sessionID == "" ||
		len(sessionID) > maxActiveAgentSessionIDSize || strings.TrimSpace(sessionID) != sessionID {
		return activeAgentContextKey{}, false
	}
	return activeAgentContextKey{connector: connectorName, sessionID: sessionID}, true
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
		// The evicted session may still be active because only authenticated
		// lifecycle events can prove otherwise. Keep that loss of exact context
		// explicit so a later tool request cannot turn it into a safe negative.
		cache.uncertain = true
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
	canonicalPath, caseInsensitive, valid := exactActiveAgentFile(filePath)
	if !valid {
		return
	}
	cache.seedLoadedFile(
		key,
		canonicalPath,
		caseInsensitive,
		cache.currentTime(),
	)
}

func (cache *activeAgentContextCache) seedLoadedFile(
	key activeAgentContextKey,
	canonicalPath string,
	caseInsensitive bool,
	now time.Time,
) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.sessions == nil {
		cache.sessions = make(map[activeAgentContextKey]activeAgentContextSession)
	}
	session, exists := cache.sessions[key]
	if !exists {
		cache.makeRoomLocked()
		session = activeAgentContextSession{
			uncertain: cache.uncertain,
			updatedAt: now,
		}
	}
	for _, existing := range session.files {
		if existing == canonicalPath {
			session.setCaseInsensitive(canonicalPath, caseInsensitive)
			session.updatedAt = now
			cache.sessions[key] = session
			return
		}
	}
	if len(session.files) >= maxActiveAgentContextFiles {
		session.uncertain = true
		session.updatedAt = now
		cache.sessions[key] = session
		return
	}
	session.files = append(session.files, canonicalPath)
	session.setCaseInsensitive(canonicalPath, caseInsensitive)
	session.updatedAt = now
	cache.sessions[key] = session
}

func (session *activeAgentContextSession) setCaseInsensitive(
	filePath string,
	enabled bool,
) {
	index := slices.Index(session.caseInsensitiveFiles, filePath)
	if enabled && index < 0 {
		session.caseInsensitiveFiles = append(
			session.caseInsensitiveFiles,
			filePath,
		)
	} else if !enabled && index >= 0 {
		session.caseInsensitiveFiles = slices.Delete(
			session.caseInsensitiveFiles,
			index,
			index+1,
		)
	}
}

func (cache *activeAgentContextCache) begin(connectorName, sessionID string) {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return
	}
	now := cache.currentTime()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.sessions == nil {
		cache.sessions = make(map[activeAgentContextKey]activeAgentContextSession)
	}
	if _, exists := cache.sessions[key]; !exists {
		cache.makeRoomLocked()
	}
	// SessionStart and CwdChanged are authenticated lifecycle proof that no
	// previously loaded instruction file remains active for this session.
	cache.sessions[key] = activeAgentContextSession{updatedAt: now}
}

func (cache *activeAgentContextCache) end(connectorName, sessionID string) {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return
	}
	cache.mu.Lock()
	delete(cache.sessions, key)
	cache.mu.Unlock()
}

func (cache *activeAgentContextCache) snapshot(connectorName, sessionID string) activeAgentContextSnapshot {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	now := cache.currentTime()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, ok := cache.sessions[key]
	if !ok {
		return activeAgentContextSnapshot{uncertain: cache.uncertain}
	}
	session.updatedAt = now
	cache.sessions[key] = session
	return activeAgentContextSnapshot{
		files: append([]string(nil), session.files...),
		caseInsensitiveFiles: append(
			[]string(nil),
			session.caseInsensitiveFiles...,
		),
		uncertain: session.uncertain,
	}
}

// applyClaudeCodeActiveAgentContext consumes only authenticated, typed Claude
// Code lifecycle fields. It never reads req.Payload or ToolInput, preventing a
// generic payload, command mention, or tool argument from manufacturing trusted
// instruction-file context.
func (a *APIServer) applyClaudeCodeActiveAgentContext(ctx context.Context, req claudeCodeHookRequest) activeAgentContextSnapshot {
	const connectorName = "claudecode"
	if a == nil || authenticatedHookConnector(ctx) != connectorName {
		return activeAgentContextSnapshot{}
	}
	switch req.HookEventName {
	case "SessionStart", "CwdChanged":
		a.activeAgentContext.begin(connectorName, req.SessionID)
	case "SessionEnd":
		a.activeAgentContext.end(connectorName, req.SessionID)
	case "InstructionsLoaded":
		a.activeAgentContext.seed(connectorName, req.SessionID, req.FilePath)
	case "PreToolUse", "PermissionRequest":
		return a.activeAgentContext.snapshot(connectorName, req.SessionID)
	}
	return activeAgentContextSnapshot{}
}
