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
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

const (
	maxActiveAgentContextFiles     = 32
	maxActiveAgentContextSessions  = 256
	maxActiveAgentContextEvictions = maxActiveAgentContextSessions
	maxActiveAgentContextPathSize  = 4 << 10
	maxActiveAgentSessionIDSize    = 512
	// maxStartupInstructionFiles and maxStartupDirectories bound a session's
	// instruction-file snapshot (instruction_startup.go). A directory that
	// does not fit stays unsnapshotted, so its files keep the call-time proof.
	maxStartupInstructionFiles = 256
	maxStartupDirectories      = 1024
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

// activeAgentContextKey scopes authority to one session of one connector.
// scope is the sandbox binding ID for sandbox traffic and empty for the
// host, so a sandbox that names a host session ID (or another sandbox's)
// can neither read nor reset that session's instruction-file authority.
// caller is the verified caller of a managed gateway (verifiedSessionCaller)
// and empty on a per-user gateway, so one enrolled user's session can
// neither read nor reset another user's session of the same ID.
type activeAgentContextKey struct {
	scope     string
	caller    string
	connector string
	sessionID string
}

type activeAgentContextSession struct {
	files                []string
	caseInsensitiveFiles []string
	startupFiles         map[string]string
	startupKnown         bool
	// startupDirs are the directories, normalized as instructionDirectoryKey
	// does, whose instruction files startupFiles records. A directory the
	// session had not reached is not in it (instruction_startup.go).
	startupDirs []string
	// startupDirIDs are the file system identities of startupDirs, where
	// known: another spelling of a recorded directory keeps its record.
	startupDirIDs map[string]string
	// identities maps each loaded file to the hook client's file identity
	// of it (hookpaths.LoadedIdentityPrefix). Two loaded names of one file
	// (hard links) keep one entry each (GAP-1414).
	identities map[string]string
	// awaitingStart is set while no start event of the session has reached
	// the gateway: a call (or load) came first (GAP-0973). Its first start
	// is then the start of the same session, not a new generation, so it
	// keeps what the calls before it recorded (startKey).
	awaitingStart            bool
	caseInsensitiveUncertain bool
	uncertain                bool
	// saved: the session's saved record holds its startup snapshot as it
	// is now (saveInstructionLoads). An eviction of a snapshot no record
	// holds loses the session's first sighting (lost).
	saved     bool
	updatedAt time.Time
}

type activeAgentContextSnapshot struct {
	files                    []string
	caseInsensitiveFiles     []string
	startupFiles             map[string]string
	startupKnown             bool
	startupDirs              []string
	identities               map[string]string
	caseInsensitiveUncertain bool
	uncertain                bool
}

// startupCovers reports whether the snapshot recorded the instruction files
// of directory, a key of instructionDirectoryKey.
func (snapshot activeAgentContextSnapshot) startupCovers(directory string) bool {
	return snapshot.startupKnown && slices.Contains(snapshot.startupDirs, directory)
}

type activeAgentContextEviction struct {
	caseInsensitiveUncertain bool
}

// activeAgentContextCache is an APIServer-owned, process-local authority
// cache. Its zero value is ready for use so tests and small server fixtures
// that construct APIServer directly retain the production behavior.
type activeAgentContextCache struct {
	mu        sync.Mutex
	sessions  map[activeAgentContextKey]activeAgentContextSession
	evictions map[activeAgentContextKey]activeAgentContextEviction
	// These flags are a fail-closed fallback only if the independently bounded
	// eviction index itself saturates.
	uncertain                bool
	caseInsensitiveUncertain bool
	// lost are sessions this process evicted with a first sighting that no
	// saved record holds; lostAll is set when more were lost than it holds.
	// Neither takes a new first sighting (firstSightingKey).
	lost    map[activeAgentContextKey]struct{}
	lostAll bool
	now     func() time.Time
	// storeMu orders the writes of a session's load record
	// (saveInstructionLoads) with the state each one copies. It guards the
	// store's pruned index too (instructionLoadPrunedName): pruned and
	// prunedAll hold it once prunedLoaded.
	storeMu      sync.Mutex
	pruned       map[string]struct{}
	prunedAll    bool
	prunedLoaded bool
}

func (cache *activeAgentContextCache) currentTime() time.Time {
	if cache.now != nil {
		return cache.now()
	}
	return time.Now()
}

func exactActiveAgentFile(filePath string) (string, bool, bool) {
	canonicalName, ok := syntacticActiveAgentFile(filePath)
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

func syntacticActiveAgentFile(filePath string) (string, bool) {
	if filePath == "" || len(filePath) > maxActiveAgentContextPathSize ||
		strings.TrimSpace(filePath) != filePath || !filepath.IsAbs(filePath) ||
		filepath.Clean(filePath) != filePath {
		return "", false
	}
	return canonicalActiveAgentFileName(filepath.Base(filePath))
}

func syntacticActiveAgentFileCandidate(filePath string) bool {
	canonicalName, ok := syntacticActiveAgentFile(filePath)
	// This classifies only exact-identity failures. A native POSIX case alias
	// already succeeded above; an unproved folded spelling remains noise.
	return ok && (filepath.Separator != '/' ||
		filepath.Base(filePath) == canonicalName)
}

// canonicalActiveAgentFileName is the instruction name value spells: every
// protected name, openclaw.json included, so a loaded openclaw.json keeps
// its load record and identity like the others (GAP-1126).
func canonicalActiveAgentFileName(value string) (string, bool) {
	for _, canonical := range hookpaths.InstructionFileNames {
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
		aliasPath = filepath.Join(filepath.Dir(filePath), strings.ToUpper(base))
		if aliasPath == filePath {
			return false
		}
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
	return validScopedActiveAgentContextKey("", connectorName, sessionID)
}

func validScopedActiveAgentContextKey(scope, connectorName, sessionID string) (activeAgentContextKey, bool) {
	connectorName = canonicalConnectorRulePackKey(connectorName)
	if connectorName == "" || sessionID == "" ||
		len(sessionID) > maxActiveAgentSessionIDSize || strings.TrimSpace(sessionID) != sessionID {
		return activeAgentContextKey{}, false
	}
	return activeAgentContextKey{scope: scope, connector: connectorName, sessionID: sessionID}, true
}

// makeRoomLocked evicts the oldest session when the cache is full. To prevent
// sandbox sessions from evicting host sessions, it only evicts sessions from
// the same scope as the key that needs room: sandbox keys evict sandbox
// sessions, host keys evict host sessions.
func (cache *activeAgentContextCache) makeRoomLocked(needsRoom activeAgentContextKey) {
	if len(cache.sessions) < maxActiveAgentContextSessions {
		return
	}
	// Only evict from the same scope: sandbox evicts sandbox, host evicts host.
	isSandbox := needsRoom.scope != ""
	var oldestKey activeAgentContextKey
	var oldestTime time.Time
	found := false
	for key, session := range cache.sessions {
		// Only consider sessions from the same scope category.
		candidateIsSandbox := key.scope != ""
		if candidateIsSandbox != isSandbox {
			continue
		}
		if !found || session.updatedAt.Before(oldestTime) ||
			session.updatedAt.Equal(oldestTime) && activeAgentContextKeyLess(key, oldestKey) {
			oldestKey = key
			oldestTime = session.updatedAt
			found = true
		}
	}
	if found {
		evicted := cache.sessions[oldestKey]
		delete(cache.sessions, oldestKey)
		if evicted.uncertain || len(evicted.files) != 0 {
			cache.rememberEvictionLocked(oldestKey, evicted, isSandbox)
		}
		if evicted.startupKnown && !evicted.saved {
			cache.rememberLostLocked(oldestKey)
		}
	}
}

// rememberLostLocked records that key's first sighting is gone: no saved
// record restores it. Past the bound every session is taken as lost, so a
// session's own file never becomes one that was there before it.
func (cache *activeAgentContextCache) rememberLostLocked(key activeAgentContextKey) {
	if cache.lostAll {
		return
	}
	if len(cache.lost) >= maxInstructionLoadRecords {
		cache.lost, cache.lostAll = nil, true
		return
	}
	if cache.lost == nil {
		cache.lost = make(map[activeAgentContextKey]struct{})
	}
	cache.lost[key] = struct{}{}
}

func (cache *activeAgentContextCache) rememberEvictionLocked(
	key activeAgentContextKey,
	session activeAgentContextSession,
	isSandbox bool,
) {
	caseInsensitive := session.caseInsensitiveUncertain ||
		len(session.caseInsensitiveFiles) != 0
	if eviction, exists := cache.evictions[key]; exists {
		eviction.caseInsensitiveUncertain =
			eviction.caseInsensitiveUncertain || caseInsensitive
		cache.evictions[key] = eviction
		return
	}
	if len(cache.evictions) < maxActiveAgentContextEvictions {
		if cache.evictions == nil {
			cache.evictions = make(
				map[activeAgentContextKey]activeAgentContextEviction,
			)
		}
		cache.evictions[key] = activeAgentContextEviction{
			caseInsensitiveUncertain: caseInsensitive,
		}
		return
	}
	// Never drop authority loss when both bounded indexes saturate. This rare
	// fallback retains the previous fail-closed behavior without making the
	// ordinary single-cache-eviction path process-wide.
	// However, sandbox eviction overflow should not set a process-wide flag
	// that would affect host sessions. Sandbox evictions stay scoped.
	if !isSandbox {
		cache.uncertain = true
		cache.caseInsensitiveUncertain =
			cache.caseInsensitiveUncertain || caseInsensitive
	}
}

func (cache *activeAgentContextCache) consumeEvictionLocked(
	key activeAgentContextKey,
) (bool, bool) {
	if eviction, exists := cache.evictions[key]; exists {
		delete(cache.evictions, key)
		return true, eviction.caseInsensitiveUncertain
	}
	return cache.uncertain, cache.caseInsensitiveUncertain
}

func activeAgentContextKeyLess(left, right activeAgentContextKey) bool {
	if left.scope != right.scope {
		return left.scope < right.scope
	}
	if left.caller != right.caller {
		return left.caller < right.caller
	}
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
	cache.seedKey(key, filePath, "")
}

// seedKey records a loaded instruction file. identity is the hook client's
// file identity of it, read as the user (hookpaths.LoadedIdentityPrefix), or
// empty.
func (cache *activeAgentContextCache) seedKey(key activeAgentContextKey, filePath, identity string) {
	canonicalPath, caseInsensitive, valid := exactActiveAgentFile(filePath)
	if !valid {
		if !syntacticActiveAgentFileCandidate(filePath) {
			return
		}
		now := cache.currentTime()
		// A symlinked instruction file (or one under a linked directory) is
		// the file it reaches: keep the loaded name and the identity of that
		// file, so a write to it under another name is judged by its
		// identity (GAP-0971, hookpaths.InstructionFiles), also after the
		// link is moved. The hook client's identity, read as the user, wins
		// (a gateway that cannot read the file, ProtectHome, GAP-1064). A
		// load proved this way is no loss of context, so it does not make
		// every instruction-named write of the session suspect; only a load
		// whose file cannot be identified does.
		if identity == "" {
			identity = hookpaths.FileIdentity(filePath)
		}
		if identity == "" {
			cache.markUncertain(key, now)
			return
		}
		cache.seedLoadedFile(key, filePath, false, now)
		cache.seedLoadedIdentity(key, filePath, identity)
		return
	}
	cache.seedLoadedFile(
		key,
		canonicalPath,
		caseInsensitive,
		cache.currentTime(),
	)
	cache.seedLoadedIdentity(key, canonicalPath, identity)
}

// seedLoadedIdentity keeps the hook client's identity of a recorded loaded
// file, so a gateway that cannot read the user's files matches a write
// target's identity (hookpaths.FileIdentitiesKey) with it.
func (cache *activeAgentContextCache) seedLoadedIdentity(key activeAgentContextKey, filePath, identity string) {
	if identity == "" {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, ok := cache.sessions[key]
	if !ok || !slices.Contains(session.files, filePath) ||
		len(session.identities) >= maxActiveAgentContextFiles && session.identities[filePath] == "" {
		return
	}
	if session.identities == nil {
		session.identities = make(map[string]string)
	}
	session.identities[filePath] = identity
	cache.sessions[key] = session
}

// seedSandboxKey records an instruction file a sandboxed Claude Code loaded.
// Its identity is proved on the host file the sandbox path is mounted from;
// both the sandbox spelling (absolute paths the agent types) and the mapped
// host spelling (paths resolved against the mapped working directory) are
// recorded, because tool-call analysis sees both. Without a host view
// (copy mode, or a path outside the mount) the file cannot be proved and
// the session is marked uncertain, which fails closed.
func (cache *activeAgentContextCache) seedSandboxKey(
	key activeAgentContextKey,
	view *sandboxauth.FSView,
	filePath string,
) {
	canonicalName, ok := syntacticActiveAgentFile(filePath)
	if !ok {
		return
	}
	hostPath, err := view.HostPath(filePath)
	if err != nil {
		if syntacticActiveAgentFileCandidate(filePath) {
			cache.markUncertain(key, cache.currentTime())
		}
		return
	}
	hostCanonical, caseInsensitive, valid := exactActiveAgentFile(hostPath)
	if !valid {
		cache.markUncertain(key, cache.currentTime())
		return
	}
	now := cache.currentTime()
	cache.seedLoadedFile(key, path.Join(path.Dir(filePath), canonicalName), caseInsensitive, now)
	cache.seedLoadedFile(key, hostCanonical, caseInsensitive, now)
}

func (cache *activeAgentContextCache) markUncertain(
	key activeAgentContextKey,
	now time.Time,
) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.sessions == nil {
		cache.sessions = make(map[activeAgentContextKey]activeAgentContextSession)
	}
	session, exists := cache.sessions[key]
	if !exists {
		uncertain, caseInsensitiveUncertain :=
			cache.consumeEvictionLocked(key)
		cache.makeRoomLocked(key)
		session = activeAgentContextSession{
			caseInsensitiveUncertain: caseInsensitiveUncertain,
			uncertain:                uncertain,
			awaitingStart:            !uncertain,
		}
	}
	// The authenticated event identifies an instruction-file candidate, but
	// native identity could not be proved. Retain any exact entries while
	// making that authority loss explicit; case folding remains proof-gated.
	session.uncertain = true
	session.updatedAt = now
	cache.sessions[key] = session
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
		uncertain, caseInsensitiveUncertain :=
			cache.consumeEvictionLocked(key)
		cache.makeRoomLocked(key)
		session = activeAgentContextSession{
			caseInsensitiveUncertain: caseInsensitiveUncertain,
			uncertain:                uncertain,
			awaitingStart:            !uncertain,
			updatedAt:                now,
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
		if caseInsensitive {
			session.caseInsensitiveUncertain = true
		}
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
	cache.beginKey(key)
}

func (cache *activeAgentContextCache) beginKey(key activeAgentContextKey) {
	cache.resetKey(key, false)
}

func (cache *activeAgentContextCache) beginKeyPreservingStartup(key activeAgentContextKey) {
	cache.resetKey(key, true)
}

func (cache *activeAgentContextCache) resetKey(key activeAgentContextKey, preserveStartup bool) {
	now := cache.currentTime()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.sessions == nil {
		cache.sessions = make(map[activeAgentContextKey]activeAgentContextSession)
	}
	delete(cache.evictions, key)
	if !preserveStartup {
		// A new generation takes its own snapshot.
		delete(cache.lost, key)
	}
	if _, exists := cache.sessions[key]; !exists {
		cache.makeRoomLocked(key)
	}
	// A CwdChanged clears explicit loads but does not make a file created
	// after SessionStart into an instruction the agent loaded at startup.
	previous := cache.sessions[key]
	next := activeAgentContextSession{updatedAt: now}
	if preserveStartup {
		next.awaitingStart = previous.awaitingStart
		next.startupFiles = maps.Clone(previous.startupFiles)
		next.startupKnown = previous.startupKnown
		next.startupDirs = slices.Clone(previous.startupDirs)
		next.startupDirIDs = maps.Clone(previous.startupDirIDs)
	}
	cache.sessions[key] = next
}

// startKey records a start event of key with its startup snapshot. The
// first start of a session whose calls reached the gateway before it and
// took its first sighting (awaitingStart, startupKnown) is that session's
// own late start: what those calls recorded stands, a directory they
// sighted keeps its first record (so a file the session created there stays
// its own), and the start only adds the directories they had not reached.
// Any other start is a new generation: it resets the session and takes a
// new snapshot. That is a start the session ID already had, one that says
// so (newGeneration: a resume, clear, compact or reset), and a start after
// loads alone, as before.
func (cache *activeAgentContextCache) startKey(key activeAgentContextKey, newGeneration bool, files map[string]string, dirs []string, dirIDs map[string]string) {
	cache.mu.Lock()
	session, exists := cache.sessions[key]
	late := exists && session.awaitingStart && session.startupKnown && !newGeneration
	if late {
		session.awaitingStart = false
		session.updatedAt = cache.currentTime()
		cache.sessions[key] = session
	}
	cache.mu.Unlock()
	if !late {
		cache.beginKey(key)
		cache.setStartupKey(key, files, dirs, dirIDs)
		return
	}
	if files != nil && len(dirs) != 0 {
		cache.extendStartupKey(key, files, dirs, dirIDs, nil, nil)
	}
}

func (cache *activeAgentContextCache) setStartupKey(key activeAgentContextKey, files map[string]string, dirs []string, dirIDs map[string]string) {
	if files == nil || len(dirs) == 0 {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, ok := cache.sessions[key]
	if !ok {
		return
	}
	session.startupFiles = maps.Clone(files)
	session.startupDirs = slices.Clone(dirs)
	session.startupDirIDs = maps.Clone(dirIDs)
	session.startupKnown = true
	session.saved = false
	cache.sessions[key] = session
}

// firstSightingKey gives a session without a snapshot its first sighting:
// one whose start sent no startup evidence, or the first inspect call of a
// session without a start hook. It never replaces a concurrent call's
// snapshot or treats an evicted, unknown session as new.
func (cache *activeAgentContextCache) firstSightingKey(key activeAgentContextKey, files map[string]string, dirs []string, dirIDs map[string]string) bool {
	if files == nil || len(dirs) == 0 {
		return false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, exists := cache.sessions[key]
	if exists && session.startupKnown {
		return false
	}
	// A session whose first sighting this process lost is not new, also
	// when a later event of it is held: a file that exists now may be one
	// it created. Past the bound, any session it does not hold is taken as
	// lost.
	if _, lost := cache.lost[key]; lost {
		return false
	}
	if !exists {
		if _, evicted := cache.evictions[key]; evicted || cache.uncertain || cache.lostAll {
			return false
		}
		if cache.sessions == nil {
			cache.sessions = make(map[activeAgentContextKey]activeAgentContextSession)
		}
		cache.makeRoomLocked(key)
		session.awaitingStart = true
	}
	session.startupFiles = maps.Clone(files)
	session.startupDirs = slices.Clone(dirs)
	session.startupDirIDs = maps.Clone(dirIDs)
	session.startupKnown = true
	session.saved = false
	session.updatedAt = cache.currentTime()
	cache.sessions[key] = session
	return true
}

// extendStartupKey adds the directories a running session reaches for the
// first time to its snapshot, with the instruction files they held then. A
// directory already in the snapshot keeps its first record, so a file the
// session created there stays a file it created. A directory whose file
// system identity is a recorded directory's is another spelling of it (a
// symlink, a case variant on a case-insensitive volume, a Windows short
// name): it keeps that directory's first record. files and dirIDs are keyed
// like startupFiles and startupDirs; a directory that does not fit stays out.
//
// bound gives recorded directories that were missing when the session first
// reached them the identity they have now (instructionSighting.bound). It is
// applied first, so a directory the session created keeps its empty first
// record under another spelling too. An identity a recorded directory
// already has is not given to another one: that directory, like each of
// stale (one that is a link now), was moved or linked onto the missing
// spelling, so its empty record is dropped and dirs records it again.
func (cache *activeAgentContextCache) extendStartupKey(key activeAgentContextKey, files map[string]string, dirs []string, dirIDs, bound map[string]string, stale []string) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, ok := cache.sessions[key]
	if !ok || !session.startupKnown {
		return false
	}
	changed := false
	clone := func() {
		if !changed {
			session.startupFiles = maps.Clone(session.startupFiles)
			if session.startupFiles == nil {
				session.startupFiles = make(map[string]string)
			}
			session.startupDirs = slices.Clone(session.startupDirs)
			session.startupDirIDs = maps.Clone(session.startupDirIDs)
			changed = true
		}
	}
	drop := slices.Clone(stale)
	for _, dir := range slices.Sorted(maps.Keys(bound)) {
		identity := bound[dir]
		if identity == "" || session.startupDirIDs[dir] != "" || !slices.Contains(session.startupDirs, dir) {
			continue
		}
		if startupDirWithIdentity(session, identity) != "" {
			drop = append(drop, dir)
			continue
		}
		clone()
		if session.startupDirIDs == nil {
			session.startupDirIDs = make(map[string]string)
		}
		session.startupDirIDs[dir] = identity
	}
	for _, dir := range drop {
		if session.startupDirIDs[dir] != "" || !slices.Contains(session.startupDirs, dir) {
			continue
		}
		clone()
		session.startupDirs = slices.DeleteFunc(session.startupDirs, func(recorded string) bool { return recorded == dir })
		maps.DeleteFunc(session.startupFiles, func(file, _ string) bool { return instructionParent(file) == dir })
	}
	for _, dir := range dirs {
		if slices.Contains(session.startupDirs, dir) {
			continue
		}
		if len(session.startupDirs) >= maxStartupDirectories {
			break
		}
		held := make(map[string]string)
		identity := dirIDs[dir]
		if original := startupDirWithIdentity(session, identity); original != "" {
			for file, fileIdentity := range session.startupFiles {
				if instructionParent(file) == original {
					held[instructionFileIn(dir, path.Base(file))] = fileIdentity
				}
			}
		} else {
			for file, fileIdentity := range files {
				if instructionParent(file) == dir {
					held[file] = fileIdentity
				}
			}
		}
		if len(session.startupFiles)+len(held) > maxStartupInstructionFiles {
			continue
		}
		if !changed {
			session.startupFiles = maps.Clone(session.startupFiles)
			if session.startupFiles == nil {
				session.startupFiles = make(map[string]string)
			}
			session.startupDirs = slices.Clone(session.startupDirs)
			session.startupDirIDs = maps.Clone(session.startupDirIDs)
			changed = true
		}
		maps.Copy(session.startupFiles, held)
		session.startupDirs = append(session.startupDirs, dir)
		if identity != "" {
			if session.startupDirIDs == nil {
				session.startupDirIDs = make(map[string]string)
			}
			session.startupDirIDs[dir] = identity
		}
	}
	if changed {
		session.saved = false
		cache.sessions[key] = session
	}
	return changed
}

// startupDirWithIdentity is the recorded directory with file system
// identity, if any.
func startupDirWithIdentity(session activeAgentContextSession, identity string) string {
	if identity == "" {
		return ""
	}
	for _, dir := range session.startupDirs {
		if session.startupDirIDs[dir] == identity {
			return dir
		}
	}
	return ""
}

func (cache *activeAgentContextCache) end(connectorName, sessionID string) {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return
	}
	cache.endKey(key)
}

func (cache *activeAgentContextCache) endKey(key activeAgentContextKey) {
	cache.mu.Lock()
	delete(cache.sessions, key)
	delete(cache.evictions, key)
	delete(cache.lost, key)
	cache.mu.Unlock()
}

// loseKey records that key, which the cache does not hold, lost its first
// sighting (rememberLostLocked).
func (cache *activeAgentContextCache) loseKey(key activeAgentContextKey) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if _, held := cache.sessions[key]; !held {
		cache.rememberLostLocked(key)
	}
}

// markSavedKey records whether key's saved record holds its state as it is
// now (saveInstructionLoads).
func (cache *activeAgentContextCache) markSavedKey(key activeAgentContextKey, saved bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if session, ok := cache.sessions[key]; ok {
		session.saved = saved
		cache.sessions[key] = session
	}
}

// startupDirsKey returns the directories of key's instruction-file
// snapshot, if the session has one, and the last of them (at most limit)
// that have no file system identity: the directories that were missing when
// the session first reached them.
func (cache *activeAgentContextCache) startupDirsKey(key activeAgentContextKey, limit int) (dirs, unbound []string, ok bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, ok := cache.sessions[key]
	if !ok || !session.startupKnown {
		return nil, nil, false
	}
	for index := len(session.startupDirs) - 1; index >= 0 && len(unbound) < limit; index-- {
		if dir := session.startupDirs[index]; session.startupDirIDs[dir] == "" {
			unbound = append(unbound, dir)
		}
	}
	return slices.Clone(session.startupDirs), unbound, true
}

// sessionKey returns a copy of the session the cache holds for key.
func (cache *activeAgentContextCache) sessionKey(key activeAgentContextKey) (activeAgentContextSession, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, ok := cache.sessions[key]
	if !ok {
		return activeAgentContextSession{}, false
	}
	session.files = slices.Clone(session.files)
	session.caseInsensitiveFiles = slices.Clone(session.caseInsensitiveFiles)
	session.identities = maps.Clone(session.identities)
	session.startupFiles = maps.Clone(session.startupFiles)
	session.startupDirs = slices.Clone(session.startupDirs)
	session.startupDirIDs = maps.Clone(session.startupDirIDs)
	return session, true
}

// restoreKey gives key the loads a previous gateway process recorded for it
// (restoreInstructionLoads), unless this process already holds the session.
// An eviction this process remembers for key keeps the session uncertain.
func (cache *activeAgentContextCache) restoreKey(key activeAgentContextKey, record instructionLoadRecord, now time.Time) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if _, exists := cache.sessions[key]; exists {
		return
	}
	if cache.sessions == nil {
		cache.sessions = make(map[activeAgentContextKey]activeAgentContextSession)
	}
	uncertain, caseInsensitiveUncertain := false, false
	if _, evicted := cache.evictions[key]; evicted {
		uncertain, caseInsensitiveUncertain = cache.consumeEvictionLocked(key)
	}
	delete(cache.lost, key)
	cache.makeRoomLocked(key)
	cache.sessions[key] = activeAgentContextSession{
		saved:                    true,
		files:                    slices.Clone(record.Files),
		caseInsensitiveFiles:     slices.Clone(record.CaseInsensitiveFiles),
		identities:               maps.Clone(record.LoadedIdentities),
		startupFiles:             maps.Clone(record.StartupFiles),
		startupKnown:             record.StartupKnown,
		startupDirs:              slices.Clone(record.StartupDirs),
		startupDirIDs:            maps.Clone(record.StartupDirIDs),
		awaitingStart:            record.AwaitingStart && !uncertain,
		uncertain:                uncertain,
		caseInsensitiveUncertain: caseInsensitiveUncertain,
		updatedAt:                now,
	}
}

func (cache *activeAgentContextCache) snapshot(connectorName, sessionID string) activeAgentContextSnapshot {
	key, ok := validActiveAgentContextKey(connectorName, sessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	return cache.snapshotKey(key)
}

func (cache *activeAgentContextCache) snapshotKey(key activeAgentContextKey) activeAgentContextSnapshot {
	now := cache.currentTime()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	session, ok := cache.sessions[key]
	if !ok {
		if eviction, exists := cache.evictions[key]; exists {
			return activeAgentContextSnapshot{
				caseInsensitiveUncertain: eviction.caseInsensitiveUncertain,
				uncertain:                true,
			}
		}
		return activeAgentContextSnapshot{
			caseInsensitiveUncertain: cache.caseInsensitiveUncertain,
			uncertain:                cache.uncertain,
		}
	}
	session.updatedAt = now
	cache.sessions[key] = session
	return activeAgentContextSnapshot{
		files:        append([]string(nil), session.files...),
		identities:   maps.Clone(session.identities),
		startupFiles: maps.Clone(session.startupFiles),
		startupKnown: session.startupKnown,
		startupDirs:  slices.Clone(session.startupDirs),
		caseInsensitiveFiles: append(
			[]string(nil),
			session.caseInsensitiveFiles...,
		),
		caseInsensitiveUncertain: session.caseInsensitiveUncertain,
		uncertain:                session.uncertain,
	}
}

// applyClaudeCodeActiveAgentContext consumes only authenticated, typed Claude
// Code lifecycle fields. It never reads req.Payload or ToolInput, preventing a
// generic payload, command mention, or tool argument from manufacturing trusted
// instruction-file context. The managed hook client's identity of a loaded
// file (hookpaths.LoadedIdentityPrefix) only adds protection: it makes more
// writes writes to that file, never fewer.
func (a *APIServer) applyClaudeCodeActiveAgentContext(ctx context.Context, req claudeCodeHookRequest) activeAgentContextSnapshot {
	const connectorName = "claudecode"
	if a == nil || authenticatedHookConnector(ctx) != connectorName {
		return activeAgentContextSnapshot{}
	}
	view, sandboxed := sandboxHookView(ctx)
	key, ok := instructionStartupKey(ctx, connectorName, req.SessionID)
	if !ok {
		return activeAgentContextSnapshot{}
	}
	switch req.HookEventName {
	case "SessionStart":
		a.startInstructionSession(ctx, key, req.HookEventName, req.Source, req.CWD)
	case "CwdChanged":
		a.restoreInstructionLoads(key)
		a.activeAgentContext.beginKeyPreservingStartup(key)
		a.saveInstructionLoads(key)
	case "SessionEnd":
		a.activeAgentContext.endKey(key)
		a.saveInstructionLoads(key)
		a.clearInstructionSightingLoss(key)
	case "InstructionsLoaded":
		// A load recorded before this gateway started is still this
		// session's load.
		a.restoreInstructionLoads(key)
		if sandboxed {
			a.activeAgentContext.seedSandboxKey(key, view, req.FilePath)
		} else {
			a.activeAgentContext.seedKey(key, req.FilePath,
				resolvedWritesFromContext(ctx)[hookpaths.LoadedIdentityPrefix+req.FilePath])
		}
		a.saveInstructionLoads(key)
	case "PreToolUse", "PermissionRequest":
		a.restoreInstructionLoads(key)
		a.extendInstructionStartup(ctx, key, req.CWD)
		return a.activeAgentContext.snapshotKey(key)
	}
	return activeAgentContextSnapshot{}
}
