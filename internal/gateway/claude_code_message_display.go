// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// Claude Code streams the text it displays through MessageDisplay, one hook
// call per chunk. Redaction runs per record at projection time, so one row
// per chunk let a secret the model streamed across a chunk boundary reach the
// stores in pieces that no detector recognizes (GAP-0511). The gateway now
// holds the chunks of one message and writes one llm_response row for the
// whole message: when the final chunk arrives, when the session sends any
// other hook event, when the message has been idle for claudeDisplayIdle, or
// when it is evicted. A message longer than claudeDisplayMaxBytes, the
// content a row keeps, is written in parts cut after whitespace, so a
// provider token (which has none) never spans two rows.
const (
	claudeDisplayMaxBytes    = hookLLMSpanMaxContentBytes
	claudeDisplayMaxMessages = 256
	claudeDisplayIdle        = 20 * time.Second
	// claudeDisplayCutWindow is how far back from the size limit a part
	// looks for whitespace to end on.
	claudeDisplayCutWindow = 4096
)

type claudeDisplayKey struct {
	sessionID, agentID, responseID string
}

type claudeDisplayChunk struct {
	index int
	delta string
}

type claudeDisplayMessage struct {
	// ctx is the detached context of the chunk whose sink policy is the
	// strictest seen, so a message is never written under a raw policy one
	// of its chunks did not have.
	ctx  context.Context
	meta llmEventMeta
	// ordered: the message has a reported id, so its chunks are joined in
	// their reported index order (async hook calls can arrive out of order).
	ordered bool
	chunks  []claudeDisplayChunk
	size    int
	born    uint64
	timer   *time.Timer
}

type claudeDisplayFlush struct {
	ctx     context.Context
	meta    llmEventMeta
	content string
	final   bool
}

// claudeDisplayBuffer is the zero-value-ready set of messages in flight.
type claudeDisplayBuffer struct {
	mu       sync.Mutex
	seq      uint64
	messages map[claudeDisplayKey]*claudeDisplayMessage
}

// bufferClaudeCodeDisplay adds one MessageDisplay chunk and writes what the
// chunk completed.
func (a *APIServer) bufferClaudeCodeDisplay(ctx context.Context, meta llmEventMeta, index int, delta string, final bool) {
	key := claudeDisplayKey{
		sessionID: strings.TrimSpace(meta.SessionID), agentID: strings.TrimSpace(meta.AgentID),
		responseID: meta.ResponseID,
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, flush := range a.claudeDisplays.add(ctx, a, key, meta, index, delta, final) {
		a.emitClaudeCodeDisplayFlush(ctx, flush)
	}
}

// flushClaudeCodeDisplays writes every message of the session still held:
// another hook event of the session means its displayed messages ended.
func (a *APIServer) flushClaudeCodeDisplays(ctx context.Context, sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if a == nil || sessionID == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, flush := range a.claudeDisplays.takeSession(sessionID) {
		a.emitClaudeCodeDisplayFlush(ctx, flush)
	}
}

func (a *APIServer) flushIdleClaudeCodeDisplay(key claudeDisplayKey, born uint64) {
	if flush, ok := a.claudeDisplays.take(key, born); ok {
		a.emitClaudeCodeDisplayFlush(context.Background(), flush)
	}
}

// emitClaudeCodeDisplayFlush writes one row under the message's own context,
// bounded by the deadline of the call that flushed it (or the hook
// persistence grace when a timer did).
func (a *APIServer) emitClaudeCodeDisplayFlush(current context.Context, flush claudeDisplayFlush) {
	if strings.TrimSpace(flush.content) == "" {
		return
	}
	ctx := flush.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	var cancel context.CancelFunc
	if deadline, ok := current.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ctx, deadline)
	} else {
		ctx, cancel = context.WithTimeout(ctx, agentHookPersistGrace)
	}
	defer cancel()
	finish := "streaming"
	if flush.final {
		finish = "stop"
	}
	a.emitLLMResponseEventV8(ctx, flush.meta, flush.content, "", []string{finish})
}

func (b *claudeDisplayBuffer) add(
	ctx context.Context, a *APIServer, key claudeDisplayKey, meta llmEventMeta,
	index int, delta string, final bool,
) []claudeDisplayFlush {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.messages == nil {
		b.messages = make(map[claudeDisplayKey]*claudeDisplayMessage)
	}
	var flushes []claudeDisplayFlush
	message := b.messages[key]
	if message == nil {
		if len(b.messages) >= claudeDisplayMaxMessages {
			if flush, ok := b.evictOldestLocked(); ok {
				flushes = append(flushes, flush)
			}
		}
		b.seq++
		message = &claudeDisplayMessage{born: b.seq, ordered: meta.ResponseIDReported}
		born := message.born
		message.timer = time.AfterFunc(claudeDisplayIdle, func() { a.flushIdleClaudeCodeDisplay(key, born) })
		b.messages[key] = message
	}
	if message.ctx == nil || !claudeDisplayRedacts(message.ctx) || claudeDisplayRedacts(ctx) {
		message.ctx = context.WithoutCancel(ctx)
	}
	message.meta = meta
	message.chunks = append(message.chunks, claudeDisplayChunk{index: index, delta: delta})
	message.size += len(delta)
	if message.size > claudeDisplayMaxBytes {
		content, last := message.joined()
		for len(content) > claudeDisplayMaxBytes {
			cut := claudeDisplayCut(content, claudeDisplayMaxBytes)
			flushes = append(flushes, claudeDisplayFlush{ctx: message.ctx, meta: message.meta, content: content[:cut]})
			content = content[cut:]
		}
		message.chunks = []claudeDisplayChunk{{index: last, delta: content}}
		message.size = len(content)
	}
	if final {
		flushes = append(flushes, b.removeLocked(key, message, true))
	} else {
		message.timer.Reset(claudeDisplayIdle)
	}
	return flushes
}

func (b *claudeDisplayBuffer) take(key claudeDisplayKey, born uint64) (claudeDisplayFlush, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	message := b.messages[key]
	if message == nil || message.born != born {
		return claudeDisplayFlush{}, false
	}
	return b.removeLocked(key, message, false), true
}

func (b *claudeDisplayBuffer) takeSession(sessionID string) []claudeDisplayFlush {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys []claudeDisplayKey
	for key := range b.messages {
		if key.sessionID == sessionID {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return b.messages[keys[i]].born < b.messages[keys[j]].born })
	flushes := make([]claudeDisplayFlush, 0, len(keys))
	for _, key := range keys {
		flushes = append(flushes, b.removeLocked(key, b.messages[key], false))
	}
	return flushes
}

func (b *claudeDisplayBuffer) evictOldestLocked() (claudeDisplayFlush, bool) {
	var oldest claudeDisplayKey
	var found *claudeDisplayMessage
	for key, message := range b.messages {
		if found == nil || message.born < found.born {
			oldest, found = key, message
		}
	}
	if found == nil {
		return claudeDisplayFlush{}, false
	}
	return b.removeLocked(oldest, found, false), true
}

func (b *claudeDisplayBuffer) removeLocked(key claudeDisplayKey, message *claudeDisplayMessage, final bool) claudeDisplayFlush {
	delete(b.messages, key)
	if message.timer != nil {
		message.timer.Stop()
	}
	content, _ := message.joined()
	return claudeDisplayFlush{ctx: message.ctx, meta: message.meta, content: content, final: final}
}

// joined returns the message text and the highest chunk index in it.
func (message *claudeDisplayMessage) joined() (string, int) {
	if message.ordered {
		sort.SliceStable(message.chunks, func(i, j int) bool { return message.chunks[i].index < message.chunks[j].index })
	}
	var builder strings.Builder
	builder.Grow(message.size)
	last := 0
	for i, chunk := range message.chunks {
		builder.WriteString(chunk.delta)
		if i == 0 || chunk.index > last {
			last = chunk.index
		}
	}
	return builder.String(), last
}

// claudeDisplayCut is where a part of at most limit bytes of content ends:
// just after the last whitespace within claudeDisplayCutWindow of the limit,
// else at the last rune boundary before it. content is longer than limit.
func claudeDisplayCut(content string, limit int) int {
	cut := limit
	for cut > 0 && !utf8.RuneStart(content[cut]) {
		cut--
	}
	if cut == 0 {
		return limit
	}
	for i := cut; i > 0 && i > cut-claudeDisplayCutWindow; i-- {
		if claudeDisplaySpace(content[i-1]) {
			return i
		}
	}
	return cut
}

func claudeDisplaySpace(value byte) bool {
	return value == ' ' || value == '\n' || value == '\t' || value == '\r'
}

// claudeDisplayRedacts reports whether ctx's sink policy is anything but raw.
func claudeDisplayRedacts(ctx context.Context) bool {
	return redaction.SinkPolicyFromContext(ctx) != redaction.SinkPolicyRaw
}
