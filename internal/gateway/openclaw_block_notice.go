// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// GAP-0644: OpenClaw gives a plugin no way to show the user a blocked tool
// call. The block reason reaches only the tool result, which the model
// paraphrases, and the OpenClaw TUI drops tool events at its default verbose
// level. The one place DefenseClaw owns on that screen is the model reply,
// which already carries the [DefenseClaw] banner for proxy blocks.
//
// The inspect endpoint records each enforced OpenClaw tool block here, keyed by
// the tool call id the plugin sends. The next model request that carries the
// tool result for that id takes the notice, and the proxy puts one line in
// front of the first text of the reply (stream or not). A notice is taken by one
// request, so a block is shown once and an allowed call never has one. A reply
// with no text (another tool call) or an upstream error gives the notice back
// until it expires, so the line lands on the first reply that has text.

const (
	openClawBlockNoticeTTL       = 2 * time.Minute
	openClawBlockNoticeCap       = 256
	openClawBlockNoticeMark      = "[DefenseClaw] Tool call blocked"
	openClawBlockNoticeMaxBody   = 32 << 20
	openClawBlockNoticeMaxFrame  = 4 << 20
	openClawBlockNoticeKeyLength = 32
)

type openClawBlockNotice struct {
	key, line string
	at        time.Time
}

var openClawBlockNotices struct {
	mu      sync.Mutex
	entries []openClawBlockNotice
}

// openClawToolCallKey normalizes a tool call id so the plugin hook id and the
// id a provider adapter sends back compare equal: the OpenClaw Responses ids
// are "<call id>|<item id>", and other providers need ids restricted to
// letters, digits, "_" and "-".
func openClawToolCallKey(id string) string {
	id = strings.TrimSpace(id)
	if i := strings.Index(id, "|"); i >= 0 {
		id = id[:i]
	}
	var b strings.Builder
	for _, r := range id {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("_-", r)) {
			b.WriteRune(r)
		} else {
			b.WriteString("_")
		}
		if b.Len() >= openClawBlockNoticeKeyLength {
			break
		}
	}
	return b.String()
}

func openClawNoticeText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return 0x20
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "..."
	}
	return s
}

func openClawBlockNoticeLine(tool string, ruleIDs []string, reason string) string {
	var b strings.Builder
	b.WriteString(openClawBlockNoticeMark)
	if t := openClawNoticeText(tool, 64); t != "" {
		b.WriteString(": " + t)
	}
	for _, id := range ruleIDs {
		if id = openClawNoticeText(id, 96); id != "" {
			b.WriteString(" (rule " + id + ")")
			break
		}
	}
	if r := openClawNoticeText(redaction.Reason(reason), 240); r != "" {
		b.WriteString(" - " + r)
	}
	return b.String()
}

// rememberOpenClawBlockNotice records an enforced block of one OpenClaw tool
// call. A call without an id cannot be matched to its tool result and has none.
func rememberOpenClawBlockNotice(toolCallID, tool string, ruleIDs []string, reason string) {
	key := openClawToolCallKey(toolCallID)
	if key == "" {
		return
	}
	openClawBlockNotices.mu.Lock()
	defer openClawBlockNotices.mu.Unlock()
	now := openClawToolOutcomeNow()
	openClawBlockNotices.entries = append(pruneOpenClawBlockNotices(openClawBlockNotices.entries, now),
		openClawBlockNotice{key: key, line: openClawBlockNoticeLine(tool, ruleIDs, reason), at: now})
	if n := len(openClawBlockNotices.entries); n > openClawBlockNoticeCap {
		openClawBlockNotices.entries = openClawBlockNotices.entries[n-openClawBlockNoticeCap:]
	}
}

func pruneOpenClawBlockNotices(entries []openClawBlockNotice, now time.Time) []openClawBlockNotice {
	kept := entries[:0]
	for _, e := range entries {
		if now.Sub(e.at) < openClawBlockNoticeTTL {
			kept = append(kept, e)
		}
	}
	return kept
}

func openClawBlockNoticesPending() bool {
	openClawBlockNotices.mu.Lock()
	defer openClawBlockNotices.mu.Unlock()
	return len(openClawBlockNotices.entries) > 0
}

// openClawRequestToolCallKeys collects the normalized tool call ids a model
// request names, in any provider shape: tool_call_id (Chat Completions),
// call_id (Responses), tool_use_id (Anthropic) and toolUseId (Bedrock).
func openClawRequestToolCallKeys(body []byte) map[string]bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if dec.Decode(&doc) != nil {
		return nil
	}
	keys := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				if s, ok := val.(string); ok {
					switch k {
					case "tool_call_id", "call_id", "tool_use_id", "toolUseId":
						if key := openClawToolCallKey(s); key != "" {
							keys[key] = true
						}
					}
					continue
				}
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(doc)
	return keys
}

func takeOpenClawBlockNotices(body []byte) []openClawBlockNotice {
	if !openClawBlockNoticesPending() {
		return nil
	}
	keys := openClawRequestToolCallKeys(body)
	if len(keys) == 0 {
		return nil
	}
	openClawBlockNotices.mu.Lock()
	defer openClawBlockNotices.mu.Unlock()
	now := openClawToolOutcomeNow()
	openClawBlockNotices.entries = pruneOpenClawBlockNotices(openClawBlockNotices.entries, now)
	var taken []openClawBlockNotice
	kept := make([]openClawBlockNotice, 0, len(openClawBlockNotices.entries))
	for _, e := range openClawBlockNotices.entries {
		if keys[e.key] {
			taken = append(taken, e)
		} else {
			kept = append(kept, e)
		}
	}
	openClawBlockNotices.entries = kept
	return taken
}

func restoreOpenClawBlockNotices(notices []openClawBlockNotice) {
	if len(notices) == 0 {
		return
	}
	openClawBlockNotices.mu.Lock()
	defer openClawBlockNotices.mu.Unlock()
	openClawBlockNotices.entries = append(notices, pruneOpenClawBlockNotices(openClawBlockNotices.entries, openClawToolOutcomeNow())...)
	if n := len(openClawBlockNotices.entries); n > openClawBlockNoticeCap {
		openClawBlockNotices.entries = openClawBlockNotices.entries[n-openClawBlockNoticeCap:]
	}
}

// openClawNoticeReply reports whether an assistant turn is a model reply that
// carries a notice line, not a block message DefenseClaw wrote. History
// laundering drops the second kind and keeps the first, whose text after the
// notice is the model own answer.
func openClawNoticeReply(text string) bool {
	if !strings.HasPrefix(text, openClawBlockNoticeMark) {
		return false
	}
	_, rest, found := strings.Cut(text, "\n\n")
	return found && strings.TrimSpace(rest) != ""
}

// isDefenseClawBlockTurn is the laundering test for one assistant turn text.
func isDefenseClawBlockTurn(text string) bool {
	return strings.HasPrefix(text, defenseClawBlockBanner) && !openClawNoticeReply(text)
}

type openClawNoticeBody struct {
	io.Reader
	io.Closer
}

// openClawBlockNoticeMiddleware prefixes the first reply text that follows an
// OpenClaw tool block with the block notice. Requests with no pending notice
// pass through untouched and unbuffered.
func openClawBlockNoticeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Body == nil || !openClawBlockNoticesPending() {
			next.ServeHTTP(w, r)
			return
		}
		orig := r.Body
		body, err := io.ReadAll(io.LimitReader(orig, openClawBlockNoticeMaxBody+1))
		r.Body = openClawNoticeBody{Reader: io.MultiReader(bytes.NewReader(body), orig), Closer: orig}
		if err != nil || len(body) > openClawBlockNoticeMaxBody {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		notices := takeOpenClawBlockNotices(body)
		if len(notices) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		nw := &openClawNoticeWriter{ResponseWriter: w, notices: notices}
		lines := make([]string, len(notices))
		for i, n := range notices {
			lines[i] = n.line
		}
		nw.prefix = strings.Join(lines, "\n") + "\n\n"
		next.ServeHTTP(nw, r)
		nw.finish()
	})
}

const (
	noticeUndecided = iota
	noticePass
	noticeSSE
	noticeJSON
)

// openClawNoticeWriter rewrites the first assistant text of a model reply. It
// understands Chat Completions, Responses and Anthropic Messages streams and
// bodies, and Bedrock Converse bodies; any other reply passes through and
// drops the notice.
type openClawNoticeWriter struct {
	http.ResponseWriter
	notices []openClawBlockNotice
	prefix  string
	mode    int
	status  int
	started bool
	applied bool
	buf     []byte
	// Responses stream state: the item and content part the line went into,
	// so the done events and the final response carry the same text.
	itemID, partIdx string
}

func (w *openClawNoticeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *openClawNoticeWriter) WriteHeader(code int) {
	if w.started {
		return
	}
	w.started, w.status = true, code
	ct := strings.ToLower(w.Header().Get("Content-Type"))
	enc := strings.ToLower(w.Header().Get("Content-Encoding"))
	switch {
	case code < 200 || code >= 300:
		w.mode = noticePass
		restoreOpenClawBlockNotices(w.notices)
		w.notices = nil
	case enc != "" && enc != "identity":
		w.mode = noticePass
	case strings.Contains(ct, "text/event-stream"):
		w.mode = noticeSSE
		w.Header().Del("Content-Length")
	case strings.Contains(ct, "json"):
		w.mode = noticeJSON
		return
	default:
		w.mode = noticePass
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *openClawNoticeWriter) Write(p []byte) (int, error) {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	switch w.mode {
	case noticeJSON:
		w.buf = append(w.buf, p...)
		if len(w.buf) > openClawBlockNoticeMaxBody {
			w.release()
		}
		return len(p), nil
	case noticeSSE:
		w.buf = append(w.buf, p...)
		return len(p), w.drainSSE(false)
	}
	return w.ResponseWriter.Write(p)
}

// release gives up rewriting: what is buffered goes out as it is.
func (w *openClawNoticeWriter) release() {
	if w.mode == noticeJSON {
		w.ResponseWriter.WriteHeader(w.status)
	}
	w.mode = noticePass
	if len(w.buf) > 0 {
		_, _ = w.ResponseWriter.Write(w.buf)
		w.buf = nil
	}
}

func (w *openClawNoticeWriter) Flush() {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	if w.mode == noticeJSON {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *openClawNoticeWriter) finish() {
	switch w.mode {
	case noticeJSON:
		var out []byte
		out, w.applied = w.rewriteBody(w.buf)
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		w.ResponseWriter.WriteHeader(w.status)
		_, _ = w.ResponseWriter.Write(out)
	case noticeSSE:
		_ = w.drainSSE(true)
	}
	// A reply with no text to lead with, or none at all, leaves the notice for
	// the next reply; a reply in a format that is not rewritten drops it.
	if w.mode != noticePass && !w.applied {
		restoreOpenClawBlockNotices(w.notices)
	}
}

func sseFrameEnd(b []byte) (int, int) {
	lf, crlf := bytes.Index(b, []byte("\n\n")), bytes.Index(b, []byte("\r\n\r\n"))
	switch {
	case lf >= 0 && (crlf < 0 || lf < crlf):
		return lf, 2
	case crlf >= 0:
		return crlf, 4
	}
	return -1, 0
}

func (w *openClawNoticeWriter) drainSSE(final bool) error {
	for {
		idx, n := sseFrameEnd(w.buf)
		if idx < 0 {
			break
		}
		frame := append([]byte(nil), w.buf[:idx+n]...)
		w.buf = w.buf[idx+n:]
		if _, err := w.ResponseWriter.Write(w.rewriteFrame(frame)); err != nil {
			return err
		}
	}
	if len(w.buf) > openClawBlockNoticeMaxFrame || (final && len(w.buf) > 0) {
		rest := w.buf
		w.buf = nil
		if !final {
			w.mode = noticePass
		}
		_, err := w.ResponseWriter.Write(rest)
		return err
	}
	return nil
}

func decodeNoticeJSON(raw []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

func encodeNoticeJSON(obj map[string]any) ([]byte, bool) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(obj) != nil {
		return nil, false
	}
	return bytes.TrimRight(out.Bytes(), "\n"), true
}

// rewriteFrame puts the notice in one SSE frame when it carries text that
// should lead with it, and keeps the Responses done events in step with the
// deltas.
func (w *openClawNoticeWriter) rewriteFrame(frame []byte) []byte {
	if w.applied && w.itemID == "" {
		return frame
	}
	lines := bytes.Split(frame, []byte("\n"))
	dataAt := -1
	for i, l := range lines {
		if bytes.HasPrefix(l, []byte("data:")) {
			if dataAt >= 0 {
				return frame
			}
			dataAt = i
		}
	}
	if dataAt < 0 {
		return frame
	}
	line := lines[dataAt]
	cr := bytes.HasSuffix(line, []byte("\r"))
	payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
	obj, ok := decodeNoticeJSON(payload)
	if !ok || !w.rewriteEvent(obj) {
		return frame
	}
	enc, ok := encodeNoticeJSON(obj)
	if !ok {
		return frame
	}
	lines[dataAt] = append([]byte("data: "), enc...)
	if cr {
		lines[dataAt] = append(lines[dataAt], "\r"...)
	}
	return bytes.Join(lines, []byte("\n"))
}

func (w *openClawNoticeWriter) rewriteEvent(obj map[string]any) bool {
	typ, _ := obj["type"].(string)
	switch {
	case typ == "content_block_delta":
		if w.applied {
			return false
		}
		d, _ := obj["delta"].(map[string]any)
		if d != nil && d["type"] == "text_delta" {
			return w.prefixField(d, "text")
		}
	case strings.HasPrefix(typ, "response."):
		return w.rewriteResponsesEvent(typ, obj)
	case typ == "" && !w.applied:
		choices, _ := obj["choices"].([]any)
		if len(choices) == 0 {
			return false
		}
		c0, _ := choices[0].(map[string]any)
		delta, _ := c0["delta"].(map[string]any)
		if delta != nil {
			return w.prefixField(delta, "content")
		}
	}
	return false
}

// prefixField puts the notice in front of a non-empty string field and counts
// it as shown.
func (w *openClawNoticeWriter) prefixField(m map[string]any, key string) bool {
	s, _ := m[key].(string)
	if s == "" {
		return false
	}
	m[key] = w.prefix + s
	w.applied = true
	return true
}

func noticeKey(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func (w *openClawNoticeWriter) rewriteResponsesEvent(typ string, obj map[string]any) bool {
	if typ == "response.output_text.delta" {
		if w.applied || !w.prefixField(obj, "delta") {
			return false
		}
		w.itemID, w.partIdx = noticeKey(obj["item_id"]), noticeKey(obj["content_index"])
		if w.itemID == "" {
			w.itemID = "-"
		}
		return true
	}
	if !w.applied {
		return false
	}
	switch typ {
	case "response.output_text.done":
		if noticeKey(obj["item_id"]) == w.itemID && noticeKey(obj["content_index"]) == w.partIdx {
			return w.prefixDone(obj, "text")
		}
	case "response.content_part.done":
		part, _ := obj["part"].(map[string]any)
		if part != nil && noticeKey(obj["item_id"]) == w.itemID && noticeKey(obj["content_index"]) == w.partIdx {
			return w.prefixDone(part, "text")
		}
	case "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		return w.prefixItem(item)
	case "response.completed", "response.incomplete", "response.done":
		resp, _ := obj["response"].(map[string]any)
		output, _ := resp["output"].([]any)
		for _, o := range output {
			item, _ := o.(map[string]any)
			if w.prefixItem(item) {
				return true
			}
		}
	}
	return false
}

func (w *openClawNoticeWriter) prefixDone(m map[string]any, key string) bool {
	s, _ := m[key].(string)
	if s == "" || strings.HasPrefix(s, w.prefix) {
		return false
	}
	m[key] = w.prefix + s
	return true
}

func (w *openClawNoticeWriter) prefixItem(item map[string]any) bool {
	if item == nil || noticeKey(item["id"]) != w.itemID {
		return false
	}
	idx, err := strconv.Atoi(w.partIdx)
	content, _ := item["content"].([]any)
	if err != nil || idx < 0 || idx >= len(content) {
		return false
	}
	part, _ := content[idx].(map[string]any)
	return part != nil && w.prefixDone(part, "text")
}

// rewriteBody puts the notice in front of the first text of a non-streamed
// reply. The second result is false when the body has no text to lead with.
func (w *openClawNoticeWriter) rewriteBody(body []byte) ([]byte, bool) {
	obj, ok := decodeNoticeJSON(body)
	if !ok {
		return body, false
	}
	if !w.rewriteBodyObject(obj) {
		return body, false
	}
	out, ok := encodeNoticeJSON(obj)
	if !ok {
		return body, false
	}
	return out, true
}

func (w *openClawNoticeWriter) rewriteBodyObject(obj map[string]any) bool {
	// Chat Completions.
	if choices, _ := obj["choices"].([]any); len(choices) > 0 {
		c0, _ := choices[0].(map[string]any)
		msg, _ := c0["message"].(map[string]any)
		if msg != nil {
			if w.prefixField(msg, "content") {
				return true
			}
			return w.prefixParts(msg["content"], "text")
		}
	}
	// Responses.
	if output, _ := obj["output"].([]any); len(output) > 0 {
		for _, o := range output {
			item, _ := o.(map[string]any)
			if item != nil && item["type"] == "message" && w.prefixParts(item["content"], "text") {
				return true
			}
		}
		return false
	}
	// Bedrock Converse.
	if out, _ := obj["output"].(map[string]any); out != nil {
		msg, _ := out["message"].(map[string]any)
		return msg != nil && w.prefixParts(msg["content"], "text")
	}
	// Anthropic Messages.
	if obj["type"] == "message" {
		return w.prefixParts(obj["content"], "text")
	}
	return false
}

// prefixParts puts the notice in the first part that has a non-empty text.
func (w *openClawNoticeWriter) prefixParts(parts any, key string) bool {
	list, _ := parts.([]any)
	for _, p := range list {
		if part, _ := p.(map[string]any); part != nil && w.prefixField(part, key) {
			return true
		}
	}
	return false
}
