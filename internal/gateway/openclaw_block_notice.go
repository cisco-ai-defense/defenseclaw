// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// GAP-0644: OpenClaw gives a plugin no way to show the user a blocked tool
// call. The block reason reaches only the tool result, which the model
// paraphrases, and the OpenClaw TUI drops tool events at its default verbose
// level. The one place DefenseClaw owns on that screen is the model reply,
// which already carries the [DefenseClaw] banner for proxy blocks.
//
// The inspect endpoint records each enforced OpenClaw tool block under the
// call id the plugin sends with the inspect request. A model request of this
// OpenClaw route that carries a tool-result message with that id takes the
// notice, and the proxy puts one line in front of the first text of the reply
// (stream or not). Nothing else names a call: no text of the result, of the
// user or of the model, no tool name. The body is decoded first and only the
// id field of each tool-result message is read, so the same words in any other
// place name no call. OpenClaw rewrites an id before it replays the call to
// some providers (Anthropic Messages, Chat Completions, Bedrock Converse): only
// letters and digits are kept and the id is cut to 40 characters, so
// "toolu_bdrk_01ab" comes back as "toolubdrk01ab". The result is tied to the
// block when its id is that replay form of the recorded id, and two calls whose
// ids have one replay form are ambiguous to those adapters (see
// replayToolCallID); a Responses or Gemini result carries the id as recorded, so
// it neither matches the replay form nor is made ambiguous by it. A new id for a
// repeated id matches nothing and the notice waits until it expires: the line
// is UX only, so when the tie is unknown nothing is shown. A Responses id is "<call id>|<item id>" and the result carries the
// call id alone; OpenClaw drops the item id from the replayed call unless it
// replays the reasoning too, so the result is tied to the block by the call id
// when the request names no item of the call, and every inspected call is
// remembered by its call id, so a second call under it makes the block
// ambiguous. A provider whose results carry no call id (Ollama, Gemini without
// ids) cannot be keyed and shows nothing. An allowed call records nothing.
//
// The line is shown only when the tie is unambiguous, and an unclear tie shows
// nothing. A call id is not unique: OpenClaw replay rewrites a repeated id, two
// sessions of one account can send the same one, and one session can reuse it.
// A block is unambiguous when
//   - its call id was inspected exactly once (every OpenClaw tool call the
//     inspect endpoint sees, allowed or blocked, is noted with its id for a
//     while; a second call of any session or outcome under the id, before or
//     after the block, makes the block ambiguous);
//   - the request is of the session of the block, and
//   - the plugin observed that session for this very request. The plugin stamps
//     the session header from its last tool context, which can be stale, so the
//     header alone is not proof: the plugin marks the one model request that
//     follows a tool call with SessionBoundHeader, and only a marked request
//     names a session here. An unmarked request, or one with no session, claims
//     nothing.
//
// An ambiguous block shows nothing and is consumed silently by the first result
// that claims it, and so is a block whose call part a request visibly carries
// in several items (never kept for a later, shorter replay of the same result). A notice is taken by one request, so a block is shown once. A
// reply with no text to lead with, or in a format that is not rewritten, gives
// the notice back until it expires, so the line lands on the first reply that
// can carry it. A reply DefenseClaw wrote itself (it starts with the block
// banner) is never prefixed, so history laundering still recognises it.

// SessionBoundHeader is set to "1" by the OpenClaw plugin on the one model
// request that follows a tool call, the request whose session header the plugin
// has just observed (GAP-0644).
const SessionBoundHeader = "X-DefenseClaw-Session-Bound"

const (
	openClawBlockNoticeTTL      = 2 * time.Minute
	openClawBlockNoticeCap      = 256
	openClawSeenCallTTL         = 30 * time.Minute
	openClawSeenCallCap         = 1024
	openClawBlockNoticeMark     = "[DefenseClaw] Tool call blocked"
	openClawBlockNoticeMaxBody  = 32 << 20
	openClawBlockNoticeMaxFrame = 4 << 20
)

type openClawBlockNotice struct {
	// callID is the id OpenClaw gave the blocked call; the result message of
	// that call carries it back.
	callID string
	// session is the session id the plugin sent with the inspect request; a
	// notice recorded with none is never claimed.
	session string
	line    string
	at      time.Time
	// ambiguous is set when any other inspected call used the same call key:
	// no result can be told apart, so the notice is consumed by the first
	// result that claims it and shows nothing.
	ambiguous bool
	// replayAmbiguous is set when another inspected call has a different id
	// with the same replay form (replayToolCallID). Only a result of an
	// adapter that replays ids in that form cannot tell the two apart; a
	// Responses result carries the id as OpenClaw recorded it.
	replayAmbiguous bool
}

// openClawSeenCall is one tool call the inspect endpoint saw, kept only to
// tell that a call id was used twice. key is the call key of its id and replay
// is the replay form of the whole id.
type openClawSeenCall struct {
	key    string
	replay string
	at     time.Time
}

// noticeCallKey is the part of a call id that names the call. OpenClaw names a
// Responses call "<call id>|<item id>" and sends the call id alone back with
// the result, so two ids with one call key are one call to a result. Any other
// id is its own key.
func noticeCallKey(id string) string {
	if i := strings.Index(id, "|"); i > 0 {
		return id[:i]
	}
	return id
}

// replayToolCallID is the form OpenClaw replays a tool call id in to a provider
// that takes only letters and digits (its "strict" tool call id mode, used for
// the Anthropic Messages, Chat Completions and Bedrock Converse transcripts):
// every other character is dropped and the rest is cut to 40 characters, and an
// id with nothing left becomes a fixed word. A provider id that is already in
// that form replays unchanged. Only the first use of an id in a transcript
// gets this form; a repeated id gets a hash or counter suffix, which no longer
// names the call, so it is not matched.
func replayToolCallID(id string) string {
	b := make([]byte, 0, len(id))
	for i := 0; i < len(id); i++ {
		if c := id[i]; c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5a || c >= 0x61 && c <= 0x7a {
			b = append(b, c)
		}
	}
	switch {
	case len(b) == 0:
		return "sanitizedtoolid"
	case len(b) > 40:
		b = b[:40]
	}
	return string(b)
}

var openClawBlockNotices struct {
	mu      sync.Mutex
	entries []openClawBlockNotice
	seen    []openClawSeenCall
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

// openClawBlockNoticeLine is the one line the user reads. The reason goes
// through the sink projection (rule ids kept, literals redacted) and never
// follows the operator's log reveal flag: this text is part of a model reply.
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
	if r := openClawNoticeText(redaction.ForSinkReason(reason), 240); r != "" {
		b.WriteString(" - " + r)
	}
	return b.String()
}

// openClawNoticeAllowed is false for a Secure Client configuration, whose
// inspect answers stay byte for byte as they were.
func openClawNoticeAllowed(cfg *config.Config) bool {
	return cfg == nil || !cfg.SecureClientIntegration()
}

// rememberOpenClawBlockNotice records an enforced block of one OpenClaw tool
// call under its call id and session. A call without an id cannot be tied to
// its result and records nothing. Nothing in the inspect call tells two events
// of one id apart, so a second call under the id is ambiguous with the block.
func rememberOpenClawBlockNotice(tool, callID, session string, ruleIDs []string, reason string) {
	line := openClawBlockNoticeLine(tool, ruleIDs, reason)
	recordOpenClawToolCall(callID, session, &line)
}

// observeOpenClawToolCall notes an OpenClaw tool call that was not blocked, so
// a block recorded under the same call id is known to be ambiguous. It records
// no notice.
func observeOpenClawToolCall(callID string) {
	recordOpenClawToolCall(callID, "", nil)
}

// recordOpenClawToolCall notes one inspected call and, when blockLine is set,
// records its block notice. A second call under an id makes every live block
// under that id ambiguous, whichever came first.
func recordOpenClawToolCall(callID, session string, blockLine *string) {
	if callID == "" {
		return
	}
	openClawBlockNotices.mu.Lock()
	defer openClawBlockNotices.mu.Unlock()
	now := openClawToolOutcomeNow()
	entries := pruneOpenClawBlockNotices(openClawBlockNotices.entries, now)
	// The inspect side does not know which adapter will carry the result, so it
	// keeps both ties: calls with one call key, which every adapter confuses,
	// and calls with one replay form, which only the adapters that replay ids
	// in that form confuse.
	key, replay := noticeCallKey(callID), replayToolCallID(callID)
	seen := openClawBlockNotices.seen[:0]
	used, usedReplay := false, false
	for _, c := range openClawBlockNotices.seen {
		if now.Sub(c.at) < openClawSeenCallTTL {
			used = used || c.key == key
			usedReplay = usedReplay || (c.key != key && c.replay == replay)
			seen = append(seen, c)
		}
	}
	seen = append(seen, openClawSeenCall{key: key, replay: replay, at: now})
	if n := len(seen); n > openClawSeenCallCap {
		seen = seen[n-openClawSeenCallCap:]
	}
	openClawBlockNotices.seen = seen

	recorded := false
	for i := range entries {
		switch {
		case noticeCallKey(entries[i].callID) == key:
			entries[i].ambiguous = true
			recorded = recorded || entries[i].session == session
		case replayToolCallID(entries[i].callID) == replay:
			entries[i].replayAmbiguous = true
		}
	}
	// A second block of one call key and session adds no entry: the first is
	// already ambiguous and the pair is consumed by one result.
	if blockLine != nil && !recorded {
		entries = append(entries, openClawBlockNotice{callID: callID, session: session, line: *blockLine, at: now, ambiguous: used, replayAmbiguous: usedReplay})
	}
	openClawBlockNotices.entries = entries
	capOpenClawBlockNotices()
}

func capOpenClawBlockNotices() {
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

// openClawBlockNoticesPending reports whether a live notice waits for its
// block result. Expired notices are dropped first, so one block costs later
// requests at most the notice lifetime.
func openClawBlockNoticesPending() bool {
	openClawBlockNotices.mu.Lock()
	defer openClawBlockNotices.mu.Unlock()
	openClawBlockNotices.entries = pruneOpenClawBlockNotices(openClawBlockNotices.entries, openClawToolOutcomeNow())
	return len(openClawBlockNotices.entries) > 0
}

// inSession is true only for a request that names the session of the block. The
// caller passes no session for a request whose session the plugin did not
// observe, and a block recorded with none is never claimed.
func (n openClawBlockNotice) inSession(session string) bool {
	return session != "" && n.session == session
}

// takeOpenClawBlockNotices removes and returns the live notices whose call id
// the request body carries on a tool-result message. The same id anywhere else
// in the request takes nothing. A result id claimed by more than one live
// block of the request session is ambiguous and takes nothing.
func takeOpenClawBlockNotices(body []byte, session string) []openClawBlockNotice {
	// The body is decoded before any id is read: JSON allows the same string
	// to be spelled with escapes, which a raw byte search misses.
	ids := toolResultIDs(body)
	if len(ids) == 0 {
		return nil
	}
	openClawBlockNotices.mu.Lock()
	defer openClawBlockNotices.mu.Unlock()
	entries := pruneOpenClawBlockNotices(openClawBlockNotices.entries, openClawToolOutcomeNow())
	claimed := make([]bool, len(entries))
	// replayed marks a claim made by a result of an adapter that replays ids in
	// the strict form, which cannot tell calls of one replay form apart.
	replayed := make([]bool, len(entries))
	// dropped marks a block of the request session whose call part this
	// request carries in several items, so its result cannot be told apart.
	// The notice is consumed with nothing shown, so a later replay of the same
	// result with fewer items cannot attach it to an unrelated reply. One
	// other item of the call part is a sibling call and drops nothing. The
	// several-item rule comes before the id match: an id equal to the call
	// part (a call OpenClaw gave no item id) is no more provable than a
	// "<call>|<item>" one when the request shows several candidate items.
	dropped := make([]bool, len(entries))
	for _, r := range ids {
		claim := -1
		count := 0
		for i, e := range entries {
			if !e.inSession(session) {
				continue
			}
			switch {
			case r.items > 1 && noticeCallKey(e.callID) == r.id:
				dropped[i] = true
			case e.isResultOf(r):
				claim = i
				count++
			}
		}
		if count == 1 {
			claimed[claim] = true
			replayed[claim] = replayed[claim] || r.replays
		}
	}
	var taken []openClawBlockNotice
	kept := make([]openClawBlockNotice, 0, len(entries))
	for i, e := range entries {
		switch {
		case claimed[i] && !e.ambiguous && (!replayed[i] || !e.replayAmbiguous):
			taken = append(taken, e)
		case claimed[i] || dropped[i]:
		default:
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
	capOpenClawBlockNotices()
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
// OpenClaw tool block with the block notice. Only a request that authorized
// proves is the gateway owner and that is not routed to another connector is
// read, and only while a live notice waits; every other request passes through
// untouched and unbuffered.
func openClawBlockNoticeMiddleware(next http.Handler, authorized func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Body == nil || !openClawNoticeRoute(r) || !authorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !openClawBlockNoticesPending() {
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
		session := ""
		if strings.TrimSpace(r.Header.Get(SessionBoundHeader)) == "1" {
			session = strings.TrimSpace(r.Header.Get(SessionIDHeader))
		}
		notices := takeOpenClawBlockNotices(body, session)
		if len(notices) == 0 {
			// A live notice waits and this request did not claim it. The line
			// names no call, session or text: it only tells a live run which
			// condition kept the notice off the screen.
			fmt.Fprintf(os.Stderr, "[guardrail] openclaw block notice: pending, not claimed by %s (session_bound=%t)\n", r.URL.Path, session != "")
			next.ServeHTTP(w, r)
			return
		}
		// The line is written into the reply text, so the reply must reach the
		// writer as plain text. The model client asks for a compressed reply
		// (undici adds accept-encoding) and the passthrough forwards that
		// header, so a provider that compresses a stream would send back
		// bytes the writer cannot rewrite and the line would be lost. Without
		// the header the proxy transport asks for gzip itself and hands over
		// the decoded reply, which the client reads as an ordinary reply.
		r.Header.Del("Accept-Encoding")
		nw := &openClawNoticeWriter{ResponseWriter: w, notices: notices}
		lines := make([]string, len(notices))
		for i, n := range notices {
			lines[i] = n.line
		}
		nw.prefix = strings.Join(lines, "\n") + "\n\n"
		next.ServeHTTP(nw, r)
		nw.finish()
		fmt.Fprintf(os.Stderr, "[guardrail] openclaw block notice: claimed by %s, shown=%t (mode=%d status=%d content_type=%q content_encoding=%q)\n",
			r.URL.Path, nw.applied, nw.mode, nw.status, w.Header().Get("Content-Type"), w.Header().Get("Content-Encoding"))
	})
}

type proxyConnectorKey struct{}

// openClawNoticeRoute is true only for a request that is OpenClaw's: routed
// with the /c/openclaw/ prefix, or unprefixed (OpenClaw's own fetch
// interceptor sends no prefix) while the connector this gateway serves is
// OpenClaw. Traffic of any other connector, prefixed or not, and a request
// whose serving connector is unknown, never takes a notice.
func openClawNoticeRoute(r *http.Request) bool {
	routed, _ := r.Context().Value(proxyConnectorKey{}).(string)
	if routed != "" {
		return routed == "openclaw"
	}
	return thresholdConnectorFrom(r.Context()) == "openclaw"
}

const (
	noticePass = iota
	noticeSSE
	noticeNDJSON
	noticeEventStream
	noticeJSON
)

// openClawNoticeWriter rewrites the first assistant text of a model reply. It
// understands Chat Completions, Responses, Anthropic Messages, Gemini and Ollama
// streams and bodies, and Bedrock Converse bodies and event streams; any other
// reply passes through and the notice waits for a later one.
type openClawNoticeWriter struct {
	http.ResponseWriter
	notices []openClawBlockNotice
	prefix  string
	mode    int
	status  int
	started bool
	applied bool
	// synthetic is set when the first text is a reply DefenseClaw wrote: it is
	// left as it is, and the notice waits.
	synthetic bool
	gzipped   bool
	buf       []byte
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
	enc := strings.ToLower(strings.TrimSpace(w.Header().Get("Content-Encoding")))
	switch {
	case code < 200 || code >= 300:
		w.mode = noticePass
	case enc == "gzip" && strings.Contains(ct, "json") && !strings.Contains(ct, "ndjson"):
		w.mode, w.gzipped = noticeJSON, true
		return
	case enc != "" && enc != "identity":
		w.mode = noticePass
	case strings.Contains(ct, "text/event-stream"):
		w.mode = noticeSSE
		w.Header().Del("Content-Length")
	case strings.Contains(ct, "ndjson"):
		w.mode = noticeNDJSON
		w.Header().Del("Content-Length")
	case strings.Contains(ct, "application/vnd.amazon.eventstream"):
		w.mode = noticeEventStream
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
	case noticeSSE, noticeNDJSON, noticeEventStream:
		w.buf = append(w.buf, p...)
		return len(p), w.drain(false)
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
		w.finishJSON()
	case noticeSSE, noticeNDJSON, noticeEventStream:
		_ = w.drain(true)
	}
	// A reply with no text to lead with, a DefenseClaw-written reply, an error
	// or a format that is not rewritten leaves the notice for the next reply.
	if !w.applied {
		restoreOpenClawBlockNotices(w.notices)
	}
}

func (w *openClawNoticeWriter) finishJSON() {
	out := w.buf
	if w.gzipped {
		if plain, ok := gunzipNoticeBody(w.buf); ok {
			if rewritten, applied := w.rewriteBody(plain); applied {
				w.applied, out = true, rewritten
				w.Header().Del("Content-Encoding")
			}
		}
	} else {
		out, w.applied = w.rewriteBody(w.buf)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.ResponseWriter.WriteHeader(w.status)
	_, _ = w.ResponseWriter.Write(out)
}

func gunzipNoticeBody(raw []byte) ([]byte, bool) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	plain, err := io.ReadAll(io.LimitReader(zr, openClawBlockNoticeMaxBody+1))
	if err != nil || len(plain) > openClawBlockNoticeMaxBody {
		return nil, false
	}
	return plain, true
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

func lineFrameEnd(b []byte) (int, int) {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return i, 1
	}
	return -1, 0
}

// eventStreamFrameEnd reads the total length from the prelude of an AWS event
// stream message. A length no message can have gives up (-2).
func eventStreamFrameEnd(b []byte) (int, int) {
	if len(b) < 4 {
		return -1, 0
	}
	total := int(binary.BigEndian.Uint32(b[:4]))
	if total < 16 || total > openClawBlockNoticeMaxFrame {
		return -2, 0
	}
	if len(b) < total {
		return -1, 0
	}
	return total, 0
}

func (w *openClawNoticeWriter) drain(final bool) error {
	frameEnd, rewrite := sseFrameEnd, w.rewriteFrame
	switch w.mode {
	case noticeNDJSON:
		frameEnd, rewrite = lineFrameEnd, w.rewriteLine
	case noticeEventStream:
		frameEnd, rewrite = eventStreamFrameEnd, w.rewriteEventStreamMessage
	}
	for {
		idx, n := frameEnd(w.buf)
		if idx == -2 {
			return w.flushRest(false)
		}
		if idx < 0 {
			break
		}
		frame := append([]byte(nil), w.buf[:idx+n]...)
		w.buf = w.buf[idx+n:]
		if _, err := w.ResponseWriter.Write(rewrite(frame)); err != nil {
			return err
		}
	}
	if len(w.buf) > openClawBlockNoticeMaxFrame || (final && len(w.buf) > 0) {
		return w.flushRest(final)
	}
	return nil
}

// flushRest sends what is buffered unchanged and, unless the reply is over,
// stops rewriting.
func (w *openClawNoticeWriter) flushRest(final bool) error {
	rest := w.buf
	w.buf = nil
	if !final {
		w.mode = noticePass
	}
	_, err := w.ResponseWriter.Write(rest)
	return err
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

func encodeNoticeJSON(obj any) ([]byte, bool) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(obj) != nil {
		return nil, false
	}
	return bytes.TrimRight(out.Bytes(), "\n"), true
}

// rewritePayload puts the notice in one JSON event when it carries text that
// should lead with it, and keeps the Responses done events in step with the
// deltas.
func (w *openClawNoticeWriter) rewritePayload(payload []byte) ([]byte, bool) {
	obj, ok := decodeNoticeJSON(payload)
	if !ok || !w.rewriteEvent(obj) {
		return nil, false
	}
	return encodeNoticeJSON(obj)
}

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
	enc, ok := w.rewritePayload(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:"))))
	if !ok {
		return frame
	}
	lines[dataAt] = append([]byte("data: "), enc...)
	if cr {
		lines[dataAt] = append(lines[dataAt], "\r"...)
	}
	return bytes.Join(lines, []byte("\n"))
}

// rewriteLine handles one line of a newline-delimited JSON stream (Ollama).
func (w *openClawNoticeWriter) rewriteLine(line []byte) []byte {
	if w.applied {
		return line
	}
	body := bytes.TrimRight(line, "\r\n")
	enc, ok := w.rewritePayload(bytes.TrimSpace(body))
	if !ok {
		return line
	}
	return append(enc, line[len(body):]...)
}

// rewriteEventStreamMessage handles one message of a Bedrock ConverseStream.
func (w *openClawNoticeWriter) rewriteEventStreamMessage(frame []byte) []byte {
	if w.applied {
		return frame
	}
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	if err != nil || msg.Headers.Get(":event-type") == nil || msg.Headers.Get(":event-type").String() != "contentBlockDelta" {
		return frame
	}
	obj, ok := decodeNoticeJSON(msg.Payload)
	if !ok {
		return frame
	}
	delta, _ := obj["delta"].(map[string]any)
	if delta == nil || !w.prefixField(delta, "text") {
		return frame
	}
	payload, ok := encodeNoticeJSON(obj)
	if !ok {
		w.applied = false
		return frame
	}
	msg.Payload = payload
	var out bytes.Buffer
	if eventstream.NewEncoder().Encode(&out, msg) != nil {
		w.applied = false
		return frame
	}
	return out.Bytes()
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
		// Chat Completions chunk, Gemini candidate or Ollama message.
		if choices, _ := obj["choices"].([]any); len(choices) > 0 {
			c0, _ := choices[0].(map[string]any)
			delta, _ := c0["delta"].(map[string]any)
			return delta != nil && w.prefixField(delta, "content")
		}
		if w.prefixGemini(obj) {
			return true
		}
		msg, _ := obj["message"].(map[string]any)
		return msg != nil && w.prefixField(msg, "content")
	}
	return false
}

// prefixGemini puts the notice in the first answer part of a Gemini reply.
func (w *openClawNoticeWriter) prefixGemini(obj map[string]any) bool {
	cands, _ := obj["candidates"].([]any)
	if len(cands) == 0 {
		return false
	}
	c0, _ := cands[0].(map[string]any)
	content, _ := c0["content"].(map[string]any)
	if content == nil {
		return false
	}
	parts, _ := content["parts"].([]any)
	for _, p := range parts {
		part, _ := p.(map[string]any)
		if part == nil {
			continue
		}
		if thought, _ := part["thought"].(bool); thought {
			continue
		}
		if w.prefixField(part, "text") {
			return true
		}
	}
	return false
}

// prefixField puts the notice in front of a non-empty string field and counts
// it as shown. A text that starts with the block banner is a reply DefenseClaw
// wrote: it stays as it is and nothing after it is prefixed.
func (w *openClawNoticeWriter) prefixField(m map[string]any, key string) bool {
	s, _ := m[key].(string)
	if s == "" || w.synthetic {
		return false
	}
	if strings.HasPrefix(strings.TrimLeft(s, " \t\r\n"), defenseClawBlockBanner) {
		w.synthetic = true
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
	var doc any
	if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '[' {
		// A Gemini reply streamed without alt=sse is one JSON array of chunks.
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var arr []any
		if dec.Decode(&arr) != nil {
			return body, false
		}
		for _, el := range arr {
			if obj, _ := el.(map[string]any); obj != nil && w.rewriteBodyObject(obj) {
				doc = arr
				break
			}
		}
	} else if obj, ok := decodeNoticeJSON(body); ok && w.rewriteBodyObject(obj) {
		doc = obj
	}
	if doc == nil {
		return body, false
	}
	out, ok := encodeNoticeJSON(doc)
	if !ok {
		w.applied = false
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
	// Gemini.
	if w.prefixGemini(obj) {
		return true
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
	// Ollama chat.
	if msg, _ := obj["message"].(map[string]any); msg != nil {
		return w.prefixField(msg, "content")
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
