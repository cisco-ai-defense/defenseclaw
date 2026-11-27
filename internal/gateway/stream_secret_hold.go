// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

// The open-secret hold of a streamed reply (rel-1-0-10:GAP-0429).
//
// The mid-stream check matches a secret only once its text is complete: a
// private-key block is a key to secretshape only with its END line, and a
// token rule matches only once the token has its length. A check that runs
// while such a secret is still arriving passes, and the stream used to send
// what that check had read, so most of a key body could reach the client
// before the block. Each lane of the reply text (responseText) now reports
// an OPEN SECRET, text from the first byte that can start a secret whose
// match needs more of the stream:
//
//   - a "-----BEGIN " line not yet complete, or complete with a private-key
//     label (any label with PRIVATE KEY: PKCS#1, SEC1, DSA, PKCS#8 plain and
//     encrypted, OpenSSH, PGP), up to its END line. A complete BEGIN line of
//     another label, an END line of any label, or a line that no PEM body
//     has ends it (GAP-0428), and the search goes on after that BEGIN line,
//     so a decoy header before a key does not hide the key;
//   - the prefix of a token rule of the secret rules (streamTokenOpenEach) with
//     at least one byte of the token, the token still running at the end of
//     the lane;
//   - a digit run that can still become a card number or an SSN the
//     response rules block (streamPIIRules, rel-1-0-10:GAP-1091), from its
//     first digit, still running at the end of the lane.
//
// While the reply has an open secret, the stream paths (the /llm proxy, the
// passthrough stream and the raw forward stream) send nothing more in action
// mode: the held bytes go out once the secret has ended and a check has read
// it whole, which blocks or alerts as for any complete secret. The hold is
// bounded (the bound rule, internal/guardrail/bounded). An open private-key
// block over streamSecretMaxPEM bytes of text, more than streamSecretMaxHeld
// bytes held behind an open private-key block, an open private-key block
// with no new text for streamHoldMaxPartialAge (the paths that read on their
// own goroutine), and a stream that ends inside an open private-key block are
// TRUNCATED: the text is checked, then the unknown tier of the pack decides
// (default and permissive alert and send, strict blocks). That secret is then
// no longer held.
//
// A token or a digit run is bounded by its own length and by the end of the
// stream, so it gets no TRUNCATED verdict (rel-1-0-10:GAP-1265): a reply
// that ends a piece with a version, a port or a count is not a secret that
// could not be read. A run streamSecretMaxToken bytes long (22 digits for a
// digit run) has been decided by every rule and is no longer open, and the
// end of the stream ends it. It has no idle clock: while the upstream is
// quiet it stays held, and the next text or the end decides it, so a card
// number or a token the upstream pauses inside never goes out in part. Past
// streamSecretMaxHeld bytes held behind open runs (a long numeric table keeps
// one open at almost every piece end) the held bytes go out once the check
// has read them, with no verdict, and what follows is held again. While
// the upstream is quiet behind an open run the client gets a keep-alive, or
// the held bytes with the run masked, every streamKeepAliveAfter
// (rel-1-0-10:GAP-1307, stream_keepalive.go).
const (
	// streamSecretMaxPEM is the largest block secretshape reads as a key
	// (maxPrivateKeyPEMBytes).
	streamSecretMaxPEM = 64 << 10
	// streamSecretMaxHeld bounds the stream bytes held behind an open secret.
	streamSecretMaxHeld = 1 << 20
	// streamSecretMaxToken is longer than the shortest match of every token
	// rule (the longest minimum, SEC-PYPI-TOKEN, is 55 bytes).
	streamSecretMaxToken = 256
	// streamSecretTail is how much of the end of a lane the token check reads.
	streamSecretTail = streamSecretMaxToken + 64
	// streamPEMLineMax: secretshape reads no BEGIN line and no body line
	// longer than 80 bytes; metadata lines are up to 32+1+256.
	streamPEMLineMax = 290
)

const pemBeginMark = "-----BEGIN "

// streamTokenRules are the token shapes of the secret rules (the
// secrets.yaml of every shipped pack), each with the prefix that starts it
// and the bytes its token is made of. TestStreamTokenOpenCoversSecretRules
// fails when a pack gains a secret rule that is not listed here.
var streamTokenRules = []struct {
	rules []string
	open  string
}{
	{[]string{"SEC-AWS-KEY"}, `(?:AKIA|ASIA)[0-9A-Z]+`},
	{[]string{"SEC-ANTHROPIC", "SEC-OPENAI", "SEC-OPENAI-V2", "SEC-STRIPE"}, `[sr]k[-_][A-Za-z0-9_-]+`},
	{[]string{"SEC-GITHUB-TOKEN"}, `gh[pousr]_[A-Za-z0-9]+`},
	{[]string{"SEC-GITHUB-PAT"}, `github_pat_[A-Za-z0-9_]+`},
	{[]string{"SEC-GITLAB"}, `glpat-[A-Za-z0-9_-]+`},
	{[]string{"SEC-GOOGLE"}, `AIza[0-9A-Za-z_-]+`},
	{[]string{"SEC-SLACK-TOKEN"}, `xox[a-z]-[0-9A-Za-z-]+`},
	{[]string{"SEC-SLACK-WEBHOOK"}, `https://hooks\.slack\.com/services/[A-Za-z0-9/]+`},
	{[]string{"SEC-DISCORD-WEBHOOK"}, `https://discord(?:app)?\.com/api/webhooks/[0-9A-Za-z_/-]+`},
	{[]string{"SEC-JWT"}, `eyJ[A-Za-z0-9_.+/=-]+`},
	{[]string{"SEC-CONNSTR"}, `(?:mongodb|postgres|mysql|redis|amqp)://[^\s@]+`},
	{[]string{"SEC-BEARER", "SEC-BEARER-BARE"}, `(?i:bearer\s+[A-Za-z0-9_.~+/=-]+)`},
	{[]string{"SEC-PASSWORD-ASSIGN"}, `(?i:(?:password|passwd|pwd|passphrase)[0-9]{0,3}\\*["']?[ \t]*(?:=>|:=|==|=|:)[ \t]*\\*["']?[^\s"'` + "`" + `\\,;]+)`},
	{[]string{"SEC-SECRET-ASSIGN", "SEC-HEX-SECRET", "SEC-AWS-SECRET"}, `(?i:(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|private[_-]?key|encryption[_-]?key|signing[_-]?key|credential)s?[a-z0-9_-]{0,48}\\*["']?\s*(?:[:=,(]|\s+is\s+|=>)\s*\\*["']?[A-Za-z0-9_\-+/=.!@#$%^&*~()]+)`},
	{[]string{"SEC-SENDGRID"}, `SG\.[A-Za-z0-9_.-]+`},
	{[]string{"SEC-TWILIO"}, `SK[0-9a-fA-F]+`},
	{[]string{"SEC-NPM-TOKEN"}, `npm_[A-Za-z0-9]+`},
	{[]string{"SEC-HF-TOKEN"}, `hf_[A-Za-z0-9]+`},
	{[]string{"SEC-PYPI-TOKEN"}, `pypi-[A-Za-z0-9_-]+`},
}

// streamPIIRules are the PII shapes the response rules block
// (rel-1-0-10:GAP-1091): the card numbers (ENT-CC-*, the labelled
// PII-CARD-LABELED of privacy-high-assurance) and the SSN (ENT-BULK-SSN,
// ENT-BULK-SSN-NOHYPHEN) of the packs, and the legacy local card and SSN
// checks. One open shape covers them: a run of ASCII digits that starts at
// a word boundary, with a space, a dash or a format character (zero-width,
// which the normalized check removes) between digits, ending at the end of
// the text, or ending in such a separator or a cut UTF-8 sequence. It has at
// most 22 digits, more than the longest match (19), so it
// holds a run only while it can still become a match, from its first digit.
// TestStreamPIIOpenCoversBlockingPIIRules fails when a pack gains a card or
// SSN rule that is not listed here.
var streamPIIRules = []struct {
	rules []string
	open  string
}{
	{[]string{"ENT-CC-VISA", "ENT-CC-MC", "ENT-CC-AMEX", "ENT-CC-DISCOVER", "PII-CARD-LABELED", "ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN"},
		`\b[0-9](?:\p{Cf}*(?:` + streamPIISep + `\p{Cf}*)?[0-9]){0,21}\p{Cf}*(?:` + streamPIISep + `\p{Cf}*)?\x{FFFD}?`},
}

// streamPIISep is a separator a normalized card or SSN match may have
// between digits: white space, a Unicode space, an ASCII or Unicode dash.
const streamPIISep = `[\s\p{Zs}\-\x{2010}-\x{2015}\x{2212}]`

// streamSecretExempt are the secret rules with no token to hold: a request
// phrase, not a secret value (strict), and the private key, which has its own
// hold (secretLane.pem).
var streamSecretExempt = map[string]bool{"SEC-ENV-DUMP-REQUEST": true, "SEC-PRIVKEY": true}

// streamTokenOpenEach match a token, or a card or SSN digit run, still
// running at the end of a text: one expression per alternative of
// streamTokenOpenAlts, each anchored at the end on its own
// (streamTokenOpenStart).
var streamTokenOpenEach = func() []*regexp.Regexp {
	alts := streamTokenOpenAlts()
	out := make([]*regexp.Regexp, len(alts))
	for i, alt := range alts {
		out[i] = regexp.MustCompile(`(?:` + alt + `)$`)
	}
	return out
}()

func streamTokenOpenAlts() []string {
	alts := make([]string, 0, len(streamTokenRules)+len(streamPIIRules))
	for _, r := range streamTokenRules {
		alts = append(alts, r.open)
	}
	for _, r := range streamPIIRules {
		alts = append(alts, r.open)
	}
	return alts
}

// streamTokenOpenStart is the start of the match in tail of the
// alternatives joined into one end-anchored expression, -1 for none (the
// tests hold that expression, streamTokenOpen, as the reference). The joined
// expression matches at the leftmost offset where one of its alternatives
// matches up to the end, so the start is the least start of the
// alternatives' matches. An alternative whose required literals the
// tail lacks (rxprefilter) cannot match and is not run: the one automaton of
// every alternative read the whole tail at each piece of a stream, the
// largest cost of a streamed reply after GAP-0515 (substrate-1:GAP-1107).
func streamTokenOpenStart(tail string) int {
	text := rxprefilter.NewText(tail)
	best := -1
	for _, re := range streamTokenOpenEach {
		if !text.HoldsLiterals(re) {
			continue
		}
		if loc := re.FindStringIndex(tail); loc != nil && (best < 0 || loc[0] < best) {
			best = loc[0]
		}
	}
	return best
}

// secretLane is the open-secret state of one lane of reply text. The lane
// only grows; the state is advanced over the new text when asked.
type secretLane struct {
	pemFrom  int  // no open private-key block starts before pemFrom
	pemStart int  // start of the open BEGIN line, when pemOpen
	pemOpen  bool // a BEGIN line not yet complete or an open key block
	pemKey   bool // the BEGIN line is complete and names a private key
	pemLine  int  // start of the first line of the open block not yet read
	// tokenFrom: a token run that starts before it was given up at a bound.
	tokenFrom int
	// parked: the lane's block ended inside an open run, at reply text
	// offset parkedAt; the run stays held (rel-1-0-10:GAP-2162).
	parked    bool
	parkedAt  int
	parkLimit int
}

// pem advances the private-key state over t and reports an open BEGIN line
// or block, and whether that block passed streamSecretMaxPEM.
func (s *secretLane) pem(t string) (open, overCap bool) {
	for {
		if !s.pemOpen {
			i := strings.Index(t[s.pemFrom:], pemBeginMark)
			if i < 0 {
				s.pemFrom = max(s.pemFrom, len(t)-len(pemBeginMark)+1)
				return false, false
			}
			s.pemStart, s.pemOpen, s.pemKey = s.pemFrom+i, true, false
			s.pemLine = s.pemStart
		}
		if !s.pemKey {
			end, next, done := pemLineEnd(t, s.pemStart)
			if !done {
				if end-s.pemStart > 80 {
					s.pemSkip() // secretshape reads no longer BEGIN line
					continue
				}
				return true, false // a BEGIN line still arriving (GAP-0429)
			}
			if !privateKeyBeginLine(t[s.pemStart:end]) {
				s.pemSkip() // another label: no key (GAP-0428, GAP-0429)
				continue
			}
			s.pemKey, s.pemLine = true, next
		}
		closed := false
		for !closed {
			end, next, done := pemLineEnd(t, s.pemLine)
			line := t[s.pemLine:end]
			switch {
			case strings.HasPrefix(line, "-----END "):
				if done || pemFooterComplete(line) {
					// The END line of this label or of another one: the
					// check reads the block whole (GAP-0428).
					s.pemOpen, s.pemFrom = false, s.pemLine+len("-----END ")
					closed = true
					continue
				}
			case done && pemBodyLine(line):
				s.pemLine = next
				continue
			case done:
				// A line no PEM body has: no key; search on after the BEGIN.
				s.pemSkip()
				closed = true
				continue
			}
			// The line is still arriving.
			if len(line) > streamPEMLineMax || !pemPartialLine(line) {
				s.pemSkip()
				closed = true
				continue
			}
			return true, s.pemLine-s.pemStart > streamSecretMaxPEM
		}
	}
}

// pemSkip ends the open BEGIN line or block without a key: the search goes
// on after its BEGIN mark.
func (s *secretLane) pemSkip() {
	s.pemOpen, s.pemFrom = false, s.pemStart+len(pemBeginMark)
}

// token reports a token of a secret rule still running at the end of t.
func (s *secretLane) token(t string) bool { return s.tokenStart(t) >= 0 }

// tokenStart is the start of the token or digit run still running at the
// end of t, -1 for none.
func (s *secretLane) tokenStart(t string) int {
	from := max(len(t)-streamSecretTail, 0)
	at := streamTokenOpenStart(t[from:])
	if at < 0 {
		return -1
	}
	start := from + at
	if start < s.tokenFrom || len(t)-start >= streamSecretMaxToken {
		return -1
	}
	return start
}

// giveUp stops holding what is open in t (a bound was hit): its block and
// its token are released, and the search goes on after them.
func (s *secretLane) giveUp(t string) {
	s.pemOpen, s.pemFrom = false, len(t)
	s.tokenFrom = len(t)
}

// endRun ends the token or digit run open at the end of t: the lane has
// ended (rel-1-0-10:GAP-2154), so the run is whole. A run that starts in
// text added later is held as before.
func (s *secretLane) endRun(t string) { s.tokenFrom = len(t) }

// pemLineEnd finds the end of the line that starts at start: a line feed,
// or the two characters backslash n of JSON-escaped text (tool arguments);
// a carriage return before it, plain or escaped, is not part of the line.
// done is false when the line has not ended yet (end is len(t)); next is the
// start of the next line.
func pemLineEnd(t string, start int) (end, next int, done bool) {
	for i := start; i < len(t); i++ {
		switch t[i] {
		case '\n':
			end = i
			if end > start && t[end-1] == '\r' {
				end--
			}
			return end, i + 1, true
		case '\\':
			if i+1 >= len(t) {
				return i, len(t), false // an escape cut at the end
			}
			if t[i+1] == 'n' {
				end = i
				if end-2 >= start && t[end-2:end] == `\r` {
					end -= 2
				}
				return end, i + 2, true
			}
		}
	}
	end = len(t)
	if end > start && t[end-1] == '\r' {
		end--
	}
	if end-2 >= start && t[end-2:end] == `\r` {
		end -= 2
	}
	return end, len(t), false
}

// privateKeyBeginLine reports a complete BEGIN line of a private-key label.
func privateKeyBeginLine(line string) bool {
	if len(line) > 80 || !strings.HasSuffix(line, "-----") || len(line) < len(pemBeginMark)+len("-----") {
		return false
	}
	label := line[len(pemBeginMark) : len(line)-len("-----")]
	return strings.Contains(label, "PRIVATE KEY")
}

// pemFooterComplete reports an END line with its closing dashes, which may
// be followed by a quote or a bracket and not a line end.
func pemFooterComplete(line string) bool {
	return len(line) > len("-----END ") && strings.Contains(line[len("-----END "):], "-----")
}

// pemBodyLine reports a complete line a PEM body can have: blank (after the
// metadata), base64, or a metadata line (Proc-Type, DEK-Info, Comment).
func pemBodyLine(line string) bool {
	if line == "" {
		return true
	}
	if len(line) <= 80 && pemBase64(line) {
		return true
	}
	colon := strings.IndexByte(line, ':')
	return colon >= 1 && colon <= 32 && len(line) <= streamPEMLineMax && pemMetadataKey(line[:colon])
}

// pemPartialLine reports a start of a line that a PEM body line or an END
// line can still become.
func pemPartialLine(line string) bool {
	if strings.HasPrefix(line, "-") {
		return true
	}
	if pemBase64(line) {
		return true
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return len(line) <= 32 && pemMetadataKey(line)
	}
	return colon >= 1 && colon <= 32 && pemMetadataKey(line[:colon])
}

func pemBase64(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
		default:
			return false
		}
	}
	return true
}

func pemMetadataKey(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// openSecret is the open secret of a reply (GAP-0429).
type openSecret struct {
	open    bool // a lane ends inside a secret whose match needs more text
	pem     bool // one of them is a private-key block or BEGIN line: the end of the stream does not end it
	overCap bool // an open private-key block passed streamSecretMaxPEM
	// reasoningOnly: all open runs are parked reasoning tokens, which can
	// be masked in their own wire events while answer events stream.
	reasoningOnly bool
}

// OpenSecret advances every lane and same-choice check boundary over text
// added since the last call. The boundary state holds partial answer bytes
// behind a split secret until the existing matcher reads them whole.
func (r *responseText) OpenSecret() openSecret {
	var o openSecret
	var reasoningOpen, otherOpen bool
	for i, l := range r.lanes {
		t := l.String()
		pemOpen, over := r.secret[i].pem(t)
		o.pem = o.pem || pemOpen
		o.overCap = o.overCap || over
		tokenOpen := r.secret[i].token(t)
		if tokenOpen && r.secret[i].parked {
			if lane, ok := r.laneForIndex(i); ok && lane.field == responseFieldReasoning {
				reasoningOpen = true
			} else {
				otherOpen = true
			}
		} else if tokenOpen || pemOpen {
			otherOpen = true
		}
	}
	for i := range r.boundaries {
		b := &r.boundaries[i]
		line := r.boundaryLine(b)
		if b.final {
			b.secret.endRun(line)
			continue
		}
		if b.secret.token(line) {
			otherOpen = true
		}
	}
	o.open = reasoningOpen || otherOpen
	o.reasoningOnly = reasoningOpen && !otherOpen && !o.pem
	return o
}

// ReleaseOpenSecret stops holding what is open now, after a bound decided it.
func (r *responseText) ReleaseOpenSecret() {
	for i, l := range r.lanes {
		r.secret[i].giveUp(l.String())
	}
	for i := range r.boundaries {
		b := &r.boundaries[i]
		b.secret.giveUp(r.boundaryLine(b))
	}
}

// bufferedBytes is the size of the held chunks.
func bufferedBytes(chunks [][]byte) int {
	n := 0
	for _, c := range chunks {
		n += len(c)
	}
	return n
}
