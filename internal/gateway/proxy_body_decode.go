// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// One body decoder for the guardrail proxy (substrate-1 GAP-0189, GAP-0196).
//
// A request or a provider reply is read by the guardrail the way its
// receiver reads it, or it is not read at all. decodeBody applies the
// Content-Encoding (gzip, x-gzip, deflate, br, zstd, stacked), then the
// byte-order mark and the charset (UTF-8, UTF-16, UTF-32, ASCII, Latin-1),
// for the request, the buffered reply and the streamed reply alike, and
// sseFramer frames a server-sent-events stream as the WHATWG specification
// does. What the decoder cannot read is an error here and takes the fail
// mode at the caller (refuseUninspectable: refused on a managed install and
// in the strict tier, forwarded with an alert otherwise).

// errBodyUndecodable is the error of a body the decoder cannot read; its
// message is the reason recorded with the verdict.
type errBodyUndecodable struct{ why string }

func (e *errBodyUndecodable) Error() string { return e.why }

// streamDecodeCap bounds the decoded bytes of one streamed reply.
const streamDecodeCap = 256 << 20

// decodedBody is a body after the decoder.
type decodedBody struct {
	// Wire is the body with its Content-Encoding removed.
	Wire []byte
	// Text is Wire as UTF-8 without a byte-order mark: what is parsed and
	// inspected.
	Text []byte
	// Decoded reports that a Content-Encoding was removed.
	Decoded bool
	// Transcoded reports that Text differs from Wire (a byte-order mark or
	// another charset).
	Transcoded bool
}

// decodeBody decodes body by the Content-Encoding and the Content-Type
// charset in h. It changes neither h nor body.
func decodeBody(h http.Header, body []byte) (decodedBody, error) {
	wire, encoded, err := decodeEncodings(h, body)
	if err != nil {
		return decodedBody{}, err
	}
	text, transcoded, err := decodeCharset(h.Get("Content-Type"), wire)
	if err != nil {
		return decodedBody{}, err
	}
	return decodedBody{Wire: wire, Text: text, Decoded: encoded, Transcoded: transcoded}, nil
}

// encodingLayers are the encodings named by h in the order they were
// applied, identity dropped. The error is an unknown token or too many
// layers.
func encodingLayers(h http.Header) ([]string, error) {
	enc := uninspectableEncoding(h)
	if enc == "" {
		return nil, nil
	}
	var layers []string
	for _, l := range strings.Split(enc, ",") {
		if t := strings.TrimSpace(l); t != "" && t != "identity" {
			layers = append(layers, t)
		}
	}
	if len(layers) > replyDecodeMaxLayers {
		return nil, &errBodyUndecodable{"content-encoding " + enc + " names more than " + "4 layers"}
	}
	for _, l := range layers {
		switch l {
		case "gzip", "x-gzip", "deflate", "br", "zstd":
		default:
			return nil, &errBodyUndecodable{"content-encoding " + enc}
		}
	}
	return layers, nil
}

// decodeEncodings removes the Content-Encoding of a complete body.
func decodeEncodings(h http.Header, body []byte) ([]byte, bool, error) {
	layers, err := encodingLayers(h)
	if err != nil {
		return nil, false, err
	}
	if len(layers) == 0 {
		return body, false, nil
	}
	out := body
	for i := len(layers) - 1; i >= 0; i-- {
		if out, err = decodeReplyLayer(layers[i], out); err != nil {
			return nil, false, &errBodyUndecodable{"content-encoding " + uninspectableEncoding(h) + " could not be decoded"}
		}
	}
	return out, true, nil
}

// openEncodingReader opens one decoder layer over in.
func openEncodingReader(enc string, in io.Reader) (io.Reader, func(), error) {
	switch enc {
	case "", "identity":
		return in, func() {}, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(in)
		if err != nil {
			return nil, nil, err
		}
		return zr, func() { _ = zr.Close() }, nil
	case "deflate":
		// HTTP deflate is zlib-wrapped; some servers send raw DEFLATE.
		br := bufio.NewReader(in)
		if head, err := br.Peek(2); err == nil && head[0]&0x0f == 8 && (uint(head[0])<<8|uint(head[1]))%31 == 0 {
			if zr, err := zlib.NewReader(br); err == nil {
				return zr, func() { _ = zr.Close() }, nil
			}
		}
		fr := flate.NewReader(br)
		return fr, func() { _ = fr.Close() }, nil
	case "br":
		return brotli.NewReader(in), func() {}, nil
	case "zstd":
		zr, err := zstd.NewReader(in, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(replyDecodeCap+(1<<20)))
		if err != nil {
			return nil, nil, err
		}
		return zr, zr.Close, nil
	}
	return nil, nil, errReplyEncodingUnknown
}

// capReader fails a read past n bytes.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, errReplyDecodedTooLarge
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	return n, err
}

// newStreamDecoder wraps the body of a streamed reply in the decoders its
// Content-Encoding names. The returned close function releases them.
func newStreamDecoder(h http.Header, body io.Reader) (io.Reader, func(), error) {
	layers, err := encodingLayers(h)
	if err != nil {
		return nil, nil, err
	}
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	r := body
	for i := len(layers) - 1; i >= 0; i-- {
		dr, closeFn, err := openEncodingReader(layers[i], r)
		if err != nil {
			closeAll()
			return nil, nil, &errBodyUndecodable{"content-encoding " + uninspectableEncoding(h) + " could not be decoded"}
		}
		closers = append(closers, closeFn)
		r = &capReader{r: dr, n: streamDecodeCap}
	}
	return r, closeAll, nil
}

// decodeCharset returns body as UTF-8 text: a byte-order mark is read and
// removed, UTF-16 and UTF-32 (with or without a mark, by the Content-Type
// charset or by the null-byte pattern of a JSON text) and Latin-1 are
// transcoded; any other charset is an error.
func decodeCharset(contentType string, body []byte) ([]byte, bool, error) {
	cs := ""
	if contentType != "" {
		if _, params, err := mime.ParseMediaType(contentType); err == nil {
			cs = strings.ToLower(strings.TrimSpace(params["charset"]))
		}
	}
	switch {
	case bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}):
		return body[3:], true, nil
	case bytes.HasPrefix(body, []byte{0xFF, 0xFE, 0x00, 0x00}):
		return transcodeUTF32(body[4:], false)
	case bytes.HasPrefix(body, []byte{0x00, 0x00, 0xFE, 0xFF}):
		return transcodeUTF32(body[4:], true)
	case bytes.HasPrefix(body, []byte{0xFF, 0xFE}):
		return transcodeUTF16(body[2:], false)
	case bytes.HasPrefix(body, []byte{0xFE, 0xFF}):
		return transcodeUTF16(body[2:], true)
	}
	switch cs {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
	case "utf-16", "utf-16be":
		return transcodeUTF16(body, true)
	case "utf-16le":
		return transcodeUTF16(body, false)
	case "utf-32", "utf-32be":
		return transcodeUTF32(body, true)
	case "utf-32le":
		return transcodeUTF32(body, false)
	case "iso-8859-1", "latin1", "latin-1":
		runes := make([]rune, len(body))
		for i, b := range body {
			runes[i] = rune(b)
		}
		return []byte(string(runes)), true, nil
	default:
		return nil, false, &errBodyUndecodable{"the charset " + cs + " is not supported"}
	}
	// A JSON text always starts with an ASCII character, so a null byte in
	// the first four tells UTF-16 or UTF-32 without a mark (RFC 4627).
	if len(body) >= 4 {
		switch {
		case body[0] == 0 && body[1] == 0 && body[2] == 0 && body[3] != 0:
			return transcodeUTF32(body, true)
		case body[0] != 0 && body[1] == 0 && body[2] == 0 && body[3] == 0:
			return transcodeUTF32(body, false)
		case body[0] == 0 && body[1] != 0:
			return transcodeUTF16(body, true)
		case body[0] != 0 && body[1] == 0:
			return transcodeUTF16(body, false)
		}
	}
	return body, false, nil
}

func transcodeUTF16(b []byte, bigEndian bool) ([]byte, bool, error) {
	if len(b)%2 != 0 {
		return nil, false, &errBodyUndecodable{"the UTF-16 body has an odd length"}
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		if bigEndian {
			units[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			units[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return []byte(string(utf16.Decode(units))), true, nil
}

func transcodeUTF32(b []byte, bigEndian bool) ([]byte, bool, error) {
	if len(b)%4 != 0 {
		return nil, false, &errBodyUndecodable{"the UTF-32 body has a length that is not a multiple of four"}
	}
	runes := make([]rune, len(b)/4)
	for i := range runes {
		var v uint32
		if bigEndian {
			v = uint32(b[4*i])<<24 | uint32(b[4*i+1])<<16 | uint32(b[4*i+2])<<8 | uint32(b[4*i+3])
		} else {
			v = uint32(b[4*i+3])<<24 | uint32(b[4*i+2])<<16 | uint32(b[4*i+1])<<8 | uint32(b[4*i])
		}
		if v > utf8.MaxRune {
			return nil, false, &errBodyUndecodable{"the UTF-32 body has an invalid code point"}
		}
		runes[i] = rune(v)
	}
	return []byte(string(runes)), true, nil
}

// ---- server-sent events ---------------------------------------------------

// sseEventMax bounds the bytes of one event the framer holds.
const sseEventMax = 4 << 20

// sseEvent is one event of an event stream.
type sseEvent struct {
	// Raw is the event as the server sent it, line ends included; the proxy
	// forwards whole events only.
	Raw []byte
	// Data is the data of the event: its data lines joined by a line feed.
	Data string
	// HasData reports a data field in the event.
	HasData bool
}

// sseFramer frames an event stream as the WHATWG specification does: lines
// end in CRLF, LF or a bare CR; "data:" takes the value with or without the
// space after the colon; several data lines make one event's data; comments
// and the event, id and retry fields are kept in the raw bytes and carry no
// data; an event is dispatched at the blank line; a UTF-8 byte-order mark
// at the start is skipped.
type sseFramer struct {
	buf     []byte
	pos     int // start of the line being read, in buf
	scan    int // where the search for the end of that line resumes
	data    strings.Builder
	hasData bool
	started bool
	// Unframed counts lines that were no field and no comment (for example
	// a JSON line in a stream that was labelled event-stream).
	Unframed int
	// DataEvents counts events that carried data.
	DataEvents int
	broken     bool
}

// Broken reports an event larger than sseEventMax.
func (f *sseFramer) Broken() bool { return f.broken }

// Held returns the bytes the framer has read and not yet dispatched in an
// event. A fail mode that forwards the rest of the stream raw sends them
// first, so the agent gets every byte (GAP-0241).
func (f *sseFramer) Held() []byte { return f.buf }

// Write adds bytes to the stream and returns the events they complete. With
// final set, an unterminated last event is returned as well.
func (f *sseFramer) Write(chunk []byte, final bool) []sseEvent {
	f.buf = append(f.buf, chunk...)
	if !f.started && len(f.buf) > 0 {
		if len(f.buf) < 3 && bytes.HasPrefix([]byte{0xEF, 0xBB, 0xBF}, f.buf) && !final {
			return nil
		}
		f.started = true
		if bytes.HasPrefix(f.buf, []byte{0xEF, 0xBB, 0xBF}) {
			f.pos = 3
		}
	}
	var out []sseEvent
	for {
		from := max(f.pos, f.scan)
		i := bytes.IndexAny(f.buf[from:], "\r\n")
		if i < 0 {
			f.scan = len(f.buf) // the next read resumes here, not at the line start
			break
		}
		i += from
		next := i + 1
		if f.buf[i] == '\r' {
			if i+1 >= len(f.buf) && !final {
				f.scan = i
				break // a CR at the end may be the first half of CRLF
			}
			if i+1 < len(f.buf) && f.buf[i+1] == '\n' {
				next = i + 2
			}
		}
		line := f.buf[f.pos:i]
		f.pos = next
		f.scan = 0
		if len(line) == 0 {
			out = append(out, f.dispatch())
			continue
		}
		f.field(line)
	}
	if final && len(f.buf) > 0 {
		if f.pos < len(f.buf) {
			f.field(f.buf[f.pos:])
			f.pos = len(f.buf)
		}
		out = append(out, f.dispatch())
	}
	if len(f.buf) > sseEventMax {
		f.broken = true
	}
	return out
}

// dispatch ends the current event: the raw bytes read so far are its raw
// bytes.
func (f *sseFramer) dispatch() sseEvent {
	ev := sseEvent{Raw: append([]byte(nil), f.buf[:f.pos]...)}
	if f.hasData {
		ev.HasData = true
		ev.Data = strings.TrimSuffix(f.data.String(), "\n")
		f.DataEvents++
	}
	f.buf = append(f.buf[:0], f.buf[f.pos:]...)
	f.pos, f.scan = 0, 0
	f.data.Reset()
	f.hasData = false
	return ev
}

func (f *sseFramer) field(line []byte) {
	if line[0] == ':' {
		return // a comment
	}
	name, value := string(line), ""
	if k := bytes.IndexByte(line, ':'); k >= 0 {
		name, value = string(line[:k]), string(line[k+1:])
		value = strings.TrimPrefix(value, " ")
	}
	switch name {
	case "data":
		f.data.WriteString(value)
		f.data.WriteByte('\n')
		f.hasData = true
	case "event", "id", "retry":
	default:
		f.Unframed++
	}
}
