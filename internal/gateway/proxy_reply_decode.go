// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// A buffered provider reply the transport left encoded (GAP-0097 and
// GAP-0128, host side). The proxy never forwards the client Accept-Encoding
// (alwaysDeniedHeaders), so Go transport asks for gzip and decodes it; a
// provider may still answer br, zstd, deflate or stacked encodings it was
// not asked for. Those are decoded here before inspection and the usage
// record, and the caller gets the decoded reply. An encoding that cannot be
// decoded (an unknown token, corrupt bytes, a body over the cap) is left as
// it came, so uninspectableEncoding still names it and uninspectableReply
// refuses or alerts per mode. Streams are not decoded: an encoded stream
// takes the uninspectable path.

// replyDecodeCap bounds a decoded reply: the 10 MiB the passthrough reads.
const replyDecodeCap = 10 << 20

var (
	errReplyEncodingUnknown = errors.New("unknown content-encoding")
	errReplyDecodedTooLarge = errors.New("decoded reply over the cap")
)

// decodeReplyBody decodes body by the Content-Encoding in h (the last
// applied encoding first). On success it removes Content-Encoding and
// Content-Length from h and returns the decoded bytes and true; otherwise
// body and h are unchanged and it returns false.
func decodeReplyBody(h http.Header, body []byte) ([]byte, bool) {
	enc := uninspectableEncoding(h)
	if enc == "" {
		return body, false
	}
	layers := strings.Split(enc, ",")
	out := body
	for i := len(layers) - 1; i >= 0; i-- {
		var err error
		if out, err = decodeReplyLayer(strings.TrimSpace(layers[i]), out); err != nil {
			return body, false
		}
	}
	h.Del("Content-Encoding")
	h.Del("Content-Length")
	return out, true
}

func decodeReplyLayer(enc string, in []byte) ([]byte, error) {
	var r io.Reader
	switch enc {
	case "", "identity":
		return in, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case "deflate":
		// HTTP deflate is zlib-wrapped; some servers send raw DEFLATE.
		if zr, err := zlib.NewReader(bytes.NewReader(in)); err == nil {
			defer zr.Close()
			r = zr
		} else {
			fr := flate.NewReader(bytes.NewReader(in))
			defer fr.Close()
			r = fr
		}
	case "br":
		r = brotli.NewReader(bytes.NewReader(in))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(in), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(replyDecodeCap+(1<<20)))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		return nil, errReplyEncodingUnknown
	}
	out, err := io.ReadAll(io.LimitReader(r, replyDecodeCap+1))
	if err != nil {
		return nil, err
	}
	if len(out) > replyDecodeCap {
		return nil, errReplyDecodedTooLarge
	}
	return out, nil
}
