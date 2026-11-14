// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// A buffered provider reply the transport left encoded (GAP-0097 and
// GAP-0128, host side). The proxy never forwards the client Accept-Encoding
// (alwaysDeniedHeaders), so Go transport asks for gzip and decodes it; a
// provider may still answer br, zstd, deflate or stacked encodings it was
// not asked for. Those are decoded here before inspection and the usage
// record, and the caller gets the decoded reply. An encoding that cannot be
// decoded (an unknown token, corrupt bytes, a body over the cap) is left as
// it came, so uninspectableEncoding still names it and uninspectableReply
// refuses or alerts per mode. A stream is decoded as it is read
// (newStreamDecoder, proxy_body_decode.go).

// replyDecodeCap bounds a decoded reply: the 10 MiB the passthrough reads.
const replyDecodeCap = 10 << 20

// replyDecodeMaxLayers bounds stacked encodings: a reply that names more
// non-identity layers is uninspectable (each layer may expand to the cap,
// so the work would grow with the square of the layer count).
const replyDecodeMaxLayers = 4

var (
	errReplyEncodingUnknown = errors.New("unknown content-encoding")
	errReplyDecodedTooLarge = errors.New("decoded reply over the cap")
)

// decodeReplyBody decodes body by the Content-Encoding in h (the last
// applied encoding first). On success it removes Content-Encoding and
// Content-Length from h and returns the decoded bytes and true; otherwise
// body and h are unchanged and it returns false.
func decodeReplyBody(h http.Header, body []byte) ([]byte, bool) {
	out, encoded, err := decodeEncodings(h, body)
	if err != nil || !encoded {
		return body, false
	}
	h.Del("Content-Encoding")
	h.Del("Content-Length")
	return out, true
}

// decodeReplyLayer removes one encoding layer, bounded by replyDecodeCap.
func decodeReplyLayer(enc string, in []byte) ([]byte, error) {
	if enc == "" || enc == "identity" {
		return in, nil
	}
	r, closeFn, err := openEncodingReader(enc, bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer closeFn()
	out, err := io.ReadAll(io.LimitReader(r, replyDecodeCap+1))
	if err != nil {
		return nil, err
	}
	if len(out) > replyDecodeCap {
		return nil, errReplyDecodedTooLarge
	}
	return out, nil
}
