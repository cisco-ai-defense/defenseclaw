// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// A harness's own telemetry (OTLP) and notify calls can carry the prompt it
// was given, so a secret that capture moved into the vault from the prompt
// would still reach the gateway's audit store through them (Codex exports
// the whole prompt). While the ingress captures into a vault, the
// credentials with a capturable issuer shape in those bodies are masked
// in place before anything relays, evaluates or stores them: every
// character after the issuer prefix becomes '*', so the body keeps its
// length and its protobuf or JSON framing stays valid. A body the ingress
// cannot read (an encoding other than gzip or none) is refused, so a value
// is never forwarded unread.

// maxMaskDecodedBytes bounds a decompressed telemetry body.
const maxMaskDecodedBytes = 64 << 20

var errMaskEncoding = errors.New("unsupported content encoding")

func (a *APIServer) sandboxVaultMaskMiddleware(st *sandboxIngressState, next http.Handler) http.Handler {
	if st == nil || st.vault == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := sandboxIngressRouteFrom(r.Context())
		if !ok || (route != sandboxauth.RouteOTLP && route != sandboxauth.RouteNotify) || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeSandboxIngressError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeSandboxIngressError(w, http.StatusBadRequest, "the request body could not be read")
			return
		}
		out, changed, err := maskCapturableBody(body, r.Header.Get("Content-Encoding"))
		if err != nil {
			writeSandboxIngressError(w, http.StatusUnsupportedMediaType,
				"the body cannot be checked for secrets ("+err.Error()+"); send it uncompressed or gzip")
			return
		}
		if !changed {
			out = body
		}
		r.Body = io.NopCloser(bytes.NewReader(out))
		r.ContentLength = int64(len(out))
		r.Header.Set("Content-Length", strconv.Itoa(len(out)))
		next.ServeHTTP(w, r)
	})
}

// maskCapturableBody masks capturable credentials in a body that is plain or
// gzip-encoded, re-encoding it the same way.
func maskCapturableBody(body []byte, encoding string) ([]byte, bool, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		out, changed := vault.MaskCapturable(body)
		return out, changed, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false, errMaskEncoding
		}
		plain, err := io.ReadAll(io.LimitReader(zr, maxMaskDecodedBytes+1))
		if err != nil || len(plain) > maxMaskDecodedBytes {
			return nil, false, errMaskEncoding
		}
		masked, changed := vault.MaskCapturable(plain)
		if !changed {
			return body, false, nil
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(masked); err != nil {
			return nil, false, err
		}
		if err := zw.Close(); err != nil {
			return nil, false, err
		}
		return buf.Bytes(), true, nil
	}
	return nil, false, errMaskEncoding
}
