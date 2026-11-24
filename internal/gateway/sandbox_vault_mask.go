// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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
//
// The inspect routes (/api/v1/inspect/tool, request, response,
// tool-response) carry a tool call, a model request or a model's output,
// so they are masked the same way. Masking hides the value from the
// evaluation too, so the answer then says what capture would: in action
// mode a tool call or a model request that carried a secret is blocked
// and a response is alerted; in observe mode the answer stays and says
// what action mode would do. A block is always kept.

// maxMaskDecodedBytes bounds a decompressed telemetry body.
const maxMaskDecodedBytes = 64 << 20

var errMaskEncoding = errors.New("unsupported content encoding")

func (a *APIServer) sandboxVaultMaskMiddleware(st *sandboxIngressState, next http.Handler) http.Handler {
	if st == nil || st.vault == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := sandboxIngressRouteFrom(r.Context())
		if !ok || (route != sandboxauth.RouteOTLP && route != sandboxauth.RouteNotify && route != sandboxauth.RouteInspect) || r.Body == nil {
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
		if route != sandboxauth.RouteInspect || !changed {
			next.ServeHTTP(w, r)
			return
		}
		kind := strings.TrimPrefix(r.URL.Path, "/api/v1/inspect/")
		rec := &bufferedInspectAnswer{header: http.Header{}}
		next.ServeHTTP(rec, r)
		answer := rec.body.Bytes()
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		if rec.status >= 200 && rec.status <= 299 {
			answer = maskedInspectAnswer(kind, answer)
		}
		if string(answer) != rec.body.String() {
			// The handler audited the answer it chose: record what the
			// agent was answered.
			a.auditMaskedInspect(r.Context(), kind, answer)
		}
		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(rec.status)
		_, _ = w.Write(answer)
	})
}

// bufferedInspectAnswer holds an inspect answer so it can be raised.
type bufferedInspectAnswer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedInspectAnswer) Header() http.Header { return b.header }

func (b *bufferedInspectAnswer) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedInspectAnswer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// maskedInspectAnswer raises an inspect verdict whose request carried a
// secret the ingress masked: kind is the inspect route (tool, request,
// response, tool-response). An answer that is not a verdict is kept.
func maskedInspectAnswer(kind string, body []byte) []byte {
	var wire map[string]interface{}
	if err := json.Unmarshal(body, &wire); err != nil || wire == nil {
		return body
	}
	action, _ := wire["action"].(string)
	if action == "" {
		return body
	}
	mode, _ := wire["mode"].(string)
	stops := kind == "tool" || kind == "request"
	msg := "DefenseClaw found a secret in this " + inspectKindWhere(kind) + " and removed it from what it records and passes on. " +
		"The model has seen it: the user should rotate it with its issuer. Do not use, repeat or write the value."
	if stops {
		msg = "DefenseClaw stopped this call: it carried a secret, which DefenseClaw removed from what it records and passes on. " +
			"Never write secret values into commands, requests or files; ask the user to give the sandbox the credential " +
			"through the vault (defenseclaw sandbox vault)."
	}
	raised := true
	switch {
	case action == "block":
		raised = false
	case mode != "" && mode != "action":
		if stops {
			wire["would_block"] = true
			wire["raw_action"] = "block"
		} else if action == "allow" {
			wire["raw_action"] = "alert"
		}
	case stops:
		wire["action"], wire["raw_action"], wire["would_block"] = "block", "block", true
	case action == "allow":
		wire["action"], wire["raw_action"] = "alert", "alert"
	}
	if sev, _ := wire["severity"].(string); sev != "CRITICAL" {
		wire["severity"] = "HIGH"
	}
	if raised {
		if reason, _ := wire["reason"].(string); strings.TrimSpace(reason) == "" {
			wire["reason"] = msg
		} else {
			wire["reason"] = msg + " " + reason
		}
	}
	findings, _ := wire["findings"].([]interface{})
	wire["findings"] = append(findings, "sandbox-vault-masked-secret")
	out, err := json.Marshal(wire)
	if err != nil {
		return body
	}
	return append(out, '\n')
}

// sandboxVaultInspectRuleID is the alert of an inspect call that carried a
// secret the sandbox ingress masked.
const sandboxVaultInspectRuleID = "sandbox_vault_inspect"

// auditMaskedInspect records an inspect answer the mask raised: the route,
// the connector and the answer sent, never the value.
func (a *APIServer) auditMaskedInspect(ctx context.Context, kind string, answer []byte) {
	if a == nil || a.logger == nil {
		return
	}
	var wire map[string]interface{}
	_ = json.Unmarshal(answer, &wire)
	action, _ := wire["action"].(string)
	connectorName := ""
	if b, ok := sandboxauth.FromContext(ctx); ok {
		connectorName = b.Connector
	}
	if err := a.logger.LogAlertCtx(ctx, sandboxVaultInspectRuleID, "HIGH",
		"Sandbox inspect call carried a secret: masked before it was evaluated, recorded or relayed", map[string]any{
			"route": kind, "connector": connectorName, "action": action, "rule_id": sandboxVaultInspectRuleID,
		}); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] sandbox vault inspect alert failed route=%s: %v\n", kind, err)
	}
}

func inspectKindWhere(kind string) string {
	switch kind {
	case "response":
		return "model response"
	case "tool-response":
		return "tool output"
	}
	return "call"
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
