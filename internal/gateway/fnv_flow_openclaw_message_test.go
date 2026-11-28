// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Verification tests for the OpenClaw message lane on rel/1.0.10 (GAP-0322,
// GAP-0323, GAP-0328, GAP-0338), ported from the s7-ocrev2 reviewer probes with
// assertions. The key is the synthetic one message_text_test.go uses.

const fnvOCSecret = "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2"

func fnvOCAPI(t *testing.T, posture string) *APIServer {
	t.Helper()
	installToolCallCorpusProfileConnector(t, "openclaw", posture)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "openclaw"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	api.inspectToolScanTimeout = 10 * time.Second
	return api
}

// fnvOCPost posts the call the way the plugin does: the args and the text it
// read as content.
func fnvOCPost(t *testing.T, api *APIServer, shape any) (int, ToolInspectVerdict) {
	t.Helper()
	b, err := json.Marshal(shape)
	if err != nil {
		t.Fatal(err)
	}
	ex := extractMessageArgs(json.RawMessage(b))
	c, _ := json.Marshal(ex.Text)
	rec, v := postInspect(t, api, `{"tool":"message","args":`+string(b)+`,"content":`+string(c)+`,"direction":"outbound"}`)
	return rec.Code, v
}

func fnvOCStrs(n int, s string) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// GAP-0322: 16000 recipients are budgeted (truncated, not walked in O(N^2)):
// alert in the default pack, block in strict.
func TestFnvOpenClawRoutingArrayIsBudgeted(t *testing.T) {
	shape := map[string]any{"text": "hi", "to": fnvOCStrs(16000, "+1")}
	for posture, want := range map[string]string{"default": "alert", "strict": "block"} {
		api := fnvOCAPI(t, posture)
		t0 := time.Now()
		code, v := fnvOCPost(t, api, shape)
		if took := time.Since(t0); took > 3*time.Second {
			t.Errorf("%s: 16000 recipients took %v", posture, took)
		}
		if code != http.StatusOK || v.Action != want {
			t.Errorf("%s: http %d action %q findings %v, want 200 and %q", posture, code, v.Action, v.Findings, want)
		}
	}
}

// GAP-0328 (P1): plaintext after a base64-looking prefix is read in every
// field and every pack; a binary attachment alone stays an allow.
func TestFnvOpenClawAttachmentSkipHidesNoText(t *testing.T) {
	b64 := strings.Repeat("QUFB", 1024) // 4096 base64 characters
	key := "key: " + fnvOCSecret
	enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(key+"\n", 40)))
	cases := map[string]any{
		"message-dataurl-then-text": map[string]any{"to": "+1", "message": "data:text/plain;base64," + b64 + "\n" + key},
		"text-dataurl-then-text":    map[string]any{"to": "+1", "text": "data:a;base64," + b64 + " " + key},
		"caption-dataurl-then-text": map[string]any{"to": "+1", "message": "hi", "caption": "data:x;base64," + b64 + key},
		"buffer-then-text":          map[string]any{"to": "+1", "message": "hi", "buffer": b64 + "\n" + key},
		"Buffer-nested-then-text":   map[string]any{"to": "+1", "message": "hi", "presentation": map[string]any{"Buffer": b64 + key}},
		"buffer-encoded":            map[string]any{"to": "+1", "message": "hi", "buffer": enc},
		"control-text":              map[string]any{"to": "+1", "message": key},
	}
	for _, posture := range []string{"default", "strict"} {
		for name, shape := range cases {
			code, v := fnvOCPost(t, fnvOCAPI(t, posture), shape)
			if code != http.StatusOK || v.Action != "block" {
				t.Errorf("%s/%s: http %d action %q findings %v, want block", posture, name, code, v.Action, v.Findings)
			}
		}
	}
	rng := rand.New(rand.NewSource(3))
	bin := make([]byte, 64*1024)
	rng.Read(bin)
	code, v := fnvOCPost(t, fnvOCAPI(t, "default"), map[string]any{"to": "+1", "message": "photo", "buffer": base64.StdEncoding.EncodeToString(bin), "filename": "a.png"})
	if code != http.StatusOK || v.Action != "allow" {
		t.Errorf("random binary attachment: http %d action %q findings %v, want allow", code, v.Action, v.Findings)
	}
}

// GAP-0323: a large benign attachment or a long table is not over the read cap.
func TestFnvOpenClawBenignLargeAttachmentsAndTablesAllow(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	bin := make([]byte, 1024*1024)
	rng.Read(bin)
	raw := base64.StdEncoding.EncodeToString(bin[:300*1024])
	big := base64.StdEncoding.EncodeToString(bin)
	table := func(rows int) any {
		cells := make([]any, 0, rows*2)
		for i := 0; i < rows; i++ {
			cells = append(cells, fmt.Sprintf("row %d", i), i)
		}
		return map[string]any{"action": "send", "to": "+15551230000", "presentation": map[string]any{"title": "report", "blocks": []any{map[string]any{"type": "table", "rows": cells}}}}
	}
	cases := map[string]any{
		"attach-300k":        map[string]any{"action": "sendAttachment", "to": "+15551230000", "message": "see file", "filename": "a.png", "buffer": raw},
		"attach-1m":          map[string]any{"action": "sendAttachment", "to": "+15551230000", "message": "see file", "filename": "a.png", "buffer": big},
		"attach-1m-dataurl":  map[string]any{"action": "sendAttachment", "to": "+15551230000", "message": "see file", "buffer": "data:image/png;base64," + big},
		"attach-media-field": map[string]any{"action": "sendAttachment", "to": "+15551230000", "message": "see file", "media": "data:image/png;base64," + raw},
		"attachments-arr":    map[string]any{"action": "send", "to": "+1", "message": "two files", "attachments": []any{map[string]any{"name": "a.png", "buffer": raw}, map[string]any{"name": "b.png", "buffer": raw}}},
		"table-700":          table(700),
		"table-2000":         table(2000),
	}
	for _, posture := range []string{"default", "strict"} {
		for name, shape := range cases {
			code, v := fnvOCPost(t, fnvOCAPI(t, posture), shape)
			if code != http.StatusOK || v.Action != "allow" || len(v.Findings) != 0 {
				t.Errorf("%s/%s: http %d action %q findings %v, want a plain allow", posture, name, code, v.Action, v.Findings)
			}
		}
	}
}

// GAP-0338: a 4 MB and a 6 MB attachment under the production scan budget are
// neither a 504 nor a block in the default pack. A plain build runs the
// production deadline (inspectScanTimeout); a -race build scales it by
// raceLargeAttachmentScale so the race leg still runs this path, no skip.
func TestFnvOpenClawLargeAttachmentStaysInTheScanBudget(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	for _, mb := range []int{4, 6} {
		bin := make([]byte, mb*1024*1024)
		rng.Read(bin)
		api := fnvOCAPI(t, "default")
		api.inspectToolScanTimeout = inspectScanTimeout * raceLargeAttachmentScale // production budget; scaled under -race only
		code, v := fnvOCPost(t, api, map[string]any{"action": "sendAttachment", "to": "+15551230000", "message": "see file", "filename": "a.jpg", "buffer": base64.StdEncoding.EncodeToString(bin)})
		if code != http.StatusOK || v.Action == "block" {
			t.Errorf("%d MB attachment: http %d action %q findings %v, want 200 and no block", mb, code, v.Action, v.Findings)
		}
	}
}
