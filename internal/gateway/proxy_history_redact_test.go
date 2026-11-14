// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Round 2 of inspect-once (substrate-1 GAP-0254, GAP-0255, GAP-0256). Uses
// only what the base had, so it also runs as the fail-before on d960a3860e.

func f14Strict(r *http.Request) *http.Request {
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = "strict"
	return r.WithContext(withPinnedGeneration(r.Context(), &Generation{N: 1, Config: cfg}))
}

func f14ConverseWire() f14Wire {
	return f14Wire{name: "converse", provider: "bedrock", path: "/model/dc-test-model/converse", build: func(items []f14Item, _ bool) map[string]any {
		var list []any
		for _, it := range items {
			list = append(list, map[string]any{"role": it.kind, "content": []any{map[string]any{"text": it.text}}})
		}
		return map[string]any{"messages": list}
	}}
}

// f14RedactionRows is the audit rows of history redactions.
func f14RedactionRows(t *testing.T, rg *f14Rig) []string {
	t.Helper()
	events, err := rg.proxy.store.ListEvents(200)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	var rows []string
	for _, e := range events {
		if strings.Contains(e.Details, "redacted a refused turn") {
			rows = append(rows, e.Action+" "+e.Details)
		}
	}
	return rows
}

// GAP-0254: a prompt refused as the current turn never reaches the upstream
// when the client sends it back as history; the later benign turn goes
// through, the refused turn keeps its place and role with the placeholder,
// and each redaction writes an audit row without content. Over 4 wires x
// OSS/managed x default/strict tier x buffered/streamed, for a verified host
// session and a Substrate actor.
func TestGAP0254RefusedTurnNeverReachesTheUpstream(t *testing.T) {
	covAllowPrivate(t)
	for _, managed := range []bool{false, true} {
		covSetManaged(t, managed)
		for _, tier := range []string{"default", "strict"} {
			for _, w := range f14Wires() {
				for _, stream := range []bool{false, true} {
					for _, who := range []string{"host-session", "substrate-actor"} {
						name := fmt.Sprintf("managed=%v/%s/%s/stream=%v/%s", managed, tier, w.name, stream, who)
						t.Run(name, func(t *testing.T) {
							rg := newF14Rig(t, w.provider, "action")
							c := f14Caller{session: "redact", owner: true}
							if who == "substrate-actor" {
								c = f14Caller{actor: f14Actor(t, "redact-1", "25a1da0f-1c9b-4ef7-8248-c276138c7f54")}
							}
							if tier == "strict" {
								c.edit = f14Strict
							}
							if fwd, _ := rg.post(t, w, c, []f14Item{{"user", "please " + covMarker}}, stream); fwd {
								t.Fatal("the marker as the current turn was not refused")
							}
							next := []f14Item{{"user", "please " + covMarker}, {"assistant", "[DefenseClaw] blocked"}, {"user", "a harmless sentence"}}
							for try := 1; try <= 2; try++ {
								fwd, rec := rg.post(t, w, c, next, stream)
								if !fwd {
									t.Fatalf("try %d: the benign turn after a refused one was refused (status %d): %s", try, rec.Code, rec.Body)
								}
								f14CheckRedacted(t, w, rg.lastBody())
							}
							rows := f14RedactionRows(t, rg)
							if len(rows) != 2 {
								t.Errorf("%d redaction audit rows for 2 requests, want 2: %q", len(rows), rows)
							}
							for _, row := range rows {
								if strings.Contains(row, covMarker) || !strings.Contains(row, "turn=0") || !strings.HasPrefix(row, "guardrail-launder ") {
									t.Errorf("redaction audit row %q: want guardrail-launder, turn=0, no content", row)
								}
							}
						})
					}
				}
			}
		}
	}
}

// A body the proxy cannot rewrite (a signed Bedrock body) is refused while
// it carries the refused turn (fail closed); unsigned, the same history is
// redacted.
func TestGAP0254SignedBodyWithARefusedTurnIsRefused(t *testing.T) {
	covAllowPrivate(t)
	for _, managed := range []bool{false, true} {
		covSetManaged(t, managed)
		t.Run(fmt.Sprintf("managed=%v", managed), func(t *testing.T) {
			w := f14ConverseWire()
			rg := newF14Rig(t, w.provider, "action")
			c := f14Caller{session: "signed", owner: true}
			if fwd, _ := rg.post(t, w, c, []f14Item{{"user", covMarker}}, false); fwd {
				t.Fatal("the marker as the current turn was not refused")
			}
			next := []f14Item{{"user", covMarker}, {"assistant", "ok"}, {"user", "a harmless sentence"}}
			signed := c
			signed.edit = func(r *http.Request) *http.Request {
				r.Header.Set("X-AI-Auth", "AWS4-HMAC-SHA256 Credential=dc-test/20261114/us-east-1/bedrock/aws4_request, SignedHeaders=host, Signature=00")
				return r
			}
			if fwd, rec := rg.post(t, w, signed, next, false); fwd || bytes.Contains(rg.lastBody(), []byte(covMarker)) {
				t.Errorf("a signed body carrying a refused turn reached the upstream (status %d): %s", rec.Code, rec.Body)
			}
			if fwd, rec := rg.post(t, w, c, next, false); !fwd {
				t.Errorf("an unsigned body with the refused turn was refused (status %d): %s", rec.Code, rec.Body)
			} else if bytes.Contains(rg.lastBody(), []byte(covMarker)) {
				t.Errorf("the refused text reached the upstream: %s", rg.lastBody())
			}
		})
	}
}

// Observe mode refuses nothing, so nothing is redacted: the history goes on
// as the client sent it, and no redaction row is written.
func TestGAP0254ObserveModeIsUntouched(t *testing.T) {
	covAllowPrivate(t)
	for _, managed := range []bool{false, true} {
		covSetManaged(t, managed)
		for _, w := range f14Wires() {
			t.Run(fmt.Sprintf("managed=%v/%s", managed, w.name), func(t *testing.T) {
				rg := newF14Rig(t, w.provider, "observe")
				c := f14Caller{session: "observe", owner: true}
				if fwd, _ := rg.post(t, w, c, []f14Item{{"user", covMarker}}, false); !fwd {
					t.Fatal("observe mode refused a request")
				}
				next := []f14Item{{"user", covMarker}, {"assistant", "ok"}, {"user", "a harmless sentence"}}
				if fwd, _ := rg.post(t, w, c, next, false); !fwd {
					t.Fatal("observe mode refused a request")
				}
				if !bytes.Contains(rg.lastBody(), []byte(covMarker)) || bytes.Contains(rg.lastBody(), []byte("Removed by DefenseClaw policy")) {
					t.Errorf("observe mode changed the history: %s", rg.lastBody())
				}
				if rows := f14RedactionRows(t, rg); len(rows) != 0 {
					t.Errorf("observe mode wrote redaction rows: %q", rows)
				}
			})
		}
	}
}

// f14Recorder wraps the real guardrail and records what it is asked.
type f14Recorder struct {
	c *covInspector
	g *GuardrailInspector
}

func (r *f14Recorder) Inspect(ctx context.Context, direction, content string, m []ChatMessage, model, mode string) *ScanVerdict {
	r.c.mu.Lock()
	if direction == "prompt" {
		r.c.prompts = append(r.c.prompts, content)
	}
	r.c.mu.Unlock()
	return r.g.Inspect(ctx, direction, content, m, model, mode)
}
func (r *f14Recorder) InspectMidStream(ctx context.Context, d, content string, m []ChatMessage, model, mode string) *ScanVerdict {
	return r.Inspect(ctx, d, content, m, model, mode)
}
func (r *f14Recorder) SetScannerMode(string)      {}
func (r *f14Recorder) SetHILTConfig(bool, string) {}

// f14Cisco is an AI Defense client: down (nil verdict) or up (allow).
type f14Cisco struct{ up bool }

func (c *f14Cisco) Inspect(context.Context, []ChatMessage) *ScanVerdict {
	if !c.up {
		return nil
	}
	return allowVerdict("ai-defense")
}
func (c *f14Cisco) bindObservabilityV8(hookLifecycleMetricV8Runtime) {}

// GAP-0255: a verdict the guardrail did not reach (AI Defense unwired or
// down, managed; AI Defense down in the OSS hybrid) is not recorded: the
// history is inspected again on the next request. With AI Defense up, each
// segment is inspected once.
func TestGAP0255FailOpenIsNotRecorded(t *testing.T) {
	covAllowPrivate(t)
	for _, tc := range []struct {
		name    string
		managed bool
		scanner string
		cisco   *f14Cisco
		want    int // inspections of turn 1 over 3 requests
	}{
		{"managed-aid-unwired", true, "remote", nil, 3},
		{"managed-aid-down", true, "remote", &f14Cisco{}, 3},
		{"oss-hybrid-aid-down", false, "both", &f14Cisco{}, 3},
		{"managed-aid-up", true, "remote", &f14Cisco{up: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			covSetManaged(t, tc.managed)
			w := f14Wires()[0]
			rg := newF14Rig(t, w.provider, "action")
			g := NewGuardrailInspector(tc.scanner, nil, nil)
			g.SetManagedMode(tc.managed)
			if tc.cisco != nil {
				g.SetCiscoInspector(tc.cisco)
			}
			rg.proxy.inspector = &f14Recorder{c: rg.insp, g: g}
			c := f14Caller{session: "fail-open", owner: true}
			for k := 1; k <= 3; k++ {
				if fwd, rec := rg.post(t, w, c, f14Chat(k), false); !fwd {
					t.Fatalf("turn %d was refused (status %d): %s", k, rec.Code, rec.Body)
				}
			}
			if n := rg.insp.inspections("chat-turn-01-user-says-hello"); n != tc.want {
				t.Errorf("turn 1 was inspected %d times over 3 requests, want %d", n, tc.want)
			}
		})
	}
}

// GAP-0256: what was recorded in observe mode is inspected again in action
// mode, so the marker it alerted on is refused there.
func TestGAP0256ModeSwitchReinspects(t *testing.T) {
	covAllowPrivate(t)
	for _, managed := range []bool{false, true} {
		covSetManaged(t, managed)
		for _, w := range f14Wires() {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("managed=%v/%s/stream=%v", managed, w.name, stream), func(t *testing.T) {
					rg := newF14Rig(t, w.provider, "observe")
					c := f14Caller{session: "mode-switch", owner: true}
					if fwd, _ := rg.post(t, w, c, []f14Item{{"user", covMarker}}, stream); !fwd {
						t.Fatal("observe mode refused a request")
					}
					rg.proxy.mode, rg.proxy.cfg.Mode = "action", "action"
					next := []f14Item{{"user", covMarker}, {"assistant", "ok"}, {"user", "a harmless sentence"}}
					if fwd, _ := rg.post(t, w, c, next, stream); fwd && bytes.Contains(rg.lastBody(), []byte(covMarker)) {
						t.Errorf("a segment recorded in observe mode reached the upstream in action mode: %s", rg.lastBody())
					}
					if n := rg.insp.inspections(covMarker); n != 2 {
						t.Errorf("the marker was inspected %d times, want 2 (observe, then action)", n)
					}
				})
			}
		}
	}
}

// GAP-0256: a new policy generation inspects the history once more.
func TestGAP0256PolicyChangeReinspects(t *testing.T) {
	covAllowPrivate(t)
	for _, w := range f14Wires() {
		t.Run(w.name, func(t *testing.T) {
			rg := newF14Rig(t, w.provider, "action")
			gen := func(digest string) func(*http.Request) *http.Request {
				return func(r *http.Request) *http.Request {
					return r.WithContext(withPinnedGeneration(r.Context(), &Generation{N: 1, Digest: digest, Config: &config.Config{}}))
				}
			}
			c := f14Caller{session: "policy", owner: true, edit: gen("sha256:aaaa")}
			for k := 1; k <= 2; k++ {
				if fwd, _ := rg.post(t, w, c, f14Chat(k), false); !fwd {
					t.Fatalf("turn %d was refused", k)
				}
			}
			if n := rg.insp.inspections("chat-turn-01-user-says-hello"); n != 1 {
				t.Fatalf("turn 1 was inspected %d times under one policy, want 1", n)
			}
			c.edit = gen("sha256:bbbb")
			if fwd, _ := rg.post(t, w, c, f14Chat(3), false); !fwd {
				t.Fatal("turn 3 was refused")
			}
			if n := rg.insp.inspections("chat-turn-01-user-says-hello"); n != 2 {
				t.Errorf("turn 1 was inspected %d times after a policy change, want 2", n)
			}
		})
	}
}
