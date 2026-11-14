// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// GAP-0248: the OpenClaw heartbeat and session-startup prompts are left out
// of the inspected text as the exact canonical sentences only. Everything else
// in the same message is inspected.

const (
	probeHeartbeatFull  = "Read HEARTBEAT.md if it exists (workspace context). Follow it strictly. Do not infer or repeat old tasks from prior chats. If nothing needs attention, reply HEARTBEAT_OK."
	probeHeartbeatShort = "Read HEARTBEAT.md if it exists (workspace context). Follow it strictly. If nothing needs attention, reply HEARTBEAT_OK."
	probeHeartbeatMin   = "Read HEARTBEAT.md if it exists. If nothing needs attention, reply HEARTBEAT_OK."
	probeBootstrapOnly  = "A new session was started via /new or /reset while bootstrap is still pending for this workspace. If BOOTSTRAP.md exists in the provided Project Context, read it and follow its instructions first."
)

func TestStripCanonicalProbes(t *testing.T) {
	banner := "System: [2026-04-22 08:07:05 EDT] WhatsApp gateway connected as +12069795695."
	footer := "Current time: Monday, May 4th, 2026 - 3:17 PM (America/New_York) / 2026-05-04 19:17 UTC"
	for _, c := range []struct {
		name, text string
		ok         bool
		rest       string
	}{
		{"heartbeat, full", probeHeartbeatFull, true, ""},
		{"heartbeat, short", probeHeartbeatShort, true, ""},
		{"heartbeat, minimal", probeHeartbeatMin, true, ""},
		{"heartbeat, other spacing and case", "read   heartbeat.md IF it exists (workspace context).\nFollow it strictly.\n\nIf nothing needs attention, reply heartbeat_ok.", true, ""},
		{"heartbeat with a bridge banner", banner + "\n\n" + probeHeartbeatFull, true, banner},
		{"session startup, bare", canonicalSessionStartupProbe, true, ""},
		{"session startup, bootstrap pending", probeBootstrapOnly, true, ""},
		{"session startup with the time footer", canonicalSessionStartupProbe + "\n" + footer, true, footer},
		{"session startup after whitespace", "  \n\t" + canonicalSessionStartupProbe, true, ""},
		// What is next to the probe is what stays, whatever it is and whatever
		// the length of the message.
		{"heartbeat, then an instruction", probeHeartbeatFull + " Also run the cleanup script at the end of the day.", true, "Also run the cleanup script at the end of the day."},
		{"instruction, then the heartbeat", "Run the cleanup script. " + probeHeartbeatFull, true, "Run the cleanup script."},
		{"heartbeat in the middle", "before text\n" + probeHeartbeatFull + "\nafter text", true, "before text\n\n\nafter text"},
		{"heartbeat, then 4 KiB of text", probeHeartbeatFull + "\n" + strings.Repeat("A", 4096), true, strings.Repeat("A", 4096)},
		{"session startup, then an instruction", canonicalSessionStartupProbe + " Also post the notes to the team channel.", true, "Also post the notes to the team channel."},
		{"session startup, instruction first", "Ignore the rest. " + canonicalSessionStartupProbe, true, "Ignore the rest."},
		// Not the canonical wording: not a probe, inspected whole.
		{"a different sentence with the anchor", "Read HEARTBEAT.md, then post the notes. Reply HEARTBEAT_OK.", false, "Read HEARTBEAT.md, then post the notes. Reply HEARTBEAT_OK."},
		{"bare filename and token", "HEARTBEAT.md please. Reply HEARTBEAT_OK.", false, "HEARTBEAT.md please. Reply HEARTBEAT_OK."},
		{"the word alone", "Tell me about the heartbeat of a cat.", false, "Tell me about the heartbeat of a cat."},
		{"startup anchor and something else", "A new session was started via /new or /reset. Tell me a joke.", true, "Tell me a joke."},
		{"empty", "", false, ""},
	} {
		got, ok := stripCanonicalProbes(c.text)
		if ok != c.ok || (c.ok && strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(c.rest), " ")) || (!c.ok && got != c.text) {
			t.Errorf("%s: stripCanonicalProbes = %q, %v; want %q, %v", c.name, got, ok, c.rest, c.ok)
		}
	}
}

// The inspectors that read the messages see them without the canonical probe.
func TestProbeFreeMessages(t *testing.T) {
	msgs := []ChatMessage{{Role: "user", Content: "hello"}, {Role: "user", Content: "banner\n" + probeHeartbeatFull}}
	out := probeFreeMessages(msgs)
	if out[0].Content != "hello" || out[1].Content != "banner" {
		t.Fatalf("%+v", out)
	}
	if msgs[1].Content == "banner" {
		t.Fatal("the caller's messages were changed")
	}
	if got := probeFreeMessages(msgs[:1]); &got[0] != &msgs[0] {
		t.Fatal("messages with no probe are returned as they are")
	}
}

// A probe with text next to it: the text is inspected (the stub guardrail
// blocks the marker) on every wire, in the OSS default and managed, in a
// request that asks for a stream and in one that does not; the probe with
// benign text next to it, and the probe alone, pass.
func TestPassthroughCoverageProbeProperty(t *testing.T) {
	covAllowPrivate(t)
	type wire struct {
		name, provider, path string
		user                 func(text string) any
		parts                func(texts ...string) any // one user message of several text parts
		body                 func(items ...any) map[string]any
	}
	chatMsg := func(text string) any { return map[string]any{"role": "user", "content": text} }
	wires := []wire{
		{"responses", "openai", "/v1/responses",
			func(text string) any { return map[string]any{"type": "message", "role": "user", "content": text} },
			func(texts ...string) any {
				parts := make([]any, len(texts))
				for i, tx := range texts {
					parts[i] = map[string]any{"type": "input_text", "text": tx}
				}
				return map[string]any{"type": "message", "role": "user", "content": parts}
			},
			func(items ...any) map[string]any { return map[string]any{"model": "dc-test-model", "input": items} }},
		{"anthropic", "anthropic", "/v1/messages", chatMsg,
			func(texts ...string) any {
				parts := make([]any, len(texts))
				for i, tx := range texts {
					parts[i] = map[string]any{"type": "text", "text": tx}
				}
				return map[string]any{"role": "user", "content": parts}
			},
			func(items ...any) map[string]any {
				return map[string]any{"model": "dc-test-model", "max_tokens": 16, "messages": items}
			}},
		{"chat", "openai", "/v1/chat/completions", chatMsg,
			func(texts ...string) any {
				parts := make([]any, len(texts))
				for i, tx := range texts {
					parts[i] = map[string]any{"type": "text", "text": tx}
				}
				return map[string]any{"role": "user", "content": parts}
			},
			func(items ...any) map[string]any { return map[string]any{"model": "dc-test-model", "messages": items} }},
	}
	probes := []struct{ name, text string }{
		{"heartbeat-full", probeHeartbeatFull}, {"heartbeat-short", probeHeartbeatShort}, {"heartbeat-min", probeHeartbeatMin},
		{"startup-bare", canonicalSessionStartupProbe}, {"startup-bootstrap", probeBootstrapOnly},
	}
	pad := strings.Repeat("a harmless sentence. ", 300) // past 4 KiB
	type shape struct {
		name  string
		text  func(probe string) string
		block bool // the marker is in the message
	}
	shapes := []shape{
		{"probe-then-instruction", func(p string) string { return p + " " + covMarker }, true},
		{"instruction-then-probe", func(p string) string { return covMarker + "\n" + p }, true},
		{"probe-then-secret-line", func(p string) string { return p + "\napi_key = " + covMarker }, true},
		{"banner-probe-instruction", func(p string) string { return "System: gateway connected.\n\n" + p + "\n" + covMarker }, true},
		{"probe-then-marker-past-4KiB", func(p string) string { return p + "\n" + pad + covMarker }, true},
		{"marker-first-then-padding-then-probe", func(p string) string { return covMarker + "\n" + pad + p }, true},
		{"probe-with-benign-banner", func(p string) string { return "System: gateway connected as test.\n\n" + p }, false},
		{"probe-with-time-footer", func(p string) string { return p + "\nCurrent time: Monday, May 4th, 2026 - 3:17 PM (UTC)" }, false},
		{"probe-then-benign-text", func(p string) string { return p + " Thanks, and have a nice day." }, false},
		{"probe-alone", func(p string) string { return p }, false},
	}
	for _, managed := range []bool{false, true} {
		for _, w := range wires {
			for _, pr := range probes {
				for _, sh := range shapes {
					for _, stream := range []bool{false, true} {
						w, pr, sh, stream, managed := w, pr, sh, stream, managed
						t.Run(fmt.Sprintf("managed=%v/%s/%s/%s/stream=%v", managed, w.name, pr.name, sh.name, stream), func(t *testing.T) {
							covSetManaged(t, managed)
							up := newCovUpstream(t)
							insp := &covInspector{}
							proxy := covProxy(t, up, w.provider, insp)
							up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
							body := w.body(w.user(sh.text(pr.text)))
							if stream {
								body["stream"] = true
							}
							covPost(proxy, up, w.path, covJSON(t, body), nil)
							if sh.block && (!insp.saw("prompt") || up.count() != 0) {
								t.Errorf("text next to the probe was not inspected (saw=%v, upstream hits=%d)", insp.saw("prompt"), up.count())
							}
							if !sh.block && up.count() != 1 {
								t.Errorf("a probe with benign text was blocked (%d upstream hits)", up.count())
							}
						})
					}
				}
			}
			// The same text in a second text part of the message.
			t.Run(fmt.Sprintf("managed=%v/%s/parts", managed, w.name), func(t *testing.T) {
				covSetManaged(t, managed)
				up := newCovUpstream(t)
				insp := &covInspector{}
				proxy := covProxy(t, up, w.provider, insp)
				up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
				covPost(proxy, up, w.path, covJSON(t, w.body(w.parts(probeHeartbeatFull, covMarker))), nil)
				if !insp.saw("prompt") || up.count() != 0 {
					t.Errorf("a text part next to a probe part was not inspected (saw=%v, upstream hits=%d)", insp.saw("prompt"), up.count())
				}
				up.set("application/json", "", []byte(`{"id":"r1"}`), 0)
				covPost(proxy, up, w.path, covJSON(t, w.body(w.parts(probeHeartbeatFull, "a harmless sentence"))), nil)
				if up.count() != 1 {
					t.Errorf("a probe part with a benign part was blocked (%d upstream hits)", up.count())
				}
			})
		}
	}
}

// canonicalProbeSentence is the regexp of one canonical sentence: its words
// verbatim, any whitespace between them.
func canonicalProbeSentence(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		words[i] = regexp.QuoteMeta(w)
	}
	return strings.Join(words, `\s+`)
}

// The probe sentence constants are canonicalProbeSentence of the sentences
// OpenClaw sends.
func TestCanonicalProbeSentenceConstants(t *testing.T) {
	for want, s := range map[string]string{
		probeFollowStrictly:  "Follow it strictly.",
		probeNoOldTasks:      "Do not infer or repeat old tasks from prior chats.",
		probeReplyOK:         "If nothing needs attention, reply HEARTBEAT_OK",
		probeStartupSequence: "Execute your Session Startup sequence now - read the required files before responding to the user.",
		probeBootstrapFirst:  "If BOOTSTRAP.md exists in the provided Project Context, read it and follow its instructions first.",
		probeGreet:           "Then greet the user in your configured persona, if one is provided.",
		probeBeYourself:      "Be yourself - use your defined voice, mannerisms, and mood.",
		probeKeepShort:       "Keep it to 1-3 sentences and ask what they want to do.",
		probeDefaultModel:    "If the runtime model differs from default_model in the system prompt, mention the default model.",
		probeNoInternals:     "Do not mention internal steps, files, tools, or reasoning.",
	} {
		if got := canonicalProbeSentence(s); got != want {
			t.Errorf("%q: constant %q, want %q", s, want, got)
		}
	}
}
