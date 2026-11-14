// Regression tests from the s7-resprev2 review, round 2 of s7/response (c94bb7ce2e):
// they failed there and pass with the round 3 fixes (GAP-0428..0431).
// Secrets come from the existing fixtures; output prints counts only.

package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Q1: an open private-key block followed by an END line of another label.
func TestResprev2PEMOtherFooterTerminates(t *testing.T) {
	key := syntheticPrivateKeyPEM("RSA PRIVATE KEY")
	nl := strings.IndexByte(key, '\n')
	header := key[:nl+1]
	other := "-----END " + "CERTIFICATE" + "-----\n"
	text := "Layout:\n" + header + "MIIBodyLineNotReal\n" + other + streamGuardFiller(2000)
	check, _ := streamGuardTestCheck()
	done := make(chan string, 1)
	go func() {
		g := newCompletionStreamGuard(check, streamGuardScanEvery)
		for off := 0; off < len(text); off += 24 {
			end := min(off+24, len(text))
			if _, v := g.Push(text[off:end], []byte(text[off:end])); v != nil {
				done <- "blocked"
				return
			}
		}
		g.Finish()
		done <- "finished"
	}()
	select {
	case r := <-done:
		t.Logf("Q1 result: %s", r)
	case <-time.After(15 * time.Second):
		t.Errorf("Q1: guard did not return within 15 s (spinning in trackPEM)")
	}
}

// Q2: a non-key BEGIN line whose header is open at a push boundary, then a
// real key header in the next push more than 37 bytes before its end.
func TestResprev2DecoyHeaderThenKey(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA " + "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}))
	check, _ := streamGuardTestCheck()
	if v := check("k\n" + key); v == nil || v.Action != guardrailActionBlock {
		t.Fatalf("Q2: the generated key is not blocked whole: %+v", v)
	}
	for _, decoy := range []bool{false, true} {
		pre := streamGuardFiller(600) + "\n"
		var pushes []string
		if decoy {
			pushes = append(pushes, pre+"-----BEGIN ", "X-----\n"+key[:60])
		} else {
			pushes = append(pushes, pre+"-----BEGIN X-----\n", key[:60])
		}
		rest := key[60:] + streamGuardFiller(400)
		for off := 0; off < len(rest); off += 24 {
			pushes = append(pushes, rest[off:min(off+24, len(rest))])
		}
		g := newCompletionStreamGuard(check, streamGuardScanEvery)
		var out strings.Builder
		blocked := false
		for _, p := range pushes {
			units, v := g.Push(p, []byte(p))
			if v != nil {
				blocked = true
				break
			}
			for _, u := range units {
				out.Write(u)
			}
		}
		if !blocked {
			units, v := g.Finish()
			blocked = v != nil
			for _, u := range units {
				out.Write(u)
			}
		}
		body := key[strings.IndexByte(key, '\n')+1 : strings.LastIndex(key, "-----END")]
		leaked := 0
		for _, line := range strings.Split(body, "\n") {
			if len(line) > 8 && strings.Contains(out.String(), line) {
				leaked += len(line)
			}
		}
		t.Logf("Q2 decoy=%v: blocked=%v, key body bytes released=%d of %d", decoy, blocked, leaked, len(body))
		if leaked > 0 {
			t.Errorf("Q2 decoy=%v: %d key-body bytes reached the client", decoy, leaked)
		}
	}
}

type fixedChunkReader struct {
	b []byte
	n int
}

func (r *fixedChunkReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := min(r.n, len(p), len(r.b))
	copy(p, r.b[:n])
	r.b = r.b[n:]
	return n, nil
}

// Q3: a passthrough SSE line past 1 MiB with a multi-byte rune split at a
// read boundary: does the guard text lose bytes around later chunk ends?
func TestResprev2LongLineRuneSplit(t *testing.T) {
	secret := resprevSecret(t)
	const C = 4096
	prefix := `data: {"choices":[{"index":0,"delta":{"content":"`
	B := 257 * C
	for _, split := range []bool{false, true} {
		total := B + 3*C
		content := []byte(strings.Repeat("a ", total))[:total-len(prefix)]
		rune3 := "e"
		if split {
			rune3 = "€"
		}
		copy(content[B-1-len(prefix):], rune3)
		at := B + C - len(secret)/2 - 2 - len(prefix)
		if !split {
			at = B + C - len(secret)/2 - 2 - len(prefix)
		}
		content[at-1] = ' '
		copy(content[at:], secret)
		content[at+len(secret)] = ' '
		line := prefix + string(content) + `"}}]}` + "\n\ndata: [DONE]\n\n"
		_, insp := streamGuardTestCheck()
		proxy := newTestProxy(t, &mockProvider{}, insp, "action")
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		rec := httptest.NewRecorder()
		_, ok := proxy.streamPassthroughReply(rec, req, &fixedChunkReader{b: []byte(line), n: C}, nil, "openai", "openai", "action", "m", "")
		out := rec.Body.String()
		t.Logf("Q3 split=%v: ok=%v, out %d bytes, secret released=%v", split, ok, len(out), strings.Contains(out, secret))
		if strings.Contains(out, secret) {
			t.Errorf("Q3 split=%v: the secret reached the client", split)
		}
	}
}

// Q4: /llm, a content chunk after 10 MiB of tool-call data: released at the
// cap flush before the guard checked its text?
func TestResprev2ToolCapFlushChecksContent(t *testing.T) {
	secret := resprevSecret(t)
	bigArgs := strings.Repeat("A", 512*1024)
	for _, where := range []string{"before tools (control)", "after tools"} {
		var chunks []StreamChunk
		content := StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: "\nsee " + secret + " here\n"}}}}
		if where == "before tools (control)" {
			chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: streamGuardFiller(600)}}}}, content)
		}
		mk := func(args string) StreamChunk {
			tc := json.RawMessage(`[{"index":0,"id":"c1","type":"function","function":{"name":"big","arguments":"` + args + `"}}]`)
			return StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: tc}}}}
		}
		size := 0
		for i := 0; i < 19; i++ {
			c := mk(bigArgs)
			d, _ := json.Marshal(c)
			size += len(d)
			chunks = append(chunks, c)
		}
		probe, _ := json.Marshal(mk(""))
		last := mk(strings.Repeat("A", (10<<20)-size-len(probe)-50))
		d, _ := json.Marshal(last)
		size += len(d)
		chunks = append(chunks, last)
		cd, _ := json.Marshal(content)
		t.Logf("Q4 %s: tool bytes %d (cap %d), content chunk %d bytes", where, size, 10<<20, len(cd))
		if where == "after tools" {
			chunks = append(chunks, content)
			for i := 0; i < 3; i++ {
				chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
					Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: streamGuardFiller(300)}}}})
			}
		}
		fin := "tool_calls"
		chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fin}}})
		reqBody := mustJSON(t, map[string]interface{}{
			"model": "gpt-4", "stream": true,
			"messages": []map[string]interface{}{{"role": "user", "content": "go"}},
		})
		_, insp := streamGuardTestCheck()
		proxy := newTestProxy(t, &mockProvider{streamChunks: chunks}, insp, "action")
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		cfg := &config.Config{}
		cfg.Guardrail.RulePack = "default"
		req = req.WithContext(withPinnedGeneration(req.Context(), &Generation{N: 1, Config: cfg}))
		rec := httptest.NewRecorder()
		proxy.handleChatCompletion(rec, req)
		body := rec.Body.String()
		t.Logf("Q4 %s: out %d bytes, secret released=%v, blocked notice=%v", where, len(body), strings.Contains(body, secret), strings.Contains(body, "blocked"))
		if strings.Contains(body, secret) {
			t.Errorf("Q4 %s: the secret reached the client", where)
		}
	}
}
