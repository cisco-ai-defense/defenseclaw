// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netguard

import (
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensitivequery"
)

func TestIsPrivateOrReserved(t *testing.T) {
	cases := []struct {
		ip     string
		expect bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"192.168.1.10", true},
		{"169.254.169.254", true},
		{"169.254.170.2", true},
		{"100.64.0.1", true},
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("parse %s", tc.ip)
		}
		got := IsPrivateOrReserved(ip)
		if got != tc.expect {
			t.Errorf("IsPrivateOrReserved(%s) = %v; want %v", tc.ip, got, tc.expect)
		}
	}
}

func TestRejectInlineCredentials(t *testing.T) {
	good, _ := url.Parse("https://api.example.com/v1/chat")
	if err := RejectInlineCredentials(good); err != nil {
		t.Errorf("good url: %v", err)
	}
	bad, _ := url.Parse("https://user:pass@api.example.com/v1/chat")
	if err := RejectInlineCredentials(bad); err == nil {
		t.Errorf("inline-cred url: want error, got nil")
	}
}

func TestScrubURL(t *testing.T) {
	cases := []struct {
		in       string
		mustHide []string
		mustKeep []string
	}{
		{
			in:       "https://api.openai.com/v1/chat?api_key=sk-secret&temperature=0.7",
			mustHide: []string{"sk-secret"},
			mustKeep: []string{"api.openai.com", "temperature=0.7"},
		},
		{
			in:       "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=AIzaSyDummySecret",
			mustHide: []string{"AIzaSyDummySecret"},
			mustKeep: []string{"generativelanguage.googleapis.com"},
		},
		{
			in:       "https://user:pass@webhook.example.com/route?routing_key=pd-secret-routing",
			mustHide: []string{"user", "pass", "pd-secret-routing"},
			mustKeep: []string{"webhook.example.com"},
		},
		{
			in:       "https://api.amazonaws.com/foo?X-Amz-Signature=abc123sig&X-Amz-Credential=AKIA",
			mustHide: []string{"abc123sig", "AKIA"},
			mustKeep: []string{"api.amazonaws.com"},
		},
		{
			in:       "https://example.test/path?tok%65n=encoded-secret&safe=ok",
			mustHide: []string{"encoded-secret"},
			mustKeep: []string{"tok%65n=%3Credacted%3E", "safe=ok"},
		},
		{
			in:       "https://example.test/path?%2574oken=nested-secret;model=safe",
			mustHide: []string{"nested-secret"},
			mustKeep: []string{"%2574oken=%3Credacted%3E", "model=safe"},
		},
		{
			in:       "https://example.test/path?token%3Dencoded-secret",
			mustHide: []string{"encoded-secret"},
			mustKeep: []string{"redacted=%3Credacted%3E"},
		},
		{
			in:       "https://example.test/path?token%3Dencoded-secret%26safe%3Dok",
			mustHide: []string{"encoded-secret"},
			mustKeep: []string{"redacted=%3Credacted%3E"},
		},
		{
			in:       "https://example.test/path?token%3Dsecret=x&safe=ok",
			mustHide: []string{"token%3Dsecret"},
			mustKeep: []string{"redacted=%3Credacted%3E", "safe=ok"},
		},
	}
	for _, tc := range cases {
		got := ScrubURLString(tc.in)
		for _, h := range tc.mustHide {
			if strings.Contains(got, h) {
				t.Errorf("ScrubURLString(%q) = %q; leaked %q", tc.in, got, h)
			}
		}
		for _, k := range tc.mustKeep {
			if !strings.Contains(got, k) {
				t.Errorf("ScrubURLString(%q) = %q; missing %q", tc.in, got, k)
			}
		}
	}
}

func TestScrubURLPreservesSafeQueryBytesAndDuplicates(t *testing.T) {
	raw := "https://example.test/path?model=a%2Fb&tok%65n=first&token=second&model=last#fragment"
	got := ScrubURLString(raw)
	want := "https://example.test/path?model=a%2Fb&tok%65n=%3Credacted%3E&token=%3Credacted%3E&model=last#fragment"
	if got != want {
		t.Fatalf("ScrubURLString() = %q, want %q", got, want)
	}
}

func TestScrubURLMalformedInputNeverReturnsRaw(t *testing.T) {
	const raw = "://bad?token=do-not-log"
	got := ScrubURLString(raw)
	if got != "<unparseable-url>" || strings.Contains(got, "do-not-log") {
		t.Fatalf("ScrubURLString(%q) = %q", raw, got)
	}
}

func FuzzScrubURLStringSensitiveQueryKeys(f *testing.F) {
	const sentinel = "defenseclaw-query-secret-sentinel"
	for _, key := range []string{
		"token", "tok%65n", "%74oken", "api%5Fkey", "X-Amz%2DSignature",
		"%2574oken", "tok%6Zn", "token%3D" + sentinel,
	} {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if len(key) > 256 || strings.ContainsAny(key, "&;=#") {
			return
		}
		sensitive, valid := sensitivequery.Classify(key)
		if !sensitive && valid {
			return
		}
		got := ScrubURLString("https://example.test/path?" + key + "=" + sentinel)
		if strings.Contains(got, sentinel) {
			t.Fatalf("ScrubURLString leaked sentinel for key %q: %q", key, got)
		}
	})
}

func TestScrubURLStringQueryLimitsFailClosed(t *testing.T) {
	t.Parallel()
	const sentinel = "defenseclaw-query-secret-sentinel"
	bytePrefix := "token="
	exactBytes := bytePrefix + strings.Repeat("a", maxLoggedQueryBytes-len(bytePrefix)-len(sentinel)) + sentinel
	safeBytePrefix := "safe="
	overBytes := safeBytePrefix + strings.Repeat("a", maxLoggedQueryBytes-len(safeBytePrefix)-len(sentinel)+1) + sentinel

	exactPairs := make([]string, 0, maxLoggedQueryPairs)
	for i := 0; i < maxLoggedQueryPairs-1; i++ {
		exactPairs = append(exactPairs, "model=ok")
	}
	exactPairs = append(exactPairs, "token="+sentinel)
	overPairs := append([]string{}, exactPairs[:len(exactPairs)-1]...)
	overPairs = append(overPairs, "model=ok", "safe="+sentinel)

	for _, query := range []string{
		exactBytes,
		overBytes,
		strings.Join(exactPairs, "&"),
		strings.Join(overPairs, "&"),
	} {
		got := ScrubURLString("https://example.test/path?" + query)
		if strings.Contains(got, sentinel) {
			t.Fatalf("ScrubURLString leaked sentinel at a query limit: %q", got)
		}
	}
}

func TestScrubURLsInTextHandlesUppercaseAndNestedURLs(t *testing.T) {
	const sentinel = "defenseclaw-nested-url-secret"
	input := "outer HTTPS://gateway.example.test/callback?next=" +
		"https://inner.example.test/data?tok%65n=" + sentinel
	got := ScrubURLsInText(input)
	if strings.Contains(got, sentinel) {
		t.Fatalf("ScrubURLsInText leaked nested URL credentials: %q", got)
	}
	if !strings.Contains(strings.ToLower(got), "https://gateway.example.test") {
		t.Fatalf("ScrubURLsInText lost uppercase-scheme diagnostic context: %q", got)
	}
	if strings.Count(got, redactedQueryValue) != 1 {
		t.Fatalf("ScrubURLsInText() = %q, want one redacted nested value", got)
	}
}

func TestScrubURLsInTextLimitsFailClosed(t *testing.T) {
	t.Parallel()
	oversize := "https://example.test/?token=secret" +
		strings.Repeat("x", maxDiagnosticTextBytes)
	if got := ScrubURLsInText(oversize); got != redactedDiagnosticText {
		t.Fatalf("oversize diagnostic text = %q, want fail-closed placeholder", got)
	}

	urls := make([]string, maxDiagnosticURLs+1)
	for i := range urls {
		urls[i] = "https://example.test/?token=secret"
	}
	if got := ScrubURLsInText(strings.Join(urls, " ")); got != redactedDiagnosticText {
		t.Fatalf("excessive diagnostic URLs did not fail closed")
	}

	urls = urls[:maxDiagnosticURLs]
	got := ScrubURLsInText(strings.Join(urls, " "))
	if strings.Contains(got, "secret") || strings.Count(got, redactedQueryValue) != maxDiagnosticURLs {
		t.Fatalf("bounded diagnostic URLs were not independently scrubbed")
	}
}

func TestEndpointForDisplayRemovesAllCredentialCarriers(t *testing.T) {
	got := EndpointForDisplay("https://alice:secret@collector.example.test/v1/traces?custom_token=secret#fragment")
	if got != "https://collector.example.test/v1/traces" {
		t.Fatalf("EndpointForDisplay()=%q", got)
	}
	if got := EndpointForDisplay("127.0.0.1:4317"); got != "127.0.0.1:4317" {
		t.Fatalf("EndpointForDisplay() bare OTLP endpoint=%q", got)
	}
}

// ---------------------------------------------------------------------------
// DEFENSECLAW_ALLOW_CGNAT — operator escape hatch for Tailscale and other
// 100.64.0.0/10 overlay deployments.
//
// extraReservedCIDRs is computed once at package init() time, so the
// opt-in path can only be observed in a sub-process that boots with
// the env var set. The default path (CGNAT blocked) is already covered
// by TestIsPrivateOrReserved above.
// ---------------------------------------------------------------------------

func TestCgnatAllowed_RespectsEnv(t *testing.T) {
	// cgnatAllowed reads the env at call time and is the same
	// predicate consulted by init(). Verifying it pins the
	// contract so a refactor that drops the env check would
	// flip this assertion immediately.
	t.Setenv("DEFENSECLAW_ALLOW_CGNAT", "")
	if cgnatAllowed() {
		t.Errorf("cgnatAllowed()=true with env unset; default must block CGNAT")
	}
	t.Setenv("DEFENSECLAW_ALLOW_CGNAT", "1")
	if !cgnatAllowed() {
		t.Errorf("cgnatAllowed()=false with env=1; opt-in must take effect")
	}
	// Anything other than "1" is treated as not-set, so a typo
	// like "true" or "yes" leaves CGNAT blocked.
	for _, v := range []string{"true", "yes", "0", "false", " 1 "} {
		t.Setenv("DEFENSECLAW_ALLOW_CGNAT", v)
		if cgnatAllowed() {
			t.Errorf("cgnatAllowed()=true for env=%q; only %q must opt in", v, "1")
		}
	}
}

func TestExtraReservedCIDRs_DefaultIncludesCGNAT(t *testing.T) {
	// Sanity check: 100.64.0.0/10 must be in the default deny-list.
	// Pair this with the subprocess test below that verifies it's
	// dropped when DEFENSECLAW_ALLOW_CGNAT=1 is set before init().
	cgnat := net.ParseIP("100.64.0.1")
	if !IsPrivateOrReserved(cgnat) {
		t.Errorf("default build: 100.64.0.1 must be reserved (CGNAT default-deny)")
	}
}

// TestAllowCgnatOptIn_SubprocessFlipsClassification verifies the opt-in
// path by re-executing this binary with DEFENSECLAW_ALLOW_CGNAT=1 so
// the init-time decision actually takes effect.
func TestAllowCgnatOptIn_SubprocessFlipsClassification(t *testing.T) {
	if os.Getenv("DC_NETGUARD_CGNAT_CHILD") == "1" {
		// Child process: classify 100.64.0.1 and report.
		if IsPrivateOrReserved(net.ParseIP("100.64.0.1")) {
			os.Stdout.WriteString("BLOCKED")
		} else {
			os.Stdout.WriteString("ALLOWED")
		}
		os.Exit(0)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable() failed: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestAllowCgnatOptIn_SubprocessFlipsClassification", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"DC_NETGUARD_CGNAT_CHILD=1",
		"DEFENSECLAW_ALLOW_CGNAT=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ALLOWED") {
		t.Errorf("expected child to classify 100.64.0.1 as ALLOWED under DEFENSECLAW_ALLOW_CGNAT=1; got %q", out)
	}
}
