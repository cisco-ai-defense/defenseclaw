package gateway

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestRedactWebhookURL(t *testing.T) {
	cases := map[string]string{
		"https://hooks.slack.com/services/T0/B0/secret": "https://hooks.slack.com/***",
		"https://webhook.site/0000-1111":                "https://webhook.site/***",
		"https://u:p@example.com:8443/x?token=1#f":      "https://***@example.com:8443/***?***#***",
		"https://example.com/":                          "https://example.com",
		"not a url":                                     "***",
	}
	for in, want := range cases {
		if got := redactWebhookURL(in); got != want {
			t.Errorf("redactWebhookURL(%q) = %q, want %q", in, got, want)
		}
	}
	raw := "https://hooks.slack.com/services/T0/B0/secret"
	err := &url.Error{Op: "Post", URL: raw, Err: errors.New("dial tcp: timeout")}
	if got := scrubWebhookErr(err, raw); strings.Contains(got, "secret") || !strings.Contains(got, "dial tcp") {
		t.Errorf("scrubWebhookErr kept the secret or lost the cause: %q", got)
	}
}

// GAP-2279: retry/exhausted lines logged the full endpoint URL.
func TestWebhookRetryLogsRedactURL(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	secretPath := "/services/T0/B0/dccert-secret-path"
	var buf bytes.Buffer
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL + secretPath, Type: "generic", Enabled: true},
		{URL: "http://127.0.0.1:1" + secretPath, Type: "generic", Enabled: true},
	})
	d.logger = log.New(&buf, "", 0)
	d.retryBackoff = time.Millisecond

	d.Dispatch(testEvent())
	d.Close()

	out := buf.String()
	if strings.Contains(out, "dccert-secret-path") {
		t.Fatalf("webhook secret path leaked into gateway log:\n%s", out)
	}
	for _, want := range []string{"returned 503, attempt 1/4", "exhausted retries for " + srv.URL + "/***", "send to http://127.0.0.1:1/*** attempt 1/4 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
}
