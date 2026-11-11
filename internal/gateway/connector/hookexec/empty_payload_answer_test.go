// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"strings"
	"testing"
)

// p0-round GAP-0955: a Claude Code hook that reads no payload (an empty or
// blank stdin) never gives the allow-shaped empty answer, exit 0 with no
// output. A running gateway refuses the body as malformed and the hook
// blocks; with the gateway down it answers by its fail mode, in words.
func TestEmptyHookPayloadIsNeverASilentAllow(t *testing.T) {
	shortRestartBudget(t)
	refusing := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid JSON body","reason":"` + MalformedHookPayloadReason + `"}`))
	})
	for _, stdin := range []string{"", " \r\n"} {
		for _, mode := range []string{"closed", "open"} {
			for _, gateway := range []struct{ name, addr string }{{"up", refusing}, {"down", "127.0.0.1:1"}} {
				result, _ := runAgainstGateway(t, "claudecode", gateway.addr, func(opts *Options) {
					opts.FailMode = mode
					opts.Event = ""
					opts.Stdin = strings.NewReader(stdin)
				})
				if result.code == 0 && strings.TrimSpace(result.stdout+result.stderr) == "" {
					t.Errorf("stdin=%q mode=%s gateway %s: exit 0 with no output, an allow-shaped empty answer", stdin, mode, gateway.name)
				}
				if gateway.name == "up" && !blocked(result) {
					t.Errorf("stdin=%q mode=%s: malformed refusal not blocked: code=%d stdout=%q stderr=%q", stdin, mode, result.code, result.stdout, result.stderr)
				}
			}
		}
	}
}
