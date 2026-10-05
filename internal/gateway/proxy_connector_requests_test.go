package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-2406: a proxy connector's guarded model requests show in its
// "requests" counter; a hook connector's are counted by its hook events only.
func TestProxyConnectorRequestsCountGuardedModelCalls(t *testing.T) {
	cases := []struct {
		name string
		conn connector.Connector
		want int64
	}{
		{"openclaw", connector.NewOpenClawConnector(), 1},
		{"claudecode", connector.NewClaudeCodeConnector(), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			proxy.connector = tc.conn
			rec := postChat(t, proxy, []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`))
			if rec.Code != 200 {
				t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
			}
			got := connByName(proxy.health.Snapshot().Connectors)[tc.name].Requests
			if got != tc.want {
				t.Fatalf("%s requests = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}
