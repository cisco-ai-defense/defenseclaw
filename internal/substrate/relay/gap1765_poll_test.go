// rel-1-0-10:GAP-1765, long-poll twin (found by the RV-ATTACH review).
package relay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Long-poll: the relay writes the keys to the agent, the attachment ends
// (GET 410) and the POST's 204 arrives after that. The keys did arrive, so
// they must not be reported unsent ("type them again").
func TestPollKeysDeliveredBeforeTheEndAreNotReportedUnsent(t *testing.T) {
	var delivered atomic.Value
	gone := make(chan struct{})
	var once sync.Once
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/poll"):
			_, _ = w.Write([]byte(`{"id":"p1"}`))
		case r.Method == http.MethodGet:
			if gets.Add(1) == 1 {
				w.Header().Set("X-Dcrelay-Cursor", "1")
				_, _ = w.Write(AppendStream(nil, EncodeControl(Control{Type: CtlHello, Version: Version, Session: "s1"})))
				return
			}
			select {
			case <-gone:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusGone)
		case r.Method == http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			delivered.Store(len(b))
			once.Do(func() { close(gone) })
			time.Sleep(300 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { time.Sleep(100 * time.Millisecond); _, _ = pw.Write([]byte("LOSE\r")) }()
	var unsent atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := Attach(ctx, pr, io.Discard, AttachOptions{BaseURL: srv.URL, Token: "t", LongPoll: true, FlatRoutes: true,
		OnUnsent: func(b []byte) { unsent.Add(int64(len(b))) }})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // a late count would land here
	t.Logf("delivered=%v Sent=%d unsent=%d", delivered.Load() != nil, res.Sent, unsent.Load())
	if delivered.Load() != nil && unsent.Load() != 0 {
		t.Fatalf("the relay wrote the keys to the agent but %d were reported unsent (launcher says type them again)", unsent.Load())
	}
	// Each key is in Sent or reported unsent, never neither.
	if got := res.Sent + unsent.Load(); got != int64(len("LOSE\r")) {
		t.Fatalf("Sent %d + unsent %d = %d, want %d", res.Sent, unsent.Load(), got, len("LOSE\r"))
	}
}
