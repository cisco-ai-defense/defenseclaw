package localcontent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testWorker(t *testing.T, reply string, budget time.Duration) *Worker {
	t.Helper()
	py, e := exec.LookPath("python3")
	if e != nil {
		t.Skip("python3 unavailable")
	}
	py, _ = filepath.Abs(py)
	path := filepath.Join(t.TempDir(), "fake.py")
	code := "import sys,json\nprint('{\"ready\":true}',flush=True)\nfor line in sys.stdin:\n " + reply + "\n"
	if e := os.WriteFile(path, []byte(code), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	w, e := Start(ctx, py, []string{path}, budget)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { w.Close() })
	return w
}
func TestWorkerValidAndBusy(t *testing.T) {
	w := testWorker(t, `print('{"wolf":{"status":"scored","score":0.9,"complete":true}}',flush=True)`, time.Second)
	v, e := w.Scan(context.Background(), "content")
	if e != nil || v != .9 {
		t.Fatalf("%v %v", v, e)
	}
	w.gate <- struct{}{}
	_, e = w.Scan(context.Background(), "content")
	<-w.gate
	if e != ErrBusy {
		t.Fatal(e)
	}
	_, e = w.Scan(context.Background(), strings.Repeat("a", MaxContentBytes+1))
	if e == nil {
		t.Fatal("oversize allowed")
	}
}
func TestWorkerTimeoutPoisonsSession(t *testing.T) {
	w := testWorker(t, `sys.stdin.readline()`, 20*time.Millisecond)
	_, e := w.Scan(context.Background(), "content")
	if e == nil {
		t.Fatal("timeout allowed")
	}
	_, e = w.Scan(context.Background(), "next")
	if e != ErrUnavailable {
		t.Fatal("stale worker reused", e)
	}
}
func TestWorkerMalformedReplyFailsClosed(t *testing.T) {
	for _, r := range []string{`print('{}',flush=True)`, `print('{"wolf":{"status":"scored","score":2,"complete":true}}',flush=True)`, `print('{"wolf":{"status":"disabled","score":0,"complete":true}}',flush=True)`} {
		w := testWorker(t, r, time.Second)
		_, e := w.Scan(context.Background(), "x")
		if e == nil {
			t.Fatal("invalid reply accepted")
		}
	}
}

func TestWorkerRequestLimitDoesNotPoisonModel(t *testing.T) {
	w := testWorker(t, `print('{"reason":"wolf:token_limit","wolf":{"status":"error","score":null,"complete":false}}' if 'too-long' in line else '{"wolf":{"status":"scored","score":0.1,"complete":true}}',flush=True)`, time.Second)
	_, e := w.Scan(context.Background(), "too-long")
	if e != ErrRefused {
		t.Fatal(e)
	}
	v, e := w.Scan(context.Background(), "short")
	if e != nil || v != .1 {
		t.Fatalf("request refusal poisoned healthy model: %v %v", v, e)
	}
}

func TestWorkerConfiguredHandshake(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	py, _ = filepath.Abs(py)
	path := filepath.Join(t.TempDir(), "configured.py")
	code := `import sys,json
settings=json.loads(sys.stdin.readline())
print(json.dumps({'ready': settings.get('variant') == 'full'}),flush=True)
for line in sys.stdin:
 print('{"wolf":{"status":"scored","score":0.1,"complete":true}}',flush=True)
`
	if err := os.WriteFile(path, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := StartConfigured(ctx, py, []string{path}, time.Second, map[string]string{"variant": "full"})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	score, err := w.Scan(ctx, "fixture")
	if err != nil || score != .1 {
		t.Fatalf("score=%v error=%v", score, err)
	}
}
