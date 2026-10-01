//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A gateway that cannot start (e.g. a rule pack that does not load) must
// leave its reason in the result and in the lifecycle directory even though
// the rollback of a first install removes the log directory.
func TestFailedActivationKeepsTheGatewayOutput(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.healthy = false
	health := h.env.HealthGet
	h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
		log := h.env.P(h.env.gatewayErrorLogPath())
		_ = os.MkdirAll(filepath.Dir(log), 0o755)
		_ = os.WriteFile(log, []byte("starting\nguardrail: load rule pack /opt/x: rules/bad.yaml: invalid severity \"URGENT\"\x1b[0m\n"), 0o644)
		return health(ctx)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireError(t, r, codeActivate)
	var message string
	for _, e := range r.Errors {
		if e.Code == codeActivate {
			message = e.Message
		}
	}
	if !strings.Contains(message, `invalid severity "URGENT"`) || strings.Contains(message, "\x1b") {
		t.Fatalf("activation error lacks the sanitized gateway reason: %q", message)
	}
	kept, err := os.ReadFile(h.env.activationFailurePath())
	if err != nil || !strings.Contains(string(kept), "invalid severity") {
		t.Fatalf("gateway output not kept after rollback: %v %q", err, kept)
	}
}

func TestGatewayOutputExcerptIsBounded(t *testing.T) {
	long := strings.Repeat("x", 1000)
	lines := []string{}
	for i := 0; i < 50; i++ {
		lines = append(lines, long)
	}
	excerpt := gatewayOutputExcerpt(strings.Join(lines, "\n"))
	if got := strings.Count(excerpt, " | ") + 1; got != gatewayExcerptLines {
		t.Fatalf("excerpt lines = %d", got)
	}
	if len(excerpt) > gatewayExcerptLines*(gatewayExcerptLineBytes+10) {
		t.Fatalf("excerpt too long: %d", len(excerpt))
	}
}

// The gateway error log sits in a directory the service account owns. The
// lifecycle (root) reads it after a failed activation, so a link there must
// not copy another file into the result, and a FIFO must not hang the run
// while it holds the lifecycle lock.
func TestFailedActivationReadsOnlyARegularGatewayLog(t *testing.T) {
	for name, plant := range map[string]func(t *testing.T, log, marker string) error{
		"symlink": func(_ *testing.T, log, marker string) error { return os.Symlink(marker, log) },
		"fifo":    func(_ *testing.T, log, _ string) error { return syscall.Mkfifo(log, 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			h.healthy = false
			marker := filepath.Join(t.TempDir(), "private")
			if err := os.WriteFile(marker, []byte("marker-private-content\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			health := h.env.HealthGet
			h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
				log := h.env.P(h.env.gatewayErrorLogPath())
				if _, err := os.Lstat(log); os.IsNotExist(err) {
					_ = os.MkdirAll(filepath.Dir(log), 0o755)
					if err := plant(t, log, marker); err != nil {
						t.Errorf("plant %s: %v", name, err)
					}
				}
				return health(ctx)
			}
			done := make(chan *enterprisestatus.Result, 1)
			go func() { done <- h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}) }()
			var r *enterprisestatus.Result
			select {
			case r = <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("a FIFO at the gateway log path blocked the lifecycle run")
			}
			requireError(t, r, codeActivate)
			for _, e := range r.Errors {
				if strings.Contains(e.Message, "marker-private-content") {
					t.Fatalf("the result copied the link target: %q", e.Message)
				}
			}
			if kept, err := os.ReadFile(h.env.activationFailurePath()); err == nil && strings.Contains(string(kept), "marker-private-content") {
				t.Fatal("the kept activation output copied the link target")
			}
		})
	}
}
