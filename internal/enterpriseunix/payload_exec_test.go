//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadPayloadNamesApplicationControlExecutionRefusal(t *testing.T) {
	for _, cause := range []error{syscall.EACCES, syscall.EPERM} {
		h := newTestHost(t, "linux")
		payloadDir := h.payload("1.0.0")
		h.runner.replies = map[string]fakeReply{}
		h.runner.replies[binGateway+" --version-json"] = fakeReply{err: &os.PathError{Op: "fork/exec", Path: filepath.Join(payloadDir, binGateway), Err: cause}}
		_, err := h.env.loadPayload(context.Background(), payloadDir)
		if err == nil || !errors.Is(err, cause) || !strings.Contains(err.Error(), "application control (fapolicyd or SELinux)") || !strings.Contains(err.Error(), "noexec") || !strings.Contains(err.Error(), payloadDir) {
			t.Fatalf("loadPayload error = %v, want actionable execution refusal wrapping %v", err, cause)
		}
	}
}
