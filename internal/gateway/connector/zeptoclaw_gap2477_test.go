package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// GAP-2477: the gateway's setup rollback tears a failed ZeptoClaw setup down
// twice (partial-setup rollback, then the setup point restore). The second
// teardown must not fail just because the first one consumed the backup.
func TestZeptoClaw_TeardownTwiceAfterFailedSetup(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "zeptoclaw")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ZeptoClawConfigPathOverride = filepath.Join(configDir, "config.json")
	defer func() { ZeptoClawConfigPathOverride = "" }()

	c := NewZeptoClawConnector()
	opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	if err := c.Setup(context.Background(), opts); err == nil {
		t.Fatal("setup without providers should fail")
	}
	for i := 0; i < 2; i++ {
		if err := c.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("teardown %d: %v", i+1, err)
		}
	}
	if err := c.VerifyClean(opts); err != nil {
		t.Fatalf("verify clean: %v", err)
	}
}
