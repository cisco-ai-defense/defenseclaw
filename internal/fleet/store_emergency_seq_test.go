package fleet

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
)

func TestSQLiteStorePersistsLastEmergencySeq(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "devices.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dev := &manager.Device{TenantID: 1, FleetID: 1, DeviceID: manager.ComposeID(1, 1, 42), Status: manager.StatusOnline,
		RegisteredAt: time.Now(), LastHeartbeat: time.Now(), LastEmergencySeq: 9}
	if err := store.SaveDevice(dev); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadDevice(1, 1, 42)
	if err != nil || got == nil {
		t.Fatalf("load: %v %v", got, err)
	}
	if got.LastEmergencySeq != 9 {
		t.Fatalf("LastEmergencySeq = %d, want 9", got.LastEmergencySeq)
	}
}
