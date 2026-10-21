package manager

import "testing"

// The heartbeat's last-applied emergency sequence must reach the device record
// so operators can confirm a kill switch was applied (GET /devices/{id}).
func TestProcessHeartbeatRecordsLastEmergencySeq(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)
	if !fm.ProcessHeartbeat(1, 1, 42, &Heartbeat{DeviceID: 42, PolicyVersion: 1, LastEmergencySeq: 7, Signed: true}) {
		t.Fatal("heartbeat rejected")
	}
	dev, ok := fm.GetDevice(ComposeID(1, 1, 42))
	if !ok {
		t.Fatal("device missing")
	}
	if dev.LastEmergencySeq != 7 {
		t.Fatalf("LastEmergencySeq = %d, want 7", dev.LastEmergencySeq)
	}
}

func lastEmergencySeq(t *testing.T, fm *FleetManager) uint32 {
	t.Helper()
	dev, ok := fm.GetDevice(ComposeID(1, 1, 42))
	if !ok {
		t.Fatal("device missing")
	}
	return dev.LastEmergencySeq
}

// An unauthenticated heartbeat must not claim a kill switch was applied.
func TestProcessHeartbeatIgnoresEmergencySeqFromUnsignedHeartbeat(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)
	if !fm.ProcessHeartbeat(1, 1, 42, &Heartbeat{DeviceID: 42, UptimeSec: 10, LastEmergencySeq: 9}) {
		t.Fatal("unsigned heartbeat rejected")
	}
	if got := lastEmergencySeq(t, fm); got != 0 {
		t.Fatalf("unsigned heartbeat set LastEmergencySeq = %d, want 0", got)
	}
}

// The device persists its emergency seq across reboots, so within one key
// lineage the recorded value never decreases; a new key resets the lineage.
func TestProcessHeartbeatEmergencySeqMonotonicWithinLineage(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)
	if !fm.ProcessHeartbeat(1, 1, 42, &Heartbeat{DeviceID: 42, BootCounter: 1, UptimeSec: 10, LastEmergencySeq: 7, Signed: true}) {
		t.Fatal("heartbeat rejected")
	}
	if !fm.ProcessHeartbeat(1, 1, 42, &Heartbeat{DeviceID: 42, BootCounter: 1, UptimeSec: 20, LastEmergencySeq: 3, Signed: true}) {
		t.Fatal("same-boot heartbeat rejected")
	}
	if got := lastEmergencySeq(t, fm); got != 7 {
		t.Fatalf("same-boot lower seq: LastEmergencySeq = %d, want 7", got)
	}
	if !fm.ProcessHeartbeat(1, 1, 42, &Heartbeat{DeviceID: 42, BootCounter: 2, UptimeSec: 5, LastEmergencySeq: 2, Signed: true}) {
		t.Fatal("reboot heartbeat rejected")
	}
	if got := lastEmergencySeq(t, fm); got != 7 {
		t.Fatalf("reboot lower seq: LastEmergencySeq = %d, want 7", got)
	}

	// Re-provisioning with a new key starts a new lineage.
	fm.mu.Lock()
	resetHeartbeatLineage(fm.devices[ComposeID(1, 1, 42)])
	fm.mu.Unlock()
	if got := lastEmergencySeq(t, fm); got != 0 {
		t.Fatalf("lineage reset kept LastEmergencySeq = %d, want 0", got)
	}
	if !fm.ProcessHeartbeat(1, 1, 42, &Heartbeat{DeviceID: 42, BootCounter: 1, UptimeSec: 5, LastEmergencySeq: 1, Signed: true}) {
		t.Fatal("post-reprovision heartbeat rejected")
	}
	if got := lastEmergencySeq(t, fm); got != 1 {
		t.Fatalf("post-reprovision LastEmergencySeq = %d, want 1", got)
	}
}
