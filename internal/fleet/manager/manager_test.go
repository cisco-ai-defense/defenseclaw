package manager

import (
	"testing"
)

func TestComposeID(t *testing.T) {
	id := ComposeID(1, 5, 42)
	expected := (uint64(1) << 48) | (uint64(5) << 32) | 42
	if id != expected {
		t.Fatalf("ComposeID(1, 5, 42) = %x, want %x", id, expected)
	}
}

func TestRegisterDevice(t *testing.T) {
	fm := New(nil)
	dev, err := fm.RegisterDevice(1, 1, 100, "sbc", "1.0.0", 1, 0xFF)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dev.Status != StatusOnline {
		t.Fatalf("new device status = %s, want online", dev.Status)
	}
	if dev.PolicyVersion != 1 {
		t.Fatalf("policy_version = %d, want 1", dev.PolicyVersion)
	}

	got, ok := fm.GetDevice(ComposeID(1, 1, 100))
	if !ok {
		t.Fatal("device not found after register")
	}
	if got.HWProfile != "sbc" {
		t.Fatalf("hw_profile = %s, want sbc", got.HWProfile)
	}
}

func TestRegisterDeviceDuplicate(t *testing.T) {
	fm := New(nil)
	_, err := fm.RegisterDevice(1, 1, 100, "sbc", "1.0.0", 1, 0xFF)
	if err != nil {
		t.Fatalf("unexpected error on first register: %v", err)
	}

	// Second registration of same device should return ErrDeviceExists
	dev, err := fm.RegisterDevice(1, 1, 100, "sbc", "2.0.0", 2, 0xFF)
	if err != ErrDeviceExists {
		t.Fatalf("expected ErrDeviceExists, got %v", err)
	}
	// Safe fields should be updated
	if dev.FWVersion != "2.0.0" {
		t.Fatalf("fw_version = %s, want 2.0.0", dev.FWVersion)
	}
}

func TestParseHeartbeat(t *testing.T) {
	data := make([]byte, 32)
	// device_id = 42
	data[3] = 42
	// policy_version = 5
	data[9] = 5
	// denied_count = 3
	data[13] = 3
	// flags = 0 (online)
	data[30] = 0

	hb, err := ParseHeartbeat(data)
	if err != nil {
		t.Fatal(err)
	}
	if hb.DeviceID != 42 {
		t.Fatalf("device_id = %d, want 42", hb.DeviceID)
	}
	if hb.PolicyVersion != 5 {
		t.Fatalf("policy_version = %d, want 5", hb.PolicyVersion)
	}
	if hb.DeniedCount != 3 {
		t.Fatalf("denied_count = %d, want 3", hb.DeniedCount)
	}
}

func TestParseHeartbeatInvalidSize(t *testing.T) {
	_, err := ParseHeartbeat(make([]byte, 16))
	if err != ErrInvalidHeartbeat {
		t.Fatalf("expected ErrInvalidHeartbeat, got %v", err)
	}
}

func TestProcessHeartbeatUpdatesState(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)

	hb := &Heartbeat{
		DeviceID:      42,
		UptimeSec:     100,
		PolicyVersion: 3,
		DeniedCount:   10,
		AllowedCount:  500,
		Flags:         0,
	}
	fm.ProcessHeartbeat(1, 1, 42, hb)

	dev, _ := fm.GetDevice(ComposeID(1, 1, 42))
	if dev.PolicyVersion != 3 {
		t.Fatalf("policy_version = %d, want 3", dev.PolicyVersion)
	}
	// NEW-3 fix: First heartbeat, prev counters are 0, so delta == raw value.
	if dev.DeniedTotal != 10 {
		t.Fatalf("denied_total = %d, want 10", dev.DeniedTotal)
	}
	if dev.Status != StatusOnline {
		t.Fatalf("status = %s, want online", dev.Status)
	}

	// Second heartbeat: counters are cumulative, so delta should be applied.
	hb2 := &Heartbeat{
		DeviceID:      42,
		UptimeSec:     200,
		PolicyVersion: 3,
		DeniedCount:   15,
		AllowedCount:  600,
		Flags:         0,
	}
	fm.ProcessHeartbeat(1, 1, 42, hb2)

	dev, _ = fm.GetDevice(ComposeID(1, 1, 42))
	// Delta: 15 - 10 = 5, total = 10 + 5 = 15
	if dev.DeniedTotal != 15 {
		t.Fatalf("denied_total after second hb = %d, want 15", dev.DeniedTotal)
	}
	// Delta: 600 - 500 = 100, total = 500 + 100 = 600
	if dev.AllowedTotal != 600 {
		t.Fatalf("allowed_total after second hb = %d, want 600", dev.AllowedTotal)
	}
}

func TestHeartbeatReplayRejected(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)

	// First heartbeat at uptime 100
	hb1 := &Heartbeat{
		DeviceID:     42,
		UptimeSec:    100,
		DeniedCount:  5,
		AllowedCount: 50,
	}
	fm.ProcessHeartbeat(1, 1, 42, hb1)

	// Replay with same uptime — should be dropped
	hb2 := &Heartbeat{
		DeviceID:     42,
		UptimeSec:    100,
		DeniedCount:  999,
		AllowedCount: 999,
	}
	fm.ProcessHeartbeat(1, 1, 42, hb2)

	dev, _ := fm.GetDevice(ComposeID(1, 1, 42))
	if dev.DeniedTotal != 5 {
		t.Fatalf("denied_total = %d, want 5 (replay should be rejected)", dev.DeniedTotal)
	}

	// Replay with lower uptime — should also be dropped
	hb3 := &Heartbeat{
		DeviceID:     42,
		UptimeSec:    50,
		DeniedCount:  999,
		AllowedCount: 999,
	}
	fm.ProcessHeartbeat(1, 1, 42, hb3)

	dev, _ = fm.GetDevice(ComposeID(1, 1, 42))
	if dev.DeniedTotal != 5 {
		t.Fatalf("denied_total = %d, want 5 (stale hb should be rejected)", dev.DeniedTotal)
	}
}

func TestTamperDetectAlert(t *testing.T) {
	var fired Alert
	handler := func(a Alert) { fired = a }

	fm := New(handler)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)

	hb := &Heartbeat{
		DeviceID:  42,
		UptimeSec: 10,
		Flags:     0x04, // TAMPER_DETECT
	}
	fm.ProcessHeartbeat(1, 1, 42, hb)

	if fired.Type != AlertTamperDetect {
		t.Fatalf("expected tamper alert, got %v", fired.Type)
	}

	dev, _ := fm.GetDevice(ComposeID(1, 1, 42))
	if dev.Status != StatusLockdown {
		t.Fatalf("status = %s, want lockdown", dev.Status)
	}
}

func TestSEDegradedAlert(t *testing.T) {
	var fired Alert
	handler := func(a Alert) { fired = a }

	fm := New(handler)
	fm.RegisterDevice(1, 1, 43, "sbc", "1.0.0", 1, 0xFF)

	hb := &Heartbeat{
		DeviceID:  43,
		UptimeSec: 10,
		Flags:     0x80, // SE_DEGRADED
	}
	fm.ProcessHeartbeat(1, 1, 43, hb)

	if fired.Type != AlertSEDegraded {
		t.Fatalf("expected SE degraded alert, got %v", fired.Type)
	}
}

func TestFleetHealth(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 1, "sbc", "1.0.0", 5, 0xFF)
	fm.RegisterDevice(1, 1, 2, "sbc", "1.0.0", 5, 0xFF)
	fm.RegisterDevice(1, 1, 3, "mcu", "1.0.0", 4, 0x0F)

	health := fm.GetFleetHealth()
	if health.TotalDevices != 3 {
		t.Fatalf("total = %d, want 3", health.TotalDevices)
	}
	if health.Online != 3 {
		t.Fatalf("online = %d, want 3", health.Online)
	}
	if health.PolicyVersions[5] != 2 {
		t.Fatalf("version 5 count = %d, want 2", health.PolicyVersions[5])
	}
}
