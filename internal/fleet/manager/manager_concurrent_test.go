package manager

import (
	"sync"
	"testing"
)

func TestConcurrentProcessHeartbeatAndGetDevice(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)
	fullID := ComposeID(1, 1, 42)

	var wg sync.WaitGroup
	const goroutines = 50
	const iterations = 200

	// Concurrent heartbeats
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hb := &Heartbeat{
				DeviceID:      42,
				PolicyVersion: 3,
				DeniedCount:   1,
				AllowedCount:  1,
				Flags:         0,
			}
			for j := 0; j < iterations; j++ {
				fm.ProcessHeartbeat(1, 1, 42, hb)
			}
		}()
	}

	// Concurrent reads
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				dev, ok := fm.GetDevice(fullID)
				if !ok {
					t.Error("device not found during concurrent read")
					return
				}
				// Access fields to trigger race detector if unsafe
				_ = dev.Status
				_ = dev.DeniedTotal
				_ = dev.PolicyVersion
			}
		}()
	}

	wg.Wait()
}

func TestConcurrentCheckOfflineAndProcessHeartbeat(t *testing.T) {
	fm := New(nil)
	// Register several devices
	for i := uint32(0); i < 20; i++ {
		fm.RegisterDevice(1, 1, i, "sbc", "1.0.0", 1, 0xFF)
	}

	var wg sync.WaitGroup
	const goroutines = 20
	const iterations = 100

	// Concurrent heartbeats on various devices
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(deviceID uint32) {
			defer wg.Done()
			hb := &Heartbeat{
				DeviceID:      deviceID,
				PolicyVersion: 5,
				DeniedCount:   1,
				AllowedCount:  1,
				Flags:         0,
			}
			for j := 0; j < iterations; j++ {
				fm.ProcessHeartbeat(1, 1, deviceID, hb)
			}
		}(uint32(i))
	}

	// Concurrent offline checks
	for i := 0; i < goroutines/2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				fm.CheckOfflineDevices()
			}
		}()
	}

	wg.Wait()
}

func TestConcurrentRegisterAndGetDevice(t *testing.T) {
	fm := New(nil)

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent registrations of different devices
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			fm.RegisterDevice(1, 1, id, "sbc", "1.0.0", 1, 0xFF)
		}(uint32(i))
	}

	// Concurrent reads while registering
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			fullID := ComposeID(1, 1, id)
			// May or may not find the device depending on timing
			fm.GetDevice(fullID)
		}(uint32(i))
	}

	wg.Wait()

	// Verify all devices registered
	health := fm.GetFleetHealth()
	if health.TotalDevices != goroutines {
		t.Fatalf("expected %d devices, got %d", goroutines, health.TotalDevices)
	}
}

func TestConcurrentFleetHealth(t *testing.T) {
	fm := New(nil)
	for i := uint32(0); i < 10; i++ {
		fm.RegisterDevice(1, 1, i, "sbc", "1.0.0", 1, 0xFF)
	}

	var wg sync.WaitGroup
	const goroutines = 30
	const iterations = 100

	// Mix of reads and writes
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if n%3 == 0 {
					fm.GetFleetHealth()
				} else if n%3 == 1 {
					hb := &Heartbeat{DeviceID: uint32(n % 10), Flags: 0}
					fm.ProcessHeartbeat(1, 1, uint32(n%10), hb)
				} else {
					fm.CheckOfflineDevices()
				}
			}
		}(i)
	}

	wg.Wait()
}
