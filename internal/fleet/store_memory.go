package fleet

import (
	"fmt"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
)

// MemoryStore is an in-memory DeviceStore and DeviceKeyStore implementation
// for testing and development. Data is lost when the process exits.
type MemoryStore struct {
	mu         sync.RWMutex
	devices    map[uint64]*manager.Device
	deviceKeys map[uint64][]byte
}

// NewMemoryStore creates a new in-memory device store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		devices:    make(map[uint64]*manager.Device),
		deviceKeys: make(map[uint64][]byte),
	}
}

func (s *MemoryStore) SaveDevice(dev *manager.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	copy := *dev
	s.devices[dev.DeviceID] = &copy
	return nil
}

func (s *MemoryStore) LoadDevice(tenantID, fleetID uint16, deviceID uint32) (*manager.Device, error) {
	fullID := manager.ComposeID(tenantID, fleetID, deviceID)

	s.mu.RLock()
	defer s.mu.RUnlock()

	dev, ok := s.devices[fullID]
	if !ok {
		return nil, nil
	}

	copy := *dev
	return &copy, nil
}

func (s *MemoryStore) ListDevices() ([]*manager.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*manager.Device, 0, len(s.devices))
	for _, dev := range s.devices {
		copy := *dev
		result = append(result, &copy)
	}
	return result, nil
}

func (s *MemoryStore) DeleteDevice(tenantID, fleetID uint16, deviceID uint32) error {
	fullID := manager.ComposeID(tenantID, fleetID, deviceID)

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.devices, fullID)
	return nil
}

// SaveDeviceKey persists a per-device signing key in memory.
func (s *MemoryStore) SaveDeviceKey(deviceID uint64, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("device key must be exactly 32 bytes, got %d", len(key))
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	s.deviceKeys[deviceID] = keyCopy
	return nil
}

// LoadDeviceKey retrieves a per-device signing key from memory.
// Returns nil, nil if no key exists for the device.
func (s *MemoryStore) LoadDeviceKey(deviceID uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.deviceKeys[deviceID]
	if !ok {
		return nil, nil
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	return keyCopy, nil
}
