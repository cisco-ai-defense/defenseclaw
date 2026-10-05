package fleet

import (
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
)

// MemoryStore is an in-memory DeviceStore implementation for testing
// and development. Data is lost when the process exits.
type MemoryStore struct {
	mu      sync.RWMutex
	devices map[uint64]*manager.Device
}

// NewMemoryStore creates a new in-memory device store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		devices: make(map[uint64]*manager.Device),
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
