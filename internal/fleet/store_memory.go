// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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

	adminActive     []byte
	adminSuperseded []byte
}

// LoadAdminTokenRotation returns the admin-token rotation recorded in memory.
func (s *MemoryStore) LoadAdminTokenRotation() (active, superseded []byte, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.adminActive...), append([]byte(nil), s.adminSuperseded...), nil
}

// SaveAdminTokenRotation records an admin-token rotation in memory.
func (s *MemoryStore) SaveAdminTokenRotation(active, superseded []byte) error {
	if len(active) != 32 || (superseded != nil && len(superseded) != 32) {
		return fmt.Errorf("admin token hashes must be 32 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adminActive = append([]byte(nil), active...)
	s.adminSuperseded = append([]byte(nil), superseded...)
	return nil
}

// ClearAdminTokenRotation forgets the in-memory rotation.
func (s *MemoryStore) ClearAdminTokenRotation() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adminActive, s.adminSuperseded = nil, nil
	return nil
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

// RotateDeviceKey replaces a registered device's key and record under one lock.
func (s *MemoryStore) RotateDeviceKey(dev *manager.Device, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("device key must be exactly 32 bytes, got %d", len(key))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[dev.DeviceID]; !ok {
		return fmt.Errorf("rotate device key %d: %w", dev.DeviceID, manager.ErrDeviceNotFound)
	}
	copy := *dev
	s.devices[dev.DeviceID] = &copy
	s.deviceKeys[dev.DeviceID] = append([]byte(nil), key...)
	return nil
}

// SaveDeviceRegistration updates the in-memory device and key under one lock.
// MemoryStore has no tombstones; callers that need to clear one must use a
// persistent store that supports the complete operation.
func (s *MemoryStore) SaveDeviceRegistration(dev *manager.Device, key []byte, allowRecommission bool) error {
	if len(key) != 32 {
		return fmt.Errorf("device key must be exactly 32 bytes, got %d", len(key))
	}
	_ = allowRecommission // This store has no tombstone table.
	s.mu.Lock()
	defer s.mu.Unlock()
	devCopy := *dev
	keyCopy := append([]byte(nil), key...)
	s.devices[dev.DeviceID] = &devCopy
	s.deviceKeys[dev.DeviceID] = keyCopy
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

// DeleteDeviceKey removes a per-device signing key from memory.
func (s *MemoryStore) DeleteDeviceKey(deviceID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.deviceKeys, deviceID)
	return nil
}
