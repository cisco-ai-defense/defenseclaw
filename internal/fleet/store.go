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
	"github.com/defenseclaw/defenseclaw/internal/fleet/manager"
)

// DeviceStore is the persistence interface for fleet devices.
// Implementations handle saving and loading device state across restarts.
type DeviceStore interface {
	// SaveDevice persists the device. If the device already exists (by composite ID),
	// it is overwritten.
	SaveDevice(dev *manager.Device) error

	// LoadDevice retrieves a device by its tenant, fleet, and device IDs.
	// Returns nil and no error if the device does not exist.
	LoadDevice(tenantID, fleetID uint16, deviceID uint32) (*manager.Device, error)

	// ListDevices returns all stored devices.
	ListDevices() ([]*manager.Device, error)

	// DeleteDevice removes a device from storage.
	DeleteDevice(tenantID, fleetID uint16, deviceID uint32) error
}

// DeviceKeyStore is the persistence interface for per-device HMAC signing keys.
// Implementations persist unique 32-byte keys generated at device registration.
type DeviceKeyStore interface {
	// SaveDeviceKey persists a 32-byte per-device signing key.
	SaveDeviceKey(deviceID uint64, key []byte) error

	// LoadDeviceKey retrieves the signing key for a device.
	// Returns nil, nil if no key exists.
	LoadDeviceKey(deviceID uint64) ([]byte, error)

	// DeleteDeviceKey removes the signing key for a device.
	DeleteDeviceKey(deviceID uint64) error
}

// DecommissionStore is the persistence interface for decommission tombstones.
type DecommissionStore interface {
	// SaveDecommissioned records a device ID as decommissioned.
	SaveDecommissioned(deviceID uint64) error

	// LoadDecommissioned returns all decommissioned device IDs.
	LoadDecommissioned() ([]uint64, error)

	// DeleteDecommissioned removes a device from the tombstone table
	// on re-registration.
	DeleteDecommissioned(deviceID uint64) error

	// IsDecommissioned checks whether a device ID has a decommission tombstone.
	IsDecommissioned(deviceID uint64) (bool, error)
}

// AdminTokenStore persists Fleet admin-token rotation so a gateway restart
// does not revive a rotated-out token. Only SHA-256 hashes are stored:
// active is the token in effect after the last rotation, superseded is the
// configured token that rotation replaced. Load returns nil hashes when the
// token has never been rotated.
type AdminTokenStore interface {
	LoadAdminTokenRotation() (active, superseded []byte, err error)
	SaveAdminTokenRotation(active, superseded []byte) error
	ClearAdminTokenRotation() error
}
