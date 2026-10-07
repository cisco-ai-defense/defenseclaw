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
}
