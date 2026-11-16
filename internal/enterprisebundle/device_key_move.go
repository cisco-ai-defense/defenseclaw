// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"path"
	"strings"
)

// RefuseDeviceKeyMove checks the effective key location before a bundle is
// promoted or the installed config changes. Moving this identity also needs
// its provenance files, which a policy bundle does not carry.
func RefuseDeviceKeyMove(current, candidate []byte, platform string, layout *DeviceLayout) error {
	if len(current) == 0 {
		return nil // First installation has no device identity to move.
	}
	if layout == nil {
		standard, err := StandardDeviceLayout(platform)
		if err != nil {
			return &Error{Code: CodeStateInvalid, Detail: err.Error()}
		}
		layout = &standard
	}
	keyPath := func(raw []byte) (string, error) {
		root, err := parseConfigNode(raw)
		if err != nil {
			return "", err
		}
		value := path.Join(strings.ReplaceAll(layout.DataDir, `\`, "/"), "device.key")
		if node := nodeAt(root, "gateway", "device_key_file"); node != nil && node.Value != "" {
			value = node.Value
		}
		value = path.Clean(strings.ReplaceAll(value, `\`, "/"))
		if !strings.HasPrefix(value, "/") && (platform != PlatformWindows || !strings.Contains(value, ":")) {
			value = path.Join(strings.ReplaceAll(layout.DataDir, `\`, "/"), value)
		}
		if platform == PlatformWindows {
			value = strings.ToLower(value)
		}
		return value, nil
	}
	before, err := keyPath(current)
	if err != nil {
		return &Error{Code: CodeStateInvalid, Detail: "cannot read the installed device key path: " + err.Error()}
	}
	after, err := keyPath(candidate)
	if err != nil {
		return &Error{Code: CodeConfigInvalid, Detail: "cannot read the bundle device key path: " + err.Error()}
	}
	if before != after {
		return &Error{Code: CodeInvalidArguments, Detail: "the bundle changes gateway.device_key_file on an installed device; keep the existing path or reinstall with the new device identity path"}
	}
	return nil
}
