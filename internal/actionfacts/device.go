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

package actionfacts

import "strings"

// isRawBlockDeviceTarget reports whether value identifies a concrete block
// device that can be destructively overwritten. Character devices and other
// special sinks remain device-flavored path facts, but are not disk writes.
func isRawBlockDeviceTarget(value string) bool {
	value = strings.ReplaceAll(value, `\`, "/")
	lower := strings.ToLower(value)
	const physicalDrive = "//./physicaldrive"
	if strings.HasPrefix(lower, physicalDrive) {
		return asciiDigits(lower[len(physicalDrive):])
	}

	const deviceRoot = "/dev/"
	if !strings.HasPrefix(value, deviceRoot) {
		return false
	}
	name := value[len(deviceRoot):]
	switch {
	case letterDeviceName(name, "sd"),
		letterDeviceName(name, "vd"),
		letterDeviceName(name, "xvd"),
		letterDeviceName(name, "hd"):
		return true
	case numberedDeviceName(name, "disk", "s"),
		numberedDeviceName(name, "rdisk", "s"),
		numberedDeviceName(name, "mmcblk", "p"),
		numberedDeviceName(name, "md"),
		numberedDeviceName(name, "dm-"):
		return true
	case nvmeDeviceName(name):
		return true
	case strings.HasPrefix(name, "mapper/"):
		return safeDeviceLinkName(name[len("mapper/"):])
	case strings.HasPrefix(name, "disk/by-id/"):
		return safeDeviceLinkName(name[len("disk/by-id/"):])
	default:
		return false
	}
}

func letterDeviceName(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	suffix := value[len(prefix):]
	if suffix == "" || suffix[0] < 'a' || suffix[0] > 'z' {
		return false
	}
	return suffix[1:] == "" || asciiDigits(suffix[1:])
}

// numberedDeviceName accepts prefix<digits> with an optional
// marker<digits> suffix.
func numberedDeviceName(value, prefix string, optionalMarker ...string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	remainder := value[len(prefix):]
	digits, tail := leadingASCIIDigits(remainder)
	if digits == "" {
		return false
	}
	if len(optionalMarker) == 1 && strings.HasPrefix(tail, optionalMarker[0]) {
		digits, tail = leadingASCIIDigits(tail[len(optionalMarker[0]):])
		if digits == "" {
			return false
		}
	}
	return tail == ""
}

func nvmeDeviceName(value string) bool {
	if !strings.HasPrefix(value, "nvme") {
		return false
	}
	controller, tail := leadingASCIIDigits(value[len("nvme"):])
	if controller == "" || !strings.HasPrefix(tail, "n") {
		return false
	}
	namespace, tail := leadingASCIIDigits(tail[1:])
	if namespace == "" {
		return false
	}
	if strings.HasPrefix(tail, "p") {
		partition, remainder := leadingASCIIDigits(tail[1:])
		if partition == "" {
			return false
		}
		tail = remainder
	}
	return tail == ""
}

func leadingASCIIDigits(value string) (string, string) {
	index := 0
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
	}
	return value[:index], value[index:]
}

func asciiDigits(value string) bool {
	digits, tail := leadingASCIIDigits(value)
	return digits != "" && tail == ""
}

func safeDeviceLinkName(value string) bool {
	if value == "" || value == "." || value == ".." ||
		strings.ContainsAny(value, `/\`) {
		return false
	}
	for _, char := range value {
		if char == 0 || char == '\u007f' || char <= ' ' {
			return false
		}
	}
	return true
}
