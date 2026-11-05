// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	pathpkg "path"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"gopkg.in/yaml.v3"
)

var (
	coworkIDPattern        = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	coworkVendorPattern    = lazyregexp.New(`^[a-z][a-z0-9_-]*$`)
	coworkCollectorPattern = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}$`)
	// Anthropic's v1.7 install-arguments grammar, including the 256-byte cap.
	coworkArgsPattern = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._:=,-]{0,255}$`)
)

// CoworkDerivedDeviceMaxLen bounds a device ID derived from the host. Both
// sources are 36-character UUIDs; validation reserves this length for an
// unset device so one fleet-wide config fits the 256-byte arguments on
// every host.
const CoworkDerivedDeviceMaxLen = 64

// NormalizeCoworkDeviceID turns the host's own identifier (macOS
// IOPlatformUUID, Windows MachineGuid) into the device install argument when
// enterprise.cowork_vm_sensor.device is unset, so one MDM config or signed
// bundle gives each host its own ID. The result is one line of the install
// arguments' characters, starting with a letter or digit. It keeps only
// A-Z a-z 0-9 . _ -: ',' and '=' separate the key=value arguments and ':'
// is not needed by either UUID form, so a host value can never add or
// replace an argument.
func NormalizeCoworkDeviceID(raw string) (string, error) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case (r == '.' || r == '_' || r == '-') && b.Len() > 0:
			b.WriteRune(r)
		}
	}
	id := b.String()
	if len(id) > CoworkDerivedDeviceMaxLen {
		id = id[:CoworkDerivedDeviceMaxLen]
	}
	if !coworkIDPattern.MatchString(id) {
		return "", fmt.Errorf("config: this host's identifier %q gives no usable Cowork device ID; set enterprise.cowork_vm_sensor.device", raw)
	}
	return id, nil
}

// EffectiveMode keeps the absent Go block empty for profile validation while
// resolving it to the same off default as the schema and Python mirror.
func (c EnterpriseCoworkVMSensorConfig) EffectiveMode() string {
	if c.Mode == "" {
		return "off"
	}
	return c.Mode
}

func validateCoworkVMSensor(c EnterpriseCoworkVMSensorConfig) error {
	mode := c.EffectiveMode()
	if mode != "off" && mode != "on" {
		return fmt.Errorf("config: enterprise.cowork_vm_sensor.mode must be off or on")
	}
	if mode != "on" {
		return nil
	}
	if !coworkVendorPattern.MatchString(c.Vendor) || len(c.Vendor) > 64 {
		return fmt.Errorf("config: enterprise.cowork_vm_sensor.vendor must be Anthropic's lowercase vendor identifier")
	}
	if !coworkSourceDirAbsolute(c.SourceDir) || len(c.SourceDir) > 4096 {
		return fmt.Errorf("config: enterprise.cowork_vm_sensor.source_dir must be an absolute administrator-staged directory")
	}
	if !enterpriseSHA256Pattern.MatchString(c.PackageSHA256) {
		return fmt.Errorf("config: enterprise.cowork_vm_sensor.package_sha256 must pin the selected architecture package with 64 lowercase hexadecimal characters")
	}
	if c.SignatureSHA256 != "" && !enterpriseSHA256Pattern.MatchString(c.SignatureSHA256) {
		return fmt.Errorf("config: enterprise.cowork_vm_sensor.signature_sha256 must be 64 lowercase hexadecimal characters when set")
	}
	// An unset device is derived on each host: check the longest one.
	_, err := c.InstallArguments(strings.Repeat("d", CoworkDerivedDeviceMaxLen))
	return err
}

// Deployment candidates may be inspected on another OS. Accept an absolute
// Unix path or a drive-rooted Windows path here; the host lifecycle enforces
// its own OS paths, administrator ownership and no-link rules before use.
func coworkSourceDirAbsolute(path string) bool {
	if path == "" || strings.TrimSpace(path) != path || strings.ContainsAny(path, "\x00\r\n\"\t") {
		return false
	}
	if strings.HasPrefix(path, "/") {
		return pathpkg.Clean(path) == path
	}
	if len(path) < 3 || ((path[0] < 'A' || path[0] > 'Z') && (path[0] < 'a' || path[0] > 'z')) || path[1:3] != `:\` || strings.ContainsAny(path[3:], `/<>|?*:`) {
		return false
	}
	if len(path) == 3 {
		return true
	}
	for _, component := range strings.Split(path[3:], `\`) {
		if component == "" || component == "." || component == ".." || strings.TrimRight(component, ". ") != component {
			return false
		}
	}
	return true
}

// A typed zero-value block cannot retain whether the source explicitly set
// cowork_vm_sensor: {}. Check that presence before decoding so every loader
// enforces the standalone-only rule, even without the later schema compiler.
func validateCoworkVMSensorSource(source string, root *yaml.Node) error {
	enterprise := v8YAMLMapValue(root, "enterprise")
	block := v8YAMLMapValue(enterprise, "cowork_vm_sensor")
	if block == nil {
		return nil
	}
	mode := v8YAMLMapValue(root, "deployment_mode")
	profile := v8YAMLMapValue(enterprise, "profile")
	if mode == nil || mode.ShortTag() != "!!str" || mode.Value != "managed_enterprise" || profile == nil || profile.ShortTag() != "!!str" || profile.Value != "standalone" {
		return v8Error(source, V8YAMLErrorProfileInvalid, "$.enterprise.cowork_vm_sensor", block,
			"enterprise.cowork_vm_sensor requires deployment_mode managed_enterprise and enterprise.profile standalone",
			"remove cowork_vm_sensor from this configuration or deploy it through the standalone enterprise lifecycle")
	}
	refuse := func(path string, node *yaml.Node, summary string) error {
		return &V8SemanticError{Source: source, Path: path, Line: node.Line, Column: node.Column,
			Summary: summary, Action: "use the documented enterprise.cowork_vm_sensor settings"}
	}
	const base = "$.enterprise.cowork_vm_sensor"
	if block.Kind != yaml.MappingNode {
		return refuse(base, block, "enterprise.cowork_vm_sensor must be an object")
	}
	for i := 0; i+1 < len(block.Content); i += 2 {
		key, value := block.Content[i], block.Content[i+1]
		path := base + "." + key.Value
		if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" {
			return refuse(path, value, "Cowork VM sensor settings must be strings")
		}
		var valid bool
		switch key.Value {
		case "mode":
			valid = value.Value == "on" || value.Value == "off"
		case "tenant", "device":
			valid = len(value.Value) <= 128 && coworkIDPattern.MatchString(value.Value)
		case "collector":
			valid = len(value.Value) <= 253 && coworkCollectorPattern.MatchString(value.Value)
		case "vendor":
			valid = len(value.Value) <= 64 && coworkVendorPattern.MatchString(value.Value)
		case "source_dir":
			valid = len(value.Value) <= 4096
		case "package_sha256", "signature_sha256":
			valid = enterpriseSHA256Pattern.MatchString(value.Value)
		default:
			return refuse(path, key, "unknown Cowork VM sensor setting")
		}
		if !valid {
			return refuse(path, value, "invalid Cowork VM sensor setting")
		}
	}
	return nil
}

// InstallArguments returns the exact ASCII, no-BOM, single-line value passed
// to Anthropic's VM install script. These identifiers are never credentials.
// hostDevice is this host's normalized ID (NormalizeCoworkDeviceID), used
// only when the config sets no device; an explicit device overrides it.
func (c EnterpriseCoworkVMSensorConfig) InstallArguments(hostDevice string) (string, error) {
	device, limit := c.Device, 128
	if device == "" {
		device, limit = hostDevice, CoworkDerivedDeviceMaxLen
		if device == "" {
			return "", fmt.Errorf("config: enterprise.cowork_vm_sensor.device is unset and this host's device ID was not derived")
		}
	}
	if !coworkIDPattern.MatchString(c.Tenant) || len(c.Tenant) > 128 || !coworkIDPattern.MatchString(device) || len(device) > limit {
		return "", fmt.Errorf("config: enterprise.cowork_vm_sensor tenant and device must be nonempty ASCII identifiers of at most 128 characters")
	}
	if !coworkCollectorPattern.MatchString(c.Collector) || len(c.Collector) > 253 {
		return "", fmt.Errorf("config: enterprise.cowork_vm_sensor.collector must be a host:port without spaces or secrets")
	}
	port, err := strconv.Atoi(c.Collector[strings.LastIndexByte(c.Collector, ':')+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("config: enterprise.cowork_vm_sensor.collector port must be 1..65535")
	}
	value := "tenant=" + c.Tenant + ",device=" + device + ",collector=" + c.Collector
	if !coworkArgsPattern.MatchString(value) {
		return "", fmt.Errorf("config: enterprise.cowork_vm_sensor arguments must match Anthropic's 1..256-byte ASCII format")
	}
	return value, nil
}
