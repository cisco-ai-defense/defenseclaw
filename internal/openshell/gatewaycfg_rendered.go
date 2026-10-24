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

package openshell

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// Rendered-config mode. On a standalone managed host the administrator's
// DefenseClaw lifecycle renders the OpenShell gateway's configuration from
// enterprise.openshell into a root-owned file (gateway.toml, and gateway.env
// for the settings that are not TOML) and nothing else writes it. The user's
// sandbox daemon reads that file, never edits it, and compares what the
// gateway it drives actually runs against it (drift).

// ErrRenderedGateway means a change was asked of a gateway whose
// configuration the administrator renders.
var ErrRenderedGateway = errors.New("openshell: the gateway configuration is rendered from enterprise.openshell by your administrator and cannot be changed here")

// RenderedPaths are the rendered files a GatewayConfigurator reads in place
// of the user's own gateway.toml and gateway.env.
type RenderedPaths struct {
	// TOML is the rendered gateway.toml and Env the rendered gateway.env.
	// Env may be absent: its settings then have their defaults.
	TOML, Env string
}

// RenderedGateway is the gateway configuration the lifecycle renders.
type RenderedGateway struct {
	// BindAddress is the gateway's listener, "127.0.0.1:<port>".
	BindAddress string
	// ComputeDriver is docker or vm.
	ComputeDriver ComputeDriver
	// DriverDir is where the gateway finds openshell-driver-vm; empty keeps
	// the gateway's default search path, which includes the user's
	// ~/.local/libexec/openshell.
	DriverDir string
	// VMSandboxUID and VMSandboxGID are the identity every MicroVM
	// workload runs as; never root. Zero, the lifecycle's rendering, means
	// the account's own: gateway.toml is one file for every account and
	// DefenseClaw's images are built for the account's uid and gid, so the
	// exec shim starts each account's gateway with
	// AccountVMEnvironment, which overrides the file (GAP-0254).
	VMSandboxUID, VMSandboxGID int64
	// TelemetryEnabled lets OpenShell send its own anonymous usage
	// telemetry; off unless the organization's sandbox floor allows it.
	TelemetryEnabled bool
	// DefaultDockerNamespaceBridge renders a docker driver without a
	// sandbox_label, the 1.0.1 render: its sandboxes live in OpenShell's
	// default namespace (GatewayDefaultNamespaceTOMLFile). 1.0.1 upgrade
	// bridge, remove when 1.0.1 is out of support.
	DefaultDockerNamespaceBridge bool
}

// dockerNamespace is the docker sandbox namespace r renders:
// ManagedDockerNamespace, or OpenShell's default one under the 1.0.1
// upgrade bridge (remove with DefaultDockerNamespaceBridge).
func (r RenderedGateway) dockerNamespace() string {
	if r.DefaultDockerNamespaceBridge {
		return DefaultDockerNamespace
	}
	return ManagedDockerNamespace
}

// renderedHeader marks the files the lifecycle owns.
const renderedHeader = "# Written by the DefenseClaw enterprise lifecycle from enterprise.openshell. Do not edit.\n"

// GatewayRenderedDigestFile pins the lifecycle's intended render independently
// of gateway.toml, so a later hand edit cannot redefine its own baseline.
const GatewayRenderedDigestFile = "gateway.rendered.sha256"

// Docker sandbox namespaces. OpenShell's docker driver labels every
// container and volume it makes with its sandbox namespace
// (openshell.ai/sandbox-namespace, [openshell.drivers.docker] sandbox_label)
// and, each time its gateway starts, force-removes every supervisor, staging
// and identity container of that namespace and every channel volume of it
// whose sandbox has no container (reconcile_runtime_resources_at_startup,
// OpenShell 0.1.1 to 0.1.5), whichever account's gateway made them. Every
// account's gateway on a host shares one Docker engine. With the default
// namespace a managed account's gateway start removed the supervisors of
// another account's running sandboxes (a per-user gateway the account
// started before the host was managed) and their workloads ended
// (GAP-0566). The managed gateways get a namespace of their own, and a
// per-user gateway `defenseclaw sandbox setup` configures gets the
// account's (AccountDockerNamespace, GAP-0579): DefaultDockerNamespace stays
// with the gateways DefenseClaw does not configure and those that keep
// sandboxes in it. Managed gateways share theirs because one runs at a
// time: a second account's daemon is refused while another account's
// managed gateway runs, on the managed port or, while that account's
// gateway_port switch waits, on the old one (accountBusyError), and a
// gateway's ExecStop stops its sandboxes before it exits.
const (
	// DefaultDockerNamespace is OpenShell's own default sandbox_label.
	DefaultDockerNamespace = "default"
	// ManagedDockerNamespace is the sandbox_label of the gateways the
	// lifecycle renders.
	ManagedDockerNamespace = "defenseclaw-managed"
)

// GatewayDefaultNamespaceTOMLFile is the rendered docker configuration of
// the 1.0.1 upgrade bridge (GAP-0587): the docker driver as 1.0.1 rendered
// it, with no sandbox_label, so in OpenShell's default namespace. 1.0.1's
// managed gateways kept their sandboxes there, and a gateway lists only its
// own namespace's: on the managed one they could not start, OpenShell
// dropped them and their unpulled work was lost. The lifecycle renders the
// file on a host upgraded from a 1.0.1 docker record, and the exec shim
// starts an account's docker gateway on it while that account still keeps a
// sandbox in the default namespace (DockerNamespaceInUse, and Docker still
// has it) and none in the managed one; an account without one, or once its last one is deleted,
// moves to ManagedDockerNamespace at its next gateway start. 1.0.1 upgrade
// bridge, remove when 1.0.1 is out of support.
const GatewayDefaultNamespaceTOMLFile = "gateway-docker-default-namespace.toml"

// Validate refuses a configuration the lifecycle must not render.
func (r RenderedGateway) Validate() error {
	host, port, err := net.SplitHostPort(r.BindAddress)
	if err != nil {
		return fmt.Errorf("openshell: bind address %q is not ip:port", r.BindAddress)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("openshell: the gateway must listen on a loopback address, not %q", host)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1024 || n > 65535 {
		return fmt.Errorf("openshell: gateway port %q is outside 1024-65535", port)
	}
	if _, ok := LookupDriver(string(r.ComputeDriver)); !ok {
		return fmt.Errorf("openshell: compute driver %q is not docker or vm", r.ComputeDriver)
	}
	if r.VMSandboxUID < 0 || r.VMSandboxGID < 0 || (r.VMSandboxUID == 0) != (r.VMSandboxGID == 0) {
		return errors.New("openshell: MicroVM sandboxes run as the account's own uid and gid (neither set), or as a uid and gid that are both set; never as root")
	}
	if r.DriverDir != "" && !filepath.IsAbs(r.DriverDir) {
		return fmt.Errorf("openshell: driver_dir %q is not absolute", r.DriverDir)
	}
	return nil
}

type renderedDoc struct {
	OpenShell struct {
		Version int `toml:"version"`
		Gateway struct {
			BindAddress   string `toml:"bind_address"`
			ComputeDriver string `toml:"compute_driver"`
		} `toml:"gateway"`
		Drivers *renderedDrivers `toml:"drivers"`
	} `toml:"openshell"`
}

type renderedDrivers struct {
	Docker *renderedDockerDriver `toml:"docker,omitempty"`
	VM     *renderedVMDriver     `toml:"vm,omitempty"`
}

type renderedVMDriver struct {
	DriverDir  string `toml:"driver_dir,omitempty"`
	SandboxUID int64  `toml:"sandbox_uid,omitempty"`
	SandboxGID int64  `toml:"sandbox_gid,omitempty"`
}

// renderedDockerDriver are bindMountSettings: the docker driver honors the
// read-only mounts DefenseClaw asks for in a sandbox's driver config (the
// harness settings it keeps out of the agent's reach), which a managed run
// needs as much as any other (GAP-0449). SandboxLabel is the sandbox
// namespace of every Docker object the driver makes (ManagedDockerNamespace).
type renderedDockerDriver struct {
	AllowDriverConfig bool   `toml:"allow_driver_config"`
	EnableBindMounts  bool   `toml:"enable_bind_mounts"`
	SandboxLabel      string `toml:"sandbox_label,omitempty"`
	ResourceAdmission struct {
		Enabled bool `toml:"enabled"`
	} `toml:"resource_admission"`
}

// TOML renders gateway.toml. It holds no secrets.
func (r RenderedGateway) TOML() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var doc renderedDoc
	doc.OpenShell.Version = GatewayConfigVersion
	doc.OpenShell.Gateway.BindAddress = r.BindAddress
	doc.OpenShell.Gateway.ComputeDriver = string(r.ComputeDriver)
	switch r.ComputeDriver {
	case DriverVM:
		doc.OpenShell.Drivers = &renderedDrivers{VM: &renderedVMDriver{DriverDir: r.DriverDir, SandboxUID: r.VMSandboxUID, SandboxGID: r.VMSandboxGID}}
	case DriverDocker:
		label := ManagedDockerNamespace
		if r.DefaultDockerNamespaceBridge {
			label = "" // OpenShell's default namespace, as 1.0.1 rendered it
		}
		doc.OpenShell.Drivers = &renderedDrivers{Docker: &renderedDockerDriver{AllowDriverConfig: true, EnableBindMounts: true, SandboxLabel: label}}
	}
	body, err := toml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("openshell: render gateway.toml: %w", err)
	}
	return append([]byte(renderedHeader), body...), nil
}

// EnvFile renders gateway.env: the settings the gateway reads from its
// environment. It is empty (nil) when OpenShell's telemetry is allowed,
// which is the gateway's own default.
func (r RenderedGateway) EnvFile() []byte {
	if r.TelemetryEnabled {
		return nil
	}
	return []byte(renderedHeader + EnvTelemetryEnabled + "=false\n")
}

// RenderedEnvironment reads the rendered gateway.env at envPath (a root-owned
// file, see readRenderedFile) and returns the KEY=VALUE entries the gateway
// must be started with. The gateway reads OpenShell's telemetry switch from
// its environment, which gateway.toml cannot carry, and its unit starts it
// through the exec shim with a fixed environment: the shim appends this to it.
// Only the settings the lifecycle renders are returned, in a canonical form,
// whatever else the file holds. A missing file returns nothing, which leaves
// the gateway's defaults (telemetry allowed, the case EnvFile renders as no
// file).
func RenderedEnvironment(envPath string) ([]string, error) {
	data, _, err := readRenderedFile(envPath)
	if err != nil {
		return nil, err
	}
	var env []string
	if v, ok := parseEnvFile(data)[EnvTelemetryEnabled]; ok {
		b, perr := strconv.ParseBool(strings.TrimSpace(v))
		if perr != nil {
			return nil, fmt.Errorf("openshell: %s sets %s to %q, not true or false", envPath, EnvTelemetryEnabled, v)
		}
		env = append(env, EnvTelemetryEnabled+"="+strconv.FormatBool(b))
	}
	return env, nil
}

// ForAccount returns the configuration with the MicroVM identity the render
// leaves open filled in with the account's own: what the account's gateway
// runs (AccountVMEnvironment) and what Drift compares a foreign gateway to.
func (r RenderedGateway) ForAccount(uid, gid int64) RenderedGateway {
	if r.VMSandboxUID == 0 && r.VMSandboxGID == 0 {
		r.VMSandboxUID, r.VMSandboxGID = uid, gid
	}
	return r
}

// AccountVMEnvironment is what the exec shim adds to the environment of an
// account's gateway so that every MicroVM workload runs as the account: the
// gateway takes these over gateway.toml's sandbox_uid and sandbox_gid. The
// rendered gateway.toml is one file for all accounts, and an Active
// Directory account's uid is above 90 million, so no fixed value in it can
// match the images built for the account (GAP-0254).
func AccountVMEnvironment(uid, gid int) []string {
	return []string{
		envVMSandboxUID + "=" + strconv.Itoa(uid),
		envVMSandboxGID + "=" + strconv.Itoa(gid),
	}
}

// RenderedDigest is the digest the sandbox daemon's settings carry for a
// rendered configuration: "sha256:" over the two files.
func RenderedDigest(tomlData, envData []byte) string {
	sum := sha256.New()
	sum.Write(tomlData)
	sum.Write([]byte("\x00"))
	sum.Write(envData)
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

// ReadRenderedGatewayDigest reads the administrator's pinned render digest.
// Older installations have no pin until their 1.0.4 ensure writes one.
func ReadRenderedGatewayDigest(path string) (string, error) {
	data, _, err := readRenderedFile(path)
	if err != nil || data == nil {
		return "", err
	}
	digest := strings.TrimSpace(string(data))
	if len(digest) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("openshell: rendered gateway digest is invalid")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
		return "", fmt.Errorf("openshell: rendered gateway digest is invalid: %w", err)
	}
	return digest, nil
}

// ReadRenderedGateway reads the rendered configuration at tomlPath and
// envPath (the root-owned files readRenderedFile accepts; gateway.env may be
// absent) and returns it with its RenderedDigest. A missing gateway.toml is
// an error: nothing was rendered.
func ReadRenderedGateway(tomlPath, envPath string) (RenderedGateway, string, error) {
	tomlData, info, err := readRenderedFile(tomlPath)
	if err != nil {
		return RenderedGateway{}, "", err
	}
	if info == nil {
		return RenderedGateway{}, "", fmt.Errorf("openshell: %s does not exist", tomlPath)
	}
	envData, _, err := readRenderedFile(envPath)
	if err != nil {
		return RenderedGateway{}, "", err
	}
	r, err := ParseRenderedGateway(tomlData, envData)
	if err != nil {
		return RenderedGateway{}, "", err
	}
	return r, RenderedDigest(tomlData, envData), nil
}

// ParseRenderedGateway reads a rendered configuration back.
func ParseRenderedGateway(tomlData, envData []byte) (RenderedGateway, error) {
	var doc renderedDoc
	if err := toml.Unmarshal(tomlData, &doc); err != nil {
		return RenderedGateway{}, fmt.Errorf("openshell: parse the rendered gateway.toml: %w", err)
	}
	r := RenderedGateway{
		BindAddress:      doc.OpenShell.Gateway.BindAddress,
		ComputeDriver:    ComputeDriver(doc.OpenShell.Gateway.ComputeDriver),
		TelemetryEnabled: true,
	}
	if doc.OpenShell.Drivers != nil && doc.OpenShell.Drivers.VM != nil {
		vm := doc.OpenShell.Drivers.VM
		r.DriverDir, r.VMSandboxUID, r.VMSandboxGID = vm.DriverDir, vm.SandboxUID, vm.SandboxGID
	}
	if doc.OpenShell.Drivers != nil && doc.OpenShell.Drivers.Docker != nil {
		r.DefaultDockerNamespaceBridge = strings.TrimSpace(doc.OpenShell.Drivers.Docker.SandboxLabel) == ""
	}
	if v, ok := parseEnvFile(envData)[EnvTelemetryEnabled]; ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			r.TelemetryEnabled = b
		}
	}
	return r, nil
}

// SettingDrift is one setting of the running gateway's configuration that is
// not what the lifecycle rendered.
type SettingDrift struct {
	Field, Want, Have string
}

func (d SettingDrift) String() string {
	return fmt.Sprintf("%s is %s, enterprise.openshell renders %s", d.Field, d.Have, d.Want)
}

// Drift lists where the gateway configuration s describes differs from want.
// It reads the settings that decide who can reach the gateway and what runs
// sandboxes: the listener, the compute driver, the MicroVM workload identity
// and OpenShell's telemetry. No drift is a nil slice.
func (s *GatewayConfigState) Drift(want RenderedGateway) []SettingDrift {
	var drift []SettingDrift
	add := func(field, wantValue, have string) {
		if wantValue != have {
			drift = append(drift, SettingDrift{Field: field, Want: wantValue, Have: have})
		}
	}
	driver := string(s.ComputeDriver)
	if driver == "" {
		driver = string(DriverDocker)
	}
	add("compute driver", string(want.ComputeDriver), driver)
	wantHost, wantPort, werr := net.SplitHostPort(want.BindAddress)
	if host, port, err := s.listenAddress(s.Env); err != nil {
		drift = append(drift, SettingDrift{Field: "gateway listener", Want: want.BindAddress, Have: "unreadable"})
	} else if werr == nil {
		add("gateway listener", net.JoinHostPort(wantHost, wantPort), net.JoinHostPort(host, port))
	}
	if want.ComputeDriver == DriverVM {
		id := s.VM.Identity()
		add("MicroVM workload identity", VMIdentity{UID: want.VMSandboxUID, GID: want.VMSandboxGID}.String(), id.String())
	}
	if want.ComputeDriver == DriverDocker {
		// A gateway lists only its own namespace's sandboxes: one made in
		// another is lost to the rendered gateway, with its unpulled work,
		// and one in the shared default namespace removes the supervisors
		// of other accounts' sandboxes each time it starts.
		have := s.DockerNamespace
		if have == "" {
			have = DefaultDockerNamespace
		}
		add("Docker sandbox namespace", want.dockerNamespace(), have)
	}
	add("OpenShell telemetry", strconv.FormatBool(want.TelemetryEnabled), strconv.FormatBool(s.TelemetryEnabled()))
	return drift
}

// lstatNoError is os.Lstat that reports a missing path as nil, nil.
func lstatNoError(p string) (fs.FileInfo, error) {
	info, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return info, err
}

// readRenderedFile reads one of the rendered files: a regular file, never a
// link, owned by root and writable by no one else, in a directory that is
// too. A missing file is nil data and no error.
func readRenderedFile(p string) ([]byte, fs.FileInfo, error) {
	info, err := lstatNoError(p)
	if err != nil {
		return nil, nil, fmt.Errorf("openshell: %s: %w", p, err)
	}
	if info == nil {
		return nil, nil, nil
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("openshell: %s is not a regular file", p)
	}
	if !renderedOwnerOK(info) {
		return nil, nil, fmt.Errorf("openshell: %s is not a root-owned file that only root can write, so it is not the administrator's rendered configuration", p)
	}
	if dir, derr := lstatNoError(filepath.Dir(p)); derr != nil || dir == nil || !renderedOwnerOK(dir) {
		return nil, nil, fmt.Errorf("openshell: %s is in a directory that is not root-owned and closed to other writers", filepath.Dir(p))
	}
	data, err := readSmallFile(p, maxGatewayFileBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("openshell: read %s: %w", p, err)
	}
	return data, info, nil
}
