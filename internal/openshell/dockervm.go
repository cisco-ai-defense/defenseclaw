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
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TroubleshootingURL is the sandbox guide's troubleshooting section.
const TroubleshootingURL = "https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/#troubleshooting"

// ErrNoProbeImage means no image the Docker VM's kernel can be checked in
// is on this machine. Doctor never pulls one itself.
var ErrNoProbeImage = errors.New("openshell: no local image to check the Docker VM's kernel in")

// Linux errno values the probe reports (the same on amd64 and arm64).
const (
	linuxENOSYS     = 38
	linuxEOPNOTSUPP = 95
)

// vmLandlockScript runs in the probe container. It asks the kernel for
// its Landlock ABI with landlock_create_ruleset(NULL, 0,
// LANDLOCK_CREATE_RULESET_VERSION), syscall 444 on amd64 and arm64, which
// needs no privilege, and prints the kernel release and the ABI or the
// errno.
const vmLandlockScript = `import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
abi = libc.syscall(ctypes.c_long(444), ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(1))
print("kernel", os.uname().release)
if abi >= 0:
    print("landlock", abi)
else:
    e = ctypes.get_errno()
    print("errno", e, errno.errorcode.get(e, "?"))
`

// dockerVMLandlock asks the kernel Docker runs containers on (on macOS,
// the one of Docker Desktop's Linux VM, not this host's) for its Landlock
// ABI. The probe is a short container without network, capabilities or a
// writable root, in the first of images already on this machine: it is
// never pulled. The base image, and every overlay image built on it,
// ships /usr/bin/python3.
func dockerVMLandlock(ctx context.Context, run Runner, images []string) (abi int, kernel string, err error) {
	image := ""
	for _, img := range images {
		if img == "" {
			continue
		}
		if _, err := run.Output(ctx, Command{Name: "docker", Args: []string{"image", "inspect", "--format", "{{.Id}}", img}, Timeout: 30 * time.Second}); err == nil {
			image = img
			break
		}
	}
	if image == "" {
		return 0, "", ErrNoProbeImage
	}
	out, err := run.Output(ctx, Command{Name: "docker", Args: []string{"run", "--rm", "--pull", "never", "--network", "none",
		"--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--entrypoint", "/usr/bin/python3", image, "-I", "-S", "-c", vmLandlockScript}, Timeout: 2 * time.Minute})
	if err != nil {
		return 0, "", fmt.Errorf("the probe container failed: %v: %s", err, lastLine(out))
	}
	var answer []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 2 && fields[0] == "kernel":
			kernel = fields[1]
		case len(fields) >= 2 && (fields[0] == "landlock" || fields[0] == "errno"):
			answer = fields
		}
	}
	if len(answer) == 0 {
		return 0, kernel, fmt.Errorf("unexpected probe output %q", lastLine(out))
	}
	n, perr := strconv.Atoi(answer[1])
	switch {
	case perr != nil:
		return 0, kernel, fmt.Errorf("unexpected probe output %q", strings.Join(answer, " "))
	case answer[0] == "landlock":
		return n, kernel, nil
	case n == linuxENOSYS:
		return 0, kernel, ErrLandlockMissing
	case n == linuxEOPNOTSUPP:
		return 0, kernel, ErrLandlockDisabled
	}
	// EPERM, for one, is a seccomp profile that refuses the call: that
	// says nothing about the kernel.
	return 0, kernel, fmt.Errorf("landlock_create_ruleset failed with errno %s", strings.Join(answer[1:], " "))
}

// DockerEngineOS is the operating system `docker info` reports for the
// engine the docker CLI talks to: "Docker Desktop" on Docker Desktop, the
// VM's distribution under Colima. It is one short call, with none of the
// Landlock probe's container.
func DockerEngineOS(ctx context.Context, run Runner) (string, error) {
	out, err := run.Output(ctx, Command{Name: "docker", Args: []string{"info", "--format", "{{.OperatingSystem}}"}, Timeout: 15 * time.Second})
	if err != nil {
		return "", fmt.Errorf("docker info: %v: %s", err, lastLine(out))
	}
	return strings.TrimSpace(string(out)), nil
}

// IsDockerDesktop reports an engine operating system (DockerEngineOS, or
// docker info's OperatingSystem) of Docker Desktop, whose Linux VM kernel
// (linuxkit) is built without Landlock.
func IsDockerDesktop(engineOS string) bool { return strings.Contains(engineOS, "Docker Desktop") }

// lastLine is the last non-empty line of a command's output.
func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// dockerVMLandlockCheck checks Landlock where the docker driver runs
// sandboxes off Linux: in the kernel of the Linux VM Docker runs
// containers in, once Docker answers.
func (r *doctorRun) dockerVMLandlockCheck(ctx context.Context) Check {
	c := Check{ID: CheckIDLandlock, Title: "Landlock"}
	if !r.docker {
		c.Status, c.Detail = StatusSkip, "the Docker daemon is not available"
		return c
	}
	vm := "the Linux VM Docker runs in"
	unsupported := &Fix{Summary: fmt.Sprintf("run sandboxes in OpenShell MicroVMs, which have their own kernel (`defenseclaw sandbox setup` switches the gateway to them), "+
		"or run Docker in a Linux VM whose kernel enables Landlock ABI %d or newer", MinLandlockABI), Command: TroubleshootingURL}
	if r.desktop {
		vm = "Docker Desktop's Linux VM"
		unsupported = &Fix{Summary: "macOS sandboxes cannot run on Docker Desktop's kernel: run them in OpenShell MicroVMs, which have their own " +
			"(`defenseclaw sandbox setup` switches the gateway to them; details in the sandbox guide)", Command: TroubleshootingURL}
	}
	abi, kernel, err := r.DockerVMLandlockABI(ctx)
	named := vm
	if kernel != "" {
		named += " (kernel " + kernel + ")"
	}
	switch {
	case errors.Is(err, ErrNoProbeImage):
		c.Status = StatusWarn
		c.Detail = "not checked: sandboxes run on the kernel of " + vm + ", which DefenseClaw checks in the OpenShell base image, and that image is not on this machine yet"
		c.Fix = &Fix{Summary: "download the OpenShell base image (about 4 GB; the harness images are built on it), then check again",
			Command: "docker pull " + DefaultBaseImage, Automatic: true, Apply: r.pullBaseImage}
	case errors.Is(err, ErrLandlockMissing):
		c.Status, c.Detail, c.Fix = StatusFail, named+" has no Landlock, and OpenShell sandboxes need it", unsupported
	case errors.Is(err, ErrLandlockDisabled):
		c.Status, c.Detail, c.Fix = StatusFail, named+" has Landlock turned off, and OpenShell sandboxes need it", unsupported
	case err != nil:
		c.Status, c.Detail = StatusWarn, "could not check "+named+": "+err.Error()
	case abi < MinLandlockABI:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%s has Landlock ABI %d; OpenShell needs ABI %d or newer", named, abi, MinLandlockABI)
		c.Fix = unsupported
	default:
		c.Status, c.Detail = StatusPass, fmt.Sprintf("ABI %d in %s", abi, vm)
	}
	return c
}

// pullBaseImage downloads the pinned OpenShell base image, so that the
// Docker VM's kernel can be checked in it.
func (r *doctorRun) pullBaseImage(ctx context.Context) error {
	if out, err := r.Runner.Output(ctx, Command{Name: "docker", Args: []string{"pull", DefaultBaseImage}, Timeout: 30 * time.Minute}); err != nil {
		return fmt.Errorf("docker pull %s: %v: %s", DefaultBaseImage, err, lastLine(out))
	}
	return nil
}
