// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"testing"
)

// The mount tables of real Substrate v1.0.0 actors (rr2 on E1, a
// claudecode template of this branch): gVisor and microVM.
const (
	gvisorMountinfo = "1 0 0:1 / / rw - 9p none rw\n2 1 0:2 / /dev rw - tmpfs none rw\n3 1 0:3 / /sys ro - sysfs none ro\n" +
		"4 1 0:4 / /tmp rw - tmpfs none rw\n5 1 0:5 / /proc rw - proc none rw\n6 2 0:6 / /dev/pts rw - devpts none rw\n" +
		"7 2 0:7 / /dev/shm rw - tmpfs none rw\n8 1 0:8 / /run/ate ro - tmpfs none ro\n"
	microvmMountinfo = "1 0 0:1 / / rw - overlay none rw\n2 1 0:2 / /proc rw - proc proc rw\n3 1 0:3 / /dev rw - tmpfs tmpfs rw\n" +
		"4 3 0:4 / /dev/pts rw - devpts devpts rw\n5 3 0:5 / /dev/mqueue rw - mqueue mqueue rw\n6 3 0:6 / /dev/shm rw - tmpfs shm rw\n" +
		"7 1 0:7 / /sys ro - sysfs sysfs ro\n8 1 0:8 / /tmp rw - tmpfs tmpfs rw\n9 1 0:9 / /run/ate ro - tmpfs tmpfs ro\n" +
		"10 7 0:10 / /sys/firmware ro - tmpfs tmpfs ro\n11 2 0:2 /acpi /proc/acpi ro - proc proc ro\n12 2 0:2 /interrupts /proc/interrupts ro - proc proc ro\n" +
		"13 2 0:2 /keys /proc/keys ro - proc proc ro\n14 2 0:2 /timer_list /proc/timer_list ro - proc proc ro\n15 2 0:2 /bus /proc/bus ro - proc proc ro\n" +
		"16 2 0:2 /fs /proc/fs ro - proc proc ro\n17 2 0:2 /irq /proc/irq ro - proc proc ro\n18 2 0:2 /sys /proc/sys ro - proc proc ro\n"
)

// GAP-0576 item 6: admission refuses a data mount path in a system folder
// (GAP-0441), but an attested image symlink below WORKDIR into a system
// folder plus a data volume landed there, and the relay allowed it: only
// DefenseClaw's own paths were checked. The relay refuses a resolved mount
// point in a system folder; the runtime's own mounts of real gVisor and
// microVM actors, and data mounts below WORKDIR, are not refused.
func TestGAP0576MountInASystemFolderIsRefused(t *testing.T) {
	cfg, _ := builtConfig(t, "claudecode")
	for name, info := range map[string]string{"gVisor": gvisorMountinfo, "microVM": microvmMountinfo} {
		for _, extra := range []string{"", mountLine("/work"), mountLine("/work/data"), mountLine("/etc/hosts") + mountLine("/etc/resolv.conf") + mountLine("/etc/hostname")} {
			if got := mountRefusal(t, []byte(info+extra), cfg.Relay.Protected, nil); got != "" {
				t.Errorf("%s actor with %q: refused (%s)", name, extra, got)
			}
		}
		for _, extra := range []string{mountLine("/run"), mountLine("/run/user/1000"), mountLine("/boot/efi")} {
			if got := mountRefusal(t, []byte(info+extra), cfg.Relay.Protected, nil); got != "" {
				t.Errorf("%s actor with a host mount %q: refused (%s)", name, extra, got)
			}
		}
		for _, mp := range []string{"/usr/lib/x86_64-linux-gnu", "/etc/ld.so.preload", "/etc/profile.d", "/lib/x86_64-linux-gnu/security", "/lib64", "/usr/bin", "/bin", "/sbin/x"} {
			if got := mountRefusal(t, []byte(info+mountLine(mp)), cfg.Relay.Protected, nil); got != mp {
				t.Errorf("%s actor, a data mount at %s: kitMountRefusal = %q, want it refused", name, mp, got)
			}
		}
	}
}
