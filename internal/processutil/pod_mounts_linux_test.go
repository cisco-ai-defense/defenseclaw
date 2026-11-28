// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"errors"
	"strings"
	"testing"
)

// fakePodMounts gives this process the chart container's mount layout
// (GAP-1031): a read-only overlay root and its own mount on each folder.
func fakePodMounts(t testing.TB, folders ...string) {
	t.Helper()
	table := "1 0 0:30 / / ro,relatime - overlay overlay rw\n"
	for i, d := range folders {
		table += "2" + strings.Repeat("0", i) + " 1 259:1 /volumes/kubernetes.io~empty-dir/f " +
			strings.ReplaceAll(d, " ", `\040`) + " rw,relatime - ext4 /dev/root rw\n"
	}
	old := podMountInfo
	podMountInfo = func() ([]byte, error) { return []byte(table), nil }
	t.Cleanup(func() { podMountInfo = old })
}

// podChartMountInfo is the skill-scanner sidecar's mount table under
// containerd: readOnlyRootFilesystem, the skill-scan-tmp emptyDir on /tmp,
// the skill-scan emptyDir (medium Memory) and the pod's /dev/shm.
const podChartMountInfo = `1426 1340 0:312 / / ro,relatime master:450 - overlay overlay rw,lowerdir=/var/lib/containerd/l1,upperdir=/var/lib/containerd/u,workdir=/var/lib/containerd/w
1427 1426 0:315 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1428 1426 0:316 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
1429 1428 0:317 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
1430 1428 0:306 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
1431 1426 0:308 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
1432 1426 0:290 / /run/defenseclaw-scan rw,relatime - tmpfs tmpfs rw,size=65536k
1433 1426 259:1 /var/lib/kubelet/pods/7f0c/volumes/kubernetes.io~empty-dir/skill-scan-tmp /tmp rw,relatime - ext4 /dev/root rw
1434 1426 259:1 /var/lib/kubelet/pods/7f0c/etc-hosts /etc/hosts rw,relatime - ext4 /dev/root rw
1435 1428 0:291 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k
`

func withMountInfo(t *testing.T, table string, err error) {
	t.Helper()
	old := podMountInfo
	podMountInfo = func() ([]byte, error) { return []byte(table), err }
	t.Cleanup(func() { podMountInfo = old })
}

// The real pod shape still runs: the chart's container passes.
func TestGAP1031PodMountsAcceptTheChartContainer(t *testing.T) {
	withMountInfo(t, podChartMountInfo, nil)
	if err := podMountsCheck("/tmp", []string{"/dev/shm"}); err != nil {
		t.Fatalf("the chart's sidecar container was refused: %v", err)
	}
	// A clear folder the container does not have is skipped, as Reset
	// skips it.
	if err := podMountsCheck("/tmp", []string{"/no/such/dc-gap1031"}); err != nil {
		t.Fatalf("a missing clear folder was refused: %v", err)
	}
}

// GAP-1031: a host, where PID 1 and non-root come from unshare, is refused
// with a reason that names it.
func TestGAP1031PodMountsRefuseHostShapes(t *testing.T) {
	for _, c := range []struct {
		name, table, want string
		err               error
	}{
		{"rhel-root-tmp", "22 1 253:0 / / rw,relatime shared:1 - xfs /dev/mapper/rhel-root rw\n" +
			"23 22 0:21 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw\n",
			"root filesystem is writable", nil},
		{"tmpfs-tmp", "22 1 253:0 / / rw,relatime - ext4 /dev/sda1 rw\n" +
			"30 22 0:40 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n" +
			"23 22 0:21 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n",
			"root filesystem is writable", nil},
		{"read-only-root-no-tmp-mount", "22 1 0:30 / / ro,relatime - composefs composefs ro\n" +
			"23 22 0:21 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n",
			"/tmp is not a mount of its own", nil},
		{"read-only-root-no-shm-mount", "22 1 0:30 / / ro,relatime - overlay overlay rw\n" +
			"30 22 0:40 / /tmp rw - tmpfs tmpfs rw\n" +
			"31 22 0:41 / /dev rw - devtmpfs devtmpfs rw\n",
			"/dev/shm is not a mount of its own", nil},
		{"remounted-rw-root", "22 1 0:30 / / ro,relatime - overlay overlay rw\n" +
			"30 22 0:40 / /tmp rw - tmpfs tmpfs rw\n" +
			"23 22 0:21 / /dev/shm rw - tmpfs tmpfs rw\n" +
			"40 22 253:0 / / rw,relatime - xfs /dev/vda1 rw\n",
			"root filesystem is writable", nil},
		{"no-root", "30 22 0:40 / /tmp rw - tmpfs tmpfs rw\n", "lists no root filesystem", nil},
		{"unreadable", "", "cannot read its mount table", errors.New("permission denied")},
	} {
		t.Run(c.name, func(t *testing.T) {
			withMountInfo(t, c.table, c.err)
			err := podMountsCheck("/tmp", []string{"/dev/shm"})
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "empties no folder") {
				t.Fatalf("podMountsCheck = %v, want a refusal naming %q", err, c.want)
			}
		})
	}
}

func TestGAP1031MountPathEscapes(t *testing.T) {
	m := parseMountInfo([]byte("1 0 0:30 / / ro - overlay overlay rw\n2 1 0:31 / /scan\\040tmp rw - tmpfs tmpfs rw\n"))
	if _, ok := m["/scan tmp"]; !ok || !m["/"].readOnly || m["/scan tmp"].readOnly {
		t.Fatalf("parsed mounts = %#v", m)
	}
	if got := unescapeMountPath(`/a\134b\04`); got != `/a\b\04` {
		t.Fatalf("unescape = %q", got)
	}
}
