// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// podMountInfo reads this process's mount table. Tests replace it to give
// the helper processes the chart's container layout.
var podMountInfo = func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }

// podMountsCheck refuses the pod-contained mode outside the chart's sidecar
// container, before Reset removes anything (GAP-1031). Being PID 1 and not
// root does not prove a container: `unshare -U -p -f --mount-proc` gives
// any user that on a host, where the scratch folder is the host's shared
// /tmp and the clear folders are the host's /dev/shm. The chart's container
// has a read-only root filesystem (readOnlyRootFilesystem) and its own
// volume mounted on each folder Reset empties (the skill-scan-tmp emptyDir
// on /tmp, the pod's /dev/shm). A clear folder that does not exist is
// skipped, as Reset skips it.
func podMountsCheck(scratch string, clear []string) error {
	b, err := podMountInfo()
	if err != nil {
		return fmt.Errorf("cannot read its mount table, so it empties no folder: %v", err)
	}
	mounts := parseMountInfo(b)
	root, ok := mounts["/"]
	if !ok {
		return errors.New("its mount table lists no root filesystem, so it empties no folder")
	}
	if !root.readOnly {
		return errors.New("its root filesystem is writable, so this is not the chart's sidecar container (readOnlyRootFilesystem); it empties no folder outside a pod")
	}
	for i, dir := range append([]string{scratch}, clear...) {
		if _, err := os.Lstat(dir); i > 0 && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if _, ok := mounts[dir]; !ok {
			return fmt.Errorf("%s is not a mount of its own (the chart mounts the container's own volume there); it empties no folder outside a pod", dir)
		}
	}
	return nil
}

// podMount is the topmost mount on one mount point.
type podMount struct {
	readOnly bool
}

// parseMountInfo maps each mount point of a /proc/<pid>/mountinfo table to
// its topmost mount (a later line on the same point covers an earlier one).
func parseMountInfo(b []byte) map[string]podMount {
	mounts := map[string]podMount{}
	for _, line := range bytes.Split(b, []byte("\n")) {
		f := strings.Fields(string(line))
		if len(f) < 6 {
			continue
		}
		ro := false
		for _, o := range strings.Split(f[5], ",") {
			if o == "ro" {
				ro = true
			}
		}
		mounts[unescapeMountPath(f[4])] = podMount{readOnly: ro}
	}
	return mounts
}

// unescapeMountPath undoes the kernel's octal escapes (\040 for a space) in
// a mountinfo path.
func unescapeMountPath(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}
