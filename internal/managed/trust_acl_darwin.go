//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// darwinACLInspectionTimeout bounds one `/bin/ls -lde` run. An Endpoint
// Security client that stalls the exec, or a hung volume, must not block
// config load, a guardian tick or the audit open indefinitely.
const darwinACLInspectionTimeout = 5 * time.Second

// inspectDarwinACL is replaced in tests.
var inspectDarwinACL = func(ctx context.Context, path string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	return cmd.Output()
}

// readDarwinACL returns the `ls -lde` output for path. A timeout or exec
// failure is transient (a busy Endpoint Security client, a volume waking up),
// so it is retried once before it is reported.
func readDarwinACL(path string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), darwinACLInspectionTimeout)
		output, err := inspectDarwinACL(ctx, path)
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()
		if err == nil {
			return output, nil
		}
		if timedOut {
			lastErr = fmt.Errorf("inspect macOS ACL for %s: timed out after %s", path, darwinACLInspectionTimeout)
		} else {
			lastErr = fmt.Errorf("inspect macOS ACL for %s: %w", path, err)
		}
	}
	return nil, lastErr
}

// validateTrustedPathACL rejects effective macOS ACL entries that grant
// write-like authority to a principal other than root, wheel or admin. macOS
// keeps the mode bits unchanged when an ACL is added, so ignoring the extended
// entries would misclassify an attacker-writable path as administrator-trusted.
// Read, deny and inherit-only entries grant no write on the object itself and
// are not judged.
func validateTrustedPathACL(path string) error {
	output, err := readDarwinACL(path)
	if err != nil {
		return err
	}
	return JudgeDarwinACLOutput(path, output)
}
