// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
)

// runWindowsSecretRecoveryProtocol makes the detached helper passive until
// the parent has observed a live gateway and is about to stop it. The parent
// holds both change locks until it has written CANCEL on success. An armed
// helper sees EOF instead only when the parent died or a restart failed.
func runWindowsSecretRecoveryProtocol(input io.Reader, ready io.Writer, lock func() (func(), error), start func() error) error {
	if _, err := io.WriteString(ready, "READY\n"); err != nil {
		return err
	}
	arm := make([]byte, len("ARM\n"))
	n, err := io.ReadFull(input, arm)
	if errors.Is(err, io.EOF) && n == 0 {
		return nil // Refusal or no-op: no restart was attempted.
	}
	if err != nil || string(arm) != "ARM\n" {
		return fmt.Errorf("invalid gateway restart recovery arm: %w", errors.Join(err, errors.New("unexpected marker")))
	}
	release, err := lock()
	if err != nil {
		return err
	}
	defer release()
	cancel := make([]byte, len("CANCEL\n"))
	if _, err := io.ReadFull(input, cancel); err == nil && string(cancel) == "CANCEL\n" {
		return nil
	}
	return start()
}
