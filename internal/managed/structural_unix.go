//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MoveAsideStructural renames a structurally wrong object DefenseClaw owns (a
// symlink, an extra hard link, or the wrong object type) to
// `<name>.defenseclaw-moved-<UTC timestamp>` next to it, so the caller can
// recreate a canonical object in its place. A rename moves the directory
// entry itself: it never follows a symlink and never touches the other links
// of a hard-linked file. The move is logged as a boundary finding with the
// reason. It returns the new name.
//
// Callers use it only on paths DefenseClaw owns. An OS or Secure Client
// ancestor and a user's home are never moved; the caller logs and continues,
// or skips that user.
func MoveAsideStructural(path, reason string) (string, error) {
	clean := filepath.Clean(path)
	moved := fmt.Sprintf("%s.defenseclaw-moved-%s", clean, time.Now().UTC().Format("20060102T150405.000000000Z"))
	fields := map[string]string{"path": clean, "reason": reason, "action": "moved_aside", "moved_to": moved}
	if err := os.Rename(clean, moved); err != nil {
		fields["repair_error"] = err.Error()
		EmitResilienceEvent(MarkerBoundary, fields)
		return "", fmt.Errorf("move aside %s: %w", clean, err)
	}
	EmitResilienceEvent(MarkerBoundary, fields)
	return moved, nil
}
