// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"io"
	"os"
)

// rollbackNoteOutput is where a rollback reports a file it put back, kept or
// found deleted.
var rollbackNoteOutput io.Writer = os.Stderr

// restoreUneditedForRollback is the first step of a rollback conversion of an
// agent file (hook entries rewritten into the form an earlier release owns).
// A file that still holds exactly the bytes DefenseClaw last committed was not
// edited since setup, so its saved pre-setup bytes go back with one
// compare-and-swap replace, and no conversion is needed: the earlier release
// finds nothing of DefenseClaw in it, and the bytes are the ones the operator
// had. keepCopy, when set, saves the current bytes first.
//
// The replace commits only while the file is still the bytes it read. A save
// that lands in between is the operator own: it is kept as saved and the file
// continues to the conversion, which edits only the DefenseClaw entries. A file
// the operator deleted is left deleted. Any other file (no record, a drifted
// record, other bytes) is not touched here, and the conversion runs as before.
// It reports true when the file needs no conversion.
func restoreUneditedForRollback(dataDir, connectorName, path string, keepCopy func(current []byte) error) (bool, error) {
	rec, ok := managedFileBackupFor(dataDir, connectorName, path)
	if !ok || !rec.Existed || rec.PostSHA256 == "" || rec.PostSHA256 == managedBackupDriftedHash ||
		!managedBackupDigestMatches(rec) {
		return false, nil
	}
	offered, restored := false, false
	left := ""
	err := atomicTransformFileWithStateDir(path, dataDir, 0o600,
		func(current []byte, exists bool) (atomicTransformResult, error) {
			restored = false
			switch {
			case !exists:
				if offered {
					left = "deleted"
				}
				return atomicTransformResult{Keep: true}, nil
			case sha256Hex(current) != rec.PostSHA256:
				if offered {
					left = "saved"
				}
				return atomicTransformResult{Keep: true}, nil
			}
			if keepCopy != nil {
				if err := keepCopy(current); err != nil {
					return atomicTransformResult{}, err
				}
			}
			offered, restored, left = true, true, ""
			return atomicTransformResult{Data: rec.PristineBytes}, nil
		})
	if err != nil {
		return false, err
	}
	switch {
	case restored:
		if err := os.Remove(managedFileBackupPath(dataDir, rec.Connector, rec.LogicalName)); err != nil && !os.IsNotExist(err) {
			return true, err
		}
		fmt.Fprintf(rollbackNoteOutput, "  %s: not edited since setup; put back the bytes it held before DefenseClaw\n", path)
		return true, nil
	case left == "saved":
		fmt.Fprintf(rollbackNoteOutput, "  WARNING %s: saved while DefenseClaw was rolling it back; kept as saved, only the DefenseClaw entries are rewritten\n", path)
	case left == "deleted":
		fmt.Fprintf(rollbackNoteOutput, "  %s: deleted while DefenseClaw was rolling it back; left deleted\n", path)
		return true, nil
	}
	return false, nil
}
