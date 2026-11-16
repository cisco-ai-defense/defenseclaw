// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "runtime"

// ArchiveRecoveryHint says how to read an audit store that was moved aside
// without changing it. SQLite can change the files it opens, so the operator
// copies the whole set first and works on the copy. A store whose first 16
// bytes were zeroed opens only after the header is written back, and that
// repair is made on the copy, never on the archive (rel-1-0-2:GAP-0647; the
// upgrade guide says the same). Start, status and doctor
// (cli/defenseclaw/commands/cmd_doctor.py) print it. It ends with the repair
// command, so callers print nothing after it on the same line.
func ArchiveRecoveryHint(archive string) string {
	return archiveRecoveryHintFor(runtime.GOOS, archive)
}

func archiveRecoveryHintFor(goos, archive string) string {
	repair := `printf 'SQLite format 3\000' | dd of=<copy> bs=16 count=1 conv=notrunc`
	if goos == "windows" {
		repair = "PowerShell: $f=[IO.File]::OpenWrite('<copy>'); $f.Write([Text.Encoding]::ASCII.GetBytes(\"SQLite format 3`0\"),0,16); $f.Close()"
	}
	return "To read its audit records, first copy " + archive + " together with its -wal, -shm and any -journal files " +
		"to a new folder and work only on the copy, because SQLite can change the files it opens. " +
		"Then run sqlite3 <copy> .recover on the copy. If SQLite says the copy is not a database, its first 16 bytes " +
		"were zeroed: write the SQLite header back on the copy, never on the archive, and run .recover again. " +
		"To write it, run: " + repair
}
