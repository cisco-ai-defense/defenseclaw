// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestR107CopyOfAnExtractionDirectoryKeepsItsScope: a recursive or archive
// copy (cp -a, -r, -a -t, rsync -a) of an extraction directory copies the
// links the archive may make, so a later write under the copy gets the
// verdict of the write into the extraction scope itself, per user and
// managed (rel-1-0-6:GAP-0283). The copy alone, a read of the copy and an
// unrelated copy after an extraction stay allowed.
func TestR107CopyOfAnExtractionDirectoryKeepsItsScope(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"write into the extraction scope", "project", `tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "block"},
		{"cp -a of the extraction directory, write the copy", "project", `tar -xf keys.tar -C d0 && cp -a d0 e0 && echo k >> e0/k`, "block"},
		{"cp -a -t of the extraction directory, write the copy", "project", `tar -xf keys.tar -C d0 && cp -a -t e1 d0 && echo k >> e1/d0/k`, "block"},
		{"cp -r of the extraction directory, write the copy", "project", `tar -xf keys.tar -C d0 && cp -r d0 e3 && echo k >> e3/k`, "block"},
		{"rsync -a of the extraction directory, write the copy", "project", `tar -xf keys.tar -C d0 && rsync -a d0/ e2/ && echo k >> e2/k`, "block"},
		{"copy of the copy, write it", "project", `tar -xf keys.tar -C d0 && cp -a d0 e0 && cp -a e0 f0 && echo k >> f0/k`, "block"},
		{"cp -a of the extraction directory alone", "project", `tar -xf keys.tar -C d0 && cp -a d0 e0`, "allow"},
		{"cp -a of the extraction directory, read the copy", "project", `tar -xf keys.tar -C d0 && cp -a d0 e0 && cat e0/k`, "allow"},
		{"unrelated copy after an extraction, plain write", "project", `tar -xzf pkg.tgz -C build && cp -a ordinary dist && echo hi > report.txt`, "allow"},
	})
}
