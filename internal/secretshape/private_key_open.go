// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package secretshape

import "strings"

// OpenPrivateKeyPEMStart is the offset of the last private-key PEM header in
// text whose footer has not arrived yet, or -1. A header line that is still
// being written ("-----BEGIN RSA PRI") counts as open too. A stream that
// releases text as it is checked holds everything from this offset on, so a
// key is never sent in part before ValidPrivateKeyPEMAt can see all of it.
// A block longer than the PEM bound no longer counts as open.
func OpenPrivateKeyPEMStart(text string) int {
	start := strings.LastIndex(text, "-----BEGIN ")
	if start < 0 || len(text)-start > maxPrivateKeyPEMBytes {
		return -1
	}
	headerEnd, _, ok := privateKeyLineEnd(text, start)
	if !ok {
		if len(text)-start <= 80 && !strings.ContainsAny(text[start:], "\r\n") {
			return start // the header line is not complete yet
		}
		return -1
	}
	header := text[start:headerEnd]
	if !strings.HasSuffix(header, "-----") {
		return -1
	}
	label := strings.TrimSuffix(strings.TrimPrefix(header, "-----BEGIN "), "-----")
	if !allowedPrivateKeyLabel(label) {
		return -1
	}
	if strings.Contains(text[headerEnd:], "-----END "+label+"-----") {
		return -1
	}
	return start
}

// PrivateKeyHeaderLabel is the label of a complete private-key PEM header
// line ("-----BEGIN RSA PRIVATE KEY-----" gives "RSA PRIVATE KEY"), and false
// for any other line. The line is given without its line separator.
func PrivateKeyHeaderLabel(line string) (string, bool) {
	if !strings.HasPrefix(line, "-----BEGIN ") || !strings.HasSuffix(line, "-----") || len(line) > 80 {
		return "", false
	}
	label := strings.TrimSuffix(strings.TrimPrefix(line, "-----BEGIN "), "-----")
	if !allowedPrivateKeyLabel(label) {
		return "", false
	}
	return label, true
}
