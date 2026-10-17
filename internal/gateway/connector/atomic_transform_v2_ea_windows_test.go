// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

func eaPayloadForTest(name, value string) []byte {
	data := make([]byte, 8+len(name)+1+len(value))
	data[5] = byte(len(name))
	binary.LittleEndian.PutUint16(data[6:], uint16(len(value)))
	copy(data[8:], name)
	copy(data[8+len(name)+1:], value)
	return data
}

func TestAtomicTransformV2EAReaderRefusesNativeReadAndAbortFailures(t *testing.T) {
	readFailure, abortFailure := errors.New("fixture read failure"), errors.New("fixture abort failure")
	reads, aborts := 0, 0
	reader := &atomicTransformV2BackupReader{call: func(_ *os.File, buffer []byte, abort bool, context *uintptr) (uint32, bool, error) {
		if abort {
			aborts++
			return 0, false, abortFailure
		}
		reads++
		*context = 1
		copy(buffer, "data")
		return uint32(len(buffer)), false, readFailure
	}}
	if n, err := io.ReadFull(reader, make([]byte, 4)); n != 0 || !errors.Is(err, readFailure) {
		t.Fatal("full-count failed native read was trusted")
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, readFailure) || reads != 1 {
		t.Fatal("native read failure was not latched")
	}
	if err := reader.Close(); !errors.Is(err, readFailure) || !errors.Is(err, abortFailure) {
		t.Fatal("failure evidence was dropped")
	}
	_ = reader.Close()
	if aborts != 1 {
		t.Fatal("ambiguous abort was retried")
	}

	payload := eaPayloadForTest("FIXTURE", "ordinary metadata")
	encoded := bytes.NewReader(eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 2, Size: int64(len(payload))}, payload))
	reader = &atomicTransformV2BackupReader{call: func(_ *os.File, buffer []byte, abort bool, context *uintptr) (uint32, bool, error) {
		if abort {
			return 0, false, abortFailure
		}
		*context = 1
		n, _ := encoded.Read(buffer)
		return uint32(n), true, nil
	}}
	raw, preserved, classification, err := atomicTransformV2WindowsObserveEAFromReader(reader)
	if !errors.Is(err, abortFailure) || raw != nil || preserved != nil || classification != atomicTransformEAUnknown {
		t.Fatal("failed native reader cleanup returned trusted metadata")
	}
}

func eaBackupForTest(header atomicTransformV2BackupStreamHeader, body []byte) []byte {
	var buffer bytes.Buffer
	_ = binary.Write(&buffer, binary.LittleEndian, header)
	buffer.Write(body)
	return buffer.Bytes()
}

func eaChainForTest(entries ...[]byte) []byte {
	var chain []byte
	for index, raw := range entries {
		entry := append([]byte(nil), raw...)
		if index == len(entries)-1 {
			binary.LittleEndian.PutUint32(entry, 0)
			chain = append(chain, entry...)
			continue
		}
		aligned := (len(entry) + 3) &^ 3
		binary.LittleEndian.PutUint32(entry, uint32(aligned))
		chain = append(chain, entry...)
		chain = append(chain, make([]byte, aligned-len(entry))...)
	}
	return chain
}

func TestAtomicTransformV2CanonicalPreservedEAAccountsOnlyKernelPurgeCache(t *testing.T) {
	first := eaPayloadForTest("OWNED_First", "first exact value")
	first[4] = 0x80
	last := eaPayloadForTest("owned_last", "last exact value")
	cache := eaPayloadForTest("$KeRnEl.PuRgE.SEC.FILEHASH", "opaque OS cache")
	input := eaChainForTest(first, cache, last)
	want := eaChainForTest(first, last)
	canonical, err := atomicTransformV2CanonicalPreservedEA(input)
	if err != nil || !bytes.Equal(canonical, want) {
		t.Fatalf("mixed ordinary/cache EA canonicalization changed user metadata: %v", err)
	}
	// The exact raw payload remains available for full race witnessing; this
	// helper must never edit the caller's source bytes in place.
	if !bytes.Equal(input, eaChainForTest(first, cache, last)) {
		t.Fatal("canonicalization changed raw EA source")
	}
	cacheOnly, err := atomicTransformV2CanonicalPreservedEA(cache)
	if err != nil || len(cacheOnly) != 0 {
		t.Fatal("documented kernel purge cache was not treated as volatile")
	}
	for _, name := range []string{"$Kernel.Purge", "$Kernel.PurgeX.SEC.FILEHASH", "$Kernel.Persistent", "$Kernel.SEC.FILEHASH"} {
		if _, err := atomicTransformV2CanonicalPreservedEA(eaPayloadForTest(name, "value")); err == nil {
			t.Fatalf("unknown or near-prefix kernel namespace accepted: %q", name)
		}
	}
	for _, name := range []string{"$KernelX.Purge.SEC.FILEHASH", "ordinary$Kernel.Purge.SEC.FILEHASH", "$kernelpurge.value"} {
		data := eaPayloadForTest(name, "ordinary exact value")
		got, err := atomicTransformV2CanonicalPreservedEA(data)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("ordinary near-prefix EA was not preserved: %q, %v", name, err)
		}
	}
	for _, name := range []string{"$Kernel.Purge.SEC.FILEHASH", "$KERNEL.РURGE.SEC.FILEHASH", "$Kernel.Purge.\xff", "owned\x00name"} {
		if _, err := atomicTransformV2CanonicalPreservedEA(eaPayloadForTest(name, "value")); err == nil {
			t.Fatal("ambiguous EA name encoding accepted")
		}
	}
}

func TestAtomicTransformV2BoundedEAStreamRejectsAmbiguity(t *testing.T) {
	payload := eaPayloadForTest("DEFENSECLAW_TEST", "owned ordinary EA value")
	valid := eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 2, Size: int64(len(payload))}, payload)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"duplicate", append(append([]byte(nil), valid...), valid...)},
		{"attributes", eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 2, Attributes: 1, Size: int64(len(payload))}, payload)},
		{"named", eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 2, NameBytes: 2, Size: int64(len(payload))}, append([]byte{1, 0}, payload...))},
		{"negative", eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 2, Size: -1}, nil)},
		{"too_large", eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 2, Size: atomicTransformV2MaxEABytes + 1}, nil)},
		{"truncated", valid[:len(valid)-1]},
		{"partial_header", []byte{2}},
		{"bad_entry", eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 2, Size: 8}, make([]byte, 8))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := atomicTransformV2ReadEAStream(bytes.NewReader(tc.data)); err == nil {
				t.Fatal("malformed EA stream accepted")
			}
		})
	}
	// The source may contain other metadata streams, but only the EA bytes are
	// returned to the writer. In particular, a link/security/main stream is not
	// replayed onto Stage.
	prefix := eaBackupForTest(atomicTransformV2BackupStreamHeader{ID: 5, Size: 4}, []byte("link"))
	got, stream, err := atomicTransformV2ReadEAStream(bytes.NewReader(append(prefix, valid...)))
	if err != nil || stream == nil || stream.ID != 2 || stream.Size != int64(len(payload)) || !bytes.Equal(got, payload) {
		t.Fatalf("bounded EA extraction failed: %v", err)
	}
}

func TestAtomicTransformV2EAPayloadRejectsMalformedEntryChains(t *testing.T) {
	valid := eaPayloadForTest("DEFENSECLAW_TEST", "value")
	if err := atomicTransformV2ValidateEAPayload(valid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unknown_flags", "zero_name", "embedded_null", "missing_terminator", "trailing", "offset_inside", "offset_outside", "unaligned"} {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			switch name {
			case "unknown_flags":
				data[4] = 1
			case "zero_name":
				data[5] = 0
			case "embedded_null":
				data[8] = 0
			case "missing_terminator":
				data[8+int(data[5])] = 1
			case "trailing":
				data = append(data, 0)
			case "offset_inside":
				binary.LittleEndian.PutUint32(data, 4)
			case "offset_outside":
				binary.LittleEndian.PutUint32(data, uint32(len(data)+100))
			case "unaligned":
				binary.LittleEndian.PutUint32(data, uint32(len(data)))
			}
			if err := atomicTransformV2ValidateEAPayload(data); err == nil {
				t.Fatal("malformed EA entry accepted")
			}
		})
	}
	first := eaPayloadForTest("SAME", "one")
	offset := (len(first) + 3) &^ 3
	data := make([]byte, offset)
	copy(data, first)
	binary.LittleEndian.PutUint32(data, uint32(offset))
	data = append(data, eaPayloadForTest("same", "two")...)
	if err := atomicTransformV2ValidateEAPayload(data); err == nil {
		t.Fatal("case-colliding EA entries accepted")
	}
}
