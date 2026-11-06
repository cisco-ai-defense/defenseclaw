// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Reviewer probe round 3: decoder memory and time bounds.
package hookpaths

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func rv4Tar(t *testing.T, bigBytes int64, link bool) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if link {
		tw.WriteHeader(&tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: "../../.ssh/authorized_keys", Mode: 0o777})
	}
	tw.WriteHeader(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644, Size: bigBytes})
	tw.Write(make([]byte, bigBytes))
	tw.Close()
	return buf.Bytes()
}

func rv4Measure(t *testing.T, label, path string) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	kind := tarArchiveKind(path)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	home := filepath.Dir(filepath.Dir(path))
	start2 := time.Now()
	members := tarProtectedLinkMembers(path, filepath.Join(filepath.Dir(path), "d1"), home)
	t.Logf("BOUND|%s|kind=%d|%dms|totalalloc=%dMB|sysdelta=%dMB|members=%d|%dms", label, kind, elapsed.Milliseconds(),
		(after.TotalAlloc-before.TotalAlloc)>>20, (after.Sys-before.Sys)>>20, len(members), time.Since(start2).Milliseconds())
	if label == "xz-dict-00" && kind != 2 {
		t.Errorf("ordinary xz archive kind=%d, want link evidence", kind)
	}
	if (strings.HasPrefix(label, "xz-dict-") && label != "xz-dict-00" || label == "zstd-bomb-200M") &&
		after.TotalAlloc-before.TotalAlloc > 80<<20 {
		t.Errorf("%s allocated %d bytes while reading", label, after.TotalAlloc-before.TotalAlloc)
	}
}

// A small header can request a large dictionary before any tar member is
// decoded. Keep that allocation below the archive reader's fixed budget.
func TestGX054XZDictionaryBound(t *testing.T) {
	var buf bytes.Buffer
	w, err := (xz.WriterConfig{DictCap: 1 << 20}).NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(rv4Tar(t, 10, false)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	plainStream := append([]byte(nil), b...)
	hs := int(b[12]+1) * 4
	patched := false
	for i := 14; i+2 < 12+hs-4; i++ {
		if b[i] == 0x21 && b[i+1] == 0x01 {
			b[i+2] = 29
			patched = true
			break
		}
	}
	if !patched {
		t.Fatal("xz dictionary property absent")
	}
	binary.LittleEndian.PutUint32(b[12+hs-4:], crc32.ChecksumIEEE(b[12:12+hs-4]))
	path := filepath.Join(t.TempDir(), "header.txz")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if got := tarArchiveKind(path); got != 0 {
		t.Errorf("kind=%d, want unreadable", got)
	}
	runtime.ReadMemStats(&after)
	if used := after.TotalAlloc - before.TotalAlloc; used > 80<<20 {
		t.Errorf("xz header allocated %d bytes", used)
	}
	if err := os.WriteFile(path, append(plainStream, b...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := tarArchiveKind(path); got != 0 {
		t.Errorf("later xz stream kind=%d, want unreadable", got)
	}
}

func TestRV4DecoderBounds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home", "project")
	os.MkdirAll(dir, 0o700)
	// xz: real stream, then the block header dictionary byte raised (CRC fixed)
	for _, dict := range []byte{0, 30, 36, 37, 40} {
		var buf bytes.Buffer
		w, err := xz.WriterConfig{DictCap: 1 << 20}.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(rv4Tar(t, 10, true))
		w.Close()
		b := buf.Bytes()
		if dict != 0 {
			hs := int(b[12]+1) * 4
			patched := false
			for i := 14; i+2 < 12+hs-4; i++ {
				if b[i] == 0x21 && b[i+1] == 0x01 {
					b[i+2] = dict
					patched = true
					break
				}
			}
			binary.LittleEndian.PutUint32(b[12+hs-4:], crc32.ChecksumIEEE(b[12:12+hs-4]))
			if !patched {
				t.Logf("BOUND|xz-dict-%d|not patched", dict)
			}
		}
		p := filepath.Join(dir, "x.txz")
		os.WriteFile(p, b, 0o600)
		rv4Measure(t, "xz-dict-"+string('0'+dict/10)+string('0'+dict%10), p)
	}
	// zstd: windows below, at and above the cap; then a decompression bomb
	for _, win := range []int{1 << 20, 64 << 20, 128 << 20} {
		var buf bytes.Buffer
		enc, err := zstd.NewWriter(&buf, zstd.WithWindowSize(win), zstd.WithEncoderConcurrency(1))
		if err != nil {
			t.Fatal(err)
		}
		enc.Write(rv4Tar(t, 10, true))
		enc.Close()
		p := filepath.Join(dir, "x.tzst")
		os.WriteFile(p, buf.Bytes(), 0o600)
		rv4Measure(t, "zstd-win-"+itoa(win>>20)+"M", p)
	}
	for _, size := range []int64{60 << 20, 200 << 20} {
		var buf bytes.Buffer
		enc, _ := zstd.NewWriter(&buf, zstd.WithWindowSize(8<<20), zstd.WithEncoderConcurrency(1))
		enc.Write(rv4Tar(t, size, false))
		enc.Close()
		p := filepath.Join(dir, "bomb.tzst")
		os.WriteFile(p, buf.Bytes(), 0o600)
		t.Logf("BOUND|bomb file %d bytes", buf.Len())
		rv4Measure(t, "zstd-bomb-"+itoa(int(size>>20))+"M", p)
		var xb bytes.Buffer
		xw, _ := xz.WriterConfig{DictCap: 1 << 20}.NewWriter(&xb)
		xw.Write(rv4Tar(t, size, false))
		xw.Close()
		p2 := filepath.Join(dir, "bomb.txz")
		os.WriteFile(p2, xb.Bytes(), 0o600)
		rv4Measure(t, "xz-bomb-"+itoa(int(size>>20))+"M", p2)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
