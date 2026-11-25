//go:build linux

package actionfacts

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// credentialWalkReadBuffer is the getdents64 buffer of one folder read, the
// size os.File.ReadDir reads with: a huge folder is read in pieces of it.
const credentialWalkReadBuffer = 8192

// credentialWalkBuffers are the read buffers of the walk's workers.
var credentialWalkBuffers = sync.Pool{New: func() any {
	buf := make([]byte, credentialWalkReadBuffer)
	return &buf
}}

// linux_dirent64: d_ino (8 bytes), d_off (8), d_reclen (2), d_type (1),
// then d_name, NUL-terminated within d_reclen.
const (
	direntReclenAt = 16
	direntTypeAt   = 18
	direntNameAt   = 19
)

// readCredentialWalkFolder calls each with the entries of dir in the order
// and with the types os.File.ReadDir gives them (getdents64 order, "." and
// ".." and entries with no inode left out, a symbolic link not a folder, an
// unknown type read with lstat and an entry gone meanwhile skipped), until
// each returns false; regular is a regular file the entry itself is (not a
// link to one). name is valid only during the call. It decodes the
// entries in a pooled buffer and opens the folder without the runtime
// poller: no DirEntry per entry, which made a walk at the bound allocate
// about 8 MB and slowed every hook call that walks (substrate-1:GAP-0709).
// A folder that cannot be opened or read on ends the read, as an error of
// ReadDir does. dirfd is the folder's descriptor, for credentialWalkSearchable.
func readCredentialWalkFolder(dir string, each func(name []byte, folder, regular bool, dirfd int) bool) {
	fd, err := credentialWalkOpen(dir)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(fd) }()
	held := credentialWalkBuffers.Get().(*[]byte)
	defer credentialWalkBuffers.Put(held)
	buf := *held
	for {
		n, err := unix.Getdents(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n <= 0 {
			return
		}
		for off := 0; off < n; {
			entry := buf[off:n]
			if len(entry) < direntNameAt {
				return
			}
			reclen := int(binary.NativeEndian.Uint16(entry[direntReclenAt:]))
			if reclen < direntNameAt || reclen > len(entry) {
				return
			}
			off += reclen
			if binary.NativeEndian.Uint64(entry) == 0 {
				continue
			}
			name := entry[direntNameAt:reclen]
			if end := bytes.IndexByte(name, 0); end >= 0 {
				name = name[:end]
			}
			if len(name) == 0 || name[0] == '.' && (len(name) == 1 || len(name) == 2 && name[1] == '.') {
				continue
			}
			folder := entry[direntTypeAt] == unix.DT_DIR
			regular := entry[direntTypeAt] == unix.DT_REG
			if entry[direntTypeAt] == unix.DT_UNKNOWN {
				var st unix.Stat_t
				err := credentialWalkLstat(fd, string(name), &st)
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				if err != nil {
					return
				}
				folder = st.Mode&unix.S_IFMT == unix.S_IFDIR
				regular = st.Mode&unix.S_IFMT == unix.S_IFREG
			}
			if !each(name, folder, regular, fd) {
				return
			}
		}
	}
}

// credentialWalkSearchable reports a folder, open as dirfd, whose files can
// be looked up (its search permission): a relative check on the descriptor,
// no lookup of a path (substrate-1:GAP-0674, RV-T6C P4-1).
func credentialWalkSearchable(dirfd int) bool {
	for {
		_, _, errno := unix.Syscall(unix.SYS_FACCESSAT, uintptr(dirfd), uintptr(unsafe.Pointer(&credentialWalkDot[0])), unix.X_OK)
		if errno != unix.EINTR {
			return errno == 0
		}
	}
}

// credentialWalkDot is ".", NUL-terminated, for credentialWalkSearchable: a
// check that converts no string.
var credentialWalkDot = [2]byte{'.', 0}

func credentialWalkOpen(dir string) (int, error) {
	for {
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		if !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
}

func credentialWalkLstat(fd int, name string, st *unix.Stat_t) error {
	for {
		err := unix.Fstatat(fd, name, st, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
