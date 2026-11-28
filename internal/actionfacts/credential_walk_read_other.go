//go:build !linux

package actionfacts

import "os"

// credentialPathWalkBatch is the entries of one ReadDir of a folder: a huge
// folder is read in pieces of it.
const credentialPathWalkBatch = 512

// readCredentialWalkFolder calls each with the entries of dir in
// os.File.ReadDir order until each returns false; name is valid only during
// the call, and regular is a regular file the entry itself is (not a link to
// one). A folder that cannot be opened or read on ends the read. Linux
// decodes the entries itself (credential_walk_read_linux.go,
// substrate-1:GAP-0709). dirfd is -1: there is no descriptor to check.
func readCredentialWalkFolder(dir string, each func(name []byte, folder, regular bool, dirfd int) bool) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	for {
		batch, err := f.ReadDir(credentialPathWalkBatch)
		for _, entry := range batch {
			if !each([]byte(entry.Name()), entry.IsDir(), entry.Type().IsRegular(), -1) {
				return
			}
		}
		if err != nil || len(batch) < credentialPathWalkBatch {
			return // the end of the folder, or a folder that cannot be read on
		}
	}
}

// credentialWalkSearchable: without a descriptor the first file of a folder
// is looked up by its path instead (scan).
func credentialWalkSearchable(int) bool { return false }
