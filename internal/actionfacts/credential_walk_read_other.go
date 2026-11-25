//go:build !linux

package actionfacts

import "os"

// credentialPathWalkBatch is the entries of one ReadDir of a folder: a huge
// folder is read in pieces of it.
const credentialPathWalkBatch = 512

// readCredentialWalkFolder calls each with the entries of dir in
// os.File.ReadDir order until each returns false; name is valid only during
// the call. A folder that cannot be opened or read on ends the read. Linux
// decodes the entries itself (credential_walk_read_linux.go,
// substrate-1:GAP-0709).
func readCredentialWalkFolder(dir string, each func(name []byte, folder bool) bool) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	for {
		batch, err := f.ReadDir(credentialPathWalkBatch)
		for _, entry := range batch {
			if !each([]byte(entry.Name()), entry.IsDir()) {
				return
			}
		}
		if err != nil || len(batch) < credentialPathWalkBatch {
			return // the end of the folder, or a folder that cannot be read on
		}
	}
}
