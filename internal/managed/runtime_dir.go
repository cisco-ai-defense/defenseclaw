package managed

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// PinnedDeploymentMode reports the machine-wide deployment mode pin, for
// callers that distinguish a managed runtime tree without a loaded config.
func PinnedDeploymentMode() string {
	return os.Getenv(DeploymentModeEnv)
}

// PrepareServiceRuntimeDir readies a gateway runtime directory for use.
//
// safefile enforces a private-state contract: the caller must be the sole
// owner. A managed enterprise runtime tree is Administrators-owned with a
// service-SID writer ACE, so managed paths are validated against the managed
// trust model, which accepts that layout.
//
// The managed branch validates the PARENT ancestor chain before calling
// Mkdir so we do not create a child under an untrusted directory even in
// the transient case where mkdir succeeds and the subsequent validation
// then fails. The leaf itself is validated after Mkdir completes.
func PrepareServiceRuntimeDir(deploymentMode, path, label string) error {
	if !IsManagedEnterprise(deploymentMode) {
		return safefile.ProtectDirectory(path)
	}
	serviceAccount := os.Getenv(WindowsServiceAccountEnv)
	// Validate the parent chain first. If the leaf already exists we
	// then run the full validation directly; otherwise we create the
	// leaf and validate again (which now covers both parent + leaf).
	if err := ValidateTrustedServiceRuntimeDir(
		filepath.Dir(path), label+" parent", serviceAccount,
	); err != nil {
		return err
	}
	// Only the leaf is created; a missing ancestor means the installer-provisioned
	// tree is incomplete and must surface.
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return ValidateTrustedServiceRuntimeDir(path, label, serviceAccount)
}

// PrepareServiceRuntimeFile is the regular-file counterpart to
// PrepareServiceRuntimeDir. The file must already exist.
func PrepareServiceRuntimeFile(deploymentMode, path, label string) error {
	if IsManagedEnterprise(deploymentMode) {
		return ValidateTrustedServiceRuntimeFilePath(path, label, os.Getenv(WindowsServiceAccountEnv))
	}
	return safefile.ProtectFile(path)
}

// WriteServiceRuntimeFile atomically publishes a file the gateway owns at
// runtime, such as a generated token or persisted state.
//
// safefile.WritePrivate imposes the private-state contract on the parent
// directory: sole ownership by the writer, and a DACL of that owner plus
// SYSTEM. A managed enterprise runtime directory is Administrators-owned and
// shared with the service through a narrow writer ACE, so managed paths are
// validated against the managed trust model and published in place under the
// installer's inheritable DACL.
func WriteServiceRuntimeFile(deploymentMode, path, label string, data []byte) error {
	if !IsManagedEnterprise(deploymentMode) {
		return safefile.WritePrivate(path, data)
	}
	if label == "" {
		label = "managed runtime file"
	}
	serviceAccount := os.Getenv(WindowsServiceAccountEnv)
	if err := ValidateTrustedServiceRuntimeDir(
		filepath.Dir(path), label+" directory", serviceAccount,
	); err != nil {
		return err
	}
	// A replacement keeps the destination's own descriptor, so an existing file
	// must still be trusted before it is written through.
	if _, err := os.Lstat(path); err == nil {
		if err := ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return publishServiceRuntimeFile(path, data, true)
}

// publishServiceRuntimeFile stages the payload to a temp file in the
// same directory as `path`, then atomically renames it into place via
// safefile.ReplaceFile.
//
// Windows DACL note (T3.4 follow-up): os.CreateTemp inherits the parent
// directory's DACL. The parent has already been validated as trusted
// (ValidateTrustedServiceRuntimeDir: Administrators-owned, no untrusted
// write ACEs, service-SID writer ACE only) both before AND after
// CreateTemp (see the post-CreateTemp re-validation immediately below).
// The inherited DACL is therefore always the trusted managed-runtime
// DACL. A stronger defense-in-depth would be to explicitly PROTECT the
// temp handle's DACL against future parent-DACL mutation mid-write; that
// requires a platform-specific hook and is tracked as a Tier 3 punch-
// list follow-up (T3.4) so the DACL-building code lives with the rest
// of the Windows runtime-tree ACL logic rather than being reinvented
// here.
func publishServiceRuntimeFile(path string, data []byte, revalidateAfterCreateTemp bool) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".defenseclaw-runtime-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	// Re-validate the parent directory after CreateTemp: an attacker
	// with sufficient rights could in principle swap `dir` between the
	// caller's pre-write ValidateTrustedServiceRuntimeDir and the
	// CreateTemp above. Re-running the check on the same path forces
	// any post-swap directory to fail owner/DACL validation and
	// prevents the write from landing in an untrusted tree. The temp
	// file we already opened points at whatever kernel object the swap
	// installed; the deferred os.Remove(name) removes it regardless.
	//
	// Only managed enterprise callers ask for the re-validation — the
	// direct unit-test entry point exercises this function against
	// test-owned tempdirs where the managed trust check would fail.
	if revalidateAfterCreateTemp {
		if err := ValidateTrustedServiceRuntimeDir(
			dir, "managed runtime file directory (post-createtemp)", os.Getenv(WindowsServiceAccountEnv),
		); err != nil {
			_ = temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return safefile.ReplaceFile(name, path)
}
