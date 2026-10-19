// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"golang.org/x/sys/unix"
)

// All paths below this helper are fixed artifact members or newly generated
// synthetic fixture names. Relative opens walk every component without links.
func openRelative(parent *os.File, name string, flags int) (*os.File, error) {
	if parent == nil || name == "" || len(name) > 4096 || !filepath.IsLocal(name) || strings.ContainsRune(name, 0) {
		return nil, errors.New("fixed relative object refused")
	}
	parts := strings.Split(name, "/")
	if len(parts) > 16 {
		return nil, errors.New("fixed object depth refused")
	}
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return nil, errors.New("fixed object component refused")
		}
		access := unix.O_RDONLY | unix.O_DIRECTORY
		if i == len(parts)-1 {
			access = flags | unix.O_NONBLOCK
		}
		next, err := unix.Openat(fd, part, access|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "fixed-held-object"), nil
}

func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("exact absolute directory refused")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), "filesystem-root")
	defer root.Close()
	return openRelative(root, strings.TrimPrefix(path, "/"), unix.O_RDONLY|unix.O_DIRECTORY)
}

func privateDirectory(file *os.File) error {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		return errors.New("fixed owned private directory refused")
	}
	return nil
}

func boundedFile(parent *os.File, path string, maximum int64, expected string) (*os.File, []byte, error) {
	file, err := openRelative(parent, path, unix.O_RDONLY)
	if err != nil {
		return nil, nil, errors.New("reviewed fixed artifact open refused")
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = file.Close()
		}
	}()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&06000 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > maximum {
		return nil, nil, errors.New("reviewed fixed artifact type/size/link refused")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != stat.Size || digestBytes(data) != expected {
		return nil, nil, errors.New("reviewed fixed artifact bytes differ")
	}
	accepted = true
	return file, data, nil
}

func validateELF(data []byte, static bool) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("reviewed ELF structure refused")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_X86_64 || (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) {
		return errors.New("reviewed ELF target differs")
	}
	for _, p := range file.Progs {
		if static && (p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC) {
			return errors.New("required static ELF has loader dependency")
		}
		if p.Type == elf.PT_INTERP {
			value, err := io.ReadAll(io.LimitReader(p.Open(), 128))
			if err != nil || string(value) != "/lib64/ld-linux-x86-64.so.2\x00" {
				return errors.New("trusted peer interpreter differs")
			}
		}
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		values, err := file.DynString(tag)
		if err != nil || len(values) != 0 {
			return errors.New("trusted ELF relative loader search refused")
		}
	}
	libraries, err := file.ImportedLibraries()
	if err != nil {
		return errors.New("trusted ELF dependencies unreadable")
	}
	for _, name := range libraries {
		if static || (name != "libgcc_s.so.1" && name != "libc.so.6" && name != "ld-linux-x86-64.so.2") {
			return errors.New("trusted peer dependency differs")
		}
	}
	return nil
}

type images struct{ peer, bwrap, payload *bridgeprocess.Image }

func (i *images) close() error {
	return errors.Join(i.peer.Close(), i.bwrap.Close(), i.payload.Close())
}

func admitImages(ctx context.Context, receiptPath string, registry reviewedRegistry) (_ artifactReceipt, _ *images, resultErr error) {
	var receipt artifactReceipt
	if registry.validate() != nil {
		return receipt, nil, errUnreviewed
	}
	if filepath.Base(receiptPath) != "REVIEWED-ARTIFACTS.json" {
		return receipt, nil, errors.New("fixed reviewed artifact receipt filename required")
	}
	root, err := openDirectory(filepath.Dir(receiptPath))
	if err != nil {
		return receipt, nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	file, data, err := boundedFile(root, "REVIEWED-ARTIFACTS.json", 64<<10, registry.ReceiptSHA)
	if err != nil {
		return receipt, nil, err
	}
	if err := file.Close(); err != nil {
		return receipt, nil, err
	}
	receipt, err = admitReceipt(data, registry)
	if err != nil {
		return receipt, nil, err
	}
	proofs := []struct{ path, hash string }{
		{"proofs/STATIC-CLOSURE.json", receipt.StaticClosureSHA},
		{"proofs/peer-PROVENANCE.json", receipt.Builds[0].ProvenanceSHA},
		{"proofs/payload-PROVENANCE.json", receipt.Builds[1].ProvenanceSHA},
		{"source/payload-main_linux.go", receipt.PayloadSourceSHA},
	}
	if receipt.Scope == claudeVersionScope {
		proofs = proofs[:2]
		proofs = append(proofs, struct{ path, hash string }{"proofs/loader-PROVENANCE.json", receipt.Builds[1].ProvenanceSHA}, struct{ path, hash string }{"proofs/LOADER-CLOSURE.json", receipt.LoaderClosureSHA}, struct{ path, hash string }{"source/claude-manifest.json", receipt.ClaudeVersion.ManifestSHA}, struct{ path, hash string }{"source/claude-manifest.json.sig", receipt.ClaudeVersion.SignatureSHA}, struct{ path, hash string }{"source/claude-release-key.asc", receipt.ClaudeVersion.KeySHA})
	}
	for _, proof := range proofs {
		f, _, err := boundedFile(root, proof.path, 4<<20, proof.hash)
		if err != nil {
			return receipt, nil, err
		}
		if err := f.Close(); err != nil {
			return receipt, nil, err
		}
	}
	sealed := &images{}
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, sealed.close())
		}
	}()
	for index, identity := range receipt.Images {
		source, data, err := boundedFile(root, identity.Path, identity.Size, identity.SHA)
		if err != nil {
			return receipt, nil, err
		}
		elfErr := validateELF(data, index != 0)
		if receipt.Scope == claudeVersionScope && index == 2 {
			elfErr = validateClaudeELF(data, false)
		}
		if int64(len(data)) != identity.Size || elfErr != nil {
			_ = source.Close()
			return receipt, nil, errors.New("fixed admitted ELF differs")
		}
		image, err := bridgeprocess.SealImage(ctx, source, "sha256:"+identity.SHA)
		closeErr := source.Close()
		if err != nil || closeErr != nil {
			_ = image.Close()
			return receipt, nil, errors.Join(err, closeErr)
		}
		switch index {
		case 0:
			sealed.peer = image
		case 1:
			sealed.bwrap = image
		case 2:
			sealed.payload = image
		}
	}
	if receipt.Scope == claudeVersionScope {
		file, data, err := boundedFile(root, receipt.Loader.Path, receipt.Loader.Size, receipt.Loader.SHA)
		if err != nil {
			return receipt, nil, err
		}
		if err := errors.Join(validateClaudeELF(data, true), file.Close()); err != nil {
			return receipt, nil, err
		}
	}
	accepted = true
	return receipt, sealed, nil
}

type canary struct {
	file, parent  *os.File
	name          string
	device, inode uint64
}

type fixedFixture struct {
	root, work, home, temporary, outside, readonly *os.File
	parent                                         *os.File
	loader                                         *os.File
	name                                           string
	path                                           string
	canaries                                       []canary
}

type fixtureSetupError struct {
	path  string
	cause error
}

func (e *fixtureSetupError) Error() string {
	return "fixed fixture setup failed; new synthetic root retained"
}
func (e *fixtureSetupError) Unwrap() error { return e.cause }

func identity(file *os.File) (uint64, uint64, error) {
	var stat unix.Stat_t
	err := unix.Fstat(int(file.Fd()), &stat)
	return uint64(stat.Dev), stat.Ino, err
}

func createCanary(parent *os.File, name string) (canary, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return canary{}, err
	}
	writer := os.NewFile(uintptr(fd), "fixed-new-canary")
	_, writeErr := writer.WriteString(sentinel)
	device, inode, idErr := identity(writer)
	if err := errors.Join(writeErr, idErr, writer.Sync(), writer.Close()); err != nil {
		return canary{}, err
	}
	reader, err := openRelative(parent, name, unix.O_RDONLY)
	if err != nil {
		return canary{}, err
	}
	d, i, err := identity(reader)
	if err != nil || d != device || i != inode {
		_ = reader.Close()
		return canary{}, errors.New("new fixed canary identity changed")
	}
	return canary{reader, parent, name, device, inode}, nil
}

func (c canary) verify() error {
	file, err := openRelative(c.parent, c.name, unix.O_RDONLY)
	if err != nil {
		return errors.New("original fixed canary name missing or redirected")
	}
	defer file.Close()
	device, inode, err := identity(file)
	if err != nil || device != c.device || inode != c.inode {
		return errors.New("original fixed canary identity differs")
	}
	var stat unix.Stat_t
	if unix.Fstat(int(c.file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != int64(len(sentinel)) {
		return errors.New("original fixed canary shape differs")
	}
	data := make([]byte, len(sentinel)+1)
	n, err := c.file.ReadAt(data, 0)
	if err != io.EOF || string(data[:n]) != sentinel {
		return errors.New("original fixed canary bytes changed")
	}
	return nil
}

func (f *fixedFixture) close() error {
	var result error
	for _, c := range f.canaries {
		result = errors.Join(result, c.file.Close())
	}
	for _, object := range []*os.File{f.work, f.home, f.temporary, f.outside, f.loader, f.root, f.parent} {
		if object != nil {
			result = errors.Join(result, object.Close())
		}
	}
	return result // retained synthetic names are never recursively removed here
}

func newFixture(suite string) (_ *fixedFixture, resultErr error) {
	parent, root := os.NewFile(7, "fixed-inherited-fixture-parent"), os.NewFile(8, "fixed-inherited-fixture-root")
	defer parent.Close()
	defer root.Close()
	var st unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&unix.S_ISVTX == 0 {
		return nil, errors.New("fixed inherited fixture parent refused")
	}
	var value [512]byte
	n, err := unix.Readlink("/proc/self/fd/8", value[:])
	if err != nil || n <= 0 || n >= len(value) {
		return nil, errors.New("fixed fixture display refused")
	}
	display := string(value[:n])
	name := filepath.Base(display)
	nonce := strings.TrimPrefix(name, "dc-axis-native-peer-")
	if filepath.Dir(display) != "/tmp" || len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" || name != "dc-axis-native-peer-"+nonce {
		return nil, errors.New("fixed fixture display refused")
	}
	if suite == claudeVersionSuite {
		loader, err := inheritedVersionLoader(root, 9)
		if err != nil {
			return nil, err
		}
		defer loader.Close()
		return initializeFixtureWithLoader(parent, root, "/tmp", nonce, loader)
	}
	return initializeFixture(parent, root, "/tmp", nonce)
}

// Inert filesystem tests create their own private parent; live creation belongs
// exclusively to the trusted outer driver before its first USER namespace clone.
func newFixtureUnder(parent *os.File, displayParent, nonce string) (*fixedFixture, error) {
	if len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return nil, errors.New("fixed nonce refused")
	}
	name := "dc-axis-native-peer-" + nonce
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return nil, err
	}
	root, err := openRelative(parent, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, &fixtureSetupError{path: filepath.Join(displayParent, name), cause: err}
	}
	defer root.Close()
	return initializeFixture(parent, root, displayParent, nonce)
}

func initializeFixture(parent, heldRoot *os.File, displayParent, nonce string) (*fixedFixture, error) {
	return initializeFixtureWithLoader(parent, heldRoot, displayParent, nonce, nil)
}

func initializeFixtureWithLoader(parent, heldRoot *os.File, displayParent, nonce string, loader *os.File) (_ *fixedFixture, resultErr error) {
	if parent == nil || heldRoot == nil || len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return nil, errors.New("fixed held fixture identity refused")
	}
	name := "dc-axis-native-peer-" + nonce
	f := &fixedFixture{path: filepath.Join(displayParent, name), name: name}
	accepted := false
	defer func() {
		if !accepted {
			resultErr = &fixtureSetupError{path: f.path, cause: errors.Join(resultErr, f.close())}
		}
	}()
	parentFD, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	f.parent = os.NewFile(uintptr(parentFD), "fixed-held-fixture-parent")
	rootFD, err := unix.FcntlInt(heldRoot.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(rootFD), "fixed-held-fixture-root")
	f.root = root
	if err := privateDirectory(root); err != nil {
		return nil, err
	}
	correlated, err := openRelative(parent, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	d, i, idErr := identity(correlated)
	hd, hi, heldErr := identity(root)
	if err := errors.Join(idErr, heldErr, correlated.Close()); err != nil || d != hd || i != hi {
		return nil, errors.New("fixed fixture held identity differs")
	}
	if loader != nil {
		if err := verifyVersionLoader(root, loader); err != nil {
			return nil, err
		}
		fd, err := unix.FcntlInt(loader.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			return nil, err
		}
		f.loader = os.NewFile(uintptr(fd), "fixed-worker-held-loader")
	}
	// A fresh descriptor for "." avoids sharing an inherited directory offset.
	// Only the already held, private, same-user root is traversed.
	emptyFD, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	empty := os.NewFile(uintptr(emptyFD), "fixed-fixture-empty-check")
	entryErr := verifyInitialFixtureEntries(empty, loader != nil)
	if closeErr := empty.Close(); entryErr != nil || closeErr != nil {
		return nil, errors.Join(entryErr, closeErr)
	}
	for _, item := range []struct {
		name   string
		target **os.File
	}{{"work", &f.work}, {"home", &f.home}, {"tmp", &f.temporary}, {"outside", &f.outside}} {
		if err := unix.Mkdirat(int(root.Fd()), item.name, 0700); err != nil {
			return nil, err
		}
		*item.target, err = openRelative(root, item.name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return nil, err
		}
		if err := privateDirectory(*item.target); err != nil {
			return nil, err
		}
	}
	for _, item := range []struct {
		parent *os.File
		name   string
	}{{f.work, "fixture-seal"}, {f.home, "fixture-seal"}, {f.temporary, "fixture-seal"}, {root, "readonly"}, {f.outside, "read-canary"}, {f.outside, "write-canary"}} {
		c, err := createCanary(item.parent, item.name)
		if err != nil {
			return nil, err
		}
		f.canaries = append(f.canaries, c)
		if item.name == "readonly" {
			f.readonly = c.file
		}
	}
	// This is a host-positive write-access control without changing bytes.
	write, err := openRelative(f.outside, "write-canary", unix.O_WRONLY)
	if err != nil {
		return nil, errors.New("host outside write-positive control failed")
	}
	if err := write.Close(); err != nil {
		return nil, err
	}
	if err := f.verify(false); err != nil {
		return nil, err
	}
	accepted = true
	return f, nil
}

func (f *fixedFixture) verify(writes bool) error {
	if f.loader != nil {
		if err := verifyVersionLoader(f.root, f.loader); err != nil {
			return err
		}
	}
	// Sample name correlation before/after each case; this does not claim an
	// atomic guarantee against a concurrent same-UID rename during execution.
	for _, item := range []struct {
		parent, held *os.File
		name         string
	}{{f.parent, f.root, f.name}, {f.root, f.outside, "outside"}} {
		current, err := openRelative(item.parent, item.name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return errors.New("fixed host path correlation refused")
		}
		d, i, idErr := identity(current)
		hd, hi, heldErr := identity(item.held)
		closeErr := current.Close()
		if errors.Join(idErr, heldErr, closeErr) != nil || d != hd || i != hi {
			return errors.New("fixed host path identity differs")
		}
	}
	for _, file := range []*os.File{f.root, f.work, f.home, f.temporary, f.outside} {
		if err := privateDirectory(file); err != nil {
			return err
		}
	}
	for _, c := range f.canaries {
		if err := c.verify(); err != nil {
			return err
		}
	}
	if writes {
		for _, directory := range []*os.File{f.work, f.home, f.temporary} {
			file, err := openRelative(directory, "allowed-write", unix.O_RDONLY)
			if err != nil {
				return errors.New("fixed permitted write missing")
			}
			data, readErr := io.ReadAll(io.LimitReader(file, int64(len(sentinel)+1)))
			if err := errors.Join(readErr, file.Close()); err != nil || string(data) != sentinel {
				return errors.New("fixed permitted write bytes differ")
			}
		}
	}
	return nil
}

func (f *fixedFixture) bindingIdentity() (string, error) {
	var values []string
	for _, file := range []*os.File{f.root, f.work, f.home, f.temporary, f.readonly, f.outside} {
		device, inode, err := identity(file)
		if err != nil {
			return "", err
		}
		values = append(values, fmt.Sprintf("%d:%d", device, inode))
	}
	if f.loader != nil {
		d, i, err := identity(f.loader)
		if err != nil {
			return "", err
		}
		values = append(values, fmt.Sprintf("%d:%d", d, i))
	}
	return digestBytes([]byte(strings.Join(values, "\x00"))), nil
}

func newEvidence(path string) (*os.File, error) {
	if filepath.Clean(path) != path || !filepath.IsAbs(path) || !strings.HasPrefix(filepath.Base(path), "native-peer-fixed-") {
		return nil, errors.New("fresh native-peer-fixed-* result directory required")
	}
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := privateDirectory(parent); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(path), 0700); err != nil {
		return nil, err
	}
	return openRelative(parent, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY)
}

func runNative(ctx context.Context, opts options, registry reviewedRegistry, record map[string]any, permit workerPermit, owner *cleanupOwner) (resultErr error) {
	record["native_stage"] = "host_admission"
	defer func() { record["native_errno"] = startErrnoClass(resultErr) }()
	if !permit.granted || owner == nil {
		return errors.New("owned outer namespace grant required")
	}
	if runtime.GOARCH != "amd64" || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("native unprivileged Linux amd64 is required")
	}
	if registry.validate() != nil {
		return errUnreviewed
	}
	record["native_stage"] = "evidence_directory"
	evidence, err := newEvidence(opts.evidence)
	if err != nil {
		return err
	}
	defer func() {
		record["passed"] = resultErr == nil
		if resultErr != nil {
			record["error"] = "fixed_native_observation_or_cleanup_failed"
		}
		data, err := json.MarshalIndent(record, "", "  ")
		if err == nil {
			fd, openErr := unix.Openat(int(evidence.Fd()), "RESULT.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
			err = openErr
			if err == nil {
				file := os.NewFile(uintptr(fd), "fixed-private-result")
				_, writeErr := file.Write(append(data, '\n'))
				err = errors.Join(writeErr, file.Sync(), file.Close())
			}
		}
		resultErr = errors.Join(resultErr, err, evidence.Close())
		if resultErr != nil {
			record["passed"] = false
		}
	}()
	defer func() {
		resultErr = errors.Join(resultErr, owner.retry())
		record["pending_native_cleanup"] = len(owner.pending)
		if opts.suite == claudeVersionSuite {
			record["pending_version_resources"] = len(owner.heldResources)
		}
	}()
	record["native_stage"] = "artifact_admission"
	receipt, admitted, err := admitImages(ctx, opts.receipt, registry)
	if admitted != nil {
		defer func() { resultErr = errors.Join(resultErr, admitted.close()) }()
	}
	if err != nil {
		return err
	}
	record["artifact_receipt_sha256"] = registry.ReceiptSHA
	record["native_stage"] = "fixture_capability"
	f, err := newFixture(opts.suite)
	if err != nil {
		var retained *fixtureSetupError
		if errors.As(err, &retained) {
			record["fixture_retained"] = true
			record["synthetic_fixture"] = retained.path
		}
		return err
	}
	defer func() {
		if opts.suite == claudeVersionSuite {
			resultErr = errors.Join(resultErr, owner.releaseResource(f.close))
		} else {
			resultErr = errors.Join(resultErr, f.close())
		}
	}()
	record["fixture_retained"] = true
	record["synthetic_fixture"] = f.path
	record["native_stage"] = "fixture_identity"
	fixtureID, err := f.bindingIdentity()
	if err != nil {
		return err
	}
	cases, err := casesForSuite(opts.suite)
	if err != nil {
		return err
	}
	results := make([]caseResult, 0, len(cases))
	for _, mode := range cases {
		record["native_case"] = mode
		record["native_stage"] = "host_canary_verification"
		if err := f.verify(false); err != nil {
			return err
		}
		record["native_stage"] = "fixed_plan"
		var plan bridgeproto.Preparation
		switch opts.suite {
		case claudeVersionSuite:
			plan, err = claudeVersionPlan()
		case "lifecycle":
			plan, err = lifecyclePlan(mode)
		default:
			plan, err = fixedPlan(mode, f.path+"/outside")
		}
		if err != nil {
			return err
		}
		record["native_stage"] = "fixed_binding"
		binding, err := fixedBinding(filepath.Base(f.path)+":"+mode, fixtureID, plan, receipt)
		if err != nil {
			return err
		}
		// Each fixed case reserves this complete unique identity until native
		// Close returns. A refusal/cleanup error stops the loop permanently.
		ownerCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		record["native_stage"] = "peer_start"
		record["native_start_attempted"] = true
		if record["execution_performed"] != true {
			record["execution_performed"] = nil
		}
		readInputs := []*os.File{f.readonly}
		if opts.suite == claudeVersionSuite {
			readInputs = []*os.File{f.loader, f.loader}
		}
		session, startErr := bridgeprocess.Start(ownerCtx, binding, plan, bridgeprocess.Inputs{
			Peer: admitted.peer, Bubblewrap: admitted.bwrap, Payload: admitted.payload, CWD: f.work,
			Read: readInputs, Write: []*os.File{f.work, f.home, f.temporary},
		}, bridgeowner.Limits{WriteTimeout: time.Second, CleanupTimeout: 10 * time.Second})
		if session == nil && record["execution_performed"] != true {
			record["execution_performed"] = false
		}
		result := caseResult{Mode: mode}
		var tree *treeObservation
		if mode == "tree-cancel" {
			tree = &treeObservation{work: f.work}
		}
		if startErr == nil && session != nil && session.Protocol != nil {
			record["native_stage"] = "peer_protocol"
			if opts.suite == "lifecycle" {
				var beforeCancel, beforeDestroy func(context.Context) error
				if tree != nil {
					beforeCancel = tree.beforeCancel
					beforeDestroy = tree.stableBeforeDestroy
				}
				result, err = exerciseLifecycle(ownerCtx, session.Protocol, binding, plan, mode, beforeCancel, beforeDestroy)
			} else {
				result, err = exercise(ownerCtx, session.Protocol, binding, plan, mode)
			}
		} else if startErr == nil {
			err = errors.New("native factory returned no owned session")
		} else {
			err = startErr
		}
		if tree != nil {
			result.TreeHeartbeats = &tree.evidence
		}
		if result.Started {
			record["peer_started_reply_observed"] = true
		}
		if result.VersionOutput {
			record["execution_performed"], record["claude_version_output_observed"] = true, true
		}
		if result.PayloadMarker {
			record["execution_performed"] = true
			record["fixed_payload_marker_observed"] = true
		}
		if session != nil {
			closeErr := owner.close(session)
			result.NativeCleanup = closeErr == nil
			err = errors.Join(err, closeErr)
		}
		if tree != nil {
			err = errors.Join(err, tree.close())
		}
		cancel()
		if err == nil {
			err = f.verify(mode == "boundaries")
		}
		caseError(&result, err)
		results = append(results, result)
		record["cases"] = results
		if err != nil {
			return err
		}
	}
	record["native_stage"] = "complete"
	record["host_outside_read_and_write_positive_controls"] = true
	record["original_canary_identities_and_bytes_preserved"] = true
	return nil
}
