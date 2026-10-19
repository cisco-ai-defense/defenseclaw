// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	imageSHA    = "eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23"
	imageSize   = 254858400
	receiptSHA  = "a9c38cec7b47197f04e6016eada1e9743e218f3b0ee8d77c1c913a5d2351fa3a"
	receiptName = "claude-2.1.292-root-image-review.json"
	imageName   = "claude-reviewed.exe"
	fixtureName = "claude-path-control-fixture"
)

type localReceipt struct {
	Schema                  string `json:"schema"`
	Verified                bool   `json:"verified"`
	ExecutionPerformed      *bool  `json:"execution_performed"`
	ProductionQualification *bool  `json:"production_qualification"`
	Image                   string `json:"image"`
	SHA256                  string `json:"sha256"`
	Size                    int64  `json:"size"`
	ProductVersion          string `json:"product_version"`
	SignatureStatus         string `json:"signature_status"`
	SignerOrganization      string `json:"signer_organization"`
	SignerThumbprint        string `json:"signer_thumbprint"`
}

func decodeReceipt(raw []byte) (localReceipt, error) {
	var value localReceipt
	if len(raw) == 0 || len(raw) > 65536 || digest(raw) != receiptSHA {
		return value, errors.New("the source-pinned independent local image receipt is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return value, errors.New("fixed local receipt JSON differs")
	}
	return value, validateMetadata(value)
}

func validateMetadata(value localReceipt) error {
	if !value.Verified || value.ExecutionPerformed == nil || *value.ExecutionPerformed ||
		value.ProductionQualification == nil || *value.ProductionQualification ||
		value.Schema != "fixed-reviewed-anthropic-claude-version-v1" ||
		value.SHA256 != imageSHA || value.Size != imageSize || value.ProductVersion != "2.1.292.0" ||
		value.SignatureStatus != "Valid" || value.SignerOrganization != "Anthropic, PBC" ||
		value.SignerThumbprint != "0D7581D2C51C59DF686C3000C70BF543F9F6C6CB" {
		return errors.New("the fixed signed Claude image metadata differs")
	}
	return nil
}

func digest(raw []byte) string {
	value := sha256.Sum256(raw)
	return hex.EncodeToString(value[:])
}

type heldFiles []*os.File

func (files heldFiles) close() error {
	var err error
	for _, file := range slices.Backward(files) {
		if file.Close() != nil {
			err = errors.Join(err, errors.New("held file or directory close failed"))
		}
	}
	return err
}

type fileID struct {
	Volume uint64
	ID     [16]byte
}

func identity(file *os.File) (fileID, error) {
	var id fileID
	if windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))) != nil {
		return id, errors.New("held file identity query refused")
	}
	return id, nil
}

func openPinned(path string, directory bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("pinned name encoding refused")
	}
	access, share, flags := uint32(windows.GENERIC_READ), uint32(windows.FILE_SHARE_READ), uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		// LIST_DIRECTORY is required for real anti-rename sharing. Attribute-only
		// handles did not establish it in the earlier native synthetic control.
		access = windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL
		share |= windows.FILE_SHARE_WRITE
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, errors.New("retained path open refused")
	}
	file := os.NewFile(uintptr(handle), "held-fixed-object")
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		(!directory && info.NumberOfLinks != 1) {
		_ = file.Close()
		return nil, errors.New("retained path object type, link count or reparse refused")
	}
	return file, nil
}

func pinParents(path string) (files heldFiles, resultErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) < 3 || path[1:3] != `:\` || strings.Contains(path[2:], ":") {
		return nil, errors.New("ordinary absolute mounted local path required")
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return nil, errors.New("fixed NTFS mounted volume identity refused")
	}
	var parents []string
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		parents = append(parents, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	slices.Reverse(parents)
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, files.close())
			files = nil
		}
	}()
	for _, parent := range parents {
		file, err := openPinned(parent, true)
		if err != nil {
			return files, err
		}
		files = append(files, file)
	}
	return files, nil
}

func readFixed(file *os.File, size int64, expected string) error {
	info, err := file.Stat()
	if err != nil || info.Size() != size || !info.Mode().IsRegular() {
		return errors.New("fixed input size or type differs")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("fixed input seek refused")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, size+1))
	if err != nil || n != size || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("fixed input hash differs")
	}
	return nil
}

func finalPath(file *os.File, flags uint32) (string, error) {
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), flags)
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		return "", errors.New("held final path query refused")
	}
	return windows.UTF16ToString(buffer[:n]), nil
}

type application struct{ label, path string }

func applicationNames(guid, native, dos string) ([]application, error) {
	if !strings.HasPrefix(guid, `\\?\Volume{`) || !strings.Contains(guid, `}\`) ||
		!strings.HasPrefix(native, `\Device\HarddiskVolume`) ||
		!strings.HasPrefix(dos, `\\?\`) || len(dos) < 8 || dos[5:7] != `:\` ||
		strings.ContainsAny(guid+native+dos, "\x00\"\r\n") ||
		filepath.Base(guid) != imageName || filepath.Base(native) != imageName || filepath.Base(dos) != imageName {
		return nil, errors.New("held image spellings have an unsupported fixed local shape")
	}
	return []application{{"volume_guid", guid}, {"globalroot_native", `\\?\GLOBALROOT` + native}, {"ordinary_dos", dos[4:]}}, nil
}

type fixture struct {
	files          heldFiles
	root           *os.Root
	image          *os.File
	dosRoot, argv0 string
	applications   []application
}

func (f *fixture) close() error {
	err := f.root.Close()
	if err != nil {
		err = errors.New("held private root close failed")
	}
	return errors.Join(err, f.files.close())
}

func prepareFixture(evidence string, retained *bool) (_ *fixture, resultErr error) {
	parents, err := pinParents(filepath.Join(evidence, receiptName))
	if err != nil {
		return nil, err
	}
	f := &fixture{files: parents}
	defer func() {
		if resultErr != nil {
			if f.root != nil {
				_ = f.root.Close()
			}
			resultErr = errors.Join(resultErr, f.files.close())
		}
	}()
	if safefile.ValidatePrivateHandle(windows.Handle(parents[len(parents)-1].Fd())) != nil {
		return nil, errors.New("existing helper evidence directory must be private")
	}
	receipt, err := openPinned(filepath.Join(evidence, receiptName), false)
	if err != nil {
		return nil, err
	}
	f.files = append(f.files, receipt)
	raw, err := io.ReadAll(io.LimitReader(receipt, 65537))
	if err != nil {
		return nil, errors.New("receipt read refused")
	}
	metadata, err := decodeReceipt(raw)
	if err != nil {
		return nil, err
	}
	parents, err = pinParents(metadata.Image)
	if err != nil {
		return nil, err
	}
	f.files = append(f.files, parents...)
	source, err := openPinned(metadata.Image, false)
	if err != nil {
		return nil, err
	}
	f.files = append(f.files, source)
	if err := readFixed(source, imageSize, imageSHA); err != nil {
		return nil, err
	}
	path := filepath.Join(evidence, fixtureName)
	if created, err := safefile.CreatePrivateDirectory(path); err != nil || !created {
		return nil, errors.New("fresh private fixture creation refused")
	}
	*retained = true // Never remove a successful or failed diagnostic fixture.
	rootPin, err := openPinned(path, true)
	if err != nil {
		return nil, err
	}
	f.files = append(f.files, rootPin)
	if safefile.ValidatePrivateHandle(windows.Handle(rootPin.Fd())) != nil {
		return nil, errors.New("private fixture descriptor refused")
	}
	f.root, err = os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("private root open refused")
	}
	rootCheck, err := f.root.Open(".")
	if err != nil {
		return nil, errors.New("private root identity open refused")
	}
	defer rootCheck.Close()
	if err := sameIdentity(rootPin, rootCheck); err != nil {
		return nil, err
	}
	for _, name := range []string{"bin", "home", "tmp", "workspace", `home\AppData`, `home\AppData\Roaming`, `home\AppData\Local`} {
		if f.root.Mkdir(name, 0700) != nil {
			return nil, errors.New("fresh private child creation refused")
		}
		directory, err := openPinned(filepath.Join(path, name), true)
		if err != nil {
			return nil, err
		}
		f.files = append(f.files, directory)
	}
	copy, err := f.root.OpenFile(filepath.Join("bin", imageName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("private fixed image creation refused")
	}
	_, seekErr := source.Seek(0, io.SeekStart)
	if seekErr != nil {
		_ = copy.Close()
		return nil, errors.New("held source copy seek refused")
	}
	n, copyErr := io.Copy(copy, io.LimitReader(source, imageSize+1))
	closeErr := copy.Close()
	if seekErr != nil || copyErr != nil || closeErr != nil || n != imageSize {
		return nil, errors.New("fixed image copy failed")
	}
	f.image, err = openPinned(filepath.Join(path, "bin", imageName), false)
	if err != nil {
		return nil, err
	}
	f.files = append(f.files, f.image)
	if err := readFixed(f.image, imageSize, imageSHA); err != nil {
		return nil, err
	}
	f.dosRoot, err = finalPath(rootPin, 0)
	if err != nil {
		return nil, err
	}
	f.argv0, err = finalPath(f.image, 0)
	if err != nil {
		return nil, err
	}
	guid, err := finalPath(f.image, 1)
	if err != nil {
		return nil, err
	}
	native, err := finalPath(f.image, 2)
	if err != nil {
		return nil, err
	}
	f.applications, err = applicationNames(guid, native, f.argv0)
	if err != nil {
		return nil, err
	}
	for _, name := range f.applications {
		file, err := openPinned(name.path, false)
		if err != nil {
			return nil, err
		}
		f.files = append(f.files, file)
		if err := sameIdentity(f.image, file); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func sameIdentity(expected, observed *os.File) error {
	want, err := identity(expected)
	if err != nil {
		return err
	}
	got, err := identity(observed)
	if err != nil {
		return err
	}
	if want != got {
		return errors.New("held image or directory identity mismatch")
	}
	return nil
}
