// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Fixed contributor input, never a registry for arbitrary local executables.
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
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const claudeImageSHA = "eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23"
const claudeImageSize int64 = 254858400
const claudeProductVersion = "2.1.292.0"
const claudeSignerThumbprint = "0D7581D2C51C59DF686C3000C70BF543F9F6C6CB"
const claudeSiblingName = "claude-reviewed.exe"
const claudeArtifactVariant = "standalone_std_fixed_signed_claude_version"
const claudeArtifactScope = "fixed_windows_native_psec_signed_claude_version"
const claudeControlVariant = "standalone_std_fixed_signed_claude_create_control"
const claudeControlScope = "fixed_windows_uncontained_claude_create_control"

func isClaudeMode(mode string) bool {
	return mode == "claude-version-only" || mode == "claude-create-control-only"
}

// An independent reviewer records signature/version facts for the fixed image.
// Its SHA256/size below are source-pinned authority; receipt fields cannot admit
// another executable. No signature subprocess, network or payload runs here.
type localClaudeReceipt struct {
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

type fixedLocalImage struct {
	file *os.File
	held pinnedImages
}

func validateLocalClaudeMetadata(value localClaudeReceipt) error {
	if value.Schema != "fixed-reviewed-anthropic-claude-version-v1" || !value.Verified ||
		value.ExecutionPerformed == nil || *value.ExecutionPerformed ||
		value.ProductionQualification == nil || *value.ProductionQualification ||
		value.SHA256 != claudeImageSHA || value.Size != claudeImageSize ||
		value.ProductVersion != claudeProductVersion || value.SignatureStatus != "Valid" ||
		value.SignerOrganization != "Anthropic, PBC" || value.SignerThumbprint != claudeSignerThumbprint {
		return errors.New("only the independently reviewed signed Claude 2.1.292 image is accepted")
	}
	return nil
}

func decodeLocalClaudeReceipt(raw []byte) (localClaudeReceipt, error) {
	var value localClaudeReceipt
	if len(raw) == 0 || len(raw) > 64*1024 || !utf8.Valid(raw) {
		return value, errors.New("local-image receipt encoding or bound refused")
	}
	keys := json.NewDecoder(bytes.NewReader(raw))
	if token, err := keys.Token(); err != nil || token != json.Delim('{') {
		return value, errors.New("local-image receipt must be one flat object")
	}
	allowed := map[string]bool{
		"schema": true, "verified": true, "execution_performed": true, "production_qualification": true,
		"image": true, "sha256": true, "size": true, "product_version": true,
		"signature_status": true, "signer_organization": true, "signer_thumbprint": true,
	}
	seen := map[string]bool{}
	for keys.More() {
		token, err := keys.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || !allowed[name] {
			return value, errors.New("duplicate or malformed local-image field")
		}
		seen[name] = true
		var scalar json.RawMessage
		if err := keys.Decode(&scalar); err != nil || len(scalar) == 0 || scalar[0] == '[' || scalar[0] == '{' {
			return value, errors.New("local-image fields must be scalars")
		}
	}
	if token, err := keys.Token(); err != nil || token != json.Delim('}') {
		return value, errors.New("local-image object is incomplete")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return value, errors.New("local-image receipt has trailing data")
	}
	return value, nil
}

// Hold all ordinary mounted NTFS ancestors against rename/removal; unlike file
// pinning alone, list access establishes independent directory-name custody.
// Directory metadata/content remain mutable under existing caller permissions.
func pinImageParents(path string) (pinnedImages, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) < 3 ||
		path[1:3] != `:\` || strings.Contains(path[2:], ":") || strings.ContainsRune(path, 0) {
		return nil, errors.New("ordinary absolute local image path required")
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return nil, errors.New("local image mount identity refused")
	}
	var names []string
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		names = append(names, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	slices.Reverse(names)
	var held pinnedImages
	for _, name := range names {
		encoded, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, errors.Join(err, held.Close())
		}
		handle, err := windows.CreateFile(encoded, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return nil, errors.Join(errors.New("cannot retain image ancestor"), held.Close())
		}
		file := os.NewFile(uintptr(handle), name)
		held = append(held, file)
		var information windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &information) != nil ||
			information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, errors.Join(errors.New("image ancestor type/reparse refusal"), held.Close())
		}
	}
	return held, nil
}

func checkLocalClaudeReceipt(path, receiptSHA string) (imageResult fixedLocalImage, resultErr error) {
	if !shaPattern.MatchString(receiptSHA) {
		return fixedLocalImage{}, errors.New("an independent local-image receipt pin is required")
	}
	file, actual, err := pinFile(path, 64*1024)
	if err != nil {
		return fixedLocalImage{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			resultErr = errors.Join(resultErr, imageResult.held.Close())
			imageResult = fixedLocalImage{}
		}
	}()
	if actual != receiptSHA {
		return fixedLocalImage{}, errors.New("local-image receipt changed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fixedLocalImage{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return fixedLocalImage{}, err
	}
	value, err := decodeLocalClaudeReceipt(raw)
	if err != nil {
		return fixedLocalImage{}, err
	}
	if err := validateLocalClaudeMetadata(value); err != nil {
		return fixedLocalImage{}, err
	}
	held, err := pinImageParents(value.Image)
	if err != nil {
		return fixedLocalImage{}, err
	}
	image, digest, err := pinFile(value.Image, claudeImageSize)
	if err != nil {
		return fixedLocalImage{}, errors.Join(err, held.Close())
	}
	held = append(held, image)
	information, err := image.Stat()
	var native windows.ByHandleFileInformation
	if err != nil || information.Size() != claudeImageSize || digest != claudeImageSHA ||
		windows.GetFileInformationByHandle(windows.Handle(image.Fd()), &native) != nil || native.NumberOfLinks != 1 ||
		native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fixedLocalImage{}, errors.Join(errors.New("fixed local Claude image changed"), held.Close())
	}
	return fixedLocalImage{file: image, held: held}, nil
}

// Copy only a held, verified image into the held fresh private bin. Root.OpenFile
// is relative to its retained directory handle, not a late DOS-name reopen.
func copyFixedImage(root *os.Root, name string, source *os.File, size int64, expected string) (resultErr error) {
	if name != claudeSiblingName && name != filepath.Base(binaryName) {
		return errors.New("unknown fixed image basename")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	destination, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, destination.Close()) }()
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, size+1))
	if err != nil || count != size || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.Join(errors.New("fixed private image copy differs"), err)
	}
	return destination.Sync()
}

func stageClaudeVersionImages(value *receipt, runtimeImages pinnedImages, source fixedLocalImage, root string) (_ string, _ pinnedImages, resultErr error) {
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		return "", nil, err
	}
	held, err := pinImageParents(filepath.Join(bin, claudeSiblingName))
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, held.Close())
		}
	}()
	anchor, err := os.OpenRoot(bin)
	if err != nil {
		return "", nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, anchor.Close()) }()
	opened, err := anchor.Open(".")
	if err != nil {
		return "", nil, err
	}
	observed, observedErr := opened.Stat()
	expected, expectedErr := held[len(held)-1].Stat()
	closeErr := opened.Close()
	if observedErr != nil || expectedErr != nil || closeErr != nil || !os.SameFile(observed, expected) {
		return "", nil, errors.New("private image bin identity changed")
	}
	var runtime *os.File
	for index, component := range value.Binaries {
		if component.Path == binaryName && index < len(runtimeImages) {
			runtime = runtimeImages[index]
		}
	}
	if runtime == nil || source.file == nil {
		return "", nil, errors.New("held fixed source images are absent")
	}
	for _, item := range []struct {
		name, digest string
		file         *os.File
		size         int64
	}{{filepath.Base(binaryName), value.BinarySHA, runtime, value.BinarySize},
		{claudeSiblingName, claudeImageSHA, source.file, claudeImageSize}} {
		if err := copyFixedImage(anchor, item.name, item.file, item.size, item.digest); err != nil {
			return "", nil, err
		}
		image, digest, err := pinFile(filepath.Join(bin, item.name), item.size)
		if err != nil {
			return "", nil, err
		}
		held = append(held, image)
		if digest != item.digest {
			return "", nil, errors.New("private image changed before retention")
		}
	}
	return filepath.Join(bin, filepath.Base(binaryName)), held, nil
}
