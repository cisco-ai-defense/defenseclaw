//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	windowsNamespacePurgeMaxDescriptorSize = 64 * 1024
	windowsNamespacePurgeACLHeaderSize     = 8
	windowsNamespacePurgeCertRunIDLength   = 10
)

var (
	windowsNamespacePurgeRootScope     = validateWindowsNamespacePurgeProductionRoot
	windowsNamespacePurgeAncestorTrust = func(path string) error {
		return managed.ValidateTrustedDirectoryAncestor(path, "namespace cleanup parent")
	}
	// Tests substitute an already-pinned in-tree identity to prove that purge
	// refuses to remove the executable inode that is performing the cleanup.
	// Production always resolves and pins the current executable itself.
	windowsNamespacePurgeExecutable = openWindowsNamespacePurgeExecutable
	// Tests use this seam to create a competing name after every pre-existing
	// inode has been pinned. Production leaves it nil.
	windowsNamespacePurgePostPin func(string) error
	// Tests use the node-aware seam to prove the final file link-count check.
	// Production leaves it nil.
	windowsNamespacePurgePostValidation func(*windowsNamespacePurgeNode) error
)

type windowsNamespacePurgeDescriptorSet struct {
	directories []*windows.SECURITY_DESCRIPTOR
	files       []*windows.SECURITY_DESCRIPTOR
	quarantine  *windows.SECURITY_DESCRIPTOR
}

type windowsNamespacePurgeNode struct {
	parent    windows.Handle
	name      string
	label     string
	handle    windows.Handle
	directory bool
	identity  string
	names     map[string]struct{}
	children  []*windowsNamespacePurgeNode
}

func (node *windowsNamespacePurgeNode) close() {
	if node == nil {
		return
	}
	for _, child := range node.children {
		child.close()
	}
	if node.handle != 0 {
		_ = windows.CloseHandle(node.handle)
		node.handle = 0
	}
}

type windowsNamespacePurgeBudget struct {
	entries int
}

// PurgeWindowsNamespaceRoot validates and, when requested, removes one exact
// machine-owned directory tree. It never discovers roots, follows reparse
// points, adopts unknown descriptors, or deletes through a path-only check.
func PurgeWindowsNamespaceRoot(
	request WindowsNamespacePurgeRequest,
) (WindowsNamespacePurgeReport, error) {
	report := WindowsNamespacePurgeReport{
		SchemaVersion:    WindowsNamespacePurgeSchemaVersion,
		Root:             request.Root,
		ExpectedIdentity: request.ExpectedIdentity,
	}
	fail := func(err error) (WindowsNamespacePurgeReport, error) {
		report.Error = err.Error()
		return report, err
	}

	descriptors, err := validateWindowsNamespacePurgeRequest(request)
	if err != nil {
		return fail(err)
	}
	err = runWindowsManagedRuntimeSetupPrivilege(func() error {
		return purgeWindowsNamespaceRootPrivileged(request, descriptors, &report)
	})
	if err != nil {
		return fail(err)
	}
	report.OK = true
	return report, nil
}

func validateWindowsNamespacePurgeRequest(
	request WindowsNamespacePurgeRequest,
) (*windowsNamespacePurgeDescriptorSet, error) {
	if request.SchemaVersion != WindowsNamespacePurgeSchemaVersion {
		return nil, fmt.Errorf(
			"enterprise hooks: unsupported Windows namespace purge schema version %d",
			request.SchemaVersion,
		)
	}
	if err := validateWindowsNamespacePurgeRootPath(request.Root); err != nil {
		return nil, err
	}
	if err := windowsNamespacePurgeRootScope(request.Root); err != nil {
		return nil, err
	}
	if request.ExpectedIdentity != "" && !validWindowsManagedRuntimeIdentity(request.ExpectedIdentity) {
		return nil, fmt.Errorf("enterprise hooks: Windows namespace purge identity is invalid")
	}
	if _, err := parseWindowsNamespacePurgeGatewaySID(request.GatewayServiceSID); err != nil {
		return nil, err
	}
	return windowsNamespacePurgeCanonicalDescriptors(request.GatewayServiceSID)
}

func validateWindowsNamespacePurgeRootPath(path string) error {
	if path == "" || strings.TrimSpace(path) != path || strings.Contains(path, "/") {
		return fmt.Errorf("enterprise hooks: Windows namespace purge root is empty, padded, or noncanonical")
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("enterprise hooks: Windows namespace purge root contains a control character")
		}
	}
	clean := filepath.Clean(path)
	if clean != path || !filepath.IsAbs(clean) || filepath.Dir(clean) == clean {
		return fmt.Errorf("enterprise hooks: Windows namespace purge root must be a canonical absolute child path")
	}
	leaf := filepath.Base(clean)
	if leaf == "" || leaf == "." || leaf == ".." || strings.TrimRight(leaf, " .") != leaf {
		return fmt.Errorf("enterprise hooks: Windows namespace purge root has an unsafe leaf")
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("enterprise hooks: Windows namespace purge root is not on fixed mounted NTFS: %w", err)
	}
	return nil
}

func validateWindowsNamespacePurgeProductionRoot(path string) error {
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve trusted Program Files for namespace cleanup: %w", err)
	}
	base := filepath.Join(programFiles, "Cisco", "Cisco Secure Client")
	production := filepath.Join(base, "DefenseClaw")
	if strings.EqualFold(path, production) {
		return nil
	}
	certification := filepath.Join(base, "DefenseClaw-Cert")
	leaf := filepath.Base(path)
	if !strings.EqualFold(filepath.Dir(path), certification) ||
		len(leaf) != windowsNamespacePurgeCertRunIDLength ||
		leaf != strings.ToLower(leaf) {
		return fmt.Errorf("enterprise hooks: namespace cleanup root is outside the exact DefenseClaw install layouts")
	}
	for _, character := range leaf {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return fmt.Errorf("enterprise hooks: certification namespace cleanup root has an invalid run ID")
		}
	}
	return nil
}

func parseWindowsNamespacePurgeGatewaySID(value string) (*windows.SID, error) {
	parts := strings.Split(value, "-")
	if len(parts) != 9 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "80" {
		return nil, fmt.Errorf("enterprise hooks: namespace cleanup gateway SID is not an exact NT SERVICE SID")
	}
	for _, part := range parts[4:] {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, fmt.Errorf("enterprise hooks: namespace cleanup gateway SID is noncanonical")
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(parsed, 10) != part {
			return nil, fmt.Errorf("enterprise hooks: namespace cleanup gateway SID is noncanonical")
		}
	}
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || sid.String() != value {
		return nil, fmt.Errorf("enterprise hooks: namespace cleanup gateway SID is invalid")
	}
	return sid, nil
}

func windowsNamespacePurgeCanonicalDescriptors(
	gatewaySID string,
) (*windowsNamespacePurgeDescriptorSet, error) {
	adminDirectory, err := windowsTargetsManifestCanonicalDescriptor(true)
	if err != nil {
		return nil, err
	}
	adminFile, err := windowsTargetsManifestCanonicalDescriptor(false)
	if err != nil {
		return nil, err
	}
	build := func(sddl, label string) (*windows.SECURITY_DESCRIPTOR, error) {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: build canonical namespace cleanup %s descriptor: %w", label, err)
		}
		return descriptor, nil
	}
	installDirectory, err := build(
		"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
		"InstallDirectory",
	)
	if err != nil {
		return nil, err
	}
	serviceInstallDirectory, err := build(
		fmt.Sprintf(
			"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;%s)",
			gatewaySID,
		),
		"ServiceInstallDirectory",
	)
	if err != nil {
		return nil, err
	}
	installFile, err := build(
		"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)",
		"InstallFile",
	)
	if err != nil {
		return nil, err
	}
	serviceInstallFile, err := build(
		fmt.Sprintf(
			"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;%s)",
			gatewaySID,
		),
		"ServiceInstallFile",
	)
	if err != nil {
		return nil, err
	}
	return &windowsNamespacePurgeDescriptorSet{
		directories: []*windows.SECURITY_DESCRIPTOR{
			adminDirectory,
			installDirectory,
			serviceInstallDirectory,
		},
		files: []*windows.SECURITY_DESCRIPTOR{
			adminFile,
			installFile,
			serviceInstallFile,
		},
		quarantine: adminDirectory,
	}, nil
}

func windowsNamespacePurgeDescriptorsEqual(
	actual, expected *windows.SECURITY_DESCRIPTOR,
) (bool, error) {
	if actual == nil || expected == nil || !actual.IsValid() || !expected.IsValid() {
		return false, fmt.Errorf("security descriptor is unavailable or invalid")
	}
	actualControl, _, err := actual.Control()
	if err != nil {
		return false, err
	}
	expectedControl, _, err := expected.Control()
	if err != nil {
		return false, err
	}
	// NTFS may add the benign AutoInherited provenance bit when persisting an
	// otherwise identical protected descriptor. No owner, group, DACL, ACE, or
	// other control-bit difference is accepted.
	actualControl &^= windows.SE_DACL_AUTO_INHERITED
	expectedControl &^= windows.SE_DACL_AUTO_INHERITED
	if actualControl != expectedControl {
		return false, nil
	}
	actualOwner, actualOwnerDefaulted, err := actual.Owner()
	if err != nil {
		return false, err
	}
	expectedOwner, expectedOwnerDefaulted, err := expected.Owner()
	if err != nil {
		return false, err
	}
	if actualOwner == nil || expectedOwner == nil ||
		actualOwnerDefaulted != expectedOwnerDefaulted ||
		!actualOwner.Equals(expectedOwner) {
		return false, nil
	}
	actualGroup, actualGroupDefaulted, err := actual.Group()
	if err != nil {
		return false, err
	}
	expectedGroup, expectedGroupDefaulted, err := expected.Group()
	if err != nil {
		return false, err
	}
	if actualGroup == nil || expectedGroup == nil ||
		actualGroupDefaulted != expectedGroupDefaulted ||
		!actualGroup.Equals(expectedGroup) {
		return false, nil
	}
	actualDACL, actualDACLDefaulted, err := actual.DACL()
	if err != nil {
		return false, err
	}
	expectedDACL, expectedDACLDefaulted, err := expected.DACL()
	if err != nil {
		return false, err
	}
	if actualDACL == nil || expectedDACL == nil || actualDACLDefaulted != expectedDACLDefaulted {
		return false, nil
	}
	actualBytes, err := windowsNamespacePurgeACLBytes(actualDACL)
	if err != nil {
		return false, err
	}
	expectedBytes, err := windowsNamespacePurgeACLBytes(expectedDACL)
	if err != nil {
		return false, err
	}
	equal := bytes.Equal(actualBytes, expectedBytes)
	runtime.KeepAlive(actual)
	runtime.KeepAlive(expected)
	return equal, nil
}

func windowsNamespacePurgeACLBytes(acl *windows.ACL) ([]byte, error) {
	if acl == nil {
		return nil, fmt.Errorf("DACL is unavailable")
	}
	header := unsafe.Slice((*byte)(unsafe.Pointer(acl)), windowsNamespacePurgeACLHeaderSize)
	size := int(binary.LittleEndian.Uint16(header[2:4]))
	if size < windowsNamespacePurgeACLHeaderSize || size > windowsNamespacePurgeMaxDescriptorSize {
		return nil, fmt.Errorf("DACL length is invalid")
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(acl)), size), nil
}

func purgeWindowsNamespaceRootPrivileged(
	request WindowsNamespacePurgeRequest,
	descriptors *windowsNamespacePurgeDescriptorSet,
	report *WindowsNamespacePurgeReport,
) error {
	if request.ExpectedIdentity == "" {
		exists, err := windowsNamespacePurgeRootExists(request.Root)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("enterprise hooks: Windows namespace purge root appeared without an authenticated identity")
		}
		return nil
	}

	parentPath := filepath.Dir(request.Root)
	if err := windowsNamespacePurgeAncestorTrust(parentPath); err != nil {
		return fmt.Errorf("enterprise hooks: reject namespace cleanup parent: %w", err)
	}
	parent, err := openWindowsNamespacePurgeParent(parentPath)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(parent)
	executableHandle, executableIdentity, err := windowsNamespacePurgeExecutable()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(executableHandle)

	rootAccess := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES |
		windows.READ_CONTROL | windows.SYNCHRONIZE | windows.DELETE |
		windows.FILE_WRITE_ATTRIBUTES | windows.WRITE_DAC | windows.WRITE_OWNER)
	rootHandle, err := openWindowsNamespacePurgeChild(
		parent,
		filepath.Base(request.Root),
		rootAccess,
		true,
		0,
	)
	if err != nil {
		if windowsNamespacePurgeChildMissing(err) {
			return fmt.Errorf("enterprise hooks: authenticated Windows namespace purge root is absent")
		}
		return fmt.Errorf("enterprise hooks: open Windows namespace purge root without following: %w", err)
	}
	rootIdentity, err := windowsManagedRuntimeHandleIdentity(rootHandle, true)
	if err != nil {
		_ = windows.CloseHandle(rootHandle)
		return fmt.Errorf("enterprise hooks: inspect Windows namespace purge root: %w", err)
	}
	if rootIdentity != request.ExpectedIdentity {
		_ = windows.CloseHandle(rootHandle)
		return fmt.Errorf("enterprise hooks: Windows namespace purge root identity changed")
	}

	root := &windowsNamespacePurgeNode{
		parent:    parent,
		name:      filepath.Base(request.Root),
		label:     request.Root,
		handle:    rootHandle,
		directory: true,
		identity:  rootIdentity,
	}
	defer root.close()
	budget := &windowsNamespacePurgeBudget{entries: 1}
	if err := pinWindowsNamespacePurgeTree(root, 0, budget, descriptors, true); err != nil {
		return err
	}
	if windowsNamespacePurgeTreeContainsIdentity(root, executableIdentity) {
		return fmt.Errorf("enterprise hooks: namespace cleanup refuses to remove its running executable identity")
	}
	if windowsNamespacePurgePostPin != nil {
		if err := windowsNamespacePurgePostPin(request.Root); err != nil {
			return fmt.Errorf("enterprise hooks: Windows namespace purge post-pin check: %w", err)
		}
	}
	if err := revalidateWindowsNamespacePurgeTree(root, descriptors, true, false); err != nil {
		return fmt.Errorf("enterprise hooks: Windows namespace purge tree changed after full preflight: %w", err)
	}
	if request.ValidateOnly {
		return nil
	}
	if err := applyWindowsNamespacePurgeQuarantine(root.handle, descriptors.quarantine); err != nil {
		return err
	}
	if err := revalidateWindowsNamespacePurgeTree(root, descriptors, true, true); err != nil {
		return fmt.Errorf("enterprise hooks: Windows namespace purge tree changed after quarantine: %w", err)
	}
	if windowsNamespacePurgePostValidation != nil {
		if err := windowsNamespacePurgePostValidation(root); err != nil {
			return fmt.Errorf("enterprise hooks: Windows namespace purge post-validation check: %w", err)
		}
	}
	if err := deleteWindowsNamespacePurgeNode(root, descriptors, true, report); err != nil {
		return err
	}
	report.Removed = true
	return nil
}

func windowsNamespacePurgeRootExists(path string) (bool, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: inspect absent Windows namespace purge root: %w", err)
	}
	if closeErr := windows.CloseHandle(handle); closeErr != nil {
		return false, fmt.Errorf("enterprise hooks: close Windows namespace purge root probe: %w", closeErr)
	}
	return true, nil
}

func openWindowsNamespacePurgeParent(path string) (windows.Handle, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: pin namespace cleanup parent without following: %w", err)
	}
	identity, identityErr := windowsManagedRuntimeHandleIdentity(handle, true)
	if identityErr != nil || identity == "" {
		_ = windows.CloseHandle(handle)
		if identityErr == nil {
			identityErr = fmt.Errorf("parent identity is unavailable")
		}
		return 0, fmt.Errorf("enterprise hooks: reject namespace cleanup parent handle: %w", identityErr)
	}
	return handle, nil
}

func openWindowsNamespacePurgeExecutable() (windows.Handle, string, error) {
	path, err := os.Executable()
	if err != nil {
		return 0, "", fmt.Errorf("enterprise hooks: resolve namespace cleanup executable: %w", err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return 0, "", fmt.Errorf("enterprise hooks: resolve absolute namespace cleanup executable: %w", err)
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return 0, "", fmt.Errorf("enterprise hooks: namespace cleanup executable path is untrusted: %w", err)
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return 0, "", err
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, "", fmt.Errorf("enterprise hooks: pin namespace cleanup executable without following: %w", err)
	}
	identity, err := windowsNamespacePurgeHandleIdentity(handle, false, false)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return 0, "", fmt.Errorf("enterprise hooks: inspect namespace cleanup executable identity: %w", err)
	}
	return handle, identity, nil
}

func windowsNamespacePurgeTreeContainsIdentity(
	node *windowsNamespacePurgeNode,
	identity string,
) bool {
	if node == nil || identity == "" {
		return false
	}
	if !node.directory && node.identity == identity {
		return true
	}
	for _, child := range node.children {
		if windowsNamespacePurgeTreeContainsIdentity(child, identity) {
			return true
		}
	}
	return false
}

func openWindowsNamespacePurgeChild(
	parent windows.Handle,
	name string,
	access uint32,
	directoryOnly bool,
	share uint32,
) (windows.Handle, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\\/\x00") {
		return 0, fmt.Errorf("enterprise hooks: invalid namespace cleanup child name")
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	options := uint32(
		windows.FILE_OPEN_REPARSE_POINT |
			windows.FILE_OPEN_FOR_BACKUP_INTENT |
			windows.FILE_SYNCHRONOUS_IO_NONALERT,
	)
	if directoryOnly {
		options |= windows.FILE_DIRECTORY_FILE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		access,
		&attributes,
		&status,
		nil,
		0,
		share,
		windows.FILE_OPEN,
		options,
		0,
		0,
	)
	return handle, err
}

func windowsNamespacePurgeChildMissing(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_DELETE_PENDING) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func pinWindowsNamespacePurgeTree(
	node *windowsNamespacePurgeNode,
	depth int,
	budget *windowsNamespacePurgeBudget,
	descriptors *windowsNamespacePurgeDescriptorSet,
	root bool,
) error {
	if node == nil || node.handle == 0 || budget == nil {
		return fmt.Errorf("enterprise hooks: Windows namespace purge preflight state is unavailable")
	}
	if depth > windowsQuarantineMaxDepth {
		return fmt.Errorf(
			"enterprise hooks: Windows namespace purge exceeds maximum depth %d",
			windowsQuarantineMaxDepth,
		)
	}
	if err := validateWindowsNamespacePurgeNode(node, descriptors, root, false); err != nil {
		return err
	}
	if !node.directory {
		return nil
	}
	remaining := windowsQuarantineMaxEntries - budget.entries
	names, err := windowsNamespacePurgeDirectoryNames(node.handle, remaining)
	if err != nil {
		return fmt.Errorf("enterprise hooks: enumerate Windows namespace purge directory %s: %w", node.label, err)
	}
	node.names = make(map[string]struct{}, len(names))
	for _, name := range names {
		budget.entries++
		if budget.entries > windowsQuarantineMaxEntries {
			return fmt.Errorf(
				"enterprise hooks: Windows namespace purge exceeds maximum entry count %d",
				windowsQuarantineMaxEntries,
			)
		}
		node.names[name] = struct{}{}
		access := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES |
			windows.READ_CONTROL | windows.SYNCHRONIZE | windows.DELETE |
			windows.FILE_WRITE_ATTRIBUTES)
		handle, err := openWindowsNamespacePurgeChild(node.handle, name, access, false, 0)
		if err != nil {
			return fmt.Errorf("enterprise hooks: pin Windows namespace purge child %q without following: %w", name, err)
		}
		directory, identity, err := inspectWindowsNamespacePurgeHandle(handle)
		if err != nil {
			_ = windows.CloseHandle(handle)
			return fmt.Errorf("enterprise hooks: reject Windows namespace purge child %q: %w", name, err)
		}
		child := &windowsNamespacePurgeNode{
			parent:    node.handle,
			name:      name,
			label:     filepath.Join(node.label, name),
			handle:    handle,
			directory: directory,
			identity:  identity,
		}
		node.children = append(node.children, child)
		if err := pinWindowsNamespacePurgeTree(
			child,
			depth+1,
			budget,
			descriptors,
			false,
		); err != nil {
			return err
		}
	}
	return nil
}

func inspectWindowsNamespacePurgeHandle(handle windows.Handle) (bool, string, error) {
	attributes, err := windowsQuarantineHandleAttributes(handle)
	if err != nil {
		return false, "", err
	}
	if attributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return false, "", fmt.Errorf("object is a reparse point or device")
	}
	directory := attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	identity, err := windowsNamespacePurgeHandleIdentity(handle, directory, true)
	if err != nil {
		return false, "", err
	}
	return directory, identity, nil
}

func windowsNamespacePurgeHandleIdentity(
	handle windows.Handle,
	directory bool,
	requireSingleLink bool,
) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return "", fmt.Errorf("object has an unsafe type")
	}
	if !directory && requireSingleLink && info.NumberOfLinks != 1 {
		return "", fmt.Errorf("file has %d hard links", info.NumberOfLinks)
	}
	return fmt.Sprintf(
		"%08x:%08x%08x",
		info.VolumeSerialNumber,
		info.FileIndexHigh,
		info.FileIndexLow,
	), nil
}

func validateWindowsNamespacePurgeNode(
	node *windowsNamespacePurgeNode,
	descriptors *windowsNamespacePurgeDescriptorSet,
	root bool,
	rootQuarantined bool,
) error {
	if node == nil || node.handle == 0 {
		return fmt.Errorf("enterprise hooks: Windows namespace purge handle is unavailable")
	}
	directory, identity, err := inspectWindowsNamespacePurgeHandle(node.handle)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Windows namespace purge object %s: %w", node.label, err)
	}
	if directory != node.directory || identity != node.identity {
		return fmt.Errorf("enterprise hooks: Windows namespace purge object identity changed: %s", node.label)
	}
	var allowed []*windows.SECURITY_DESCRIPTOR
	if root && rootQuarantined {
		allowed = []*windows.SECURITY_DESCRIPTOR{descriptors.quarantine}
	} else if node.directory {
		allowed = descriptors.directories
		if root {
			// A prior crash may leave this exact authenticated inode already
			// quarantined. Accept only the built-in canonical quarantine form.
			allowed = append(append([]*windows.SECURITY_DESCRIPTOR(nil), allowed...), descriptors.quarantine)
		}
	} else {
		allowed = descriptors.files
	}
	matched, err := windowsNamespacePurgeHandleMatches(node.handle, allowed)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect Windows namespace purge descriptor for %s: %w", node.label, err)
	}
	if !matched {
		return fmt.Errorf("enterprise hooks: Windows namespace purge object has a foreign descriptor: %s", node.label)
	}
	return nil
}

func windowsNamespacePurgeHandleMatches(
	handle windows.Handle,
	allowed []*windows.SECURITY_DESCRIPTOR,
) (bool, error) {
	actual, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	if actual == nil {
		return false, fmt.Errorf("security descriptor is unavailable")
	}
	for _, candidate := range allowed {
		if candidate == nil {
			return false, fmt.Errorf("allowed security descriptor is unavailable")
		}
		equal, err := windowsNamespacePurgeDescriptorsEqual(actual, candidate)
		runtime.KeepAlive(candidate)
		if err != nil {
			return false, err
		}
		if equal {
			return true, nil
		}
	}
	return false, nil
}

func revalidateWindowsNamespacePurgeTree(
	node *windowsNamespacePurgeNode,
	descriptors *windowsNamespacePurgeDescriptorSet,
	root bool,
	rootQuarantined bool,
) error {
	if err := validateWindowsNamespacePurgeNode(node, descriptors, root, rootQuarantined); err != nil {
		return err
	}
	if node.directory {
		if err := requireWindowsNamespacePurgeNames(node.handle, node.names, node.label); err != nil {
			return err
		}
	}
	for _, child := range node.children {
		if err := revalidateWindowsNamespacePurgeTree(child, descriptors, false, false); err != nil {
			return err
		}
	}
	return nil
}

func requireWindowsNamespacePurgeNames(
	handle windows.Handle,
	expected map[string]struct{},
	label string,
) error {
	names, err := windowsNamespacePurgeDirectoryNames(handle, len(expected))
	if err != nil {
		return fmt.Errorf("enterprise hooks: Windows namespace purge names changed for %s: %w", label, err)
	}
	if len(names) != len(expected) {
		return fmt.Errorf("enterprise hooks: Windows namespace purge names changed for %s", label)
	}
	for _, name := range names {
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("enterprise hooks: Windows namespace purge directory %s gained entry %q", label, name)
		}
	}
	return nil
}

func windowsNamespacePurgeDirectoryNames(handle windows.Handle, maximum int) ([]string, error) {
	if maximum < 0 || maximum > windowsQuarantineMaxEntries {
		return nil, fmt.Errorf("directory enumeration bound is invalid")
	}
	aligned := make([]uint64, windowsQuarantineDirectoryBufferSize/8)
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&aligned[0])), windowsQuarantineDirectoryBufferSize)
	names := make([]string, 0, min(maximum, 16))
	infoClass := uint32(windows.FileFullDirectoryRestartInfo)
	for {
		err := windows.GetFileInformationByHandleEx(
			handle,
			infoClass,
			&buffer[0],
			uint32(len(buffer)),
		)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		for offset := 0; ; {
			if offset < 0 || offset+windowsFullDirectoryInfoNameOffset > len(buffer) {
				return nil, fmt.Errorf("invalid directory record")
			}
			next := *(*uint32)(unsafe.Pointer(&buffer[offset]))
			nameBytes := *(*uint32)(unsafe.Pointer(&buffer[offset+60]))
			if nameBytes%2 != 0 ||
				uint64(offset)+windowsFullDirectoryInfoNameOffset+uint64(nameBytes) > uint64(len(buffer)) {
				return nil, fmt.Errorf("invalid directory name length")
			}
			nameUnits := unsafe.Slice(
				(*uint16)(unsafe.Pointer(&buffer[offset+windowsFullDirectoryInfoNameOffset])),
				int(nameBytes/2),
			)
			name := windows.UTF16ToString(nameUnits)
			if name != "." && name != ".." {
				if name == "" || strings.ContainsAny(name, "\\/\x00") {
					return nil, fmt.Errorf("invalid directory child name")
				}
				if len(names) >= maximum {
					return nil, fmt.Errorf("directory exceeds bounded entry count %d", maximum)
				}
				names = append(names, name)
			}
			if next == 0 {
				break
			}
			if next < windowsFullDirectoryInfoNameOffset ||
				uint64(offset)+uint64(next) >= uint64(len(buffer)) {
				return nil, fmt.Errorf("invalid directory continuation")
			}
			offset += int(next)
		}
		infoClass = uint32(windows.FileFullDirectoryInfo)
	}
}

func applyWindowsNamespacePurgeQuarantine(
	handle windows.Handle,
	descriptor *windows.SECURITY_DESCRIPTOR,
) error {
	if descriptor == nil {
		return fmt.Errorf("enterprise hooks: Windows namespace quarantine descriptor is unavailable")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve Windows namespace quarantine owner: %w", err)
	}
	if owner == nil {
		return fmt.Errorf("enterprise hooks: Windows namespace quarantine owner is unavailable")
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve Windows namespace quarantine group: %w", err)
	}
	if group == nil {
		return fmt.Errorf("enterprise hooks: Windows namespace quarantine group is unavailable")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve Windows namespace quarantine DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("enterprise hooks: Windows namespace quarantine DACL is unavailable")
	}
	securityInformation := windows.SECURITY_INFORMATION(
		windows.OWNER_SECURITY_INFORMATION |
			windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION |
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	err = windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		securityInformation,
		owner,
		group,
		dacl,
		nil,
	)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return fmt.Errorf("enterprise hooks: quarantine Windows namespace root by handle: %w", err)
	}
	return nil
}

func deleteWindowsNamespacePurgeNode(
	node *windowsNamespacePurgeNode,
	descriptors *windowsNamespacePurgeDescriptorSet,
	root bool,
	report *WindowsNamespacePurgeReport,
) error {
	if err := validateWindowsNamespacePurgeNode(node, descriptors, root, root); err != nil {
		return fmt.Errorf("enterprise hooks: Windows namespace purge object changed before deletion: %w", err)
	}
	if node.directory {
		if err := requireWindowsNamespacePurgeNames(node.handle, node.names, node.label); err != nil {
			return err
		}
	}
	for _, child := range node.children {
		if err := deleteWindowsNamespacePurgeNode(child, descriptors, false, report); err != nil {
			return err
		}
	}
	if node.directory {
		names, err := windowsNamespacePurgeDirectoryNames(node.handle, 0)
		if err != nil {
			return fmt.Errorf("enterprise hooks: Windows namespace purge directory is not empty after child removal: %s: %w", node.label, err)
		}
		if len(names) != 0 {
			return fmt.Errorf("enterprise hooks: Windows namespace purge directory is not empty after child removal: %s", node.label)
		}
	}
	attributes, err := windowsQuarantineHandleAttributes(node.handle)
	if err != nil {
		return err
	}
	if !node.directory {
		identity, err := windowsNamespacePurgeHandleIdentity(node.handle, false, true)
		if err != nil || identity != node.identity {
			if err == nil {
				err = fmt.Errorf("file identity changed")
			}
			return fmt.Errorf(
				"enterprise hooks: Windows namespace purge file changed immediately before disposition %s: %w",
				node.label,
				err,
			)
		}
	}
	if err := markWindowsQuarantineHandleForDeletion(node.handle, attributes); err != nil {
		return fmt.Errorf("enterprise hooks: mark Windows namespace purge object for deletion %s: %w", node.label, err)
	}
	if err := windows.CloseHandle(node.handle); err != nil {
		return fmt.Errorf("enterprise hooks: close deleted Windows namespace purge object %s: %w", node.label, err)
	}
	node.handle = 0
	if err := requireWindowsNamespacePurgeChildAbsent(node.parent, node.name); err != nil {
		return fmt.Errorf("enterprise hooks: Windows namespace purge binding remains for %s: %w", node.label, err)
	}
	report.EntriesRemoved++
	return nil
}

func requireWindowsNamespacePurgeChildAbsent(parent windows.Handle, name string) error {
	handle, err := openWindowsNamespacePurgeChild(
		parent,
		name,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		false,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
	)
	if windowsNamespacePurgeChildMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_ = windows.CloseHandle(handle)
	return windows.ERROR_ALREADY_EXISTS
}
