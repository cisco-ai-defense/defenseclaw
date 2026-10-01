// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Darwin
import Foundation
import Security

enum GatewayAdminFailure: LocalizedError {
    case refused(String)
    case authorization(OSStatus)

    var exitCode: Int32 {
        if case .authorization(errAuthorizationCanceled) = self { return 130 }
        return 77
    }

    var errorDescription: String? {
        switch self {
        case .refused(let message):
            return message
        case .authorization(errAuthorizationCanceled):
            return "Administrator authorization cancelled. No gateway action was performed. (macOS \(errAuthorizationCanceled))"
        case .authorization(let status):
            return "macOS could not authorize this gateway action (status \(status)). No gateway action was performed. Try again and complete the system authorization prompt."
        }
    }
}

/// Request actual authorization immediately before privileged work. A successful
/// zero-timeout preauthorization in the app is only permission to proceed to
/// this check; it does not contain an already granted administrator credential.
/// The injected request keeps the real flag handoff and no-work-on-denial
/// boundary testable without displaying a password prompt in automated tests.
enum GatewayAdminAuthorization {
    static func perform<Result>(
        request: (AuthorizationFlags) -> OSStatus,
        operation: () throws -> Result
    ) throws -> Result {
        let status = request([.extendRights, .interactionAllowed])
        guard status == errAuthorizationSuccess else {
            throw GatewayAdminFailure.authorization(status)
        }
        return try operation()
    }
}

struct InvokingAccount {
    let uid: uid_t
    let gid: gid_t
    let name: String
    let home: String

    init(uid: uid_t) throws {
        guard uid > 0 else {
            throw GatewayAdminFailure.refused("An authenticated login account is required.")
        }
        var record = passwd()
        var found: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 65_536)
        let status = buffer.withUnsafeMutableBufferPointer {
            getpwuid_r(uid, &record, $0.baseAddress, $0.count, &found)
        }
        guard status == 0, found != nil,
              let accountName = record.pw_name, let accountHome = record.pw_dir else {
            throw GatewayAdminFailure.refused("The requesting account could not be resolved.")
        }
        self.uid = uid
        gid = record.pw_gid
        name = String(cString: accountName)
        home = String(cString: accountHome)
        withExtendedLifetime(buffer) { }
        guard GatewayAdminPolicy.isCanonicalAbsolutePath(home), home != "/", !name.isEmpty else {
            throw GatewayAdminFailure.refused("The requesting account has no valid home directory.")
        }
    }
}

enum GatewayAdminTrust {
    static let stagingRoot = "/Library/PrivilegedHelperTools/com.cisco.defenseclaw.macos.GatewayAdmin"
    static let legacyStagedGateway = stagingRoot + "/defenseclaw-gateway"

    // UID comes only from the authenticated XPC account, never a request field.
    // Operator-controlled executables must never be reused across accounts.
    static func stagingDirectory(uid: uid_t) -> String {
        stagingRoot + "/uid-" + String(uid)
    }

    static func verifySignature(at path: String, requirement: String) throws {
        var code: SecStaticCode?
        var required: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code,
              SecRequirementCreateWithString(requirement as CFString, [], &required) == errSecSuccess,
              let required,
              SecStaticCodeCheckValidity(
                  code,
                  SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures),
                  required
              ) == errSecSuccess else {
            throw GatewayAdminFailure.refused(
                "Administrator gateway control requires the original Developer ID signed app and helper. Reinstall the signed application."
            )
        }
    }

    static func validateAuthorization(_ data: Data) throws {
        try withAuthorization(data) { }
    }

    static func withAuthorization<Result>(_ data: Data, operation: () throws -> Result) throws -> Result {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw GatewayAdminFailure.refused("Administrator authorization is missing or invalid.")
        }
        var definition: CFDictionary?
        guard AuthorizationRightGet(GatewayAdminPolicy.authorizationRight, &definition) == errAuthorizationSuccess,
              GatewayAdminPolicy.authorizationDefinitionIsSafe(definition) else {
            throw GatewayAdminFailure.refused("The administrator authorization rule is unavailable or unsafe. Retry from the signed app to repair its authorization setup.")
        }
        var external = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &external) { data.copyBytes(to: $0) }
        var authorization: AuthorizationRef?
        let imported = AuthorizationCreateFromExternalForm(&external, &authorization)
        guard imported == errAuthorizationSuccess, let authorization else {
            throw GatewayAdminFailure.authorization(imported == errAuthorizationSuccess ? errAuthorizationInvalidRef : imported)
        }
        // Keep the imported reference alive through the action, then destroy
        // its grant. Authorization Services displays the native system prompt;
        // this helper never asks for or receives an administrator password.
        defer { AuthorizationFree(authorization, [.destroyRights]) }
        return try GatewayAdminAuthorization.perform(request: { flags in
            GatewayAdminPolicy.authorizationRight.withCString { name in
                var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                return withUnsafeMutablePointer(to: &item) { itemPointer in
                    var rights = AuthorizationRights(count: 1, items: itemPointer)
                    return AuthorizationCopyRights(authorization, &rights, nil, flags, nil)
                }
            }
        }, operation: operation)
    }

    /// Reject every symlink and write-granting ACL on the selected installation.
    /// Owner/root writes are allowed because this is that account's explicitly
    /// authorized installation; group and other users must not control it.
    /// As with sudo, authorization trusts that installation's runtime settings,
    /// including configured data locations and scanner programs. This helper
    /// does not promise to sandbox the already privileged gateway.
    static func validateInstallation(home: String, config: String, account: InvokingAccount) throws {
        guard GatewayAdminPolicy.isStrictDescendant(home, of: account.home),
              GatewayAdminPolicy.isStrictDescendant(config, of: home) else {
            throw GatewayAdminFailure.refused("Administrator control only supports a configuration inside your selected DefenseClaw home, within your own account home.")
        }
        try validatePath(home, permittedOwner: account.uid, finalIsDirectory: true)
        try validatePath(config, permittedOwner: account.uid, finalIsDirectory: false)
    }

    static func validatePath(_ path: String, permittedOwner: uid_t?, finalIsDirectory: Bool) throws {
        guard GatewayAdminPolicy.isCanonicalAbsolutePath(path) else {
            throw GatewayAdminFailure.refused("A canonical absolute installation path is required.")
        }
        let components = path.split(separator: "/")
        var current = ""
        for (index, component) in components.enumerated() {
            current += "/" + component
            var metadata = stat()
            guard lstat(current, &metadata) == 0 else {
                throw GatewayAdminFailure.refused("A required administrator gateway path is missing or unreadable.")
            }
            let mode = metadata.st_mode & S_IFMT
            let directoryRequired = index < components.count - 1 || finalIsDirectory
            guard mode == (directoryRequired ? S_IFDIR : S_IFREG),
                  metadata.st_uid == 0 || metadata.st_uid == permittedOwner,
                  metadata.st_mode & 0o022 == 0 else {
                throw GatewayAdminFailure.refused("Administrator gateway control refused a symlink, unexpected owner, or writable shared path.")
            }
            try rejectWriteACL(at: current)
        }
    }

    private static func rejectWriteACL(at path: String) throws {
        guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT || errno == ENOTSUP { return }
            throw GatewayAdminFailure.refused("Could not verify administrator gateway path permissions.")
        }
        try rejectWriteACL(acl)
    }

    private static func rejectWriteACL(on descriptor: Int32) throws {
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            // macOS reports ENOENT when this open file has no extended ACL.
            if errno == ENOENT || errno == ENOTSUP { return }
            throw GatewayAdminFailure.refused("Could not verify the installed gateway's permissions.")
        }
        try rejectWriteACL(acl)
    }

    private static func rejectWriteACL(_ acl: acl_t) throws {
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        var selector = ACL_FIRST_ENTRY
        while acl_get_entry(acl, Int32(selector.rawValue), &entry) == 0 {
            selector = ACL_NEXT_ENTRY
            guard let entry else { continue }
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(entry, &tag) == 0 else {
                throw GatewayAdminFailure.refused("Could not verify a filesystem access rule.")
            }
            guard tag == ACL_EXTENDED_ALLOW else { continue }
            var permissions: acl_permset_t?
            guard acl_get_permset(entry, &permissions) == 0, let permissions else {
                throw GatewayAdminFailure.refused("Could not verify a filesystem access rule.")
            }
            let writable = [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
                            ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
            if writable.contains(where: { acl_get_perm_np(permissions, $0) == 1 }) {
                throw GatewayAdminFailure.refused("Administrator gateway control refused a path with additional write permissions.")
            }
        }
    }

    /// Walk with directory descriptors so replacing a user-owned parent with
    /// a symlink cannot redirect a privileged source read outside this path.
    static func openInstalledGateway(_ path: String, permittedOwner: uid_t) throws -> Int32 {
        guard GatewayAdminPolicy.isCanonicalAbsolutePath(path) else {
            throw GatewayAdminFailure.refused("A canonical installed gateway path is required.")
        }
        let components = path.split(separator: "/").map(String.init)
        guard !components.isEmpty else {
            throw GatewayAdminFailure.refused("An installed gateway executable is required.")
        }
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw GatewayAdminFailure.refused("Could not open the filesystem root.") }
        do {
            for (index, component) in components.enumerated() {
                let directory = index < components.count - 1
                let next = openat(descriptor, component,
                                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (directory ? O_DIRECTORY : 0))
                guard next >= 0 else {
                    throw GatewayAdminFailure.refused("The installed gateway is missing, unreadable, or uses a symlink. Install a regular gateway executable at ~/.local/bin/defenseclaw-gateway.")
                }
                close(descriptor)
                descriptor = next
                var metadata = stat()
                guard fstat(descriptor, &metadata) == 0,
                      metadata.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
                      metadata.st_uid == 0 || metadata.st_uid == permittedOwner,
                      metadata.st_mode & 0o022 == 0,
                      directory || metadata.st_mode & 0o111 != 0 else {
                    throw GatewayAdminFailure.refused("The installed gateway has an unexpected owner, type, or writable shared path.")
                }
                try rejectWriteACL(on: descriptor)
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    static func scannerSearchPath(home: String, account: InvokingAccount) -> String {
        var directories = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        // Scanner commands in the explicitly authorized operator config may
        // use the selected virtualenv or installed user CLI. Never inherit the
        // GUI process PATH, and skip optional directories shared with others.
        let optional = [home + "/.venv/bin", account.home + "/.local/bin",
                        "/opt/homebrew/bin", "/usr/local/bin"]
        for directory in optional {
            guard (try? validatePath(directory, permittedOwner: account.uid, finalIsDirectory: true)) != nil else { continue }
            if !directories.contains(directory) { directories.append(directory) }
        }
        return directories.joined(separator: ":")
    }

    static func validateHelperBundle() throws {
        guard let executable = Bundle.main.executableURL else {
            throw GatewayAdminFailure.refused("The administrator helper executable could not be located.")
        }
        let helper = executable.path
        let suffix = "/" + GatewayAdminPolicy.helperRelativePath
        guard helper.hasSuffix(suffix) else {
            throw GatewayAdminFailure.refused("The administrator helper must run from its signed app bundle.")
        }
        let app = String(helper.dropLast(suffix.count))
        guard app.hasSuffix(".app") else {
            throw GatewayAdminFailure.refused("The administrator helper has an invalid app location.")
        }
        try verifySignature(at: helper, requirement: GatewayAdminPolicy.helperRequirement)
        try verifySignature(at: app, requirement: GatewayAdminPolicy.appRequirement)
    }

    static func prepareStagingDirectory(account: InvokingAccount) throws -> Int32 {
        let stagedDirectory = stagingDirectory(uid: account.uid)
        // Only fixed, root-owned directories are created. No client path is
        // ever used for a privileged copy, rename, chmod, or deletion.
        for directory in ["/Library/PrivilegedHelperTools", stagingRoot, stagedDirectory] {
            if mkdir(directory, directory == "/Library/PrivilegedHelperTools" ? 0o755 : 0o700) != 0, errno != EEXIST {
                throw GatewayAdminFailure.refused("Could not create the private administrator gateway directory.")
            }
            try validatePath(directory, permittedOwner: nil, finalIsDirectory: true)
        }
        let directory = open(stagedDirectory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else {
            throw GatewayAdminFailure.refused("Could not open the private administrator gateway directory.")
        }
        var metadata = stat()
        guard fstat(directory, &metadata) == 0, metadata.st_uid == 0,
              metadata.st_mode & 0o077 == 0 else {
            close(directory)
            throw GatewayAdminFailure.refused("The administrator gateway directory is not private and root-owned.")
        }
        return directory
    }

    static func installedGatewayPath(account: InvokingAccount) -> String {
        account.home + "/.local/bin/defenseclaw-gateway"
    }

    static func prepareInstalledGateway(account: InvokingAccount) throws -> GatewayAdminCandidate {
        try validateHelperBundle()
        let directory = try prepareStagingDirectory(account: account)
        defer { close(directory) }
        return try prepareGatewayCopy(source: installedGatewayPath(account: account),
                                      permittedOwner: account.uid, directory: directory,
                                      directoryPath: stagingDirectory(uid: account.uid))
    }

    /// Copy only the operator's fixed installed executable. Tests call this
    /// same path with private fixtures; no executable path is accepted by XPC.
    #if GATEWAY_ADMIN_HELPER_TESTING
    static var sourceCopiedForTesting: (() throws -> Void)?
    #endif

    static func prepareGatewayCopy(source: String, permittedOwner: uid_t, directory: Int32,
                                   directoryPath: String) throws -> GatewayAdminCandidate {
        let sourceFD = try openInstalledGateway(source, permittedOwner: permittedOwner)
        defer { close(sourceFD) }
        var sourceMetadata = stat()
        guard fstat(sourceFD, &sourceMetadata) == 0,
              sourceMetadata.st_size > 0, sourceMetadata.st_size <= 536_870_912 else {
            throw GatewayAdminFailure.refused("The installed gateway has an invalid size.")
        }
        let identity = GatewayAdminFileIdentity(sourceMetadata)
        let temporaryName = ".gateway-" + UUID().uuidString
        let destination = openat(directory, temporaryName,
                                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o500)
        guard destination >= 0 else {
            throw GatewayAdminFailure.refused("Could not prepare a private administrator gateway copy.")
        }
        defer { close(destination) }
        var candidate: GatewayAdminCandidate?
        defer { if candidate == nil { _ = unlinkat(directory, temporaryName, 0) } }
        var buffer = [UInt8](repeating: 0, count: 65_536)
        var total: Int64 = 0
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(sourceFD, $0.baseAddress, $0.count) }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw GatewayAdminFailure.refused("Could not read the installed gateway.") }
            if count == 0 { break }
            total += Int64(count)
            guard total <= 536_870_912 else { throw GatewayAdminFailure.refused("The installed gateway exceeds the allowed size.") }
            var offset = 0
            while offset < count {
                let written = buffer.withUnsafeBytes {
                    Darwin.write(destination, $0.baseAddress!.advanced(by: offset), count - offset)
                }
                if written < 0, errno == EINTR { continue }
                guard written > 0 else { throw GatewayAdminFailure.refused("Could not write the private gateway copy.") }
                offset += written
            }
        }
        #if GATEWAY_ADMIN_HELPER_TESTING
        try sourceCopiedForTesting?()
        #endif
        var finalMetadata = stat()
        var namedMetadata = stat()
        guard total == sourceMetadata.st_size,
              fstat(sourceFD, &finalMetadata) == 0,
              lstat(source, &namedMetadata) == 0,
              GatewayAdminFileIdentity(finalMetadata) == identity,
              GatewayAdminFileIdentity(namedMetadata) == identity,
              fsync(destination) == 0 else {
            throw GatewayAdminFailure.refused("The installed gateway changed while being copied. No gateway action was performed; retry after its update completes.")
        }
        let temporaryPath = directoryPath + "/" + temporaryName
        // Integrity, not publisher identity: an explicitly authorized source
        // installation may use an ad-hoc signed Go executable. Validate the
        // immutable copied bytes before stopping or replacing a running copy.
        try verifyGatewayIntegrity(at: temporaryPath)
        candidate = try GatewayAdminCandidate(directory: directory, directoryPath: directoryPath,
                                               temporaryName: temporaryName)
        return candidate!
    }

    static func verifyGatewayIntegrity(at path: String) throws {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw GatewayAdminFailure.refused("Could not read the private gateway copy.") }
        defer { close(descriptor) }
        var magic: UInt32 = 0
        let count = withUnsafeMutableBytes(of: &magic) { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        let executableMagic: Set<UInt32> = [0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]
        guard count == MemoryLayout<UInt32>.size, executableMagic.contains(magic) else {
            throw GatewayAdminFailure.refused("The installed gateway must be a signed Mach-O executable; scripts and unsigned programs are not supported.")
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
            throw GatewayAdminFailure.refused("The installed gateway's code signature is invalid. Rebuild or reinstall the runtime before trying again.")
        }
    }

    /// Compare only immutable private copies, after source staging and code
    /// signature integrity validation. No caller-selected path reaches XPC.
    static func gatewayDigest(at path: String) throws -> SHA256.Digest {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { throw GatewayAdminFailure.refused("Could not compare the private gateway copies.") }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_size > 0, metadata.st_size <= 536_870_912 else {
            throw GatewayAdminFailure.refused("The private gateway copy has an invalid size or type.")
        }
        var hash = SHA256()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        var total: Int64 = 0
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw GatewayAdminFailure.refused("Could not compare the private gateway copies.") }
            if count == 0 { break }
            total += Int64(count)
            guard total <= 536_870_912 else { throw GatewayAdminFailure.refused("The private gateway copy exceeds the allowed size.") }
            hash.update(data: Data(buffer.prefix(count)))
        }
        var finalMetadata = stat()
        guard total == metadata.st_size, fstat(descriptor, &finalMetadata) == 0,
              GatewayAdminFileIdentity(metadata) == GatewayAdminFileIdentity(finalMetadata) else {
            throw GatewayAdminFailure.refused("The private gateway copy changed while being compared.")
        }
        return hash.finalize()
    }

    static func currentStagedGateway(account: InvokingAccount) throws -> String? {
        let directory = stagingDirectory(uid: account.uid)
        if let current = try existingPrivateGateway(directory: directory, requiresLegacyPublisher: false) {
            return current
        }
        // Older signed app versions used a global copy. It is a safe
        // migration fallback only under that original Developer ID requirement.
        // New operator-controlled copies are always isolated by account UID.
        return try existingPrivateGateway(directory: stagingRoot, requiresLegacyPublisher: true)
    }

    static func verifyLegacyGateway(at path: String) throws {
        try verifyGatewayIntegrity(at: path)
        try verifySignature(at: path, requirement: GatewayAdminPolicy.gatewayRequirement)
    }

    private static func existingPrivateGateway(directory: String, requiresLegacyPublisher: Bool) throws -> String? {
        let gateway = directory + "/defenseclaw-gateway"
        var metadata = stat()
        if lstat(gateway, &metadata) != 0 {
            if errno == ENOENT { return nil }
            throw GatewayAdminFailure.refused("Could not inspect the administrator gateway executable.")
        }
        try validatePath(directory, permittedOwner: nil, finalIsDirectory: true)
        var directoryMetadata = stat()
        guard lstat(directory, &directoryMetadata) == 0,
              directoryMetadata.st_mode & 0o077 == 0 else {
            throw GatewayAdminFailure.refused("The administrator gateway directory is not private.")
        }
        try validatePath(gateway, permittedOwner: nil, finalIsDirectory: false)
        guard metadata.st_mode & 0o111 != 0 else {
            throw GatewayAdminFailure.refused("The private administrator gateway is not executable.")
        }
        if requiresLegacyPublisher {
            try verifyLegacyGateway(at: gateway)
        } else {
            try verifyGatewayIntegrity(at: gateway)
        }
        return gateway
    }

}

struct GatewayAdminFileIdentity: Equatable {
    let device: dev_t
    let inode: ino_t
    let size: off_t
    let owner: uid_t
    let group: gid_t
    let mode: mode_t
    let modificationSeconds: Int
    let modificationNanoseconds: Int
    let changeSeconds: Int
    let changeNanoseconds: Int

    init(_ value: stat) {
        device = value.st_dev
        inode = value.st_ino
        size = value.st_size
        owner = value.st_uid
        group = value.st_gid
        mode = value.st_mode
        modificationSeconds = value.st_mtimespec.tv_sec
        modificationNanoseconds = value.st_mtimespec.tv_nsec
        changeSeconds = value.st_ctimespec.tv_sec
        changeNanoseconds = value.st_ctimespec.tv_nsec
    }
}

final class GatewayAdminCandidate {
    private let directory: Int32
    private let directoryPath: String
    private var temporaryName: String?

    var path: String { directoryPath + "/" + (temporaryName ?? "defenseclaw-gateway") }

    init(directory: Int32, directoryPath: String, temporaryName: String) throws {
        self.directory = fcntl(directory, F_DUPFD_CLOEXEC, 0)
        guard self.directory >= 0 else {
            throw GatewayAdminFailure.refused("Could not retain the private gateway directory.")
        }
        self.directoryPath = directoryPath
        self.temporaryName = temporaryName
    }

    func activate() throws -> String {
        guard let temporaryName else { return path }
        guard renameat(directory, temporaryName, directory, "defenseclaw-gateway") == 0 else {
            throw GatewayAdminFailure.refused("Could not activate the private administrator gateway.")
        }
        self.temporaryName = nil
        _ = fsync(directory)
        return path
    }

    deinit {
        if let temporaryName { _ = unlinkat(directory, temporaryName, 0) }
        close(directory)
    }
}

/// Start is idempotent only while the installed bytes match the private copy.
/// Restart explicitly refreshes it, after verifying the candidate and
/// successfully stopping the current copy. Stop never needs the source file.
enum GatewayAdminLifecycle {
    static func perform<Candidate>(
        action: GatewayAdminAction,
        currentGateway: String?,
        prepare: () throws -> Candidate,
        path: (Candidate) -> String,
        matches: (Candidate, String) throws -> Bool,
        activate: (Candidate) throws -> String,
        run: (GatewayAdminAction, String) throws -> (Int32, String)
    ) throws -> (Int32, String) {
        if let currentGateway, action == .stop {
            return try run(.stop, currentGateway)
        }
        let candidate = try prepare()
        if let currentGateway, action == .start {
            guard try matches(candidate, currentGateway) else {
                throw GatewayAdminFailure.refused("The installed gateway differs from the administrator gateway copy. Choose Restart Gateway as Administrator to use the installed version. No gateway action was performed.")
            }
            return try run(.start, currentGateway)
        }
        if action == .stop { return try run(.stop, path(candidate)) }
        var stopOutput = ""
        if action == .restart {
            let stopped = try run(.stop, currentGateway ?? path(candidate))
            guard stopped.0 == 0 else { return stopped }
            stopOutput = stopped.1
        }
        let gateway = try activate(candidate)
        let result = try run(.start, gateway)
        return (result.0, stopOutput + result.1)
    }

}

private enum GatewayAdminExecution {
    static func run(action: GatewayAdminAction, gateway: String, home: String, config: String,
                    account: InvokingAccount) throws -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: gateway)
        process.arguments = [action.rawValue]
        process.currentDirectoryURL = URL(fileURLWithPath: "/", isDirectory: true)
        process.environment = [
            "PATH": GatewayAdminTrust.scannerSearchPath(home: home, account: account),
            "HOME": account.home,
            "USER": account.name,
            "LOGNAME": account.name,
            "SUDO_UID": String(account.uid),
            "SUDO_GID": String(account.gid),
            "SUDO_USER": account.name,
            "DEFENSECLAW_HOME": home,
            "DEFENSECLAW_CONFIG": config,
            "DEFENSECLAW_VENV": home + "/.venv",
            "NO_COLOR": "1",
        ]
        let output = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = output
        try process.run()
        try? output.fileHandleForWriting.close()
        defer { try? output.fileHandleForReading.close() }
        let descriptor = output.fileHandleForReading.fileDescriptor
        _ = fcntl(descriptor, F_SETFL, O_NONBLOCK)
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(action == .stop ? 90 : 180))
        var exitObserved: ContinuousClock.Instant?
        var capture = Data()
        var truncated = false
        var timedOut = false
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            if !process.isRunning {
                if exitObserved == nil { exitObserved = clock.now }
                if clock.now - exitObserved! > .milliseconds(500) { break }
            }
            if clock.now >= deadline {
                timedOut = true
                if process.isRunning {
                    process.terminate()
                    let terminationDeadline = clock.now.advanced(by: .seconds(5))
                    while process.isRunning, clock.now < terminationDeadline { usleep(50_000) }
                    if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
                    process.waitUntilExit()
                }
                break
            }
            var polling = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
            let polled = poll(&polling, 1, 100)
            if polled < 0, errno == EINTR { continue }
            if polled <= 0 { continue }
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if count == 0, !process.isRunning { break }
            if count > 0 {
                let retained = min(count, GatewayAdminPolicy.maximumOutputBytes - capture.count)
                if retained > 0 { capture.append(contentsOf: buffer.prefix(retained)) }
                if retained < count { truncated = true }
            }
        }
        var text = String(decoding: capture, as: UTF8.self)
        if truncated { text += "\nCommand output exceeded its safe limit. Check gateway status before retrying.\n" }
        if timedOut {
            text += "\nGateway operation timed out. Refresh gateway status before retrying; a gateway may already have started.\n"
            return (124, text)
        }
        process.waitUntilExit()
        return (truncated && process.terminationStatus == 0 ? 75 : process.terminationStatus, text)
    }
}

/// Pure state makes the idle shutdown rule testable without starting a
/// privileged service. Queued operations count before their client disconnects.
struct GatewayAdminIdleState {
    private(set) var connections = 0
    private(set) var operations = 0
    private(set) var generation: UInt64 = 0

    var isIdle: Bool { connections == 0 && operations == 0 }

    mutating func connected() { connections += 1; generation &+= 1 }
    mutating func disconnected() { connections = max(0, connections - 1); generation &+= 1 }
    mutating func operationStarted() { operations += 1; generation &+= 1 }
    mutating func operationFinished() { operations = max(0, operations - 1); generation &+= 1 }

    func canExit(observedGeneration: UInt64) -> Bool {
        isIdle && generation == observedGeneration
    }
}

private final class GatewayAdminLifetime {
    private let lock = NSLock()
    private var state = GatewayAdminIdleState()

    func connected() { update { $0.connected() } }
    func disconnected() { update { $0.disconnected() } }
    func operationStarted() { update { $0.operationStarted() } }
    func operationFinished() { update { $0.operationFinished() } }

    private func update(_ change: (inout GatewayAdminIdleState) -> Void) {
        lock.lock()
        change(&state)
        let generation = state.generation
        let scheduleExit = state.isIdle
        lock.unlock()
        guard scheduleExit else { return }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 10) { [self] in
            lock.lock()
            defer { lock.unlock() }
            // Keep the lock until exit: no accepted client can race this final
            // decision. launchd relaunches the current app helper on demand.
            if state.canExit(observedGeneration: generation) { Darwin.exit(0) }
        }
    }
}

private final class GatewayAdminSession: NSObject, GatewayAdminProtocol {
    private let uid: uid_t
    private let queue: DispatchQueue
    private let lifetime: GatewayAdminLifetime

    init(uid: uid_t, queue: DispatchQueue, lifetime: GatewayAdminLifetime) {
        self.uid = uid
        self.queue = queue
        self.lifetime = lifetime
    }

    func perform(action: String, homePath: String, configPath: String, authorization: Data,
                 withReply reply: @escaping (Int32, String) -> Void) {
        guard let operation = GatewayAdminAction(rawValue: action) else {
            reply(64, "Unsupported administrator gateway action.")
            return
        }
        lifetime.operationStarted()
        queue.async { [uid, lifetime] in
            defer { lifetime.operationFinished() }
            do {
                guard geteuid() == 0 else {
                    throw GatewayAdminFailure.refused("The gateway administrator helper is not running as root.")
                }
                let outcome = try GatewayAdminTrust.withAuthorization(authorization) {
                    let account = try InvokingAccount(uid: uid)
                    try GatewayAdminTrust.validateInstallation(home: homePath, config: configPath, account: account)
                    return try GatewayAdminLifecycle.perform(
                        action: operation,
                        currentGateway: GatewayAdminTrust.currentStagedGateway(account: account),
                        prepare: { try GatewayAdminTrust.prepareInstalledGateway(account: account) },
                        path: { $0.path },
                        matches: { candidate, current in
                            try GatewayAdminTrust.gatewayDigest(at: candidate.path) == GatewayAdminTrust.gatewayDigest(at: current)
                        },
                        activate: { try $0.activate() },
                        run: { action, gateway in
                            try GatewayAdminExecution.run(action: action, gateway: gateway,
                                                          home: homePath, config: configPath, account: account)
                        }
                    )
                }
                reply(outcome.0, outcome.1)
            } catch let error as GatewayAdminFailure {
                reply(error.exitCode, error.localizedDescription)
            } catch {
                reply(77, error.localizedDescription)
            }
        }
    }
}

private final class GatewayAdminListener: NSObject, NSXPCListenerDelegate {
    private let operations = DispatchQueue(label: GatewayAdminPolicy.serviceName + ".operations")
    private let lifetime = GatewayAdminLifetime()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard geteuid() == 0, connection.effectiveUserIdentifier > 0 else { return false }
        connection.setCodeSigningRequirement(GatewayAdminPolicy.appRequirement)
        connection.exportedInterface = NSXPCInterface(with: GatewayAdminProtocol.self)
        connection.exportedObject = GatewayAdminSession(uid: connection.effectiveUserIdentifier,
                                                        queue: operations, lifetime: lifetime)
        lifetime.connected()
        connection.invalidationHandler = { [lifetime] in lifetime.disconnected() }
        connection.resume()
        return true
    }
}

#if !GATEWAY_ADMIN_HELPER_TESTING
@main
private enum GatewayAdminMain {
    static func main() {
        guard geteuid() == 0 else {
            fputs("DefenseClaw Gateway Admin must be launched by its approved system service.\n", stderr)
            exit(77)
        }
        let delegate = GatewayAdminListener()
        let listener = NSXPCListener(machServiceName: GatewayAdminPolicy.serviceName)
        listener.delegate = delegate
        listener.resume()
        withExtendedLifetime(delegate) { RunLoop.current.run() }
    }
}

#endif
