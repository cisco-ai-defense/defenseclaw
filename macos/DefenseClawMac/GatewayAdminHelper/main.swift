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

// A per-user gateway always runs as its account (`defenseclaw-gateway start`,
// run by the app or the CLI as the logged-in user). App versions up to 1.0.8
// could run it as root through this helper; this helper now only undoes that:
// it stops the root gateway it started for the calling account, returns the
// root-owned files that gateway left in the account's DefenseClaw home, and
// deletes its private gateway copy. It never starts a gateway.

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
            return "Administrator authorization cancelled. No gateway repair was performed. (macOS \(errAuthorizationCanceled))"
        case .authorization(let status):
            return "macOS could not authorize the gateway repair (status \(status)). Nothing was changed. Try again and complete the system authorization prompt."
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
    static let stagedGatewayName = "defenseclaw-gateway"

    // UID comes only from the authenticated XPC account, never a request field.
    // Earlier app versions kept one private gateway copy per account here.
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
                "Administrator gateway repair requires the original Developer ID signed app and helper. Reinstall the signed application."
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
    /// Owner/root ownership is allowed because a root-run gateway may have left
    /// either; group and other users must not control it.
    static func validateInstallation(home: String, config: String, account: InvokingAccount) throws {
        guard GatewayAdminPolicy.isStrictDescendant(home, of: account.home),
              GatewayAdminPolicy.isStrictDescendant(config, of: home) else {
            throw GatewayAdminFailure.refused("Gateway repair only supports a configuration inside your selected DefenseClaw home, within your own account home.")
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
                throw GatewayAdminFailure.refused("A required gateway repair path is missing or unreadable.")
            }
            let mode = metadata.st_mode & S_IFMT
            let directoryRequired = index < components.count - 1 || finalIsDirectory
            guard mode == (directoryRequired ? S_IFDIR : S_IFREG),
                  metadata.st_uid == 0 || metadata.st_uid == permittedOwner,
                  metadata.st_mode & 0o022 == 0 else {
                throw GatewayAdminFailure.refused("Gateway repair refused a symlink, unexpected owner, or writable shared path.")
            }
            try rejectWriteACL(at: current)
        }
    }

    private static func rejectWriteACL(at path: String) throws {
        guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT || errno == ENOTSUP { return }
            throw GatewayAdminFailure.refused("Could not verify gateway repair path permissions.")
        }
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
                throw GatewayAdminFailure.refused("Gateway repair refused a path with additional write permissions.")
            }
        }
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

    /// Only an immutable, code-signature-valid Mach-O copy is ever executed as
    /// root, and only to stop the gateway it started.
    static func verifyGatewayIntegrity(at path: String) throws {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw GatewayAdminFailure.refused("Could not read the private gateway copy.") }
        defer { close(descriptor) }
        var magic: UInt32 = 0
        let count = withUnsafeMutableBytes(of: &magic) { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        let executableMagic: Set<UInt32> = [0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]
        guard count == MemoryLayout<UInt32>.size, executableMagic.contains(magic) else {
            throw GatewayAdminFailure.refused("The private gateway copy must be a signed Mach-O executable.")
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
            throw GatewayAdminFailure.refused("The private gateway copy's code signature is invalid.")
        }
    }

    /// The private copy an earlier app version started for this account, or
    /// nil when it never ran one.
    static func currentStagedGateway(account: InvokingAccount) throws -> String? {
        let directory = stagingDirectory(uid: account.uid)
        let gateway = directory + "/" + stagedGatewayName
        var metadata = stat()
        if lstat(gateway, &metadata) != 0 {
            if errno == ENOENT || errno == ENOTDIR { return nil }
            throw GatewayAdminFailure.refused("Could not inspect the private gateway copy.")
        }
        try validatePath(directory, permittedOwner: nil, finalIsDirectory: true)
        var directoryMetadata = stat()
        guard lstat(directory, &directoryMetadata) == 0,
              directoryMetadata.st_mode & 0o077 == 0 else {
            throw GatewayAdminFailure.refused("The private gateway directory is not private.")
        }
        try validatePath(gateway, permittedOwner: nil, finalIsDirectory: false)
        guard metadata.st_mode & 0o111 != 0 else {
            throw GatewayAdminFailure.refused("The private gateway copy is not executable.")
        }
        try verifyGatewayIntegrity(at: gateway)
        return gateway
    }

    /// Delete this account's private copy and its fixed root-owned folder
    /// (and the parent when it is left empty). No client path is used.
    static func removeStagedGateway(account: InvokingAccount) throws {
        let directory = stagingDirectory(uid: account.uid)
        var metadata = stat()
        if lstat(directory, &metadata) != 0 {
            if errno == ENOENT || errno == ENOTDIR { return }
            throw GatewayAdminFailure.refused("Could not inspect the private gateway directory.")
        }
        try validatePath(directory, permittedOwner: nil, finalIsDirectory: true)
        let descriptor = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw GatewayAdminFailure.refused("Could not open the private gateway directory.")
        }
        defer { close(descriptor) }
        for name in GatewayAdminDirectory.names(of: descriptor) ?? []
            where name == stagedGatewayName || name.hasPrefix(".gateway-") {
            guard unlinkat(descriptor, name, 0) == 0 || errno == ENOENT else {
                throw GatewayAdminFailure.refused("Could not delete the private gateway copy.")
            }
        }
        _ = rmdir(directory)
        _ = rmdir(stagingRoot)
    }
}

enum GatewayAdminDirectory {
    /// Entry names of an open directory, without "." and "..".
    static func names(of directory: Int32) -> [String]? {
        let copy = dup(directory)
        guard copy >= 0 else { return nil }
        guard let stream = fdopendir(copy) else {
            close(copy)
            return nil
        }
        defer { closedir(stream) }
        var names: [String] = []
        while let entry = readdir(stream) {
            var field = entry.pointee.d_name
            let name = withUnsafeBytes(of: &field) { raw in
                String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
            }
            if name != "." && name != ".." { names.append(name) }
        }
        return names
    }
}

/// The gateway process this home's PID record names, when it is alive and
/// runs as root. Read as root; nothing is signalled here.
enum GatewayAdminRootProcess {
    static let maximumRecordBytes = 65_536

    /// The PID and recorded executable of a `gateway.pid` record: the plain
    /// integer format or the `{"pid": N, "executable": "..."}` envelope.
    static func record(from data: Data) -> (pid: pid_t, executable: String)? {
        guard let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !text.isEmpty else { return nil }
        if let pid = Int32(text), pid > 0 { return (pid, "") }
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
              let number = object["pid"] as? NSNumber,
              CFNumberIsFloatType(number as CFNumber) == false,
              number.int64Value > 0, number.int64Value <= Int64(Int32.max) else { return nil }
        return (pid_t(number.int64Value), object["executable"] as? String ?? "")
    }

    static func owner(of pid: pid_t) -> uid_t? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&name, u_int(name.count), &info, &size, nil, 0) == 0, size > 0,
              info.kp_proc.p_pid == pid else { return nil }
        return info.kp_eproc.e_ucred.cr_uid
    }

    static func executable(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4_096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }

    /// Whether a live root process is the gateway `record` names: its
    /// executable must be the recorded one (or, for a record without one, a
    /// program named defenseclaw-gateway), so a reused PID is not mistaken
    /// for the gateway.
    static func isRootGateway(_ record: (pid: pid_t, executable: String),
                              owner: (pid_t) -> uid_t? = GatewayAdminRootProcess.owner(of:),
                              executable: (pid_t) -> String? = GatewayAdminRootProcess.executable(of:)) -> Bool {
        guard owner(record.pid) == 0, let path = executable(record.pid) else { return false }
        if !record.executable.isEmpty { return path == record.executable }
        return (path as NSString).lastPathComponent == GatewayAdminTrust.stagedGatewayName
    }

    static func liveRootGateway(home: String) -> pid_t? {
        let descriptor = open(home + "/gateway.pid", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_size > 0, metadata.st_size <= maximumRecordBytes else { return nil }
        var buffer = [UInt8](repeating: 0, count: Int(metadata.st_size))
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        guard count > 0, let parsed = Self.record(from: Data(buffer.prefix(count))),
              isRootGateway(parsed) else { return nil }
        return parsed.pid
    }
}

/// Return the root-owned folders and regular files a root-run gateway left in
/// this account's DefenseClaw home to the account. The walk is bound to
/// directory descriptors: no symlink is ever followed (O_NOFOLLOW at every
/// step), a file is changed only through its own open descriptor and only
/// while it has a single link (a hard link to a file elsewhere is skipped),
/// special files and other file systems are skipped, and the walk is bounded.
/// Modes are kept; only the owner and group change.
enum GatewayAdminOwnershipRepair {
    static let maximumEntries = 250_000
    static let maximumDepth = 32
    static let listedPaths = 12

    struct Outcome: Equatable {
        var restored: [String] = []
        var skipped: [String] = []
        var incomplete = false

        var summary: String {
            var lines: [String] = []
            if restored.isEmpty {
                lines.append("No root-owned DefenseClaw files were left in this home.")
            } else {
                let shown = restored.prefix(GatewayAdminOwnershipRepair.listedPaths).joined(separator: ", ")
                let more = restored.count > GatewayAdminOwnershipRepair.listedPaths
                    ? " and \(restored.count - GatewayAdminOwnershipRepair.listedPaths) more" : ""
                lines.append("Returned \(restored.count) root-owned files and folders to your account: \(shown)\(more).")
            }
            if !skipped.isEmpty {
                lines.append("Left \(skipped.count) root-owned items unchanged (hard-linked or special files): "
                    + skipped.prefix(GatewayAdminOwnershipRepair.listedPaths).joined(separator: ", ") + ".")
            }
            if incomplete {
                lines.append("Part of the home could not be inspected; run `defenseclaw doctor` to see what is still root-owned.")
            }
            return lines.joined(separator: "\n") + "\n"
        }
    }

    static func restore(home: String, from owner: uid_t = 0, to account: (uid: uid_t, gid: gid_t),
                        maximumEntries: Int = GatewayAdminOwnershipRepair.maximumEntries,
                        change: ((Int32, String) -> Int32)? = nil) throws -> Outcome {
        let apply = change ?? { descriptor, _ in fchown(descriptor, account.uid, account.gid) }
        let root = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else {
            throw GatewayAdminFailure.refused("Could not open the DefenseClaw home to return its files.")
        }
        defer { close(root) }
        var metadata = stat()
        guard fstat(root, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR else {
            throw GatewayAdminFailure.refused("The DefenseClaw home is not a folder.")
        }
        var outcome = Outcome()
        var visited = 0
        if metadata.st_uid == owner {
            if apply(root, ".") == 0 { outcome.restored.append(".") } else { outcome.incomplete = true }
        }

        func walk(_ directory: Int32, _ prefix: String, _ depth: Int) {
            guard depth < maximumDepth, let names = GatewayAdminDirectory.names(of: directory) else {
                outcome.incomplete = true
                return
            }
            for name in names.sorted() {
                visited += 1
                guard visited <= maximumEntries else {
                    outcome.incomplete = true
                    return
                }
                let relative = prefix.isEmpty ? name : prefix + "/" + name
                var entry = stat()
                guard fstatat(directory, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
                switch entry.st_mode & S_IFMT {
                case S_IFDIR:
                    guard entry.st_dev == metadata.st_dev else { continue }
                    let child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    guard child >= 0 else {
                        outcome.incomplete = true
                        continue
                    }
                    defer { close(child) }
                    var opened = stat()
                    guard fstat(child, &opened) == 0, opened.st_mode & S_IFMT == S_IFDIR,
                          opened.st_dev == metadata.st_dev else { continue }
                    if opened.st_uid == owner {
                        if apply(child, relative) == 0 { outcome.restored.append(relative) } else { outcome.incomplete = true }
                    }
                    walk(child, relative, depth + 1)
                case S_IFREG:
                    guard entry.st_uid == owner else { continue }
                    let file = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)
                    guard file >= 0 else {
                        outcome.incomplete = true
                        continue
                    }
                    defer { close(file) }
                    var opened = stat()
                    guard fstat(file, &opened) == 0, opened.st_mode & S_IFMT == S_IFREG,
                          opened.st_uid == owner, opened.st_dev == metadata.st_dev, opened.st_nlink == 1 else {
                        outcome.skipped.append(relative)
                        continue
                    }
                    if apply(file, relative) == 0 { outcome.restored.append(relative) } else { outcome.incomplete = true }
                case S_IFLNK:
                    // Never followed or changed; the account owns the folder
                    // holding it and can remove it.
                    continue
                default:
                    if entry.st_uid == owner { outcome.skipped.append(relative) }
                }
            }
        }
        walk(root, "", 0)
        return outcome
    }
}

/// The repair order, with every effect injected so it is testable without
/// root: stop first (only through the helper's own copy), never touch files
/// while a root gateway still serves the home, then return files and delete
/// the copy so no root gateway can run from it again.
enum GatewayAdminRepair {
    static let stillRunning = """
        A gateway is still running as root for this DefenseClaw home, and it was not started by DefenseClawMac \
        (for example `sudo defenseclaw-gateway start`). Stop it with `sudo defenseclaw-gateway stop`, then start \
        the gateway again from DefenseClawMac. Nothing was changed.

        """

    static func perform(
        stagedGateway: String?,
        liveRootGateway: () -> pid_t?,
        stop: (String) throws -> (Int32, String),
        restoreOwnership: () throws -> GatewayAdminOwnershipRepair.Outcome,
        removeStagedGateway: () throws -> Void
    ) throws -> (Int32, String) {
        var output = ""
        if let stagedGateway {
            let stopped = try stop(stagedGateway)
            output += stopped.1
        }
        if liveRootGateway() != nil {
            return (stagedGateway == nil ? 75 : 1, output + (stagedGateway == nil ? stillRunning
                : "The root gateway did not stop. Nothing else was changed; check `defenseclaw-gateway status` and retry.\n"))
        }
        let outcome = try restoreOwnership()
        try removeStagedGateway()
        output += (stagedGateway == nil ? "" : "Stopped the gateway DefenseClawMac had run as administrator.\n")
        output += outcome.summary
        return (outcome.incomplete ? 1 : 0, output)
    }
}

private enum GatewayAdminExecution {
    /// Stop the gateway the helper's private copy started, as root, against the
    /// selected installation. This is the only program the helper runs.
    static func stop(gateway: String, home: String, config: String, account: InvokingAccount) throws -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: gateway)
        process.arguments = ["stop"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/", isDirectory: true)
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
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
        let deadline = clock.now.advanced(by: .seconds(90))
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
            text += "\nStopping the root gateway timed out. Check gateway status before retrying.\n"
            return (124, text)
        }
        process.waitUntilExit()
        return (process.terminationStatus, text)
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

/// Vendor machine-policy folders agents read administrator policy from on
/// macOS (the DefenseClaw runtime's own machine-policy locations). The
/// runtime's install watcher used to create a missing watch root with mode
/// 0700, so a gateway running as root left `/etc/codex` root-owned and
/// unreadable; Codex treats an existing `/etc/codex` as an administrator
/// policy layer and pauses with "Organization settings could not be loaded"
/// when it cannot read it. After a repair stops such a gateway the helper
/// repairs these folders: an unreadable, root-owned folder tree that holds
/// nothing but empty folders is removed (`rmdir` only, deepest first); one
/// with content is left private for an administrator to review. Readable
/// folders, files, symlinks and folders owned by anyone else are never touched.
/// Only this fixed list is inspected; no client path is ever used.
enum GatewayAdminVendorPolicyGuard {
    static let vendorPolicyDirectories = [
        "/etc/codex",
        "/etc/cursor",
        "/etc/github-copilot",
        "/Library/Application Support/ClaudeCode",
        "/Library/Application Support/opencode",
    ]
    private static let maximumTreeDepth = 16
    private static let maximumTreeEntries = 512

    struct Outcome {
        var removed: [String] = []
        var preserved: [String] = []
        var notes: [String] = []
    }

    /// One repair pass; returns text for the Activity record (empty when
    /// nothing needed repair).
    static func settle(owner: uid_t = 0, directories: [String] = vendorPolicyDirectories) -> String {
        let notes = sweep(directories: directories, owner: owner).notes
        return notes.isEmpty ? "" : "\n" + notes.joined(separator: "\n") + "\n"
    }

    /// One pass over `directories`: removes empty watcher artifacts and leaves
    /// populated private policy directories unchanged.
    static func sweep(directories: [String], owner: uid_t) -> Outcome {
        var outcome = Outcome()
        for directory in directories {
            guard isRealDirectoryChain(directory),
                  let status = lstatStatus(directory),
                  status.st_uid == owner,
                  status.st_mode & S_IXOTH == 0
            else { continue }
            if let tree = emptyDirectoryTree(directory, depth: 0, counted: 0)?.0 {
                var removedAll = true
                for path in tree.reversed() where rmdir(path) != 0 {
                    removedAll = false
                    break
                }
                if removedAll {
                    outcome.removed.append(directory)
                    outcome.notes.append("Removed \(directory): a root-owned, unreadable folder holding only empty folders (created by the gateway's install watcher). Agents treat its presence as administrator policy.")
                    continue
                }
            }
            outcome.preserved.append(directory)
            outcome.notes.append("Left \(directory) private: it contains policy content or could not be safely inspected. An administrator must review its permissions; no access was broadened.")
        }
        return outcome
    }

    private static func lstatStatus(_ path: String) -> stat? {
        var status = stat()
        guard lstat(path, &status) == 0 else { return nil }
        return status
    }

    private static func isRealDirectory(_ status: stat) -> Bool {
        status.st_mode & S_IFMT == S_IFDIR
    }

    /// Every component from the root down must be a real directory — a
    /// symlinked ancestor could redirect the repair elsewhere.
    private static func isRealDirectoryChain(_ directory: String) -> Bool {
        guard directory.hasPrefix("/") else { return false }
        var current = "/"
        for component in directory.split(separator: "/") where !component.isEmpty {
            current = (current as NSString).appendingPathComponent(String(component))
            guard let status = lstatStatus(current), isRealDirectory(status) else { return false }
        }
        return true
    }

    /// The directories of a tree that holds nothing but directories, parents
    /// first; nil when a file, link or anything else is present, or the
    /// tree is too deep or wide to judge.
    private static func emptyDirectoryTree(_ directory: String, depth: Int, counted: Int) -> ([String], Int)? {
        guard depth <= maximumTreeDepth else { return nil }
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return nil }
        var tree = [directory]
        var count = counted + entries.count
        guard count <= maximumTreeEntries else { return nil }
        for entry in entries {
            let child = (directory as NSString).appendingPathComponent(entry)
            guard let status = lstatStatus(child), isRealDirectory(status) else { return nil }
            guard let (subtree, subcount) = emptyDirectoryTree(child, depth: depth + 1, counted: count) else { return nil }
            tree += subtree
            count = subcount
        }
        return (tree, count)
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
        guard GatewayAdminAction(rawValue: action) == .repair else {
            reply(64, "Unsupported administrator gateway action. This helper only repairs a gateway an earlier DefenseClawMac version ran as administrator; it never starts one.")
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
                    try GatewayAdminTrust.validateHelperBundle()
                    return try GatewayAdminRepair.perform(
                        stagedGateway: GatewayAdminTrust.currentStagedGateway(account: account),
                        liveRootGateway: { GatewayAdminRootProcess.liveRootGateway(home: homePath) },
                        stop: { gateway in
                            try GatewayAdminExecution.stop(gateway: gateway, home: homePath,
                                                           config: configPath, account: account)
                        },
                        restoreOwnership: {
                            try GatewayAdminOwnershipRepair.restore(home: homePath, to: (account.uid, account.gid))
                        },
                        removeStagedGateway: { try GatewayAdminTrust.removeStagedGateway(account: account) }
                    )
                }
                // Repair vendor policy folders a root gateway may have left
                // unreadable, outside the authorization scope: only empty
                // watcher-created trees may be removed.
                reply(outcome.0, outcome.1 + GatewayAdminVendorPolicyGuard.settle())
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
