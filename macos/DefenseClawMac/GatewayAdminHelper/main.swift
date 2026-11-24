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
// it stops the root gateway it started for the calling account (by signalling
// its verified PID; it runs no program), returns the root-owned DefenseClaw
// files that gateway left in the account's DefenseClaw home and the agent
// config files it rewrote in the account home, and deletes its private
// gateway copy. It never starts a gateway.

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

    /// Lexical and per-component checks for the helper's own fixed folders
    /// under /Library (root-owned, so the account cannot race them). The
    /// caller-selected DefenseClaw home is never trusted by path; see
    /// GatewayAdminInstallation.
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
            guard let acl = acl_get_file(current, ACL_TYPE_EXTENDED) else {
                if errno == ENOENT || errno == ENOTSUP { continue }
                throw GatewayAdminFailure.refused("Could not verify gateway repair path permissions.")
            }
            try rejectWriteACL(acl)
        }
    }

    static func rejectWriteACL(descriptor: Int32) throws {
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            // macOS reports ENOENT when an open file has no extended ACL.
            if errno == ENOENT || errno == ENOTSUP { return }
            throw GatewayAdminFailure.refused("Could not verify gateway repair path permissions.")
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

    /// Executables a gateway the helper started can run from: this account's
    /// private copy, and the shared copy that pre-import upstream app versions
    /// used (no Cisco build wrote it; it is matched only so such a gateway is
    /// stopped instead of being reported as foreign, and never deleted because
    /// other accounts may still use it). Both live in root-only folders, so a
    /// process running one of them was started by root.
    static func stagedExecutables(uid: uid_t) -> Set<String> {
        let paths = [stagingDirectory(uid: uid) + "/" + stagedGatewayName, stagingRoot + "/" + stagedGatewayName]
        return Set(paths + paths.map { "/System/Volumes/Data" + $0 })
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
        // Every folder on this path is root-owned (validatePath), so the
        // account cannot swap any of them.
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

/// The selected DefenseClaw home, opened by descriptor. The walk starts at "/"
/// and opens every component with openat and O_NOFOLLOW, checking each on its
/// own descriptor: the folders above the account home are root-owned and not
/// writable by group or others (a sticky folder excepted) or through a write
/// ACL; the account home is owned by the account; everything below it is a
/// real folder owned by root or the account, not writable by group or others
/// or through a write ACL; and everything from the account home down is on the
/// account home's volume. A folder swapped for a symlink at any point is
/// refused; one renamed away keeps the descriptor on the verified folder.
/// Everything the repair reads or changes is reached from this descriptor.
/// The home must hold a DefenseClaw config.yaml.
final class GatewayAdminInstallation {
    let descriptor: Int32
    let device: dev_t

    #if GATEWAY_ADMIN_HELPER_TESTING
    static var componentOpenedForTesting: ((Int) -> Void)?
    #endif

    init(home: String, config: String, account: InvokingAccount) throws {
        guard GatewayAdminPolicy.isStrictDescendant(home, of: account.home), config == home + "/config.yaml" else {
            throw GatewayAdminFailure.refused("Gateway repair only changes a DefenseClaw home inside your own account home, with its config.yaml.")
        }
        var current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else {
            throw GatewayAdminFailure.refused("Could not open the filesystem root.")
        }
        do {
            let homeComponents = account.home.split(separator: "/").map(String.init)
            for (index, component) in homeComponents.enumerated() {
                let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else {
                    throw GatewayAdminFailure.refused("Could not open your account home without following a symbolic link (errno \(errno)).")
                }
                close(current)
                current = next
                // The account home itself is checked below.
                guard index < homeComponents.count - 1 else { break }
                var metadata = stat()
                guard fstat(current, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_uid == 0,
                      metadata.st_mode & 0o022 == 0 || metadata.st_mode & S_ISVTX != 0 else {
                    throw GatewayAdminFailure.refused("A folder above your account home is not root-owned or is writable by other accounts.")
                }
                try GatewayAdminTrust.rejectWriteACL(descriptor: current)
            }
            let volume = try Self.verify(current, account: account, directory: true, device: nil)
            var accountHome = stat()
            guard fstat(current, &accountHome) == 0, accountHome.st_uid == account.uid else {
                throw GatewayAdminFailure.refused("Your account home is not owned by your account.")
            }
            let components = home.dropFirst(account.home.count + 1).split(separator: "/").map(String.init)
            for (index, component) in components.enumerated() {
                let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else {
                    throw GatewayAdminFailure.refused("The DefenseClaw home is missing, or a folder on its path is a symbolic link.")
                }
                close(current)
                current = next
                try Self.verify(current, account: account, directory: true, device: volume)
                #if GATEWAY_ADMIN_HELPER_TESTING
                Self.componentOpenedForTesting?(index)
                #endif
            }
            let marker = openat(current, "config.yaml", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)
            guard marker >= 0 else {
                throw GatewayAdminFailure.refused("This folder has no DefenseClaw config.yaml. Gateway repair only changes a DefenseClaw home.")
            }
            defer { close(marker) }
            try Self.verify(marker, account: account, directory: false, device: volume)
            descriptor = current
            device = volume
        } catch {
            close(current)
            throw error
        }
    }

    deinit { close(descriptor) }

    @discardableResult
    static func verify(_ descriptor: Int32, account: InvokingAccount, directory: Bool, device: dev_t?) throws -> dev_t {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG),
              metadata.st_uid == 0 || metadata.st_uid == account.uid,
              metadata.st_mode & 0o022 == 0,
              device.map({ metadata.st_dev == $0 }) ?? true else {
            throw GatewayAdminFailure.refused("Gateway repair refused a folder or file on the DefenseClaw home path: unexpected owner or type, shared write access, or another volume.")
        }
        try GatewayAdminTrust.rejectWriteACL(descriptor: descriptor)
        return metadata.st_dev
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
        // The duplicate shares the original descriptor offset; start over so
        // a second listing of the same folder is complete.
        rewinddir(stream)
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

/// The root processes this home's PID records name, read as root through the
/// home descriptor. A process counts only while it is root, its start identity
/// matches the record (the Go daemon's "sec.usec" form) and its executable is
/// the helper's copy or the recorded one, so a reused PID is never taken for
/// the gateway.
enum GatewayAdminRootProcess {
    static let maximumRecordBytes = 65_536
    /// The watchdog first: it would start the gateway again.
    static let recordNames = ["watchdog.pid", "gateway.pid"]

    struct Record: Equatable {
        var pid: pid_t
        var executable = ""
        var startIdentity = ""
    }

    struct Live: Equatable {
        var record: String
        var pid: pid_t
        var startIdentity: String
    }

    struct Found: Equatable {
        var helperStarted: [Live] = []
        var other: [Live] = []
        var isEmpty: Bool { helperStarted.isEmpty && other.isEmpty }
    }

    /// The plain integer format or the `{"pid": N, "executable": "...",
    /// "start_identity": "..."}` envelope of gateway.pid and watchdog.pid.
    static func record(from data: Data) -> Record? {
        guard let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !text.isEmpty else { return nil }
        if let pid = Int32(text), pid > 0 { return Record(pid: pid) }
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
              let number = object["pid"] as? NSNumber,
              CFNumberIsFloatType(number as CFNumber) == false,
              number.int64Value > 0, number.int64Value <= Int64(Int32.max) else { return nil }
        return Record(pid: pid_t(number.int64Value),
                      executable: object["executable"] as? String ?? "",
                      startIdentity: object["start_identity"] as? String ?? "")
    }

    static func owner(of pid: pid_t) -> uid_t? {
        kinfo(pid).map { $0.kp_eproc.e_ucred.cr_uid }
    }

    /// The kernel start time in the Go daemon's start_identity form.
    static func startIdentity(of pid: pid_t) -> String? {
        kinfo(pid).map {
            let start = $0.kp_proc.p_un.__p_starttime
            return "\(start.tv_sec)." + String(format: "%06d", Int(start.tv_usec))
        }
    }

    private static func kinfo(_ pid: pid_t) -> kinfo_proc? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard pid > 0, sysctl(&name, u_int(name.count), &info, &size, nil, 0) == 0, size > 0,
              info.kp_proc.p_pid == pid else { return nil }
        return info
    }

    static func executable(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4_096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }

    /// A start identity is compared only in the current "sec.usec" form; an
    /// older ps(1) lstart string cannot be compared and is ignored.
    static func isComparableIdentity(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 2 && parts.allSatisfy { part in
            !part.isEmpty && part.unicodeScalars.allSatisfy { ("0"..."9").contains($0) }
        }
    }

    enum Kind { case helperStarted, other }

    static func classify(_ record: Record, staged: Set<String>,
                         owner: (pid_t) -> uid_t? = GatewayAdminRootProcess.owner(of:),
                         executable: (pid_t) -> String? = GatewayAdminRootProcess.executable(of:),
                         startIdentity: (pid_t) -> String? = GatewayAdminRootProcess.startIdentity(of:)) -> (Kind, String)? {
        guard owner(record.pid) == 0, let path = executable(record.pid),
              let started = startIdentity(record.pid) else { return nil }
        if isComparableIdentity(record.startIdentity), record.startIdentity != started { return nil }
        if staged.contains(path) { return (.helperStarted, started) }
        let named = record.executable.isEmpty
            ? (path as NSString).lastPathComponent == GatewayAdminTrust.stagedGatewayName
            : path == record.executable
        return named ? (.other, started) : nil
    }

    /// The record and whether it can be trusted to choose a process to
    /// signal: only a root-owned file with a single link, which a root gateway
    /// writes itself and the account can neither forge nor hard-link in.
    static func readRecord(in home: Int32, name: String) -> (record: Record, trusted: Bool)? {
        let descriptor = openat(home, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_size > 0, metadata.st_size <= maximumRecordBytes else { return nil }
        var buffer = [UInt8](repeating: 0, count: Int(metadata.st_size))
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        guard count > 0, let parsed = record(from: Data(buffer.prefix(count))) else { return nil }
        return (parsed, metadata.st_uid == 0 && metadata.st_nlink == 1)
    }

    /// Where a classified record goes: a helper-started process is signalled
    /// only when its record is trusted; otherwise the repair refuses and
    /// changes nothing, like for a root gateway the helper did not start.
    static func place(_ kind: Kind, trusted: Bool) -> Kind {
        kind == .helperStarted && trusted ? .helperStarted : .other
    }

    static func live(in home: Int32, uid: uid_t) -> Found {
        let staged = GatewayAdminTrust.stagedExecutables(uid: uid)
        var found = Found()
        for name in recordNames {
            guard let (parsed, trusted) = readRecord(in: home, name: name),
                  let (kind, started) = classify(parsed, staged: staged) else { continue }
            let process = Live(record: name, pid: parsed.pid, startIdentity: started)
            if place(kind, trusted: trusted) == .helperStarted {
                found.helperStarted.append(process)
            } else {
                found.other.append(process)
            }
        }
        return found
    }

    /// Still the same verified process: root, same start identity, and still
    /// running one of the helper's own executables.
    static func isSame(_ process: Live, staged: Set<String>) -> Bool {
        owner(of: process.pid) == 0 && startIdentity(of: process.pid) == process.startIdentity
            && executable(of: process.pid).map(staged.contains) == true
    }
}

/// Stop a gateway the helper started by signalling its verified PID, as the
/// Go daemon does (SIGTERM, then SIGKILL after a grace period). No program
/// runs as root and nothing in the home is parsed beyond the PID records.
/// Every signal is sent only while the process is still the verified one.
enum GatewayAdminStop {
    static func stop(_ processes: [GatewayAdminRootProcess.Live],
                     isSame: (GatewayAdminRootProcess.Live) -> Bool,
                     signal send: (pid_t, Int32) -> Int32 = { Darwin.kill($0, $1) },
                     grace: Duration = .seconds(20), killGrace: Duration = .seconds(5)) -> Bool {
        for process in processes {
            guard isSame(process) else { continue }
            _ = send(process.pid, SIGTERM)
            if waitUntilGone(process, isSame: isSame, within: grace) { continue }
            if isSame(process) { _ = send(process.pid, SIGKILL) }
            guard waitUntilGone(process, isSame: isSame, within: killGrace) else { return false }
        }
        return true
    }

    private static func waitUntilGone(_ process: GatewayAdminRootProcess.Live,
                                      isSame: (GatewayAdminRootProcess.Live) -> Bool,
                                      within window: Duration) -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: window)
        while isSame(process) {
            if clock.now >= deadline { return false }
            usleep(100_000)
        }
        return true
    }
}

/// Hands one root-owned file in a folder the account can write over to the
/// account (GAP-1964). A link count read in that folder proves nothing: the
/// account adds and removes names there at will, and one lookup reads the
/// name and the count at two different moments, so a hard link to a root file
/// outside the folder that is unlinked between them reads one link (CI saw
/// it). So the file's name is first moved (renameat, which never follows a
/// link) into the holding folder (holdingPath), which is in no folder the
/// account can write (GAP-1972): every folder on its path is a real folder
/// owned by root that nobody else can write, and the holding folder is the
/// helper's own, mode 700, with no access rules, all checked by descriptor.
/// The account can neither add, remove nor rename a name there, nor rename
/// the folder, so while the file is held its count includes that name and
/// every name it has outside the account's folder: a root file the account
/// linked in reads at least two links for as long as it is held. The held
/// file is then opened by that name and checked through its own descriptor
/// (the inode inspected, the same mode and owner, exactly one link), changed
/// only through that descriptor and moved back under its name, never over a
/// name made in the meantime (then next to it, as <name>.defenseclaw-kept).
/// A file that fails the checks is moved back unchanged.
///
/// A record of where the file came from and what was inspected is written to
/// the holding folder before the move and removed once the file is back. A
/// file that could go back under neither name, or that a repair stopped part
/// way left there, stays held with its record: recover() returns it at the
/// end of the next repair of the same folder, through the same checks, and
/// unclaimed() reports one whose folder is no longer repaired. The holding
/// folder is on the startup disk's data volume, with the account homes; a
/// file on another volume cannot be moved into it and is reported instead.
final class GatewayAdminHandover {
    enum Result: Equatable { case handed(kept: Bool), skipped(kept: Bool), failed, held, refused }

    static let keptSuffix = ".defenseclaw-kept"
    static let holdingName = "com.cisco.defenseclaw.macos.GatewayAdmin"
    #if GATEWAY_ADMIN_HELPER_TESTING
    static var holdingParent = "/private/var/db"
    #else
    static let holdingParent = "/private/var/db"
    #endif
    static var holdingPath: String { holdingParent + "/" + holdingName }

    /// A held file's record: its path below the walk's root, the name the
    /// repair shows, what the walk inspected and the account it goes to.
    struct Record: Codable {
        var path: String
        var shown: String
        var inode: UInt64
        var device: Int32
        var mode: UInt16
        var owner: UInt32
        var account: UInt32
    }

    private var root: Int32
    private let account: uid_t
    private let shownPrefix: String
    private var device: dev_t = 0
    private var scope = ""
    private var holding: Int32 = -1
    private var tried = false
    private var otherVolume = false
    private var made: Set<String> = []

    /// root is the walk's own root folder, account the one the files go to,
    /// shownPrefix what the report puts before a path below root.
    init(root given: Int32, account: uid_t, shownPrefix: String = "") {
        root = dup(given)
        self.account = account
        self.shownPrefix = shownPrefix
        var status = stat()
        if root >= 0, fstat(root, &status) == 0 {
            device = status.st_dev
            scope = Self.scope(account, status)
        } else {
            tried = true
        }
    }

    deinit { finish() }

    /// Closes the folders; idempotent. The holding folder stays: a file that
    /// could not go back waits there for the next repair.
    func finish() {
        if holding >= 0 { close(holding); holding = -1 }
        if root >= 0 { close(root); root = -1 }
        tried = true
    }

    func handOver(_ directory: Int32, _ name: String, inspected entry: stat, path: String, shown: String,
                  change: (Int32) -> Int32) -> Result {
        guard entry.st_dev == device else { return .skipped(kept: false) }
        guard let holding = openHolding() else { return otherVolume ? .refused : .failed }
        let id = scope + Self.randomName()
        let record = Record(path: path, shown: shownPrefix + path, inode: UInt64(entry.st_ino), device: entry.st_dev,
                            mode: entry.st_mode, owner: entry.st_uid, account: account)
        guard Self.writeRecord(record, in: holding, as: id + ".record") else { return .failed }
        made.insert(id)
        guard renameat(directory, name, holding, id + ".held") == 0 else {
            _ = unlinkat(holding, id + ".record", 0)
            return .failed
        }
        #if GATEWAY_ADMIN_HELPER_TESTING
        // Declared by Tests/GatewayAdminHelperTests.swift: true stops the
        // repair right after the move, as if the helper died there.
        if GatewayAdminHandover.movedForTesting?(shown) == true {
            finish()
            return .failed
        }
        #endif
        return settle(id, record, into: directory, as: name, shown: shown, resumed: false, change: change)
    }

    /// Returns the files an earlier repair of this root left held, through
    /// the same checks, under their name or next to it.
    func recover(change: (Int32, String) -> Int32) -> GatewayAdminOwnershipRepair.Outcome {
        var outcome = GatewayAdminOwnershipRepair.Outcome()
        guard let holding = openHolding(), let names = GatewayAdminDirectory.names(of: holding) else { return outcome }
        for recordName in names.sorted() where recordName.hasPrefix(scope) && recordName.hasSuffix(".record") {
            let id = String(recordName.dropLast(".record".count))
            guard !made.contains(id) else { continue }
            var status = stat()
            guard fstatat(holding, id + ".held", &status, AT_SYMLINK_NOFOLLOW) == 0 else {
                // Nothing was moved, or it went back before its record was removed.
                if errno == ENOENT { _ = unlinkat(holding, recordName, 0) }
                continue
            }
            guard let record = Self.readRecord(in: holding, recordName) else {
                outcome.merge(GatewayAdminOwnershipRepair.Outcome(incomplete: true, held: [id]))
                continue
            }
            let components = record.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard let name = components.last, let directory = folder(components.dropLast()) else {
                outcome.merge(GatewayAdminOwnershipRepair.Outcome(incomplete: true, held: [record.shown]))
                continue
            }
            let result = settle(id, record, into: directory, as: name, shown: record.shown, resumed: true,
                                change: { change($0, record.shown) })
            close(directory)
            outcome.add(result, record.shown)
        }
        return outcome
    }

    /// The held files of account from a repair of a folder none of roots is
    /// (it moved or was removed), by the name the report showed.
    static func unclaimed(account: uid_t, roots: [Int32]) -> [String] {
        guard let holding = openHoldingFolder(create: false) else { return [] }
        defer { close(holding) }
        let scopes = roots.compactMap { root -> String? in
            var status = stat()
            return fstat(root, &status) == 0 ? scope(account, status) : nil
        }
        return (GatewayAdminDirectory.names(of: holding) ?? []).sorted().compactMap { name in
            guard name.hasPrefix(String(account) + "."), name.hasSuffix(".record"),
                  !scopes.contains(where: { name.hasPrefix($0) }) else { return nil }
            var status = stat()
            guard fstatat(holding, String(name.dropLast(".record".count)) + ".held", &status, AT_SYMLINK_NOFOLLOW) == 0
            else { return nil }
            return readRecord(in: holding, name)?.shown ?? name
        }
    }

    /// Checks the held file through its own descriptor, changes it when it is
    /// the file inspected (same owner and mode, one link) and moves it back.
    /// resumed: an earlier repair stopped after the move, maybe after the
    /// change, which only the helper can have made to a held file.
    private func settle(_ id: String, _ record: Record, into directory: Int32, as name: String, shown: String,
                        resumed: Bool, change: (Int32) -> Int32) -> Result {
        enum Checked { case handed, skipped, failed }
        var checked = Checked.failed
        let file = openat(holding, id + ".held", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)
        if file >= 0 {
            #if GATEWAY_ADMIN_HELPER_TESTING
            // Declared by Tests/GatewayAdminHelperTests.swift.
            GatewayAdminHandover.openedForTesting?(shown)
            #endif
            var opened = stat()
            let same = fstat(file, &opened) == 0 && UInt64(opened.st_ino) == record.inode && opened.st_dev == record.device
            if same, opened.st_mode == record.mode, opened.st_uid == record.owner, opened.st_nlink == 1 {
                checked = change(file) == 0 ? .handed : .failed
            } else if same, resumed, opened.st_mode & S_IFMT == S_IFREG, opened.st_uid == record.account,
                      opened.st_nlink == 1 {
                checked = .handed
            } else {
                checked = .skipped
            }
            close(file)
        }
        guard let kept = putBack(id + ".held", into: directory, as: name) else { return .held }
        _ = unlinkat(holding, id + ".record", 0)
        switch checked {
        case .handed: return .handed(kept: kept)
        case .skipped: return .skipped(kept: kept)
        case .failed: return .failed
        }
    }

    /// Back under its name, never replacing one made while it was held
    /// (false); then next to it, so the account still finds it (true); nil
    /// when both names are taken: it stays held for the next repair.
    private func putBack(_ held: String, into directory: Int32, as name: String) -> Bool? {
        let exclusive = UInt32(RENAME_EXCL)
        if renameatx_np(holding, held, directory, name, exclusive) == 0 { return false }
        if renameatx_np(holding, held, directory, name + Self.keptSuffix, exclusive) == 0 { return true }
        return nil
    }

    /// The folder at components below root, reached without following a
    /// link, on root's volume.
    private func folder(_ components: ArraySlice<String>) -> Int32? {
        guard root >= 0 else { return nil }
        var current = dup(root)
        for component in components {
            guard current >= 0 else { return nil }
            guard !component.isEmpty, component != ".", component != ".." else {
                close(current)
                return nil
            }
            let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(current)
            current = next
        }
        guard current >= 0 else { return nil }
        var status = stat()
        guard fstat(current, &status) == 0, status.st_dev == device else {
            close(current)
            return nil
        }
        return current
    }

    /// The holding folder, opened once per repair; nil (otherVolume) when
    /// root is not on its volume.
    private func openHolding() -> Int32? {
        if holding >= 0 { return holding }
        guard !tried else { return nil }
        tried = true
        guard let descriptor = Self.openHoldingFolder(create: true) else { return nil }
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_dev == device else {
            otherVolume = status.st_dev != device
            close(descriptor)
            return nil
        }
        holding = descriptor
        return descriptor
    }

    /// The folder that holds the holding folder, opened by descriptor from /
    /// the same way, or nil when a folder on the way is not trusted.
    private static func openHoldingParent() -> Int32? {
        var current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        for component in holdingParent.split(separator: "/").map(String.init) {
            guard current >= 0 else { return nil }
            guard isTrustedParent(current) else {
                close(current)
                return nil
            }
            let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(current)
            current = next
        }
        guard current >= 0 else { return nil }
        guard isTrustedParent(current) else {
            close(current)
            return nil
        }
        return current
    }

    /// Removes the holding folder when nothing is held in it, so a Mac
    /// that never had a file held, or has had every one returned, keeps no
    /// folder behind when DefenseClawMac is removed. A folder with a held
    /// file or record (of any account) stays: rmdir refuses it.
    @discardableResult
    static func removeEmptyHoldingFolder() -> Bool {
        guard let parent = openHoldingParent() else { return false }
        defer { close(parent) }
        return unlinkat(parent, holdingName, AT_REMOVEDIR) == 0
    }

    /// holdingPath by descriptor from /, never following a link: every folder
    /// on the way is owned by root (or this process) and nobody else can
    /// write it, and the holding folder is this process's own, mode 700, with
    /// no access rules.
    static func openHoldingFolder(create: Bool) -> Int32? {
        guard let current = openHoldingParent() else { return nil }
        defer { close(current) }
        if create, mkdirat(current, holdingName, 0o700) != 0, errno != EEXIST { return nil }
        let folder = openat(current, holdingName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard folder >= 0 else { return nil }
        var status = stat()
        guard fstat(folder, &status) == 0, status.st_mode & S_IFMT == S_IFDIR, status.st_uid == geteuid(),
              fchmod(folder, 0o700) == 0, clearAccessRules(folder),
              (try? GatewayAdminTrust.rejectWriteACL(descriptor: folder)) != nil else {
            close(folder)
            return nil
        }
        return folder
    }

    private static func isTrustedParent(_ descriptor: Int32) -> Bool {
        var status = stat()
        return fstat(descriptor, &status) == 0 && status.st_mode & S_IFMT == S_IFDIR
            && (status.st_uid == 0 || status.st_uid == geteuid()) && status.st_mode & 0o022 == 0
            && (try? GatewayAdminTrust.rejectWriteACL(descriptor: descriptor)) != nil
    }

    private static func clearAccessRules(_ descriptor: Int32) -> Bool {
        guard let empty = acl_init(0) else { return false }
        defer { acl_free(UnsafeMutableRawPointer(empty)) }
        return acl_set_fd_np(descriptor, empty, ACL_TYPE_EXTENDED) == 0 || errno == ENOTSUP
    }

    private static func scope(_ account: uid_t, _ root: stat) -> String {
        "\(account).\(root.st_dev).\(root.st_ino)."
    }

    private static func randomName() -> String {
        var random = [UInt8](repeating: 0, count: 16)
        arc4random_buf(&random, random.count)
        return random.map { String(format: "%02x", $0) }.joined()
    }

    private static func writeRecord(_ record: Record, in folder: Int32, as name: String) -> Bool {
        guard let data = try? JSONEncoder().encode(record) else { return false }
        let file = openat(folder, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { return false }
        let written = data.withUnsafeBytes { Darwin.write(file, $0.baseAddress, $0.count) }
        let durable = written == data.count && fsync(file) == 0
        close(file)
        if !durable { _ = unlinkat(folder, name, 0) }
        return durable
    }

    private static func readRecord(in folder: Int32, _ name: String) -> Record? {
        let file = openat(folder, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { return nil }
        defer { close(file) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while data.count < 65_536 {
            let count = Darwin.read(file, &buffer, buffer.count)
            guard count > 0 else { break }
            data.append(contentsOf: buffer[0..<count])
        }
        return try? JSONDecoder().decode(Record.self, from: data)
    }
}

/// Return the root-owned folders and regular files a root-run gateway left in
/// this account's DefenseClaw home to the account. Only DefenseClaw's own
/// names directly in the home are considered (ownedNames), and the folders
/// among them are walked. The walk is bound to descriptors reached from the
/// verified home descriptor: no symlink is ever followed (O_NOFOLLOW at every
/// step), a file is handed over only by GatewayAdminHandover (moved into a
/// root-only holding folder, then changed through its own descriptor while it
/// has a single link, so a hard link to a file elsewhere is never changed),
/// special files and other volumes are skipped, and the walk is bounded.
/// Modes are kept; only the owner and group change.
enum GatewayAdminOwnershipRepair {
    static let maximumEntries = 250_000
    static let maximumDepth = 32
    static let listedPaths = 12
    /// DefenseClaw's own files and folders directly in its home: the runtime
    /// files a gateway writes, its state stores and its state folders. The
    /// Python runtime (.venv) and anything else in the home are never touched.
    static let ownedNames: Set<String> = [
        "config.yaml", ".env", "gateway.pid", "watchdog.pid", "gateway-api.json", "gateway.log", "gateway.jsonl",
        "hook_contract_lock.json", "hook_contract_lock.json.lock", "active_connector.json", "ai_discovery_state.json",
        "application_protection_state.json", "redaction-correlation.key", "device.key", "device.key.provenance",
        "audit.db", "audit.db-shm", "audit.db-wal", "judge.db", "judge.db-shm", "judge.db-wal", "judge_bodies.db",
        "judge_bodies.db-shm", "judge_bodies.db-wal", "confidence_policy.yaml", "custom-providers.json",
        "guardrail_runtime.json", "picked_connector", "doctor_cache.json",
        "hooks", "acp", "cache", "logs", "policies", "quarantine", "receipts", "registries", "previous",
        "installer", "reports", "exports", "tui",
    ]

    struct Outcome: Equatable {
        var restored: [String] = []
        var skipped: [String] = []
        var incomplete = false
        /// Put back next to a file made at their name during the repair, by
        /// the name they have now (also in restored or skipped).
        var kept: [String] = []
        /// Still in the holding folder: the next repair returns them.
        var held: [String] = []
        /// Not on the holding folder's volume, so not handed over.
        var refused: [String] = []
        /// The walk reached its deadline and stopped where it was, so the
        /// helper could answer inside the app's reply budget (GAP-2003).
        var unfinished = false

        mutating func merge(_ other: Outcome) {
            restored += other.restored
            skipped += other.skipped
            incomplete = incomplete || other.incomplete
            kept += other.kept
            held += other.held
            refused += other.refused
            unfinished = unfinished || other.unfinished
        }

        /// Records one handover of shown; false when the file is not settled.
        @discardableResult
        mutating func add(_ result: GatewayAdminHandover.Result, _ shown: String) -> Bool {
            switch result {
            case .handed(let next), .skipped(let next):
                let now = next ? shown + GatewayAdminHandover.keptSuffix : shown
                if case .handed = result { restored.append(now) } else { skipped.append(now) }
                if next { kept.append(now) }
                return true
            case .failed:
                incomplete = true
            case .held:
                held.append(shown)
                incomplete = true
            case .refused:
                refused.append(shown)
                incomplete = true
            }
            return false
        }

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
                lines.append("Left \(skipped.count) root-owned items unchanged (hard links, special files, setuid or "
                    + "setgid files, and items other accounts can write): "
                    + skipped.prefix(GatewayAdminOwnershipRepair.listedPaths).joined(separator: ", ") + ".")
            }
            let listed = GatewayAdminOwnershipRepair.listedPaths
            if !kept.isEmpty {
                lines.append("Put \(kept.count) back under a new name, because a file was made at their name during the "
                    + "repair: " + kept.prefix(listed).joined(separator: ", ") + ".")
            }
            if !held.isEmpty {
                lines.append("Kept \(held.count) files in \(GatewayAdminHandover.holdingPath), where only the repair can "
                    + "reach them, because a file was made at their name and at their \(GatewayAdminHandover.keptSuffix) "
                    + "name, or their folder moved: " + held.prefix(listed).joined(separator: ", ")
                    + ". Free one of those names or put the folder back, then repair again to get them back.")
            }
            if !refused.isEmpty {
                lines.append("Left \(refused.count) root-owned files unchanged because they are not on the volume of "
                    + "\(GatewayAdminHandover.holdingParent), where the repair holds a file while it hands it over: "
                    + refused.prefix(listed).joined(separator: ", ") + ".")
            }
            if unfinished {
                lines.append("The repair stopped before it reached every file so that it could answer in time; "
                    + "repair again to return the rest.")
            } else if incomplete {
                lines.append("Part of the home was left root-owned because it could not be inspected or other accounts can "
                    + "write it; run `defenseclaw doctor` to see what is still root-owned and how to fix it.")
            }
            return lines.joined(separator: "\n") + "\n"
        }
    }

    /// Returns what owner owns under root to the account. `privateOnly` is
    /// the whole-folder return of an agent config folder
    /// (GatewayAdminAgentConfigRepair), held to the per-file rules there: a
    /// root-owned folder another account can write is neither returned nor
    /// entered (reported as skipped), a file with a setuid, setgid, group or
    /// other write bit is left as it is (reported as skipped), a folder of a
    /// third account, an account folder others can write or one on another
    /// volume is not entered, and a folder is returned only after everything in it was
    /// inspected, so a walk cut short leaves it root-owned and still listed by
    /// connector.RootOwnedAgentConfigPaths instead of returning it with
    /// unlisted root-owned children. The DefenseClaw home walk keeps the
    /// account's access first: each folder is returned before its contents.
    /// `base` is root's path below the root of a shared handover (`given`).
    /// Past `deadline` the walk stops where it is and reports itself
    /// unfinished: every file it handed over is settled, and the next repair
    /// returns the rest (GAP-2003).
    static func restore(home root: Int32, from owner: uid_t = 0, to account: (uid: uid_t, gid: gid_t),
                        names allowed: Set<String>? = GatewayAdminOwnershipRepair.ownedNames,
                        privateOnly: Bool = false,
                        maximumEntries: Int = GatewayAdminOwnershipRepair.maximumEntries,
                        until deadline: ContinuousClock.Instant? = nil,
                        handover given: GatewayAdminHandover? = nil,
                        at base: String = "",
                        change: ((Int32, String) -> Int32)? = nil) throws -> Outcome {
        let apply = change ?? { descriptor, _ in fchown(descriptor, account.uid, account.gid) }
        var metadata = stat()
        guard fstat(root, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR else {
            throw GatewayAdminFailure.refused("The DefenseClaw home is not a folder.")
        }
        let handover = given ?? GatewayAdminHandover(root: root, account: account.uid)
        defer { if given == nil { handover.finish() } }
        var outcome = Outcome()
        var visited = 0

        func late() -> Bool {
            guard let deadline, ContinuousClock.now >= deadline else { return false }
            outcome.incomplete = true
            outcome.unfinished = true
            return true
        }

        func give(_ descriptor: Int32, _ relative: String) -> Bool {
            if apply(descriptor, relative) == 0 {
                outcome.restored.append(relative)
                return true
            }
            outcome.incomplete = true
            return false
        }

        // A verified open folder: returned (when owner owns it) and walked.
        // false when anything in it was left uninspected.
        func folder(_ descriptor: Int32, _ status: stat, _ relative: String, _ prefix: String, _ depth: Int) -> Bool {
            let owned = status.st_uid == owner
            guard privateOnly else {
                if owned { _ = give(descriptor, relative) }
                return walk(descriptor, prefix, depth)
            }
            let shared = status.st_mode & 0o022 != 0
            if owned {
                if shared {
                    // Others could have placed what it holds: left as it is,
                    // and so is every folder holding it.
                    outcome.skipped.append(relative)
                    outcome.incomplete = true
                    return false
                }
                guard walk(descriptor, prefix, depth) else { return false }
                return give(descriptor, relative)
            }
            if status.st_uid == account.uid && !shared {
                return walk(descriptor, prefix, depth)
            }
            // A folder of a third account, or one others can write, is not
            // entered, so what it holds stays uninspected.
            outcome.incomplete = true
            return false
        }

        func walk(_ directory: Int32, _ prefix: String, _ depth: Int) -> Bool {
            guard depth < maximumDepth, let listed = GatewayAdminDirectory.names(of: directory) else {
                outcome.incomplete = true
                return false
            }
            var complete = true
            let names = prefix.isEmpty ? listed.filter { allowed?.contains($0) ?? true } : listed
            for name in names.sorted() {
                visited += 1
                guard visited <= maximumEntries else {
                    outcome.incomplete = true
                    return false
                }
                if late() { return false }
                let relative = prefix.isEmpty ? name : prefix + "/" + name
                var entry = stat()
                guard fstatat(directory, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
                switch entry.st_mode & S_IFMT {
                case S_IFDIR:
                    guard entry.st_dev == metadata.st_dev else {
                        // Another volume is never walked; in an agent config
                        // folder that leaves it uninspected.
                        if privateOnly { outcome.incomplete = true; complete = false }
                        continue
                    }
                    let child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    guard child >= 0 else {
                        outcome.incomplete = true
                        complete = false
                        continue
                    }
                    defer { close(child) }
                    var opened = stat()
                    guard fstat(child, &opened) == 0, opened.st_mode & S_IFMT == S_IFDIR,
                          opened.st_dev == metadata.st_dev else {
                        if privateOnly { outcome.incomplete = true; complete = false }
                        continue
                    }
                    if !folder(child, opened, relative, relative, depth + 1) { complete = false }
                case S_IFREG:
                    guard entry.st_uid == owner else { continue }
                    // A hard link (two links when inspected) is reported and
                    // never moved; one link read here proves nothing yet, so
                    // the file is handed over only through the holding folder.
                    guard entry.st_nlink == 1, !privateOnly || entry.st_mode & 0o6022 == 0 else {
                        outcome.skipped.append(relative)
                        continue
                    }
                    #if GATEWAY_ADMIN_HELPER_TESTING
                    // Declared by Tests/GatewayAdminHelperTests.swift.
                    GatewayAdminOwnershipRepair.walkFileCheckedForTesting?(relative)
                    #endif
                    if !outcome.add(handover.handOver(directory, name, inspected: entry, path: base + relative,
                                                      shown: relative, change: { apply($0, relative) }), relative) {
                        complete = false
                    }
                case S_IFLNK:
                    // Never followed or changed; the account owns the folder
                    // holding it and can remove it.
                    continue
                default:
                    if entry.st_uid == owner { outcome.skipped.append(relative) }
                }
            }
            return complete
        }
        if !late() { _ = folder(root, metadata, ".", "", 0) }
        if given == nil { outcome.merge(handover.recover(change: apply)) }
        return outcome
    }
}

/// Return the agent config files a root-run gateway rewrote in the account
/// home (its connector setup at boot) to the account. Before 1.0.9 the writers
/// left them root:600 (GAP-0848), so the account's own gateway and agent can
/// neither read nor replace them; Go lists them as
/// connector.RootOwnedAgentConfigPaths and doctor prints a sudo step. The paths
/// are fixed here: none crosses XPC, and the home comes from the account
/// record. A path is walked from the account home one name at a time with
/// O_NOFOLLOW: a folder the account owns and nobody else can write is entered;
/// a root-owned folder on the way is returned whole by the same walk as the
/// DefenseClaw home under the same file rules (`privateOnly`), and only once
/// all of it was inspected (Go lists the outermost one); the file itself is changed
/// only when it is a root-owned regular file with one link, on the home's
/// volume, with no setuid, setgid, group or other write bit, handed over by
/// GatewayAdminHandover (held outside every folder the account can write).
/// Links, other owners and anything else stay as they are.
enum GatewayAdminAgentConfigRepair {
    // BEGIN agentConfigPaths: the macOS default candidates of
    // connector.RootOwnedAgentConfigPaths, relative to the account home
    // (internal/gateway/connector/root_owned_agent_config_macapp_test.go).
    static let relativePaths: [String] = [
        ".claude/settings.json",
        ".codex/config.toml",
        ".config/amp/plugins/defenseclaw.ts",
        ".config/devin/config.json",
        ".config/opencode/plugins/defenseclaw.js",
        ".copilot/hooks/defenseclaw.json",
        ".cursor/hooks.json",
        ".gemini/config/hooks.json",
        ".hermes/config.yaml",
        ".hermes/shell-hooks-allowlist.json",
        ".kiro/agents/defenseclaw.json",
        ".kiro/hooks/defenseclaw.json",
        ".kiro/settings/cli.json",
        ".openclaw/openclaw.json",
        ".zeptoclaw/config.json",
    ]
    // END agentConfigPaths

    /// The account home as a descriptor reached without following a link,
    /// owned by the account and writable by nobody else.
    static func openAccountHome(_ home: String, uid: uid_t) throws -> Int32 {
        guard GatewayAdminPolicy.isCanonicalAbsolutePath(home), home != "/" else {
            throw GatewayAdminFailure.refused("The account has no valid home directory.")
        }
        var current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw GatewayAdminFailure.refused("The account home could not be opened.") }
        for component in home.split(separator: "/") {
            let next = openat(current, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(current)
            guard next >= 0 else {
                throw GatewayAdminFailure.refused("The account home could not be opened without following a link.")
            }
            current = next
        }
        var metadata = stat()
        guard fstat(current, &metadata) == 0, metadata.st_uid == uid, metadata.st_mode & 0o022 == 0 else {
            close(current)
            throw GatewayAdminFailure.refused("The account home is not owned by the account or is writable by others.")
        }
        return current
    }

    static func restore(home: Int32, from owner: uid_t = 0, to account: (uid: uid_t, gid: gid_t),
                        paths: [String] = GatewayAdminAgentConfigRepair.relativePaths,
                        until deadline: ContinuousClock.Instant? = nil,
                        change: ((Int32, String) -> Int32)? = nil) -> GatewayAdminOwnershipRepair.Outcome {
        let apply = change ?? { descriptor, _ in fchown(descriptor, account.uid, account.gid) }
        var outcome = GatewayAdminOwnershipRepair.Outcome()
        var homeStatus = stat()
        guard fstat(home, &homeStatus) == 0 else { return GatewayAdminOwnershipRepair.Outcome(incomplete: true) }
        let handover = GatewayAdminHandover(root: home, account: account.uid, shownPrefix: "~/")
        defer { handover.finish() }
        var returnedFolders: [String] = []
        for path in paths {
            if let deadline, ContinuousClock.now >= deadline {
                // GAP-2003: answer in time; the next repair returns the rest.
                outcome.incomplete = true
                outcome.unfinished = true
                break
            }
            if returnedFolders.contains(where: { path.hasPrefix($0 + "/") }) { continue }
            let components = path.split(separator: "/").map(String.init)
            var parent = dup(home)
            guard parent >= 0 else { outcome.incomplete = true; continue }
            var relative = ""
            for (index, name) in components.enumerated() {
                relative = relative.isEmpty ? name : relative + "/" + name
                let shown = "~/" + relative
                var entry = stat()
                guard fstatat(parent, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 else {
                    if errno != ENOENT { outcome.incomplete = true }
                    break
                }
                guard entry.st_dev == homeStatus.st_dev else { break }
                if index < components.count - 1 {
                    guard entry.st_mode & S_IFMT == S_IFDIR else { break }
                    let child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    guard child >= 0 else { outcome.incomplete = true; break }
                    var opened = stat()
                    guard fstat(child, &opened) == 0, opened.st_ino == entry.st_ino, opened.st_dev == entry.st_dev,
                          opened.st_mode & S_IFMT == S_IFDIR else {
                        close(child)
                        outcome.incomplete = true
                        break
                    }
                    if opened.st_uid == account.uid {
                        // The account's own folder: entered only while nobody
                        // else can write it, and never returned.
                        guard opened.st_mode & 0o022 == 0 else {
                            close(child)
                            break
                        }
                        close(parent)
                        parent = child
                        continue
                    }
                    if opened.st_uid == owner {
                        let inside = { (inner: String) in inner == "." ? shown : shown + "/" + inner }
                        let folder = (try? GatewayAdminOwnershipRepair.restore(
                            home: child, from: owner, to: account, names: nil, privateOnly: true, until: deadline,
                            handover: handover,
                            at: relative + "/", change: { descriptor, inner in apply(descriptor, inside(inner)) }))
                            ?? GatewayAdminOwnershipRepair.Outcome(incomplete: true)
                        outcome.merge(GatewayAdminOwnershipRepair.Outcome(
                            restored: folder.restored.map(inside), skipped: folder.skipped.map(inside),
                            incomplete: folder.incomplete, kept: folder.kept.map(inside),
                            held: folder.held.map(inside), refused: folder.refused.map(inside),
                            unfinished: folder.unfinished))
                        returnedFolders.append(relative)
                    }
                    close(child)
                    break
                }
                guard entry.st_mode & S_IFMT == S_IFREG, entry.st_uid == owner else { break }
                guard entry.st_nlink == 1, entry.st_mode & 0o6022 == 0 else {
                    outcome.skipped.append(shown)
                    break
                }
                #if GATEWAY_ADMIN_HELPER_TESTING
                // Declared by Tests/GatewayAdminHelperTests.swift.
                Self.fileCheckedForTesting?(shown)
                #endif
                outcome.add(handover.handOver(parent, name, inspected: entry, path: relative, shown: shown,
                                              change: { apply($0, shown) }), shown)
            }
            close(parent)
        }
        outcome.merge(handover.recover(change: apply))
        return outcome
    }
}

/// The repair order, with every effect injected so it is testable without
/// root: never touch anything while a root gateway the helper did not start
/// serves the home; stop the helper-started processes by verified PID; return
/// files only once none runs; then delete the private copy.
enum GatewayAdminRepair {
    static let stillRunning = """
        A gateway is still running as root for this DefenseClaw home, and it was not started by DefenseClawMac \
        (for example `sudo defenseclaw-gateway start`) or its PID record is not the root-owned file that gateway \
        wrote. Stop it with `sudo defenseclaw-gateway stop`, then start the gateway again from DefenseClawMac. \
        Nothing was changed.

        """

    static func perform(
        liveRootProcesses: () -> GatewayAdminRootProcess.Found,
        stop: ([GatewayAdminRootProcess.Live]) -> Bool,
        restoreOwnership: () throws -> GatewayAdminOwnershipRepair.Outcome,
        removeStagedGateway: () throws -> Void
    ) throws -> (Int32, String) {
        let found = liveRootProcesses()
        guard found.other.isEmpty else { return (75, stillRunning) }
        var output = ""
        if !found.helperStarted.isEmpty {
            guard stop(found.helperStarted), liveRootProcesses().isEmpty else {
                return (1, "The gateway DefenseClawMac had run as administrator did not stop. Nothing else was changed; check `defenseclaw-gateway status` and retry.\n")
            }
            output += "Stopped the gateway DefenseClawMac had run as administrator.\n"
        }
        let outcome = try restoreOwnership()
        try removeStagedGateway()
        output += outcome.summary
        let code: Int32 = outcome.unfinished ? GatewayAdminPolicy.repairUnfinishedExitCode : outcome.incomplete ? 1 : 0
        return (code, output)
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
        // The walks stop in time for the reply to reach the app inside its
        // budget (GAP-2003), counted from the request, as the app counts.
        let walkDeadline = ContinuousClock.now.advanced(by: .seconds(GatewayAdminPolicy.repairWalkSeconds))
        lifetime.operationStarted()
        queue.async { [uid, lifetime] in
            defer { lifetime.operationFinished() }
            do {
                guard geteuid() == 0 else {
                    throw GatewayAdminFailure.refused("The gateway administrator helper is not running as root.")
                }
                let outcome = try GatewayAdminTrust.withAuthorization(authorization) {
                    let account = try InvokingAccount(uid: uid)
                    try GatewayAdminTrust.validateHelperBundle()
                    // Opened right before use: every later read and change
                    // goes through this verified descriptor.
                    let installation = try GatewayAdminInstallation(home: homePath, config: configPath, account: account)
                    let staged = GatewayAdminTrust.stagedExecutables(uid: account.uid)
                    return try GatewayAdminRepair.perform(
                        liveRootProcesses: { GatewayAdminRootProcess.live(in: installation.descriptor, uid: account.uid) },
                        stop: { processes in
                            GatewayAdminStop.stop(processes, isSame: { GatewayAdminRootProcess.isSame($0, staged: staged) })
                        },
                        restoreOwnership: {
                            var outcome = try GatewayAdminOwnershipRepair.restore(
                                home: installation.descriptor, to: (account.uid, account.gid), until: walkDeadline)
                            guard let accountHome = try? GatewayAdminAgentConfigRepair.openAccountHome(
                                account.home, uid: account.uid) else {
                                outcome.incomplete = true
                                return outcome
                            }
                            defer { close(accountHome) }
                            outcome.merge(GatewayAdminAgentConfigRepair.restore(
                                home: accountHome, to: (account.uid, account.gid), until: walkDeadline))
                            // Held by an earlier repair of a folder neither walk reached now.
                            let unclaimed = GatewayAdminHandover.unclaimed(
                                account: account.uid, roots: [installation.descriptor, accountHome])
                            outcome.merge(GatewayAdminOwnershipRepair.Outcome(incomplete: !unclaimed.isEmpty, held: unclaimed))
                            // Nothing left held: the holding folder goes too.
                            if outcome.held.isEmpty, !outcome.incomplete { _ = GatewayAdminHandover.removeEmptyHoldingFolder() }
                            return outcome
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
