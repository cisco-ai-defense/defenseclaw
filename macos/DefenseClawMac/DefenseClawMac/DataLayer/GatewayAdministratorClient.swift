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

import Foundation
import Security
import ServiceManagement

/// Cancellation may prevent dispatch. Once dispatched, the system authorization
/// dialog handles cancellation and Activity waits for the helper's actual result.
final class GatewayAdministratorOperation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var dispatched = false

    func cancel() -> CLICancellationDisposition {
        lock.lock()
        defer { lock.unlock() }
        if dispatched { return .finishing }
        if cancelled { return .alreadyRequested }
        cancelled = true
        return .requested
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    func beginDispatch() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, !dispatched else { return false }
        dispatched = true
        return true
    }
}

/// Root-owned gateway state in the selected per-user DefenseClaw home: the
/// footprint of a gateway run as root for this home (the "Run gateway as
/// administrator" switch of app versions up to 1.0.8, or sudo). The app runs
/// as the login account, so a root owner on any of these fixed entries means
/// the gateway serving this home ran as root. lstat only: nothing is opened
/// or followed.
enum GatewayRootState {
    /// Every marker is one of the names the helper's repair returns
    /// (GatewayAdminOwnershipRepair.ownedNames), so a repaired home has none.
    static let markers = [
        ".", "gateway.pid", "watchdog.pid", "gateway-api.json", "hook_contract_lock.json",
        "active_connector.json", "device.key", "hooks", "gateway.log", "config.yaml",
    ]

    /// A root-owned marker and the identity of the object behind it, so the app
    /// can tell an unchanged leftover from a new one.
    struct Marker: Hashable, Sendable {
        var name: String
        var identity: String
    }

    static func rootOwnedMarkers(home: URL, accountUID: uid_t = getuid()) -> [Marker] {
        guard accountUID != 0 else { return [] }
        return markers.compactMap { name in
            var metadata = stat()
            let path = name == "." ? home.path : home.appendingPathComponent(name).path
            guard lstat(path, &metadata) == 0, metadata.st_uid == 0 else { return nil }
            return Marker(name: name, identity: "\(name):\(metadata.st_dev):\(metadata.st_ino):"
                + "\(metadata.st_ctimespec.tv_sec).\(metadata.st_ctimespec.tv_nsec)")
        }
    }

    static func fingerprint(_ markers: [Marker]) -> String {
        markers.map(\.identity).sorted().joined(separator: "|")
    }

    /// What to do when a repair has run and these are still root-owned; the
    /// app does not ask for administrator approval again until they change.
    static func unresolvedMessage(_ markers: [Marker], home: URL) -> String {
        "These DefenseClaw files are still owned by root: \(markers.map(\.name).joined(separator: ", ")). "
            + "DefenseClawMac will not ask to repair them again until they change. If a gateway started with sudo "
            + "is running, stop it first: sudo defenseclaw-gateway stop. Then return the files to your account "
            + "in Terminal and start the gateway again: sudo chown -R \"$(id -un)\" \(shellQuoted(home.path))\n"
    }

    /// A POSIX shell single-quoted word: safe to paste for any path,
    /// including spaces, `;` and embedded single quotes.
    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

/// The fingerprint of root-owned markers a repair could not clear, kept so a
/// leftover the helper skips (a hard link, a special file, a sudo-run gateway)
/// does not bring the administrator prompt back on every start.
struct GatewayRepairMemory: Sendable {
    static let key = "gatewayRootRepairUnresolved"

    var load: @Sendable () -> String?
    var save: @Sendable (String?) -> Void

    static let standard = GatewayRepairMemory(
        load: { UserDefaults.standard.string(forKey: GatewayRepairMemory.key) },
        save: { value in
            if let value { UserDefaults.standard.set(value, forKey: GatewayRepairMemory.key) } else { UserDefaults.standard.removeObject(forKey: GatewayRepairMemory.key) }
        }
    )
}

/// The per-user gateway always runs as the login account. This client only
/// asks the bundled administrator helper to move a gateway that an earlier
/// app version ran as root back to the account (GatewayAdminAction.repair).
enum GatewayAdministratorClient {
    /// The "Run gateway as administrator" switch of app versions up to 1.0.8.
    /// Removed at launch; drop this cleanup with the repair (no earlier than 1.1).
    static let retiredPreferenceKeys = ["gatewayAdministratorMode"]

    static func removeRetiredPreferences(_ defaults: UserDefaults = .standard) {
        for key in retiredPreferenceKeys { defaults.removeObject(forKey: key) }
    }

    private static var bundledServiceAvailable: Bool {
        let root = Bundle.main.bundleURL
        return FileManager.default.isExecutableFile(atPath: root.appendingPathComponent(GatewayAdminPolicy.helperRelativePath).path)
            && FileManager.default.fileExists(atPath: root.appendingPathComponent("Contents/Library/LaunchDaemons/" + GatewayAdminPolicy.serviceName + ".plist").path)
    }

    static func needsRegistration(status: SMAppService.Status, bundledServiceAvailable: Bool) -> Bool {
        bundledServiceAvailable && (status == .notRegistered || status == .notFound)
    }

    @MainActor
    static func openServiceSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    @MainActor
    private static var service: SMAppService {
        SMAppService.daemon(plistName: GatewayAdminPolicy.serviceName + ".plist")
    }

    static func repair(
        context: InstallationContext,
        operation: GatewayAdministratorOperation
    ) async -> CLIResult {
        guard context.permitsMutation else {
            return CLIResult(exitCode: 77, output: "Gateway repair refused: this installation is read only.")
        }
        if operation.isCancelled { return cancelledResult }
        do {
            try verifySignedAppAndHelper(home: context.homeRoot.path)
            let registrationResult = await registerIfNeeded()
            if let registrationResult { return registrationResult }
            if operation.isCancelled { return cancelledResult }
            // Authorization Services owns the password/Touch ID interface. No
            // password is ever returned to the app, placed in argv, or logged.
            let authorization = try await Task.detached(priority: .userInitiated) {
                try AdministratorAuthorization()
            }.value
            defer { authorization.invalidate() }
            if operation.isCancelled { return cancelledResult }
            guard operation.beginDispatch() else { return cancelledResult }
            return await perform(context: context, authorization: authorization.externalForm)
        } catch let error as AdministratorError {
            if error.status == errAuthorizationCanceled || operation.isCancelled { return cancelledResult }
            return CLIResult(exitCode: 77, output: error.localizedDescription)
        } catch {
            return CLIResult(exitCode: 77, output: "Gateway repair failed: \(error.localizedDescription)")
        }
    }

    static func resultForHelperReply(exitCode: Int32, output: String) -> CLIResult {
        CLIResult(exitCode: exitCode, output: output, cancelled: exitCode == 130)
    }

    private static var cancelledResult: CLIResult {
        CLIResult(exitCode: 130, output: "Administrator authorization cancelled. No gateway repair was sent.\n", cancelled: true)
    }

    @MainActor
    private static func registerIfNeeded() -> CLIResult? {
        do {
            if needsRegistration(status: service.status, bundledServiceAvailable: bundledServiceAvailable) {
                try service.register()
            }
            switch service.status {
            case .enabled: return nil
            case .requiresApproval:
                openServiceSettings()
                return CLIResult(exitCode: 78, output: "Administrator service approval is required to repair a gateway an earlier version ran as administrator. In System Settings → General → Login Items & Extensions, allow DefenseClawMac, then start the gateway again. The gateway has not been started.\n")
            case .notFound, .notRegistered:
                return CLIResult(exitCode: 78, output: "The administrator service is unavailable. Install the signed DefenseClawMac app in Applications, reopen it, and try again.\n")
            @unknown default:
                return CLIResult(exitCode: 78, output: "Administrator service status is unavailable. Check Login Items & Extensions before retrying.\n")
            }
        } catch {
            if service.status == .requiresApproval {
                openServiceSettings()
                return CLIResult(exitCode: 78, output: "Allow DefenseClawMac in System Settings → General → Login Items & Extensions, then retry. The gateway has not been started.\n")
            }
            return CLIResult(exitCode: 78, output: "Could not register the administrator service: \(error.localizedDescription). Install the signed app in Applications and check Login Items & Extensions.\n")
        }
    }

    private static func verifySignedAppAndHelper(home: String) throws {
        var code: SecCode?
        var requirement: SecRequirement?
        guard SecCodeCopySelf([], &code) == errSecSuccess,
              SecRequirementCreateWithString(GatewayAdminPolicy.appRequirement as CFString, [], &requirement) == errSecSuccess,
              let code, let requirement,
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else {
            throw AdministratorError(message: "This installation has gateway files owned by root, and only a Developer ID signed DefenseClawMac build can repair them from the app. Repair it in Terminal, then start the gateway again: sudo defenseclaw-gateway stop && sudo chown -R \"$(id -un)\" \(GatewayRootState.shellQuoted(home))\n")
        }
        guard bundledServiceAvailable else {
            throw AdministratorError(message: "This app build does not include its administrator helper. Install the complete signed DefenseClawMac build.")
        }
    }

    private static func perform(context: InstallationContext, authorization: Data) async -> CLIResult {
        await withCheckedContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: GatewayAdminPolicy.serviceName, options: .privileged)
            connection.remoteObjectInterface = NSXPCInterface(with: GatewayAdminProtocol.self)
            connection.setCodeSigningRequirement(GatewayAdminPolicy.helperRequirement)
            let completion = AdministratorCompletion(connection: connection, continuation: continuation)
            connection.interruptionHandler = {
                completion.finish(CLIResult(exitCode: 75, output: "The administrator service connection was interrupted. Check gateway status before retrying.\n"))
            }
            connection.invalidationHandler = {
                completion.finish(CLIResult(exitCode: 75, output: "The administrator service is unavailable. Check Login Items & Extensions and gateway status before retrying.\n"))
            }
            connection.resume()
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                completion.finish(CLIResult(exitCode: 75, output: "Administrator service error: \(error.localizedDescription). Check gateway status before retrying.\n"))
            }) as? GatewayAdminProtocol else {
                completion.finish(CLIResult(exitCode: 75, output: "Could not connect to the administrator gateway service.\n"))
                return
            }
            proxy.perform(action: GatewayAdminAction.repair.rawValue, homePath: context.homeRoot.path,
                          configPath: context.configURL.path, authorization: authorization) { code, output in
                completion.finish(resultForHelperReply(exitCode: code, output: output))
            }
            // The administrator prompt is answered before this point, so the
            // budget covers only the helper: its 90 s stop deadline plus the
            // ownership walk, with time to spare.
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 240) {
                completion.finish(CLIResult(exitCode: 124, output: "The gateway repair timed out. The gateway may still be stopping; check its status before retrying.\n"))
            }
        }
    }
}

private struct AdministratorError: LocalizedError {
    var status: OSStatus? = nil
    var message: String
    var errorDescription: String? { message }
}

private final class AdministratorAuthorization: @unchecked Sendable {
    private var reference: AuthorizationRef?
    let externalForm: Data

    init() throws {
        var reference: AuthorizationRef?
        let created = AuthorizationCreate(nil, nil, [], &reference)
        guard created == errAuthorizationSuccess, let reference else {
            throw AdministratorError(status: created, message: "macOS could not create administrator authorization (\(created)).")
        }
        self.reference = reference
        do {
            var definition: CFDictionary?
            let status = AuthorizationRightGet(GatewayAdminPolicy.authorizationRight, &definition)
            if status == errAuthorizationDenied || (status == errAuthorizationSuccess && !GatewayAdminPolicy.authorizationDefinitionIsSafe(definition)) {
                let registered = AuthorizationRightSet(reference, GatewayAdminPolicy.authorizationRight,
                    GatewayAdminPolicy.authorizationDefinition as CFDictionary,
                    "Repair a DefenseClaw gateway an earlier version ran as administrator" as CFString, nil, nil)
                guard registered == errAuthorizationSuccess else {
                    throw AdministratorError(status: registered, message: "Could not set up the gateway authorization right (\(registered)).")
                }
            } else if status != errAuthorizationSuccess {
                throw AdministratorError(status: status, message: "Could not read the gateway authorization right (\(status)).")
            }
            // With the zero-timeout rule this is only a preflight. The helper
            // requests actual authorization immediately before gateway work.
            let authorized = GatewayAdminPolicy.authorizationRight.withCString { name in
                var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                return withUnsafeMutablePointer(to: &item) { pointer in
                    var rights = AuthorizationRights(count: 1, items: pointer)
                    return AuthorizationCopyRights(reference, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
                }
            }
            guard authorized == errAuthorizationSuccess else {
                throw AdministratorError(status: authorized, message: "Administrator authorization was denied (\(authorized)).")
            }
            var form = AuthorizationExternalForm()
            let exported = AuthorizationMakeExternalForm(reference, &form)
            guard exported == errAuthorizationSuccess else {
                throw AdministratorError(status: exported, message: "Could not transfer administrator authorization (\(exported)).")
            }
            externalForm = withUnsafeBytes(of: form) { Data($0) }
        } catch {
            AuthorizationFree(reference, [.destroyRights])
            self.reference = nil
            throw error
        }
    }

    func invalidate() {
        if let reference { AuthorizationFree(reference, [.destroyRights]) }
        reference = nil
    }

    deinit { invalidate() }
}

private final class AdministratorCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<CLIResult, Never>?
    private let connection: NSXPCConnection

    init(connection: NSXPCConnection, continuation: CheckedContinuation<CLIResult, Never>) {
        self.connection = connection
        self.continuation = continuation
    }

    func finish(_ result: CLIResult) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        guard let pending else { return }
        connection.interruptionHandler = nil
        connection.invalidationHandler = nil
        connection.invalidate()
        pending.resume(returning: result)
    }
}
