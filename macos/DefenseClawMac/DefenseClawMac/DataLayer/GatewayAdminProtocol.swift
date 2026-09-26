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

/// The privileged boundary is deliberately limited to gateway lifecycle
/// operations. No executable, arguments, environment or password crosses XPC.
@objc protocol GatewayAdminProtocol {
    func perform(
        action: String,
        homePath: String,
        configPath: String,
        authorization: Data,
        withReply reply: @escaping (Int32, String) -> Void
    )
}

enum GatewayAdminAction: String, Sendable, CaseIterable {
    case start
    case stop
    case restart
}

enum GatewayAdminPolicy {
    static let serviceName = "com.cisco.defenseclaw.macos.GatewayAdmin"
    static let helperIdentifier = serviceName
    static let appIdentifier = "com.cisco.defenseclaw.macos"
    static let authorizationRight = "com.cisco.defenseclaw.macos.gateway.manage"
    /// The Developer ID team that signed this running executable. The app and
    /// its helper ship in one signed bundle, so each end requires its peer to
    /// carry its own team rather than a team compiled into the source. Ad-hoc
    /// and unsigned builds have no team and cannot use administrator mode.
    static let teamIdentifier: String? = {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(
                  staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information
              ) == errSecSuccess,
              let values = information as? [String: Any],
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String else { return nil }
        return isTeamIdentifier(team) ? team : nil
    }()
    static let helperRelativePath = "Contents/Library/LaunchServices/DefenseClawGatewayHelper"
    static let maximumOutputBytes = 1_048_576

    /// Explicit per-operation administrator authentication. Both ends verify
    /// this definition so a preexisting same-name `allow` rule is never trusted.
    static let authorizationDefinition: [String: Any] = [
        "class": "user",
        "group": "admin",
        "authenticate-user": true,
        "session-owner": false,
        "shared": false,
        "allow-root": false,
        "timeout": 0,
    ]

    static func authorizationDefinitionIsSafe(_ definition: CFDictionary?) -> Bool {
        guard let values = definition as? [String: Any] else { return false }
        return values["class"] as? String == "user"
            && values["group"] as? String == "admin"
            && values["authenticate-user"] as? Bool == true
            && values["session-owner"] as? Bool == false
            && values["shared"] as? Bool == false
            && values["allow-root"] as? Bool == false
            && (values["timeout"] as? NSNumber)?.doubleValue == 0
    }

    static let appRequirement = requirement(identifier: appIdentifier, teamIdentifier: teamIdentifier)
    static let helperRequirement = requirement(identifier: helperIdentifier, teamIdentifier: teamIdentifier)
    static let gatewayRequirement = requirement(identifier: "com.cisco.defenseclaw.gateway", teamIdentifier: teamIdentifier)

    static func isTeamIdentifier(_ value: String) -> Bool {
        value.utf8.count == 10 && value.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) }
    }

    /// Developer ID requirement for `identifier` under `teamIdentifier`.
    /// Without a valid team the requirement is `never`, which no code meets.
    static func requirement(identifier: String, teamIdentifier: String?) -> String {
        guard let teamIdentifier, isTeamIdentifier(teamIdentifier) else { return "never" }
        return "anchor apple generic and identifier \"\(identifier)\" "
            + "and certificate leaf[subject.OU] = \"\(teamIdentifier)\" "
            + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
            + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    }

    /// Lexical validation only; the helper additionally checks filesystem
    /// ownership, symlinks, and the account database for the authenticated UID.
    static func isCanonicalAbsolutePath(_ path: String) -> Bool {
        guard !path.isEmpty, path.utf8.count < 4_096, path.hasPrefix("/"),
              !path.utf8.contains(0), !path.contains("\n"), !path.contains("\r") else {
            return false
        }
        return (path as NSString).standardizingPath == path
            && !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." })
    }

    static func isStrictDescendant(_ path: String, of directory: String) -> Bool {
        isCanonicalAbsolutePath(path) && isCanonicalAbsolutePath(directory)
            && directory != "/" && path.hasPrefix(directory + "/")
    }
}
