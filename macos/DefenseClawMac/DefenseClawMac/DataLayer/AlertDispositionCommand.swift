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

import Foundation

struct AlertDispositionInvocation: Equatable, Sendable {
    let arguments: [String]
    let standardInput: String
}

enum AlertDispositionCommand {
    /// Runtime 0.8.9 keeps severity selectors and asks for confirmation before
    /// applying a broad mutation. Supplying the answer on stdin also remains
    /// compatible with older tagged runtimes that ignore it.
    static let confirmationInput = "y"

    static func acknowledge(severity: String) -> AlertDispositionInvocation {
        invocation(action: "acknowledge", severity: severity)
    }

    static func dismiss(severity: String?) -> AlertDispositionInvocation {
        invocation(action: "dismiss", severity: severity ?? "all")
    }

    static func suppliesConfirmation(for arguments: [String]) -> Bool {
        arguments.starts(with: ["alerts", "acknowledge"])
            || arguments.starts(with: ["alerts", "dismiss"])
    }

    private static func invocation(action: String, severity: String) -> AlertDispositionInvocation {
        AlertDispositionInvocation(
            arguments: ["alerts", action, "--severity", severity],
            standardInput: confirmationInput
        )
    }
}
