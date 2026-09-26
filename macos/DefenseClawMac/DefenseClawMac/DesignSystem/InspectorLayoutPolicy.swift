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

import SwiftUI

enum InspectorLayoutPolicy {
    static let width: CGFloat = 320
}

extension View {
    /// Let the table/header compress inside its available pane width instead
    /// of propagating its content minimum to the outer navigation split.
    func dcInspectorMainContent() -> some View {
        frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
    }

    /// Keep details in the same SwiftUI layout tree as the main content.
    /// A nested native inspector split can enter an AppKit constraint loop
    /// during selection, hydration, and close/reopen transitions on macOS.
    func dcInspector<Details: View>(
        isPresented: Binding<Bool>,
        @ViewBuilder content: () -> Details
    ) -> some View {
        HStack(spacing: 0) {
            dcInspectorMainContent()
            if isPresented.wrappedValue {
                Divider()
                content()
                    .frame(width: InspectorLayoutPolicy.width)
                    .frame(maxHeight: .infinity)
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel("Details")
            }
        }
        .dcInspectorMainContent()
        .onExitCommand {
            if isPresented.wrappedValue { isPresented.wrappedValue = false }
        }
    }
}
