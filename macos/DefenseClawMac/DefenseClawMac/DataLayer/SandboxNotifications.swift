// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Notification categories for sandbox events: blocked destinations carry
// Unblock (this sandbox only; "always" stays a confirmed choice in the app),
// asks and findings carry Review.

import UserNotifications

enum SandboxNotificationCategories {
    static let blocked = "dc.sandbox.blocked"
    static let review = "dc.sandbox.review"
    static let unblockAction = "dc.sandbox.unblock"
    static let openAction = "dc.sandbox.open"

    /// Unblock opens egress for a running agent, so the Mac must be
    /// unlocked first: nobody at a locked screen can lift a block from the
    /// lock screen or Notification Center.
    static let unblockOptions: UNNotificationActionOptions = [.authenticationRequired]

    static func isSandboxCategory(_ category: String) -> Bool {
        category == blocked || category == review
    }

    static var all: Set<UNNotificationCategory> {
        let unblock = UNNotificationAction(
            identifier: unblockAction, title: "Unblock for this sandbox", options: unblockOptions
        )
        let open = UNNotificationAction(identifier: openAction, title: "Review", options: [.foreground])
        return [
            UNNotificationCategory(identifier: blocked, actions: [unblock, open], intentIdentifiers: [], options: []),
            UNNotificationCategory(identifier: review, actions: [open], intentIdentifiers: [], options: []),
        ]
    }
}
