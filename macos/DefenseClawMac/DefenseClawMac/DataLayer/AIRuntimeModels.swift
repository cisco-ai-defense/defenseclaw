// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// One detection plane's state, as reported on every poll cycle.
///
/// Emitted whether the plane is up or down. If health were reported only while
/// a plane worked, a subscription that died would leave no trace, and absence
/// is the hardest thing to alert on.
struct AIRuntimePlane: Identifiable, Sendable, Hashable {
    var plane: String = ""
    var name: String = ""
    var available: Bool = false
    var running: Bool = false
    var mechanism: String = ""
    var reason: String = ""

    var id: String { plane }

    /// Short state word for a status chip.
    var badge: String {
        if running { return "up" }
        return available ? "idle" : "blind"
    }

    /// One line an operator can act on. A blind or idle plane always states
    /// why, because a plane rendering as silence is indistinguishable from a
    /// clean host.
    var summary: String {
        if running {
            return "\(name): up via \(mechanism.isEmpty ? "unknown mechanism" : mechanism)"
        }
        let detail = reason.isEmpty ? "no reason reported" : reason
        return available
            ? "\(name): available but not running — \(detail)"
            : "\(name): unavailable — \(detail)"
    }
}

/// What the discovery inventory had to say about one runtime finding.
struct AIRuntimeCorrelation: Sendable, Hashable {
    var verdict: String = ""
    var reason: String = ""
    var matchedSignalIDs: [String] = []
    var categories: [String] = []

    /// A complete scan that explains none of this. The more interesting
    /// reading, not the neutral one.
    var isUnaccounted: Bool { verdict.caseInsensitiveCompare("unaccounted") == .orderedSame }
    /// There was no usable inventory. Never spent as evidence or exoneration.
    var isUnobserved: Bool { verdict.caseInsensitiveCompare("unobserved") == .orderedSame }
}

/// One weighted signal contributing to a finding.
struct AIRuntimeSignal: Identifiable, Sendable, Hashable {
    var signalID: String = ""
    var title: String = ""
    var detail: String = ""
    var weight: Int = 0

    var id: String { signalID + "|" + detail }
}

/// One attributed egress peer.
struct AIRuntimeProvider: Identifiable, Sendable, Hashable {
    var hostname: String = ""
    var address: String = ""
    var port: Int = 0
    var category: String = ""
    var confidence: Double = 0
    var attributionSource: String = ""

    /// The port is part of the identity, not decoration.
    ///
    /// `AIRuntimeView` renders providers with an identity-based `ForEach`, so
    /// two peers that share a hostname and address but differ in port would
    /// collide and render as one -- which is exactly the shape a local model
    /// server on two ports, or one host reached over both 443 and a proxy
    /// port, produces.
    var id: String { "\(hostname)|\(address)|\(port)" }
}

/// One scored runtime finding.
struct AIRuntimeFinding: Identifiable, Sendable, Hashable {
    var findingID: String = ""
    var pid: Int = 0
    var process: String = ""
    var cmdline: String = ""
    var user: String = ""
    var agentName: String = ""
    var score: Int = 0
    var severity: String = "info"
    var signals: [AIRuntimeSignal] = []
    var providers: [AIRuntimeProvider] = []
    var correlation = AIRuntimeCorrelation()
    var firstSeen: Date?
    var lastSeen: Date?

    var id: String { findingID.isEmpty ? "\(pid)-\(process)" : findingID }

    /// Worst first.
    var severityRank: Int {
        switch severity.lowercased() {
        case "critical": return 0
        case "high": return 1
        case "medium": return 2
        case "low": return 3
        default: return 4
        }
    }

    /// The observed sequence, when this finding is a chain.
    ///
    /// Rendered as a sequence rather than a set because the order is the
    /// finding: reading a credential is a lead, and reading a credential then
    /// minting an identity then uploading is an incident.
    var chain: String {
        signals.first { $0.signalID == "agent_kill_chain" }?.detail ?? ""
    }

    var providerSummary: String {
        providers.isEmpty ? "—" : providers.map(\.hostname).joined(separator: ", ")
    }
}

/// The runtime-plane snapshot.
///
/// Coverage travels with the findings rather than in a separate call, because
/// a reader who sees only the finding count cannot tell a quiet host from a
/// blind sensor.
struct AIRuntimeSnapshot: Sendable {
    var enabled: Bool = false
    var scannedAt: Date?
    var findings: [AIRuntimeFinding] = []
    var planes: [AIRuntimePlane] = []
    var processesObserved: Int = 0
    var processesSkipped: Int = 0
    var connectionsObserved: Int = 0
    var connectionsUnattributed: Int = 0
    var degraded: Bool = false
    var degradedReasons: [String] = []

    /// Share of observed connections with no attributable owner. On an
    /// unprivileged POSIX host this is how much of the machine's egress cannot
    /// be named.
    var unattributedShare: Double {
        guard connectionsObserved > 0 else { return 0 }
        return Double(connectionsUnattributed) / Double(connectionsObserved)
    }

    /// The one-line coverage statement shown beside the finding count.
    var coverageSummary: String {
        var parts = ["\(processesObserved) processes"]
        if processesSkipped > 0 { parts.append("\(processesSkipped) partial") }
        parts.append("\(connectionsObserved) connections")
        if connectionsUnattributed > 0 { parts.append("\(connectionsUnattributed) unattributed") }
        return parts.joined(separator: ", ")
    }

    var planesNotRunning: [AIRuntimePlane] { planes.filter { !$0.running } }
}

/// Decoding helpers.
///
/// Deliberately tolerant: an older gateway that omits a field yields the zero
/// value rather than an error, because an app that fails to render on version
/// skew is worse than one that renders less.
enum AIRuntimeDecoding {
    static func snapshot(from json: Any?) -> AIRuntimeSnapshot {
        guard let dict = json as? [String: Any] else { return AIRuntimeSnapshot() }
        var snapshot = AIRuntimeSnapshot()
        snapshot.enabled = (dict["enabled"] as? Bool) ?? false
        snapshot.scannedAt = DCDates.parse(dict["scanned_at"])
        snapshot.processesObserved = (dict["processes_observed"] as? Int) ?? 0
        snapshot.processesSkipped = (dict["processes_skipped"] as? Int) ?? 0
        snapshot.connectionsObserved = (dict["connections_observed"] as? Int) ?? 0
        snapshot.connectionsUnattributed = (dict["connections_unattributed"] as? Int) ?? 0
        snapshot.degraded = (dict["degraded"] as? Bool) ?? false
        snapshot.degradedReasons = (dict["degraded_reasons"] as? [Any])?
            .compactMap { $0 as? String } ?? []
        snapshot.planes = ((dict["planes"] as? [Any]) ?? []).compactMap(plane)
        snapshot.findings = ((dict["findings"] as? [Any]) ?? [])
            .compactMap(finding)
            .sorted { lhs, rhs in
                if lhs.severityRank != rhs.severityRank { return lhs.severityRank < rhs.severityRank }
                if lhs.score != rhs.score { return lhs.score > rhs.score }
                return lhs.process < rhs.process
            }
        return snapshot
    }

    static func plane(_ raw: Any) -> AIRuntimePlane? {
        guard let dict = raw as? [String: Any] else { return nil }
        var plane = AIRuntimePlane()
        plane.plane = (dict["plane"] as? String) ?? ""
        plane.name = (dict["name"] as? String) ?? plane.plane
        plane.available = (dict["available"] as? Bool) ?? false
        plane.running = (dict["running"] as? Bool) ?? false
        plane.mechanism = (dict["mechanism"] as? String) ?? ""
        plane.reason = (dict["reason"] as? String) ?? ""
        return plane
    }

    static func finding(_ raw: Any) -> AIRuntimeFinding? {
        guard let dict = raw as? [String: Any] else { return nil }
        var finding = AIRuntimeFinding()
        finding.findingID = (dict["finding_id"] as? String) ?? ""
        finding.pid = (dict["pid"] as? Int) ?? 0
        finding.process = (dict["process"] as? String) ?? ""
        finding.cmdline = (dict["cmdline"] as? String) ?? ""
        finding.user = (dict["user"] as? String) ?? ""
        finding.agentName = (dict["agent_name"] as? String) ?? ""
        finding.score = (dict["score"] as? Int) ?? 0
        finding.severity = (dict["severity"] as? String) ?? "info"
        finding.firstSeen = DCDates.parse(dict["first_seen"])
        finding.lastSeen = DCDates.parse(dict["last_seen"])
        finding.signals = ((dict["signals"] as? [Any]) ?? []).compactMap { entry in
            guard let signal = entry as? [String: Any] else { return nil }
            return AIRuntimeSignal(
                signalID: (signal["id"] as? String) ?? "",
                title: (signal["title"] as? String) ?? "",
                detail: (signal["detail"] as? String) ?? "",
                weight: (signal["weight"] as? Int) ?? 0
            )
        }
        finding.providers = ((dict["providers"] as? [Any]) ?? []).compactMap { entry in
            guard let provider = entry as? [String: Any] else { return nil }
            return AIRuntimeProvider(
                hostname: (provider["hostname"] as? String) ?? "",
                address: (provider["address"] as? String) ?? "",
                port: (provider["port"] as? Int) ?? 0,
                category: (provider["category"] as? String) ?? "",
                confidence: (provider["confidence"] as? Double) ?? 0,
                attributionSource: (provider["attribution_source"] as? String) ?? ""
            )
        }
        if let correlation = dict["correlation"] as? [String: Any] {
            finding.correlation = AIRuntimeCorrelation(
                verdict: (correlation["verdict"] as? String) ?? "",
                reason: (correlation["reason"] as? String) ?? "",
                matchedSignalIDs: (correlation["matched_signal_ids"] as? [Any])?
                    .compactMap { $0 as? String } ?? [],
                categories: (correlation["categories"] as? [Any])?
                    .compactMap { $0 as? String } ?? []
            )
        }
        return finding
    }
}
