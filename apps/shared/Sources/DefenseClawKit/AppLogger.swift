import Foundation
import Observation

/// Severity levels for app logs.
public enum LogLevel: String, Sendable, CaseIterable, Comparable {
    case debug = "DEBUG"
    case info  = "INFO"
    case warn  = "WARN"
    case error = "ERROR"

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        let order: [LogLevel] = [.debug, .info, .warn, .error]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}

/// A single log entry.
public struct LogEntry: Identifiable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let level: LogLevel
    public let category: String
    public let message: String
    public let details: String?

    public init(level: LogLevel, category: String, message: String, details: String? = nil) {
        self.id = UUID()
        self.timestamp = Date()
        self.level = level
        self.category = category
        self.message = message
        self.details = details
    }

    /// Format as a single log line for file output.
    public var formatted: String {
        let ts = LogEntry.timestampFormatter.string(from: timestamp)
        var line = "[\(ts)] [\(level.rawValue)] [\(category)] \(message)"
        if let details, !details.isEmpty {
            line += " | \(details)"
        }
        return line
    }

    private static let timestampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return f
    }()
}

/// Thread-safe, observable application logger.
/// Keeps an in-memory ring buffer and writes to `~/.defenseclaw/app.log`.
public final class AppLogger: @unchecked Sendable {

    public static let shared = AppLogger()

    /// Max entries kept in memory.
    private let maxEntries = 5000

    /// The on-disk log file path.
    public let logFilePath: String

    private let queue = DispatchQueue(label: "com.defenseclaw.logger", qos: .utility)
    private var _entries: [LogEntry] = []
    private var fileHandle: FileHandle?

    /// Observable snapshot — updated on main actor after each write.
    @MainActor public private(set) var entries: [LogEntry] = []
    @MainActor public private(set) var entryCount: Int = 0

    private init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dir = "\(home)/.defenseclaw"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        self.logFilePath = "\(dir)/app.log"

        // Rotate if over 5 MB
        if let attrs = try? FileManager.default.attributesOfItem(atPath: logFilePath),
           let size = attrs[.size] as? Int, size > 5_000_000 {
            let backup = "\(dir)/app.log.1"
            try? FileManager.default.removeItem(atPath: backup)
            try? FileManager.default.moveItem(atPath: logFilePath, toPath: backup)
        }

        // Open file for appending
        if !FileManager.default.fileExists(atPath: logFilePath) {
            FileManager.default.createFile(atPath: logFilePath, contents: nil)
        }
        fileHandle = FileHandle(forWritingAtPath: logFilePath)
        fileHandle?.seekToEndOfFile()

        // Startup marker
        log(.info, category: "app", message: "DefenseClaw macOS app logger started",
            details: "pid=\(ProcessInfo.processInfo.processIdentifier) version=1.0.0")
    }

    deinit {
        fileHandle?.closeFile()
    }

    // MARK: - Public API

    public func log(_ level: LogLevel, category: String, message: String, details: String? = nil) {
        let entry = LogEntry(level: level, category: category, message: message, details: details)
        queue.async { [weak self] in
            guard let self else { return }
            self._entries.append(entry)
            if self._entries.count > self.maxEntries {
                self._entries.removeFirst(self._entries.count - self.maxEntries)
            }

            // Write to disk
            let line = entry.formatted + "\n"
            if let data = line.data(using: .utf8) {
                self.fileHandle?.write(data)
            }

            // Update observable snapshot
            let snapshot = self._entries
            Task { @MainActor [weak self] in
                self?.entries = snapshot
                self?.entryCount = snapshot.count
            }
        }
    }

    public func debug(_ category: String, _ message: String, details: String? = nil) {
        log(.debug, category: category, message: message, details: details)
    }

    public func info(_ category: String, _ message: String, details: String? = nil) {
        log(.info, category: category, message: message, details: details)
    }

    public func warn(_ category: String, _ message: String, details: String? = nil) {
        log(.warn, category: category, message: message, details: details)
    }

    public func error(_ category: String, _ message: String, details: String? = nil) {
        log(.error, category: category, message: message, details: details)
    }

    // MARK: - Export

    /// Returns the full log content from disk as a string.
    public func exportLogContent() -> String {
        (try? String(contentsOfFile: logFilePath, encoding: .utf8)) ?? ""
    }

    /// Returns the in-memory entries filtered by level and/or category.
    @MainActor
    public func filtered(minLevel: LogLevel = .debug, category: String? = nil, search: String? = nil) -> [LogEntry] {
        entries.filter { entry in
            entry.level >= minLevel
                && (category == nil || entry.category == category)
                && (search == nil || search!.isEmpty
                    || entry.message.localizedCaseInsensitiveContains(search!)
                    || (entry.details?.localizedCaseInsensitiveContains(search!) ?? false))
        }
    }

    /// Returns all unique categories seen so far.
    @MainActor
    public var categories: [String] {
        Array(Set(entries.map(\.category))).sorted()
    }
}
