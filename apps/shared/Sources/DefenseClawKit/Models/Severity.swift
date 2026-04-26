import Foundation

public enum Severity: String, Codable, Comparable, CaseIterable, Sendable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case info = "INFO"
    case none = "NONE"

    private var rank: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .info: return 1
        case .none: return 0
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rank < rhs.rank
    }
}
