import SwiftUI

// Shared status helpers for catalog-style lists (scan targets, inventory, …)
// so badges/reasons/colors stay consistent across busy views.

func catalogBadge(blocked: Bool, quarantined: Bool, enabled: Bool) -> String {
    if blocked { return "Blocked" }
    if quarantined { return "Quarantined" }
    return enabled ? "Enabled" : "Disabled"
}

func catalogReason(blocked: Bool, quarantined: Bool, enabled: Bool) -> String? {
    if quarantined { return "Quarantined — isolated by a scan or policy decision." }
    if blocked { return "Blocked by policy or allowlist." }
    if !enabled { return "Disabled — present but not active." }
    return nil
}

/// Status-relevant color so states are distinguishable at a glance.
func catalogStatusColor(_ badge: String) -> Color {
    switch badge {
    case "Blocked": return .red
    case "Quarantined": return .orange
    case "Enabled", "Running": return .green
    case "Configured": return .blue
    case "Disabled": return .gray
    default: return .secondary
    }
}

/// Small colored status capsule used by catalog cards/rows/detail.
struct CatalogStatusPill: View {
    let badge: String

    var body: some View {
        Text(badge)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(catalogStatusColor(badge))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(catalogStatusColor(badge).opacity(0.12), in: Capsule())
    }
}
