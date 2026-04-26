import SwiftUI
import DefenseClawKit

struct SkillRow: View {
    let skill: Skill

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: skill.blocked ? "xmark.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(skill.blocked ? .red : .green)
                .font(.caption)

            Text(skill.name)
                .font(.caption)
                .lineLimit(1)

            Spacer()

            if skill.blocked {
                Text("Blocked")
                    .font(.caption2)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(4)
            }
        }
        .padding(8)
        .background(Color.gray.opacity(0.05))
        .cornerRadius(6)
    }
}
