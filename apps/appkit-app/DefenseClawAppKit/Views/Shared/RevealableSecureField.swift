import SwiftUI

/// A masked secret input with an explicit show/hide toggle.
///
/// Use for API keys, tokens, and other secret-like values so the user can
/// verify what they typed without leaving the secret on screen by default.
/// Mirrors the styling of the plain `SecureField` sites it replaces
/// (`.roundedBorder`, privacy-sensitive redaction while masked).
struct RevealableSecureField: View {
    let placeholder: String
    @Binding var text: String
    var isEditable: Bool = true

    @State private var isRevealed = false

    var body: some View {
        HStack(spacing: 6) {
            Group {
                if isRevealed {
                    TextField(placeholder, text: $text)
                } else {
                    SecureField(placeholder, text: $text)
                }
            }
            .textFieldStyle(.roundedBorder)
            .privacySensitive(!isRevealed)
            .disabled(!isEditable)

            Button {
                isRevealed.toggle()
            } label: {
                Image(systemName: isRevealed ? "eye.slash" : "eye")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .help(isRevealed ? "Hide secret" : "Reveal secret")
            .accessibilityLabel(isRevealed ? "Hide secret" : "Reveal secret")
        }
    }
}
