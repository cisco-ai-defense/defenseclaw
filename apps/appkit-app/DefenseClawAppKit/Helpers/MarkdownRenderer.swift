import SwiftUI

struct MarkdownRenderer: View {
    let text: String

    var body: some View {
        Text(parseMarkdown(text))
            .textSelection(.enabled)
    }

    private func parseMarkdown(_ text: String) -> AttributedString {
        var attributed = AttributedString(text)

        // Bold text **text**
        let boldPattern = #/\*\*(.*?)\*\*/#
        if let match = text.firstMatch(of: boldPattern) {
            if let range = attributed.range(of: String(match.1)) {
                attributed[range].font = .body.bold()
            }
        }

        // Code blocks `code`
        let codePattern = #/`(.*?)`/#
        if let match = text.firstMatch(of: codePattern) {
            if let range = attributed.range(of: String(match.1)) {
                attributed[range].font = .monospaced(.body)()
                attributed[range].backgroundColor = .gray.opacity(0.1)
            }
        }

        return attributed
    }
}
