import SwiftUI
import AppKit

/// NSTextView wrapper that sends on Enter and inserts newline on Shift+Enter.
struct ChatTextView: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String = "Send a message..."
    var onSubmit: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        scrollView.drawsBackground = false

        let textView = ChatNSTextView()
        textView.delegate = context.coordinator
        textView.onSubmit = onSubmit
        textView.isRichText = false
        textView.allowsUndo = true
        textView.font = .systemFont(ofSize: 13)
        textView.textColor = .labelColor
        textView.drawsBackground = false
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.textContainerInset = NSSize(width: 4, height: 6)
        textView.textContainer?.widthTracksTextView = true
        textView.string = text

        scrollView.documentView = textView
        context.coordinator.textView = textView

        // Set up placeholder
        context.coordinator.updatePlaceholder()

        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let textView = scrollView.documentView as? ChatNSTextView else { return }
        if textView.string != text {
            textView.string = text
        }
        textView.onSubmit = onSubmit
        context.coordinator.updatePlaceholder()
    }

    class Coordinator: NSObject, NSTextViewDelegate {
        var parent: ChatTextView
        weak var textView: ChatNSTextView?
        private var placeholderView: NSTextField?

        init(_ parent: ChatTextView) {
            self.parent = parent
        }

        func textDidChange(_ notification: Notification) {
            guard let tv = notification.object as? NSTextView else { return }
            parent.text = tv.string
            updatePlaceholder()
        }

        func updatePlaceholder() {
            guard let textView else { return }
            if placeholderView == nil {
                let label = NSTextField(labelWithString: parent.placeholder)
                label.textColor = .placeholderTextColor
                label.font = .systemFont(ofSize: 13)
                label.translatesAutoresizingMaskIntoConstraints = false
                textView.addSubview(label)
                NSLayoutConstraint.activate([
                    label.leadingAnchor.constraint(equalTo: textView.leadingAnchor, constant: 8),
                    label.topAnchor.constraint(equalTo: textView.topAnchor, constant: 6),
                ])
                placeholderView = label
            }
            placeholderView?.isHidden = !parent.text.isEmpty
        }
    }
}

/// Custom NSTextView that intercepts Enter key.
class ChatNSTextView: NSTextView {
    var onSubmit: (() -> Void)?

    override func keyDown(with event: NSEvent) {
        let isReturn = event.keyCode == 36 // Return key
        let shiftHeld = event.modifierFlags.contains(.shift)

        if isReturn && !shiftHeld {
            // Enter without shift → send
            onSubmit?()
            return
        }

        if isReturn && shiftHeld {
            // Shift+Enter → newline
            insertNewline(nil)
            return
        }

        super.keyDown(with: event)
    }
}
