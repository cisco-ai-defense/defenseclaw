import AppKit

class TabStripItem: NSView {
    var onSelect: (() -> Void)?
    var onClose: (() -> Void)?

    private let statusDot: NSView
    private let titleLabel: NSTextField
    private let closeButton: NSButton
    private let isActive: Bool

    init(title: String, isActive: Bool, status: TabStatus) {
        self.isActive = isActive

        // Status dot
        statusDot = NSView(frame: NSRect(x: 0, y: 0, width: 8, height: 8))
        statusDot.wantsLayer = true
        statusDot.layer?.cornerRadius = 4

        switch status {
        case .idle:
            statusDot.layer?.backgroundColor = NSColor.systemGreen.cgColor
        case .streaming:
            statusDot.layer?.backgroundColor = NSColor.systemBlue.cgColor
        case .error:
            statusDot.layer?.backgroundColor = NSColor.systemRed.cgColor
        }

        // Title label
        titleLabel = NSTextField(labelWithString: title)
        titleLabel.font = .systemFont(ofSize: 12)
        titleLabel.lineBreakMode = .byTruncatingTail
        titleLabel.maximumNumberOfLines = 1

        // Close button
        closeButton = NSButton()
        closeButton.bezelStyle = .texturedRounded
        closeButton.isBordered = false
        closeButton.image = NSImage(systemSymbolName: "xmark", accessibilityDescription: "Close")
        closeButton.imageScaling = .scaleProportionallyDown

        super.init(frame: .zero)

        setupView()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupView() {
        wantsLayer = true
        layer?.backgroundColor = isActive ? NSColor.selectedContentBackgroundColor.cgColor : NSColor.controlBackgroundColor.cgColor
        layer?.cornerRadius = 6

        statusDot.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        closeButton.translatesAutoresizingMaskIntoConstraints = false

        addSubview(statusDot)
        addSubview(titleLabel)
        addSubview(closeButton)

        NSLayoutConstraint.activate([
            widthAnchor.constraint(greaterThanOrEqualToConstant: 100),
            widthAnchor.constraint(lessThanOrEqualToConstant: 200),
            heightAnchor.constraint(equalToConstant: 32),

            statusDot.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            statusDot.centerYAnchor.constraint(equalTo: centerYAnchor),
            statusDot.widthAnchor.constraint(equalToConstant: 8),
            statusDot.heightAnchor.constraint(equalToConstant: 8),

            titleLabel.leadingAnchor.constraint(equalTo: statusDot.trailingAnchor, constant: 6),
            titleLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            titleLabel.trailingAnchor.constraint(equalTo: closeButton.leadingAnchor, constant: -4),

            closeButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            closeButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            closeButton.widthAnchor.constraint(equalToConstant: 16),
            closeButton.heightAnchor.constraint(equalToConstant: 16)
        ])

        closeButton.target = self
        closeButton.action = #selector(closeButtonClicked)

        // Add click gesture for selection
        let clickGesture = NSClickGestureRecognizer(target: self, action: #selector(viewClicked))
        addGestureRecognizer(clickGesture)
    }

    @objc private func closeButtonClicked() {
        onClose?()
    }

    @objc private func viewClicked() {
        onSelect?()
    }
}
