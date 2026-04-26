import AppKit

protocol TabStripViewDelegate: AnyObject {
    func tabStripView(_ view: TabStripView, didSelectTabAt index: Int)
    func tabStripView(_ view: TabStripView, didCloseTabAt index: Int)
    func tabStripViewDidRequestNewTab(_ view: TabStripView)
}

class TabStripView: NSView {
    weak var delegate: TabStripViewDelegate?
    private var stackView: NSStackView!
    private var tabItems: [TabStripItem] = []
    private var addButton: NSButton!

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        setupView()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupView()
    }

    private func setupView() {
        wantsLayer = true
        layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor

        // Create horizontal stack view
        stackView = NSStackView()
        stackView.orientation = .horizontal
        stackView.alignment = .centerY
        stackView.spacing = 4
        stackView.edgeInsets = NSEdgeInsets(top: 0, left: 8, bottom: 0, right: 8)
        stackView.translatesAutoresizingMaskIntoConstraints = false

        addSubview(stackView)

        NSLayoutConstraint.activate([
            stackView.leadingAnchor.constraint(equalTo: leadingAnchor),
            stackView.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -50),
            stackView.topAnchor.constraint(equalTo: topAnchor),
            stackView.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])

        // Add "+" button
        addButton = NSButton()
        addButton.bezelStyle = .texturedRounded
        addButton.image = NSImage(systemSymbolName: "plus", accessibilityDescription: "New Tab")
        addButton.target = self
        addButton.action = #selector(addButtonClicked)
        addButton.translatesAutoresizingMaskIntoConstraints = false

        addSubview(addButton)

        NSLayoutConstraint.activate([
            addButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
            addButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            addButton.widthAnchor.constraint(equalToConstant: 28),
            addButton.heightAnchor.constraint(equalToConstant: 28)
        ])
    }

    func updateTabs(_ tabs: [TabInfo]) {
        // Remove old tab items
        for item in tabItems {
            stackView.removeView(item)
        }
        tabItems.removeAll()

        // Add new tab items
        for tab in tabs {
            let item = TabStripItem(title: tab.title, isActive: tab.isActive, status: tab.status)
            item.onSelect = { [weak self] in
                guard let self = self else { return }
                self.delegate?.tabStripView(self, didSelectTabAt: tab.index)
            }
            item.onClose = { [weak self] in
                guard let self = self else { return }
                self.delegate?.tabStripView(self, didCloseTabAt: tab.index)
            }

            stackView.addArrangedSubview(item)
            tabItems.append(item)
        }
    }

    @objc private func addButtonClicked() {
        delegate?.tabStripViewDidRequestNewTab(self)
    }
}
