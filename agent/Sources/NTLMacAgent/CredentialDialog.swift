import AppKit
import NTLMacCore

/// The enrolment / re-prompt panel: AppKit only. Wording, account parsing and failure
/// messages come from `CredentialPrompt`; validation and storage from `AgentService`.
/// The typed password goes straight from the secure field into a `Credential` and is
/// never logged.
@MainActor
final class CredentialDialog: NSObject, NSWindowDelegate, NSTextFieldDelegate {
    /// Set once the service exists (the service needs the prompter first).
    var service: AgentService?
    private let log: (String) -> Void

    private var panel: NSPanel?
    private let titleLabel = NSTextField(labelWithString: "")
    private let messageLabel = NSTextField(wrappingLabelWithString: "")
    private let accountField = NSTextField()
    private let passwordField = NSSecureTextField()
    private let errorLabel = NSTextField(wrappingLabelWithString: "")
    private let spinner = NSProgressIndicator()
    private lazy var okButton = NSButton(title: "Save", target: self, action: #selector(submit))
    private lazy var cancelButton = NSButton(title: "Not Now", target: self, action: #selector(cancel))
    private var checking = false
    /// Diagnostics: whether this panel has had a text-change notification yet.
    private var editSeen = false

    init(log: @escaping (String) -> Void) {
        self.log = log
    }

    /// Opens the panel, or updates its wording if it is already open (a rejected
    /// submission comes back as `validationFailed` while the user is still in it).
    func show(reason: PromptReason, account: String?) {
        let text = CredentialPrompt.text(for: reason)
        titleLabel.stringValue = text.title
        messageLabel.stringValue = text.message
        if let panel {
            panel.makeKeyAndOrderFront(nil)
            return
        }
        accountField.stringValue = account ?? ""
        passwordField.stringValue = ""
        errorLabel.stringValue = ""
        editSeen = false
        let panel = makePanel()
        self.panel = panel
        updateButtons()
        panel.center()
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        panel.makeFirstResponder(accountField.stringValue.isEmpty ? accountField : passwordField)
        log("dialog shown: \(reason.rawValue)")
    }

    // MARK: Actions

    @objc private func submit() {
        guard !checking, let service else { return }
        panel?.makeFirstResponder(nil) // commit the field being edited before reading it
        let account = accountField.stringValue
        let password = passwordField.stringValue
        // Save is never disabled for missing input: on screen, the fields' change
        // notifications didn't reach us, which left the button grey. Say what's missing.
        if let problem = CredentialPrompt.problem(account: account, password: password) {
            log("dialog: incomplete (account given: \(!account.isEmpty), password given: \(!password.isEmpty))")
            errorLabel.stringValue = problem
            return
        }
        log("dialog: submitted")
        setChecking(true)
        Task {
            let outcome = await CredentialPrompt.submit(account: account, password: password) {
                try await service.credentialReplaced($0)
            }
            setChecking(false)
            switch outcome {
            case .stored:
                log("dialog: credential validated and stored")
                close()
            case let .failed(message, clearPassword):
                log("dialog: submission not stored")
                errorLabel.stringValue = message
                if clearPassword { passwordField.stringValue = "" }
                panel?.makeFirstResponder(passwordField)
            }
        }
    }

    @objc private func cancel() {
        guard !checking else { return }
        log("dialog dismissed")
        close()
        Task { await service?.promptDismissed() }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        // The close button means "not now"; while a check is running it waits.
        cancel()
        return false
    }

    func controlTextDidChange(_ obj: Notification) {
        if !editSeen {
            editSeen = true
            log("dialog: text change notifications arriving")
        }
        errorLabel.stringValue = ""
    }

    // MARK: Private

    private func close() {
        passwordField.stringValue = ""
        panel?.orderOut(nil)
        panel = nil
    }

    private func setChecking(_ on: Bool) {
        checking = on
        on ? spinner.startAnimation(nil) : spinner.stopAnimation(nil)
        accountField.isEnabled = !on
        passwordField.isEnabled = !on
        updateButtons()
    }

    private func updateButtons() {
        okButton.isEnabled = !checking
        cancelButton.isEnabled = !checking
    }

    private func makePanel() -> NSPanel {
        let panel = NSPanel(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "Intranet Sign-in"
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.level = .floating
        panel.delegate = self

        let icon = NSImageView(image: NSImage(systemSymbolName: "lock.shield", accessibilityDescription: nil) ?? NSImage())
        icon.symbolConfiguration = .init(pointSize: 40, weight: .regular)
        titleLabel.font = .boldSystemFont(ofSize: NSFont.systemFontSize + 1)
        for label in [messageLabel, errorLabel] { label.preferredMaxLayoutWidth = 300 }
        errorLabel.textColor = .systemRed
        accountField.placeholderString = "jbloggs"
        // No `contentType`: Password AutoFill held typed usernames out of `stringValue` on
        // screen, and could offer to save the AD password to the user's synced Passwords.
        for field in [accountField, passwordField] {
            field.delegate = self
            field.widthAnchor.constraint(equalToConstant: 220).isActive = true
        }
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        okButton.keyEquivalent = "\r"
        cancelButton.keyEquivalent = "\u{1b}"

        let grid = NSGridView(views: [
            [NSTextField(labelWithString: "Username:"), accountField],
            [NSTextField(labelWithString: "Password:"), passwordField],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.rowAlignment = .firstBaseline

        let buttons = NSStackView(views: [spinner, NSView(), cancelButton, okButton])
        let text = NSStackView(views: [titleLabel, messageLabel, grid, errorLabel, buttons])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 12
        buttons.widthAnchor.constraint(equalTo: text.widthAnchor).isActive = true

        let content = NSStackView(views: [icon, text])
        content.alignment = .top
        content.spacing = 16
        content.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        panel.contentView = content
        return panel
    }
}

/// Hands prompt requests from the service to the panel on the main thread, in order.
struct DialogPrompter: CredentialPrompter {
    let dialog: CredentialDialog

    func requestCredential(reason: PromptReason, account: String?) {
        DispatchQueue.main.async {
            MainActor.assumeIsolated { dialog.show(reason: reason, account: account) }
        }
    }
}
