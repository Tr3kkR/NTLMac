import AppKit
import Foundation
import IOKit
import NTLMacCore
import os

// NTLMac agent: a per-user LaunchAgent (packaging/launchd/com.example.ntlmac.agent.plist).
// Answers the native host over XPC, owns the credential, watches for AD password changes
// and exports telemetry. The decisions are in NTLMacCore.AgentService.

let version = "0.1.0"
let logger = Logger(subsystem: "com.example.ntlmac", category: "agent")

func log(_ message: String) {
    // Never pass a password here. stderr goes to launchd's StandardErrorPath when set.
    logger.log("\(message, privacy: .public)")
    FileHandle.standardError.write(Data("NTLMacAgent: \(message)\n".utf8))
}

/// For test runs (`NTLMAC_NO_DIALOG=1`): log what would be asked, show nothing.
struct LoggingPrompter: CredentialPrompter {
    func requestCredential(reason: PromptReason, account: String?) {
        log("credential prompt requested: \(reason.rawValue) (dialog suppressed)")
    }
}

func serialNumber() -> String {
    let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
    defer { IOObjectRelease(service) }
    return IORegistryEntryCreateCFProperty(service, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0)?
        .takeRetainedValue() as? String ?? ""
}

let overrides = DebugOverrides.fromEnvironment()
if !overrides.isEmpty { log("DEBUG overrides in effect: \(overrides)") }

func loadConfig() -> NTLMacConfig? {
    do {
        if let path = overrides.configFile {
            return try ConfigLoader.decode(json: Data(contentsOf: URL(fileURLWithPath: path)))
        }
        // Pick up a profile Jamf installed or changed since the last read.
        CFPreferencesAppSynchronize(ConfigLoader.preferenceDomain as CFString)
        return try ConfigLoader.loadManaged()
    } catch {
        log("config invalid, failing closed: \(error)")
        return nil
    }
}

let policy: CodeSigningPolicy?
do {
    policy = try CodeSigningPolicy.forCurrentProcess()
} catch {
    log("cannot read this process's signature: \(error)")
    exit(EX_CONFIG)
}

let store: CredentialStore = {
    #if DEBUG
    if let path = overrides.credentialFile { return FileCredentialStore(url: URL(fileURLWithPath: path)) }
    #endif
    return KeychainCredentialStore(accessGroup: policy?.keychainAccessGroup)
}()
let latchURL = overrides.suspectLatchFile.map { URL(fileURLWithPath: $0) } ?? FileSuspectLatch.defaultURL()
let telemetryDirectory = overrides.telemetryDirectory.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? TelemetryQueue.defaultDirectory()

// The uninstaller runs `NTLMacAgent --remove-user-data` as each user (with the agent
// stopped): only this entitled binary can delete the Keychain item.
if CommandLine.arguments.dropFirst().first == "--remove-user-data" {
    let paths = overrides.suspectLatchFile == nil && overrides.telemetryDirectory == nil
        ? [UserData.defaultDirectory()] : [latchURL, telemetryDirectory]
    do {
        try UserData.remove(store: store, paths: paths)
        log("user data removed")
        exit(0)
    } catch {
        log("cannot remove all user data: \(error)")
        exit(EX_IOERR)
    }
}

// The agent accepts only the shim from its own signed package: same team ID (see
// CodeSigningPolicy.forCurrentProcess). An unsigned release build has nobody to trust.
let clientRequirement: String
do {
    guard let requirement = overrides.shimRequirement ?? policy?.shimRequirement else {
        log("not signed with a team ID and no override; refusing to start")
        exit(EX_CONFIG)
    }
    try CodeSigning.validate(requirement: requirement)
    clientRequirement = requirement
} catch {
    log("cannot build the shim requirement: \(error)")
    exit(EX_CONFIG)
}

var config = loadConfig()
let transport = SwitchableTransport()
func configureTransport(_ config: NTLMacConfig?) async {
    let endpoint = config?.otlpEndpoint.flatMap { try? OTLPHTTPTransport(endpoint: $0) }
    if config?.otlpEndpoint != nil, endpoint == nil { log("otlpEndpoint is not an https URL; telemetry stays queued") }
    await transport.use(endpoint)
}

let osVersion = ProcessInfo.processInfo.operatingSystemVersion
let telemetry: TelemetryExporter
do {
    // host.id is only reported salted: no salt in the profile, no host.id.
    let hostID = config?.hostIDSalt.map { TelemetryResource.pseudonymousHostID(serial: serialNumber(), salt: $0) } ?? ""
    telemetry = TelemetryExporter(
        recorder: TelemetryRecorder(resource: TelemetryResource(
            serviceVersion: version, hostID: hostID, osVersion: "\(osVersion.majorVersion).\(osVersion.minorVersion)"
        )),
        queue: try TelemetryQueue(directory: telemetryDirectory),
        transport: transport,
        start: Date()
    )
} catch {
    log("cannot open the telemetry queue: \(error)")
    exit(EX_CANTCREAT)
}

let dialog = CredentialDialog(log: log)
let service = AgentService(
    store: store,
    latch: FileSuspectLatch(url: latchURL),
    telemetry: telemetry,
    // `app-sso` parsing waits on spike item (b); until then enduser.id is the stored account.
    users: FixedUserProvider(realm: "", user: nil),
    prompter: overrides.noDialog ? LoggingPrompter() as CredentialPrompter : DialogPrompter(dialog: dialog),
    validator: KerberosCredentialValidator()
)
dialog.service = service

let serviceName = overrides.machServiceName ?? AgentXPC.machServiceName
let server = AgentXPCServer(listener: NSXPCListener(machServiceName: serviceName), clientRequirement: clientRequirement) { request in
    let reply = await service.handle(request)
    let outcome = if case let .decline(o) = reply { o.rawValue } else { Outcome.supplied.rawValue }
    log("request \(request.requestId) host=\(request.host) -> \(outcome)")
    return reply
}

let passwordChanges = PasswordChangeListener { name in
    log("password change notification: \(name)")
    Task { await service.passwordChangedExternally() }
}
do {
    try passwordChanges.start()
} catch {
    // Keep serving: the breaker still guards against a stale password.
    log("cannot watch for password changes: \(error)")
}

// launchd sends SIGTERM at logout: queue this interval's counters before exiting.
signal(SIGTERM, SIG_IGN)
let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
term.setEventHandler {
    Task {
        _ = try? await service.flushTelemetry()
        exit(0)
    }
}
term.resume()

Task {
    await configureTransport(config)
    await service.reload(config: config)
    server.resume()
    log("started \(version): service=\(serviceName) config=\(config != nil) credential=\(await service.credentialState().rawValue)")

    // Managed preferences have no change notification we can rely on, so poll.
    Task {
        while true {
            try? await Task.sleep(for: .seconds(60))
            let fresh = loadConfig()
            guard fresh != config else { continue }
            config = fresh
            await configureTransport(fresh)
            await service.reload(config: fresh)
            log("config reloaded: valid=\(fresh != nil)")
        }
    }
    while true {
        try? await Task.sleep(for: .seconds(TelemetryExporter.interval))
        do {
            let report = try await service.flushTelemetry()
            log("telemetry: delivered=\(report.delivered) dropped=\(report.dropped) queued=\(report.remaining)")
        } catch {
            log("telemetry flush failed: \(error)")
        }
    }
}

// An accessory app (LSUIElement in the bundle): no Dock icon or menu bar, but it can show
// the credential dialog. The main queue (XPC, signals) runs on this run loop.
NSApplication.shared.setActivationPolicy(.accessory)
NSApplication.shared.run()
