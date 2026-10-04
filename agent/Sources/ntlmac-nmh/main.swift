import Foundation
import NTLMacCore

// Native messaging host, spawned by the browser per extension connection. A thin shim:
// it forwards each request to NTLMacAgent over XPC and relays the reply. It reads no
// config and no credential. If the agent can't be reached or verified in time, it
// declines with agent_unavailable and the browser shows its own prompt.

func log(_ message: String) {
    // stdout is the browser channel; diagnostics must go to stderr (Chrome logs it).
    FileHandle.standardError.write(Data("ntlmac-nmh: \(message)\n".utf8))
}

let stdoutLock = NSLock()
func send(_ response: HostResponse) {
    do {
        let framed = try NativeMessaging.frame(JSONEncoder().encode(response))
        stdoutLock.withLock { FileHandle.standardOutput.write(framed) }
    } catch {
        log("failed to send response: \(error)")
    }
}

let overrides = DebugOverrides.fromEnvironment()
let serviceName = overrides.machServiceName ?? AgentXPC.machServiceName
// Only an agent from our own signed package (same team ID) is told anything.
// Compile it first: NSXPCConnection raises (and kills the host) on a malformed one.
let agentRequirement: String? = {
    do {
        guard let requirement = try overrides.agentRequirement ?? CodeSigningPolicy.forCurrentProcess()?.agentRequirement else { return nil }
        try CodeSigning.validate(requirement: requirement)
        return requirement
    } catch {
        log("no usable agent requirement: \(error)")
        return nil
    }
}()
if agentRequirement == nil { log("not signed with a team ID; every request will be declined") }

let forwarder = AgentForwarder {
    agentRequirement.map { AgentXPCClient(machServiceName: serviceName, agentRequirement: $0) }
}

log("started; service=\(serviceName)")

var decoder = NativeMessageDecoder()
while true {
    let chunk = FileHandle.standardInput.availableData
    if chunk.isEmpty { break } // browser closed the port
    decoder.append(chunk)
    do {
        while let message = try decoder.next() {
            guard let request = try? JSONDecoder().decode(HostRequest.self, from: message) else {
                log("ignoring malformed message")
                continue
            }
            // Concurrently: one slow request must not hold up the others past the
            // extension's timeout.
            Task.detached {
                let reply = await forwarder.forward(request.request)
                let outcome = if case let .decline(o) = reply { o.rawValue } else { Outcome.supplied.rawValue }
                log("request \(request.request.requestId) host=\(request.request.host) -> \(outcome)")
                send(reply.hostResponse(id: request.id))
            }
        }
    } catch {
        log("protocol error, exiting: \(error)")
        exit(1)
    }
}
