// Lists the windows owned by one process, on every Space, as JSON lines.
// Headless Chrome on macOS still shows its HTTP auth prompt as a real window, so this is
// how the e2e suite sees whether the browser's own sign-in prompt appeared. Owner PID and
// bounds need no Screen Recording permission (window titles would).
//
// Usage: windows <pid>
import CoreGraphics
import Foundation

guard CommandLine.arguments.count == 2, let pid = Int(CommandLine.arguments[1]) else {
    FileHandle.standardError.write(Data("usage: windows <pid>\n".utf8))
    exit(2)
}
let all = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? []
for w in all where (w[kCGWindowOwnerPID as String] as? Int) == pid {
    let bounds = w[kCGWindowBounds as String] as? [String: Double] ?? [:]
    let line: [String: Any] = [
        "layer": w[kCGWindowLayer as String] as? Int ?? 0,
        "onscreen": w[kCGWindowIsOnscreen as String] as? Bool ?? false,
        "alpha": w[kCGWindowAlpha as String] as? Double ?? 0,
        "width": bounds["Width"] ?? 0,
        "height": bounds["Height"] ?? 0,
    ]
    print(String(decoding: try JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]), as: UTF8.self))
}
