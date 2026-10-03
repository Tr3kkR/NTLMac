import Foundation
import Testing
@testable import NTLMacCore

@Suite struct NativeMessagingTests {
    @Test func encodePrefixesLittleEndianLength() throws {
        let framed = try NativeMessaging.frame(Data("{}".utf8))
        #expect(Array(framed) == [2, 0, 0, 0, 0x7B, 0x7D])
    }

    @Test func encodeRejectsMessagesOverBrowserLimit() {
        let big = Data(count: NativeMessaging.maxOutgoingBytes + 1)
        #expect(throws: NativeMessaging.Error.messageTooLarge) { try NativeMessaging.frame(big) }
    }

    @Test func decoderHandlesSplitAndCoalescedChunks() throws {
        var decoder = NativeMessageDecoder()
        let a = try NativeMessaging.frame(Data(#"{"a":1}"#.utf8))
        let b = try NativeMessaging.frame(Data(#"{"b":2}"#.utf8))
        let stream = a + b

        decoder.append(stream.prefix(3))
        #expect(try decoder.next() == nil)
        decoder.append(stream.dropFirst(3))
        #expect(try decoder.next() == Data(#"{"a":1}"#.utf8))
        #expect(try decoder.next() == Data(#"{"b":2}"#.utf8))
        #expect(try decoder.next() == nil)
    }

    @Test func decoderRejectsOversizedIncomingLength() {
        var decoder = NativeMessageDecoder()
        decoder.append(Data([0x01, 0x00, 0x01, 0x00])) // 65_537 bytes
        #expect(throws: NativeMessaging.Error.messageTooLarge) { try decoder.next() }
    }

    @Test func authRequestRoundTripsFromExtensionJSON() throws {
        let json = """
        {"id": 7, "type": "auth", "request": {"requestId": "123", "host": "app.corp.example",
         "port": 443, "urlScheme": "https", "authScheme": "ntlm", "isProxy": false}}
        """
        let msg = try JSONDecoder().decode(HostRequest.self, from: Data(json.utf8))
        #expect(msg.id == 7)
        #expect(msg.request.host == "app.corp.example")
    }

    @Test func supplyResponseEncodesCredentials() throws {
        let resp = HostResponse.supply(id: 7, username: #"CORP\jbloggs"#, password: "pw")
        let obj = try JSONSerialization.jsonObject(with: JSONEncoder().encode(resp)) as? [String: Any]
        #expect(obj?["id"] as? Int == 7)
        #expect(obj?["action"] as? String == "supply")
        #expect(obj?["username"] as? String == #"CORP\jbloggs"#)
        #expect(obj?["password"] as? String == "pw")
    }

    @Test func declineResponseCarriesOutcomeAndNoCredentials() throws {
        let resp = HostResponse.decline(id: 7, outcome: .notAllowlisted)
        let obj = try JSONSerialization.jsonObject(with: JSONEncoder().encode(resp)) as? [String: Any]
        #expect(obj?["action"] as? String == "decline")
        #expect(obj?["outcome"] as? String == "not_allowlisted")
        #expect(obj?["password"] == nil)
        #expect(obj?["username"] == nil)
    }

    @Test func responseDescriptionNeverContainsPassword() {
        let resp = HostResponse.supply(id: 1, username: "u", password: "hunter2")
        #expect(!String(describing: resp).contains("hunter2"))
        #expect(!String(reflecting: resp).contains("hunter2"))
    }
}
