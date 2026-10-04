/// Who is signed in to the Kerberos SSO extension, so enrolment never asks for a username.
///
/// The production implementation will run `app-sso -i <realm> -j`. Its JSON field names
/// are undocumented and not yet captured from a bound Mac (spike item b), so there is
/// deliberately no parser here yet: don't guess the field names.
public protocol SignedInUserProvider: Sendable {
    /// The sAMAccountName (no domain) signed in for `realm`, or nil if nobody is.
    func currentUser(realm: String) async throws -> String?
}

/// For tests and development builds.
public struct FixedUserProvider: SignedInUserProvider {
    public var realm: String
    public var user: String?

    public init(realm: String, user: String?) {
        self.realm = realm
        self.user = user
    }

    public func currentUser(realm: String) async throws -> String? {
        realm.uppercased() == self.realm.uppercased() ? user : nil
    }
}
