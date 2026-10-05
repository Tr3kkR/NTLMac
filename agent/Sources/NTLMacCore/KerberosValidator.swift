import CKerberos
import Foundation

/// krb5 error codes the validator tells apart (values from `<Kerberos/krb5.h>`).
public enum KerberosError {
    public static let principalUnknown: Int32 = -1765328378 // KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN
    public static let clientRevoked: Int32 = -1765328366 // KRB5KDC_ERR_CLIENT_REVOKED: locked or disabled
    public static let keyExpired: Int32 = -1765328361 // KRB5KDC_ERR_KEY_EXP: password expired
    public static let preauthFailed: Int32 = -1765328360 // KRB5KDC_ERR_PREAUTH_FAILED: wrong password
    public static let badIntegrity: Int32 = -1765328353 // KRB5KRB_AP_ERR_BAD_INTEGRITY: wrong password, no preauth
    public static let clockSkew: Int32 = -1765328347 // KRB5KRB_AP_ERR_SKEW
    public static let realmUnknown: Int32 = -1765328230 // KRB5_REALM_UNKNOWN
    public static let kdcUnreachable: Int32 = -1765328228 // KRB5_KDC_UNREACH
}

/// One initial-credential (AS) exchange. Returns 0 or the krb5 error code.
public protocol KerberosClient: Sendable {
    func requestInitialCredentials(principal: String, password: String) -> Int32
}

/// `krb5_get_init_creds_password` through `CKerberos`. The ticket is freed at once and never
/// written to any credential cache, so the user's own Kerberos tickets are untouched.
/// Blocks for up to the library's KDC timeouts; don't call it on the main thread.
public struct SystemKerberosClient: KerberosClient {
    public init() {}

    public func requestInitialCredentials(principal: String, password: String) -> Int32 {
        ntlmac_krb5_initial_credentials(principal, password)
    }
}

public enum KerberosValidationError: Error, Equatable {
    /// Empty or unusable account, password or realm: nothing was sent.
    case invalidInput
    /// The password is right but has expired; it must be changed first.
    case passwordExpired
    /// The account is locked out or disabled.
    case accountLocked
    /// The KDC couldn't be asked (offline, off VPN, clock skew...), so nothing is known.
    case kdcUnavailable(code: Int32)
}

/// Checks a password with exactly one AS exchange for `<account>@<REALM>` and never retries:
/// a rejected attempt is a bad-password event at the DC, and the budget is at most one per
/// password change. (On the wire that is the usual pre-authentication round trip: a first
/// AS-REQ without the password proof, answered with PREAUTH_REQUIRED, then one carrying it.)
public struct KerberosCredentialValidator: CredentialValidator {
    private let client: KerberosClient

    public init(client: KerberosClient = SystemKerberosClient()) {
        self.client = client
    }

    public func validate(_ credential: Credential, realm: String) async throws -> Bool {
        let account = credential.account
        // `@`, `/` and `\` would change which principal is asked; the dialog strips `DOMAIN\`.
        guard !account.isEmpty, !credential.password.isEmpty, !realm.isEmpty,
              account.rangeOfCharacter(from: CharacterSet(charactersIn: "@/\\")) == nil
        else { throw KerberosValidationError.invalidInput }

        let principal = "\(account)@\(realm.uppercased())"
        let client = client
        let code = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: client.requestInitialCredentials(principal: principal, password: credential.password))
            }
        }
        switch code {
        case 0: return true
        case KerberosError.preauthFailed, KerberosError.badIntegrity, KerberosError.principalUnknown: return false
        case KerberosError.keyExpired: throw KerberosValidationError.passwordExpired
        case KerberosError.clientRevoked: throw KerberosValidationError.accountLocked
        default: throw KerberosValidationError.kdcUnavailable(code: code)
        }
    }
}
