# Throwaway KDC for the credential validator

`KerberosCredentialValidator` checks a password with one Kerberos AS exchange through
the macOS Kerberos library. `swift test` covers the error mapping with a fake and calls
the real library against a closed port (`KRB5_KDC_UNREACH`). This folder adds an opt-in
check against a real MIT KDC in Docker: realm `CORP.EXAMPLE`, test account
`jbloggs` / `Passw0rd!`, pre-authentication required as in AD.

```sh
docker build -t ntlmac-test-kdc test/kdc
docker run -d --rm --name ntlmac-kdc -p 127.0.0.1:18888:88/tcp ntlmac-test-kdc
cd agent && NTLMAC_TEST_KRB5_CONFIG=$PWD/../test/kdc/client-krb5.conf \
  swift test --filter againstARealKDC
docker logs ntlmac-kdc 2>&1 | grep AS_REQ
docker stop ntlmac-kdc
```

Expected KDC log (verified 2026-10-05): the right password gives `NEEDED_PREAUTH` then
`ISSUE`; the wrong one gives `NEEDED_PREAUTH` then **exactly one** `PREAUTH_FAILED`. The
first AS-REQ carries no password proof, so it isn't a bad-password event. `klist -A`
is unchanged afterwards: the ticket is never written to a credential cache.

## Against a real AD domain (manual, test account only)

Use a test account in a test OU, never your own. On the DC, before and after, count
Security events **4771** (Kerberos pre-authentication failed) for the account, and
check its `badPwdCount`.

1. On a Mac on the corporate network or VPN: write a `krb5.conf` with
   `[libdefaults] dns_lookup_kdc = true` (or name a DC under `[realms]`).
2. Run the opt-in test with `NTLMAC_TEST_KRB5_CONFIG=<that file>` and
   `NTLMAC_TEST_REALM=<REALM>`. It uses `jbloggs` / `Passw0rd!`, so create the test
   account with those credentials, or adapt the test locally without committing it.
3. Expect one 4768 (TGT issued) for the good password, and **one** 4771 with failure
   code `0x18` for the bad one, with `badPwdCount` up by exactly 1.
4. Off VPN, the validator must throw `kdcUnavailable` and the DC must log nothing.
