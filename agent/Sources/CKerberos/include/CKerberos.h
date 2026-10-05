#ifndef NTLMAC_CKERBEROS_H
#define NTLMAC_CKERBEROS_H

#include <stdint.h>

/// One initial-credential (AS) exchange for `principal` with `password`, with no prompter
/// and no password-change dialog. The ticket is freed straight away and never stored in
/// any credential cache. Returns 0 on success, else the krb5_error_code.
int32_t ntlmac_krb5_initial_credentials(const char *principal, const char *password);

#endif
