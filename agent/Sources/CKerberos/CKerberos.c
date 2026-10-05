#include "CKerberos.h"

#include <string.h>
#include <Kerberos/krb5.h>

// Apple marks the krb5 API deprecated in favour of GSS.framework, but GSS's initial-
// credential call stores the ticket in the user's credential cache, which a validation
// must never touch. krb5_get_init_creds_password returns it in memory instead.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int32_t ntlmac_krb5_initial_credentials(const char *principal_name, const char *password) {
    krb5_context context = NULL;
    krb5_principal principal = NULL;
    krb5_get_init_creds_opt *options = NULL;
    krb5_creds creds;
    memset(&creds, 0, sizeof creds);

    krb5_error_code ret = krb5_init_context(&context);
    if (ret) return ret;
    ret = krb5_parse_name(context, principal_name, &principal);
    if (ret) goto out;
    ret = krb5_get_init_creds_opt_alloc(context, &options);
    if (ret) goto out;
    // An expired password comes back as KRB5KDC_ERR_KEY_EXP rather than a prompt.
    krb5_get_init_creds_opt_set_change_password_prompt(options, 0);

    ret = krb5_get_init_creds_password(context, &creds, principal, (char *)password,
                                       NULL, NULL, 0, NULL, options);
    if (ret == 0) krb5_free_cred_contents(context, &creds);

out:
    if (options) krb5_get_init_creds_opt_free(context, options);
    if (principal) krb5_free_principal(context, principal);
    krb5_free_context(context);
    return ret;
}
