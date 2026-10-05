# Throwaway MIT KDC for checking NTLMac's Kerberos validation locally. Test data only.
FROM debian:stable-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server \
    && rm -rf /var/lib/apt/lists/*
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY krb5.conf /etc/krb5.conf
# Pre-authentication required, as AD does: a wrong password is KDC_ERR_PREAUTH_FAILED.
RUN kdb5_util create -s -r CORP.EXAMPLE -P master-test-only \
    && kadmin.local -q 'addprinc +requires_preauth -pw Passw0rd! jbloggs@CORP.EXAMPLE'
EXPOSE 88/tcp 88/udp
CMD ["krb5kdc", "-n"]
