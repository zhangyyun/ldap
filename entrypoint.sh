#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

. ${SCRIPT_DIR}/var.sh

if [ ! -f /etc/openldap/slapd.d/cn=config.ldif ]; then
    . ${SCRIPT_DIR}/setup.sh
fi

. /usr/libexec/openldap/functions

/usr/libexec/openldap/check-config.sh
if [ $? -ne 0 ]; then
    error "OpenLDAP check config failed"
    exit 1
fi

for cert in `certificates`; do
    run_as_ldap "/usr/bin/test -e \"$cert\""
    if [ $? -ne 0 ]; then
        error "TLS certificate/key/DB '%s' was not found." "$cert"
        exit 1
    fi
done

c_rehash ${LDAP_TLS_PATH}

# tune keyfile permissions
keyfile=$(slapcat $SLAPD_GLOBAL_OPTIONS -c -H 'ldap:///cn=config???(cn=config)' 2>/dev/null | \
    ldif_unbreak | \
    grep '^olcTLSCertificateKeyFile: ' | \
    ldif_value)
chown ldap:ldap "${keyfile}"
chmod 400 "${keyfile}"

exec /usr/sbin/slapd -d stats -u ldap -h "ldaps://:${LDAP_PORT_NUMBER}/ ldapi:///" "$@"
