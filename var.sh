LDAP_ROOT="${LDAP_ROOT:-dc=kailing,dc=cn}"
LDAP_ADMIN_USERNAME="${LDAP_ADMIN_USERNAME:-Manager}"
LDAP_ADMIN_DN="${LDAP_ADMIN_USERNAME/#/cn=},${LDAP_ROOT}"
LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:-lingyun}"
LDAP_ENCRYPTED_ADMIN_PASSWORD="$(echo -n $LDAP_ADMIN_PASSWORD | slappasswd -n -T /dev/stdin)"
LDAP_LDIFS_PATH=/etc/openldap/ldifs
LDAP_TLS_PATH=${LDAP_TLS_PATH:-/etc/openldap/certs}
LDAP_TLS_KEY_FILE=${LDAP_TLS_CERT_FILE:-slapd.key}
LDAP_TLS_CERT_FILE=${LDAP_TLS_CERT_FILE:-slapd.crt}
LDAP_PORT_NUMBER=${LDAP_PORT_NUMBER:-1636}
