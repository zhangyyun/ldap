mkdir -p "${LDAP_LDIFS_PATH}"

cat > "${LDAP_LDIFS_PATH}/slapd.ldif" << EOF
#
# See slapd-config(5) for details on configuration options.
# This file should NOT be world readable.
#

dn: cn=config
objectClass: olcGlobal
cn: config
olcArgsFile: /var/run/openldap/slapd.args
olcPidFile: /var/run/openldap/slapd.pid
olcTLSCACertificatePath: ${LDAP_TLS_PATH}
olcTLSCertificateFile: ${LDAP_TLS_PATH}/${LDAP_TLS_CERT_FILE}
olcTLSCertificateKeyFile: ${LDAP_TLS_PATH}/${LDAP_TLS_KEY_FILE}

#
# Load dynamic backend modules:
# - modulepath is architecture dependent value (32/64-bit system)
# - back_sql.la backend requires openldap-servers-sql package
# - dyngroup.la and dynlist.la cannot be used at the same time
#
dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModulepath:  /usr/lib64/openldap
olcModuleload: memberof.la

#
# Schema settings
#
dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file:///etc/openldap/schema/core.ldif
include: file:///etc/openldap/schema/cosine.ldif
include: file:///etc/openldap/schema/rfc2307bis.ldif
include: file:///etc/openldap/schema/inetorgperson.ldif

#
# Frontend settings
#
dn: olcDatabase=frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: frontend

#
# Configuration database
#
dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: config
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage by dn.base="${LDAP_ADMIN_DN}" manage by * none

#
# Server status monitoring
#
dn: olcDatabase={1}monitor,cn=config
objectClass: olcDatabaseConfig
olcDatabase: monitor
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" read by dn.base="${LDAP_ADMIN_DN}" read by * none

#
# Backend database definitions
#
dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: mdb
olcDbDirectory: /var/lib/ldap
olcSuffix: ${LDAP_ROOT}
olcRootDN: ${LDAP_ADMIN_DN}
olcRootPW: ${LDAP_ENCRYPTED_ADMIN_PASSWORD}
#olcAccess: {0}to attrs=userPassword,shadowLastChange by dn.base="${LDAP_ADMIN_DN}" write by anonymous auth by self write by * none
olcAccess: {0}to attrs=userPassword,shadowLastChange by dn.base="${LDAP_ADMIN_DN}" write by anonymous auth by * none
#olcAccess: {1}to dn.subtree="\${COMPANY_DN}" by peername.ip=\${COMPANY_IP}%\${COMPANY_NETMASK} read
olcDbIndex: objectClass eq
olcDbIndex: cn,uid eq,pres
olcDbMaxSize: 1073741824

#
# Overlay memberof
#
dn: olcOverlay={0}memberof,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: {0}memberof
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfMembers
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
EOF

/usr/libexec/openldap/convert-config.sh -f "${LDAP_LDIFS_PATH}/slapd.ldif"
if [ $? -ne 0 ]; then
    echo "ldap cn=config setup failed"
    exit 1
fi
