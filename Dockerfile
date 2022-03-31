FROM centos:7

RUN yum install -y epel-release \
	&& yum makecache \
	&& yum update -y \
	&& yum install -y openldap-servers openssl-perl tini \
	&& rm -rf /etc/openldap/{certs,slapd.d}/* \
	&& yum clean all

COPY rfc2307bis.* /etc/openldap/schema/
COPY *.sh /opt/

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/entrypoint.sh"]

ENV LDAP_ROOT=
ENV LDAP_ADMIN_USERNAME=
ENV LDAP_ADMIN_PASSWORD=
ENV LDAP_TLS_PATH=/etc/openldap/certs
ENV LDAP_TLS_CERT_FILE=
ENV LDAP_TLS_KEY_FILE=
ENV LDAP_PORT_NUMBER=1636

VOLUME ["${LDAP_TLS_PATH}", "/var/lib/ldap"]

EXPOSE ${LDAP_PORT_NUMBER}
