
class Config(object):
    LDAP_HOST='ip-10-65-13-44.cn-northwest-1.compute.internal'
    LDAP_PORT=1636
    LDAP_BASE_DN='dc=kailing,dc=cn'
    LDAP_ADMIN_USERNAME='Manager'
    LDAP_ADMIN_PASSWORD='lingyun'
    ROOT_DN='cn=' + LDAP_ADMIN_USERNAME + ',' + LDAP_BASE_DN
    ROOT_PW=LDAP_ADMIN_PASSWORD
