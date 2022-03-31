import os
import hashlib
import ldap
import config
import bitarray
from ipaddress import IPv4Network
from base64 import b64encode as encode

class IDMap:
    MIN = 5000
    MAX = 65533 # 65534 is for "nobody" and 65535 is reserved
    def __init__(self):
        self.uid = bitarray.bitarray(65536)
        self.gid = bitarray.bitarray(65536)

        self.uid.setall(0)
        self.gid.setall(0)

    def set_uid(self, uid):
        if uid >= self.MIN and uid <= self.MAX:
            self.uid[uid] = 1

    def unset_uid(self, uid):
        if uid >= self.MIN and uid <= self.MAX:
            self.uid[uid] = 0

    def find_avail_uid(self):
        return self.uid.find(bitarray.bitarray('0'), self.MIN, self.MAX)

    def set_gid(self, gid):
        if gid >= self.MIN and gid <= self.MAX:
            self.gid[gid] = 1

    def unset_gid(self, gid):
        if gid >= self.MIN and gid <= self.MAX:
            self.gid[gid] = 0

    def find_avail_gid(self):
        return self.gid.find(bitarray.bitarray('0'), self.MIN, self.MAX)

class Ldap:
    def __init__(self):
        for i in range(3):
            if self.init_inner():
                break
    def init_inner(self):
        try:
            self.d = {}
            self.conn = ldap.initialize('ldaps://' + config.Config.LDAP_HOST + ':' + str(config.Config.LDAP_PORT))
            self.timeout = 5
            self.conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)

            res = self.conn.search_s(config.Config.LDAP_BASE_DN, ldap.SCOPE_ONELEVEL, 'objectClass=organization', ['o'])
            for company in res:
                company_dn = company[0]
                company_name = company[1].get('o')[0].decode('utf-8')
                if company_name not in self.d:
                    self.d[company_name] = IDMap()

                user_res = self.conn.search_s(company_dn, ldap.SCOPE_SUBTREE, 'objectClass=posixAccount', ['uidNumber'])
                for uid in user_res:
                    uid_temp = int(uid[1].get('uidNumber')[0].decode('utf-8'))
                    self.d.get(company_name).set_uid(uid_temp)

                group_res = self.conn.search_s(company_dn, ldap.SCOPE_SUBTREE, 'objectClass=posixGroup', ['gidNumber'])
                for gid in group_res:
                    gid_temp = int(gid[1].get('gidNumber')[0].decode('utf-8'))
                    self.d.get(company_name).set_gid(gid_temp)

                return True
        except ldap.NO_SUCH_OBJECT:
            base = ldap.dn.str2dn(config.Config.LDAP_BASE_DN)[0][0][1]
            base_dn = config.Config.LDAP_BASE_DN
            base_attrs = [
                ('objectClass', ['top'.encode('utf-8'),
                                 'organization'.encode('utf-8'),
                                 'dcObject'.encode('utf-8')]),
                ('dc', [str(base).encode('utf-8')]),
                ('o', [str(base).encode('utf-8')])
            ]
            self.conn.add_s(base_dn, base_attrs)
            return False
        except Exception as err:
            print('Ldap init', err)
            raise err

    def dn_exists(self, dn):
        try:
            return self.conn.search_s(dn, ldap.SCOPE_BASE) != None
        except ldap.NO_SUCH_OBJECT:
            return False
        except Exception as err:
            print('dn_exists', dn, err)
            raise err

    def get_dn_attr(self, dn, attr):
        try:
            res = self.conn.search_s(dn, ldap.SCOPE_BASE, attrlist=[attr])
            if res and attr in res[0][1]:
                return res[0][1].get(attr)
            return []
        except ldap.NO_SUCH_OBJECT:
            return []
        except Exception as err:
            print('get_dn_attr', dn, attr, err)
            raise err

    def add_company(self, companies):
        if type(companies) is str:
            companies = [companies]
        try:
            for company in companies:
                if company in self.d:
                    continue

                company_dn = "dc=" + company + "," + config.Config.LDAP_BASE_DN
                company_attrs = [
                    ('objectClass', ['top'.encode('utf-8'),
                                     'organization'.encode('utf-8'),
                                     'dcObject'.encode('utf-8')]),
                    ('dc', [str(company).encode('utf-8')]),
                    ('o', [str(company).encode('utf-8')])
                ]
                self.conn.add_s(company_dn, company_attrs)

                people_dn = "ou=People," + company_dn
                people_attrs = [
                    ('objectClass', ['top'.encode('utf-8'),
                                     'organizationalUnit'.encode('utf-8')]),
                    ('ou', ['People'.encode('utf-8')])
                ]
                self.conn.add_s(people_dn, people_attrs)

                group_dn = "ou=Groups," + company_dn
                group_attrs = [
                    ('objectClass', ['top'.encode('utf-8'),
                                     'organizationalUnit'.encode('utf-8')]),
                    ('ou', ['Groups'.encode('utf-8')])
                ]
                self.conn.add_s(group_dn, group_attrs)

                self.d[company] = IDMap()

        except Exception as err:
            print('add_company', companies, err)
            raise err

    def add_group(self, company_name, groups):
        gid_list = []
        if type(groups) is str:
            groups = [groups]
        try:
            if company_name not in self.d:
                self.add_company(company_name)

            company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
            idmap = self.d.get(company_name)
            for group in groups:
                group_dn = "cn=" + group + ",ou=Groups," + company_dn
                if self.dn_exists(group_dn):
                    gid_list.append(int(self.get_dn_attr(group_dn, 'gidNumber')[0].decode('utf-8')))
                    continue

                gid = idmap.find_avail_gid()
                group_attrs = [
                    ('objectClass', ['top'.encode('utf-8'),
                                     'groupOfMembers'.encode('utf-8'),
                                     'posixGroup'.encode('utf-8')]),
                    ('cn', [str(group).encode('utf-8')]),
                    ('gidNumber', [str(gid).encode('utf-8')])
                ]
                self.conn.add_s(group_dn, group_attrs)
                gid_list.append(gid)
                idmap.set_gid(gid)

            return gid_list

        except Exception as err:
            print('add_group', company_name, groups, err)
            raise err

    def add_one_user(self, company_dn, name, uid, gid):
        user_dn = "uid=" + name + ",ou=People," + company_dn
        if self.dn_exists(user_dn):
            return False

        password = 'lingyun'
        enc_passwd = bytes(password, 'utf-8')
        salt = os.urandom(16)
        sha = hashlib.sha1(enc_passwd) # nosec
        sha.update(salt)
        digest = sha.digest()
        b64_envelop = encode(digest + salt)
        passwd = '{{SSHA}}{}'.format(b64_envelop.decode('utf-8'))

        user_attrs = [
            ('objectClass', ['top'.encode('utf-8'),
                             'inetOrgPerson'.encode('utf-8'),
                             'posixAccount'.encode('utf-8'),
                             'shadowAccount'.encode('utf-8')]),
            ('uid', [str(name).encode('utf-8')]),
            ('cn', [str(name).encode('utf-8')]),
            ('sn', [str(name).encode('utf-8')]),
            ('uidNumber', [str(uid).encode('utf-8')]),
            ('gidNumber', [str(gid).encode('utf-8')]),
            ('homeDirectory', [str('/home/' + name).encode('utf-8')]),
            ('userPassword', [str(passwd).encode('utf-8')]),
            #('shadowLastChange', [str('/home/' + name).encode('utf-8')]),
            #('shadowMin', [str('/home/' + name).encode('utf-8')]),
            #('shadowMax', [str('/home/' + name).encode('utf-8')]),
            #('shadowWarning', [str('/home/' + name).encode('utf-8')]),
            #('shadowInactive', [str('/home/' + name).encode('utf-8')]),
            #('shadowExpire', [str('/home/' + name).encode('utf-8')])
        ]
        self.conn.add_s(user_dn, user_attrs)
        return True

    # group is None: user and group with the same name is added
    # group is not None: all users are added as members of group
    def add_user(self, company_name, users, group=None, replace=False):
        if type(users) is str:
            users = [users]
        try:
            if company_name not in self.d:
                self.add_company(company_name)

            company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
            idmap = self.d.get(company_name)

            gid = 0
            if group is not None:
                gid = self.add_group(company_name, group)[0]
            for user in users:
                if group is None:
                    gid = self.add_group(company_name, user)[0]

                uid = idmap.find_avail_uid()
                if self.add_one_user(company_dn, user, uid, gid):
                    idmap.set_uid(uid)
                if group is None:
                    self.add_user_to_group(company_name, user, user, replace)

            if group is not None:
                self.add_user_to_group(company_name, group, users, replace)

        except Exception as err:
            print('add_user', company_name, users, group, err)
            raise err

    # company & group dn must exist
    def add_user_to_group(self, company, group, users, replace=False):
        if type(users) is str:
            users = [users]

        company_dn = "dc=" + company + "," + config.Config.LDAP_BASE_DN
        group_dn = "cn=" + group + ",ou=Groups," + company_dn

        members = self.get_dn_attr(group_dn, 'member')
        members = [x.decode('utf-8') for x in members]

        add_dn = []
        add_uid = []
        for user in users:
            user_dn = "uid=" + user + ",ou=People," + company_dn
            if not replace and user_dn in members:
                continue
            add_uid.append(user.encode('utf-8'))
            add_dn.append(user_dn.encode('utf-8'))

        if len(add_dn) == 0:
            return

        group_attrs = []
        if replace:
            group_attrs.extend([
                (ldap.MOD_DELETE, 'memberUid', None),
                (ldap.MOD_DELETE, 'member', None)])
        group_attrs.extend([
            (ldap.MOD_ADD, 'memberUid', add_uid),
            (ldap.MOD_ADD, 'member', add_dn)])
        self.conn.modify_s(group_dn, group_attrs)

    def delete_company(self, companies):
        if type(companies) is str:
            companies = [companies]
        try:
            for company in companies:
                if company not in self.d:
                    continue

                company_dn = "dc=" + company + "," + config.Config.LDAP_BASE_DN
                search = self.conn.search_s(company_dn, ldap.SCOPE_SUBTREE)
                delete_list = [dn for dn, _ in search]
                delete_list.reverse()

                for dn in delete_list:
                    self.conn.delete_s(dn)
                self.remove_access(company)
                del self.d[company]
        except Exception as err:
            print('delete_company', companies, err)
            raise err

    def delete_group(self, company_name, groups):
        if type(groups) is str:
            groups = [groups]
        if company_name not in self.d:
            return

        try:
            company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
            idmap = self.d.get(company_name)
            for group in groups:
                group_dn = "cn=" + group + ",ou=Groups," + company_dn
                gid = self.get_dn_attr(group_dn, 'gidNumber')
                if len(gid) == 0:
                    continue

                self.conn.delete_s(group_dn)
                idmap.unset_gid(int(gid[0].decode('utf-8')))

        except Exception as err:
            print('delete_group', company_name, groups, err)
            raise err

    def delete_user(self, company_name, users):
        if type(users) is str:
            users = [users]
        if company_name not in self.d:
            return

        try:
            company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
            idmap = self.d.get(company_name)
            for user in users:
                user_dn = "uid=" + user + ",ou=People," + company_dn
                uid = self.get_dn_attr(user_dn, 'uidNumber')
                if len(uid) == 0:
                    continue

                self.conn.delete_s(user_dn)
                idmap.unset_uid(int(uid[0].decode('utf-8')))

        except Exception as err:
            print('delete_user', company_name, users, err)
            raise err

    def delete_group_user(self, company_name, group, users):
        if type(users) is str:
            users = [users]
        if company_name not in self.d:
            return

        try:
            company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
            group_dn = "cn=" + group + ",ou=Groups," + company_dn
            members = self.get_dn_attr(group_dn, 'member')
            members = [x.decode('utf-8') for x in members]

            del_dn = []
            del_uid = []
            for user in users:
                user_dn = "uid=" + user + ",ou=People," + company_dn
                if user_dn not in members:
                    continue

                del_dn.append(user_dn.encode('utf-8'))
                del_uid.append(user.encode('utf-8'))

            if len(del_dn) == 0:
                return

            self.conn.modify_s(group_dn, [
                (ldap.MOD_DELETE, 'memberUid', del_uid),
                (ldap.MOD_DELETE, 'member', del_dn)])

        except Exception as err:
            print('delete_group_user', company_name, group, users, err)
            raise err

    def get_access_list(self, company_name):
        company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
        dn = 'olcDatabase={2}mdb,cn=config'
        attr = 'olcAccess'
        access_list = self.conn.search_s(dn, ldap.SCOPE_BASE, attrlist=[attr])
        if access_list and attr in access_list[0][1]:
            access_list = access_list[0][1].get(attr)
        else:
            access_list = []
        access_list = [x.decode('utf-8') for x in access_list]
        return access_list
    

    def add_access(self, company_name, cidrs):
        if type(cidrs) is str:
            cidrs = [cidrs]
        if len(cidrs) == 0:
            return
        company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
        try:
            dn = 'olcDatabase={2}mdb,cn=config'
            attr = 'olcAccess'
            access_list = self.get_access_list(company_name)

            key = 'to dn.subtree="{}"'.format(company_dn)
            access = key
            cidrs.sort()
            for ip in cidrs:
                access += " by peername.ip=" + str(IPv4Network(ip).network_address) + "%" + str(IPv4Network(ip).netmask) + " read"
            found = [s.encode('utf-8') for s in access_list if key in s]
            match = [s for s in access_list if access in s]

            if len(match) > 0:
                return

            dn_attrs = []
            if len(found) > 0:
                dn_attrs.append((ldap.MOD_DELETE, attr, found))
            dn_attrs.append((ldap.MOD_ADD, attr, [access.encode('utf-8')]))
            self.conn.modify_s(dn, dn_attrs)

        except Exception as err:
            print('add_access', company_name, cidrs, err)
            raise err

    def remove_access(self, company_name):
        company_dn = "dc=" + company_name + "," + config.Config.LDAP_BASE_DN
        try:
            dn = 'olcDatabase={2}mdb,cn=config'
            attr = 'olcAccess'
            access_list = self.get_access_list(company_name)

            key = 'to dn.subtree="{}"'.format(company_dn)
            found = [s.encode('utf-8') for s in access_list if key in s]

            dn_attrs = [(ldap.MOD_DELETE, attr, found)]
            self.conn.modify_s(dn, dn_attrs)
        except Exception as err:
            print('remove_access', company_name, err)
            raise err

if __name__ == '__main__':
    l = Ldap()
    l.add_user('test1', ['alice', 'bob'], 'devel', False)
    l.delete_group_user('test1', 'devel', 'alice')
    l.add_access('noway', '192.168.0.0/24')
    l.add_access('noway2', '192.168.0.0/24')
    l.remove_access('test1')
