'''
/**
* Copyright Teradici Corporation 2012-2014. All Rights Reserved.
*
* No portions of this material may be reproduced in any form without the
* written permission of Teradici Corporation.
*
* All information contained in this document is Teradici Corporation company
* private, proprietary, and trade secret.
*
*/
'''
import platform
import ldap
import ldap.filter
import ldap.modlist
import ldap.sasl
from optparse import OptionParser

class ldap_lib(object):
    def __init__(self, server_address, username, password, domain):
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        self.ldap_server = 'ldap://%s' % server_address
        self.master_user = username
        self.master_password = password
        self.domain = '@%s' % domain
        self.base = 'DC=' + domain
        self.base = self.base.replace('.', ',DC=')

        try:
            self.admin_ldap = ldap.initialize(self.ldap_server)
            self.admin_ldap.start_tls_s()
            self.admin_ldap.simple_bind_s(self.master_user + self.domain, self.master_password)
        except ldap.LDAPError, err:
            raise err

    def get_computer_info(self, computer_name):
        """
        Get computer information
        """
        user_base = "%s" % (self.base)
        user_filter = "(&(sAMAccountName=%s$)(objectClass=computer))" \
                        % ldap.filter.escape_filter_chars(computer_name, 0)
        user_scope = ldap.SCOPE_SUBTREE
        try:
            results = self.admin_ldap.search_s(user_base, user_scope, user_filter)
        except ldap.LDAPError, err:
            raise err
        if results:
            return results[0]
        return

    def get_group_info(self, group_name):
        """
        Get group information
        """
        user_base = "%s" % (self.base)
        user_filter = "(&(objectClass=GROUP)(cn=%s))" \
                        % ldap.filter.escape_filter_chars(group_name, 0)
        user_scope = ldap.SCOPE_SUBTREE
        try:
            results = self.admin_ldap.search_s(user_base, user_scope, user_filter)
        except ldap.LDAPError, err:
            raise err
        if results:
            return results[0]
        return

    def add_computer_to_group(self, computer_to_add, group_name):
        """
        Add computer to a specific group
        """
        group_dn = self.get_group_info(group_name)[0]
        computer_dn = self.get_computer_info(computer_to_add)[0]
        member = [((ldap.MOD_ADD, 'member', [computer_dn]))]
        try:
            self.admin_ldap.modify_s(group_dn, member)
        except ldap.CONSTRAINT_VIOLATION, err:
            print err
            return False
        except ldap.LDAPError, err:
            print err
            return False
        return True

parser = OptionParser()
parser.add_option("-d", "--domain", dest="domain", help="Domain name")
parser.add_option("-a", "--address", dest="address", help="domain controller address")
parser.add_option("-u", "--user_name", dest="user_name", help="user name to login to domain controller")
parser.add_option("-p", "--password", dest="password", help="password to login to domain controller")
parser.add_option("-c", "--computer", dest="computer", help="computer to add to the group")
parser.add_option("-g", "--group", dest="group", help="group name")
(options, args) = parser.parse_args()

active_d = ldap_lib(options.address, options.user_name, options.password, options.domain)
active_d.add_computer_to_group(options.computer, options.group)
