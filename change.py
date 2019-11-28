#!/usr/bin/python

import ldap3
import argparse
import random
import string

LDAP_PASSWORD_HISTORY_SIZE = 30
DEFAULT_LDAP_SERVER_IP     = None
BASE_DN                    = None

# Change these according to your domain
assert DEFAULT_LDAP_SERVER_IP != None
assert BASE_DN                != None

def generate_random_string(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in xrange(length))

def username_to_domain_user(username):
    raise 'Change username_to_domain_user() according to your domain'
    #return username

def ldap_connect(domain_name, password, server_ip):
    search_filter = '(&(userPrincipalName='+domain_name+')(objectClass=person))'

    user_dn=''
    user_cn=''

    ldap_server = ldap3.Server(server_ip, get_info=ldap3.ALL)
    conn = ldap3.Connection(ldap_server, domain_name, password, auto_bind=True)
    conn.start_tls()

    conn.search(search_base = BASE_DN,
                search_filter = search_filter,
                search_scope  = ldap3.SUBTREE,
                attributes = ['cn', 'givenName', 'userPrincipalName'],
                paged_size = 5)

    for entry in conn.response:
        if not entry.get('dn') or not entry.get('attributes'):
            continue

        if domain_name == entry.get('attributes').get('userPrincipalName'):
            user_dn = entry.get('dn')
            return [conn, user_dn]

    return [None, None]

def change_password_single(conn, user_dn, curr_pass, new_pass):
    print 'Changing from %s to %s ...'  % (curr_pass, new_pass)

    b = ldap3.extend.microsoft.modifyPassword.modify_ad_password(conn, user_dn, curr_pass, new_pass)
    if not b:
        print 'Sorry, I messed up.'
        print 'Your password is currently ' + curr_pass
        return False

    return True


def change_password(_username, orig_pass, new_pass, server_ip):
    # Clear the previous passwords by changing the password to some random
    #   values, causing the passwords history to not contain the actually
    #   needed password

    domain_name = username_to_domain_user(_username)
    [conn, user_dn] = ldap_connect(domain_name, orig_pass, server_ip)
    if not user_dn:
        print 'NO SUCH USERNAME?? ..'
        return False

    tmp_curr_pass = orig_pass
    tmp_new_pass  = ''
    for i in xrange(LDAP_PASSWORD_HISTORY_SIZE):
        tmp_new_pass = generate_random_string(15)

        change_res = change_password_single(conn, user_dn, tmp_curr_pass, tmp_new_pass)
        if not change_res:
            # Reason already logged @ function
            return False

        tmp_curr_pass = tmp_new_pass

    # And finally change the password to the actual requested password..
    return change_password_single(conn, user_dn, tmp_curr_pass, new_pass)

def main():
    parser = argparse.ArgumentParser(description="NSFW script to change your Window's domain password")

    # Optional arguments
    parser.add_argument("-s", dest="server",
                        help="LDAP server IP",
                        default = DEFAULT_LDAP_SERVER_IP)

    # Required arguments
    required_named = parser.add_argument_group('required arguments')
    required_named.add_argument("user",
                                help="Username")
    required_named.add_argument("current_password",
                                help="Current password")
    required_named.add_argument("new_password",
                                help="New password")

    parser_args = parser.parse_args()

    username  = parser_args.user
    curr_pass = parser_args.current_password
    new_pass  = parser_args.new_password
    server_ip = parser_args.server

    change_password(username, curr_pass, new_pass, server_ip)

if __name__ == '__main__':
    main()
