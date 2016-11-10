#!/usr/bin/python
# -*- coding: utf-8 -*-


DOCUMENTATION = '''
---
module: cassandra_role

short_description: Grant Cassandra permissions
description:
    - Add/remove Cassandra Users
    - requires `pip install cassandra-driver`
    - Related Docs: https://datastax.github.io/python-driver/api/cassandra/query.html
    - Related Docs: https://docs.datastax.com/en/cql/3.3/cql/cql_reference/grant_r.html
author: "Sam Adams"
options:
  permission:
    description:
      - what permission to grant
    required: true
    choices: ["all", "create", "alter", "drop", "select", "modify", "authorize"]
  keyspace:
    description:
      - required if `all_keyspaces` == false
      - ignored if `inherit_role` is set
    required: false
    default: false
  all_keyspaces:
    description:
      - if true, `on` is ignored and the `what` is granted to all keyspaces
      - ignored if `inherit_role` is set
    required: false
    default: false
  role:
    description:
      - which role to modify
      - the role must already exist in cassandra
    required: true
  inherit_role:
    description:
      - which role permission this role should inherit (no keyspace required)
      - requires that the role already exists
    required: true
  login_hosts:
    description:
      - List of hosts to login to Cassandra with
    required: true
  login_user:
    description:
      - The superuser to login to Cassandra with
    required: true
  login_password:
    description:
      - The superuser password to login to Cassandra with
    required: true
  login_port:
    description:
      - Port to connect to cassandra on
    default: 9042
  mode:
    description:
      - Whether access should be granted or revoked.
    required: false
    default: grant
    choices: [ "grant", "revoke" ]

notes:
   - "requires cassandra-driver to be installed"

'''

EXAMPLES = '''
# Grant select for all keyspaces
- cassandra_grant: permission='select' all_keyspaces=True role=read_only login_hosts=localhost login_pass=cassandra login_user=cassandra

# Revoke modify permission to foo keyspace
- cassandra_grant: mode=revoke permission=modify keyspace=foo role=no_modify_foo login_hosts=localhost login_pass=cassandra login_user=cassandra

# Inherit roles
- cassandra_grant: mode=grant inherit_role=read_only role=my_user_role login_hosts=localhost login_pass=cassandra login_user=cassandra
'''

try:
    from cassandra.cluster import Cluster
    from cassandra.auth import PlainTextAuthProvider
    from cassandra.query import dict_factory
except ImportError:
    cassandra_dep_found = False
else:
    cassandra_dep_found = True

GET_ROLE = 'SELECT * FROM system_auth.roles WHERE role = %s limit 1;'
GET_ROLE_MEMBERS = 'SELECT * FROM system_auth.role_members WHERE role = %s'
GRANT_ROLE_TO_ROLE = 'GRANT %(inherit_role)s TO %(role)s'
REVOKE_ROLE_FROM_ROLE = 'REVOKE %(inherit_role)s FROM %(role)s'
GRANT_PERMISSION_TO_ROLE_FOR_KESYPACE_FORMAT = 'GRANT {permission} ON KEYSPACE {keyspace} TO %(role)s'
REVOKE_PERMISSION_FROM_ROLE_FOR_KESYPACE_FORMAT = 'REVOKE {permission} ON KEYSPACE {keyspace} FROM %(role)s'
GRANT_PERMISSION_TO_ROLE_FOR_ALL_KESYPACES_FORMAT = 'GRANT {permission} ON ALL KEYSPACES TO %(role)s'
REVOKE_PERMISSION_FROM_ROLE_FOR_ALL_KESYPACES_FORMAT = 'REVOKE {permission} ON ALL KEYSPACES FROM %(role)s'


def get_role(session, name):
    rows = session.execute(GET_ROLE, [name])
    for row in rows:
        return row


def would_change(existing_role, can_login, is_superuser, password):
    if password or not existing_role:
        # even setting existing password updates the `salted_hash` in the db, so no way to check has changed.
        return True
    else:
        return bool(existing_role['can_login'] != can_login or existing_role['is_superuser'] != is_superuser)


def role_has_role(session, role, inherit_role):
    rows = session.execute(GET_ROLE_MEMBERS, [inherit_role])
    for row in rows:
        if row['member'] == role:
            return True
    return False


def assign_role(session, check_mode, is_revoke, inherit_role, role):
    has_role = role_has_role(session, role, inherit_role)

    # check if we need to do anything
    if has_role and not is_revoke:
        return False
    elif not has_role and is_revoke:
        return False

    if not is_revoke:
        query = GRANT_ROLE_TO_ROLE
    else:
        query = REVOKE_ROLE_FROM_ROLE

    if not check_mode:
        session.execute(query, {'role': role, 'inherit_role': inherit_role})

    return True


def grant_role_permission(session, in_check_mode, is_revoke, permission, all_keyspaces, keyspace, role):
    permission = permission.upper()
    if is_revoke and all_keyspaces:
        # revoking for all keyspaces
        query = REVOKE_PERMISSION_FROM_ROLE_FOR_ALL_KESYPACES_FORMAT.format(permission=permission)
    elif all_keyspaces:
        # granting for all keyspaces
        query = GRANT_PERMISSION_TO_ROLE_FOR_ALL_KESYPACES_FORMAT.format(permission=permission)
    elif is_revoke:
        # revoking for a specific keyspace
        query = REVOKE_PERMISSION_FROM_ROLE_FOR_KESYPACE_FORMAT.format(permission=permission, keyspace=keyspace)
    else:
        # granting for a specific keyspace
        query = GRANT_PERMISSION_TO_ROLE_FOR_KESYPACE_FORMAT.format(permission=permission, keyspace=keyspace)

    if not in_check_mode:
        session.execute(query, {'role': role})

    # too complex to work out what will/has changed
    return True


def grant_access(session, in_check_mode, permission, role, inherit_role, keyspace, all_keyspaces, mode):
    if keyspace and all_keyspaces:
        raise Exception("Specify a keyspace or all keyspaces, not both")
    if keyspace and inherit_role:
        raise Exception("If you are inheriting a role you can't specify a keyspace")
    if all_keyspaces and inherit_role:
        raise Exception("If you are inheriting a role you can't specify all keyspaces")

    mode = mode.upper()
    is_revoke = mode != 'GRANT'

    if inherit_role:
        return assign_role(session, in_check_mode, is_revoke, inherit_role, role)
    else:
        return grant_role_permission(session, in_check_mode, is_revoke, permission, all_keyspaces, keyspace, role)


def main():
    module = AnsibleModule(
        argument_spec={
            'login_user': {
                'required': True,
                'type': 'str'
            },
            'login_password': {
                'required': True,
                'no_log': True,
                'type': 'str'
            },
            'login_hosts': {
                'required': True,
                'type': 'list'
            },
            'login_port': {
                'default': 9042,
                'type': 'int'
            },
            'permission': {
                'required': False,
                'choices': ["all", "create", "alter", "drop", "select", "modify", "authorize"]
            },
            'role': {
                'required': True,
                'aliases': ['name']
            },
            'inherit_role': {
                'required': False,
                'default': None
            },
            'keyspace': {
                'required': False,
                'default': None,
                'type': 'str'
            },
            'all_keyspaces': {
                'default': False,
                'type': 'bool'
            },
            'mode': {
                'default': "grant",
                'choices': ["grant", "revoke"]
            }
        },
        supports_check_mode=True
    )
    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    login_hosts = module.params["login_hosts"]
    login_port = module.params["login_port"]
    permission = module.params["permission"]
    role = module.params["role"]
    inherit_role = module.params["inherit_role"]
    keyspace = module.params["keyspace"]
    all_keyspaces = module.params["all_keyspaces"]
    mode = module.params["mode"]

    if not cassandra_dep_found:
        module.fail_json(msg="the python cassandra-driver module is required")

    session = None
    changed = False
    try:
        if not login_user:
            cluster = Cluster(login_hosts, port=login_port)
        else:
            auth_provider = PlainTextAuthProvider(username=login_user, password=login_password)
            cluster = Cluster(login_hosts, auth_provider=auth_provider, protocol_version=2, port=login_port)
        session = cluster.connect()
        session.row_factory = dict_factory
    except Exception, e:
        module.fail_json(
            msg="unable to connect to cassandra, check login_user and login_password are correct. Exception message: %s"
                % e)

    try:
        changed = grant_access(session, module.check_mode, permission, role, inherit_role, keyspace, all_keyspaces,
                               mode)
    except Exception, e:
        module.fail_json(msg=str(e))
    module.exit_json(changed=changed, name=role)


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
