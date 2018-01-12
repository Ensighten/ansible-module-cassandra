#!/usr/bin/python
# -*- coding: utf-8 -*-


DOCUMENTATION = '''
---
module: cassandra_role

short_description: Manage Cassandra Roles
description:
    - Add/remove Cassandra Users
    - requires `pip install cassandra-driver`
    - Related Docs: https://datastax.github.io/python-driver/api/cassandra/query.html
    - Related Docs: https://docs.datastax.com/en/cql/3.3/cql/cql_reference/create_role.html
author: "Sam Adams"
options:
  name:
    description:
      - name of the role to add or remove
    required: true
    alias: role
  password:
    description:
      - Set the role's password. 
    required: true
  superuser:
    description:
      - Create the user as a superuser?
    required: false
    default: False
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
  state:
    description:
      - Whether the role should exist.  When C(absent), removes
        the role.
    required: false
    default: present
    choices: [ "present", "absent" ]

notes:
   - "requires cassandra-driver to be installed"

'''

EXAMPLES = '''
# Create Role
- cassandra_role: name='foo' password='12345' state=present superuser=False login_hosts=localhost login_pass=cassandra login_user=cassandra

# Remove Role
- cassandra_role: name='foo' state=absent login_hosts=localhost login_pass=cassandra login_user=cassandra
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
DROP_ROLE = 'DROP ROLE %s'
ALTER_ROLE_WITH_PASS = 'ALTER ROLE %s WITH PASSWORD = %s AND LOGIN = %s AND SUPERUSER = %s'
CREATE_ROLE_WITH_PASS = 'CREATE ROLE %s WITH PASSWORD = %s AND LOGIN = %s AND SUPERUSER = %s'
CREATE_ROLE_NO_PASS = 'CREATE ROLE %s WITH LOGIN = %s AND SUPERUSER = %s'
ALTER_ROLE_NO_PASS = 'ALTER ROLE %s WITH LOGIN = %s AND SUPERUSER = %s'


def role_delete(session, in_check_mode, name):
    existing_role = get_role(session, name)
    if bool(existing_role):
        if not in_check_mode:
            session.execute(DROP_ROLE, [name])
        return True
    else:
        return False


def get_role(session, name):
    rows = session.execute(GET_ROLE, [name])
    for row in rows:
        return row


def role_save(session, check_mode, name, password, can_login, is_superuser):
    existing_role = get_role(session, name)
    if check_mode:
        return would_change(existing_role, can_login, is_superuser, password)

    do_save(session, existing_role, is_superuser, name, password, can_login)

    new_user = get_role(session, name)
    
    if bool(password):
        return not bool(existing_role)
    else:
        return bool(new_user != existing_role)


def do_save(session, existing_role, is_superuser, name, password, can_login):
    existing_role = bool(existing_role)

    if bool(password):
        params = (name, password, can_login, is_superuser)
        if existing_role:
            query = ALTER_ROLE_WITH_PASS
        else:
            query = CREATE_ROLE_WITH_PASS
    else:
        params = (name, can_login, is_superuser)
        if existing_role:
            query = ALTER_ROLE_NO_PASS
        else:
            query = CREATE_ROLE_NO_PASS
    session.execute(query, params)


def would_change(existing_role, can_login, is_superuser, password):
    if password or not existing_role:
        # even setting existing password updates the `salted_hash` in the db, so no way to check has changed.
        return True
    else:
        return bool(existing_role['can_login'] != can_login or existing_role['is_superuser'] != is_superuser)


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
            'name': {
                'required': True,
                'aliases': ['role']
            },
            'password': {
                'default': None,
                'no_log': True
            },
            'enable_login': {
                'default': False,
                'type': 'bool'
            },
            'superuser': {
                'default': False,
                'type': 'bool'
            },
            'state': {
                'default': "present",
                'choices': ["absent", "present"]
            }
        },
        supports_check_mode=True
    )
    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    login_hosts = module.params["login_hosts"]
    login_port = module.params["login_port"]
    enable_login = module.params["enable_login"]
    name = module.params["name"]
    password = module.params["password"]
    superuser = module.params["superuser"]
    state = module.params["state"]

    if not cassandra_dep_found:
        module.fail_json(msg="the python cassandra-driver module is required")

    session = None
    changed = False
    try:
        if not login_user:
            cluster = Cluster(login_hosts, port=login_port)

        else:
            auth_provider = PlainTextAuthProvider(username=login_user, password=login_password)
            cluster = Cluster(login_hosts, auth_provider=auth_provider, protocol_version=3, port=login_port)
        session = cluster.connect()
        session.row_factory = dict_factory
    except Exception, e:
        module.fail_json(
            msg="unable to connect to cassandra, check login_user and login_password are correct. Exception message: %s"
                % e)

    new_role = not bool(get_role(session, name))

    if state == "present":
        if new_role:
            changed = True
        try:
            changed = role_save(session, module.check_mode, name, password, enable_login, superuser)
        except Exception, e:
            module.fail_json(msg=str(e))
    elif state == "absent":
        try:
            changed = role_delete(session, module.check_mode, name)
        except Exception, e:
            module.fail_json(msg=str(e))

    module.exit_json(changed=changed, role=name, new_role=new_role )


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
