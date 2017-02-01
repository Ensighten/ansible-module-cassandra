#!/usr/bin/python
# -*- coding: utf-8 -*-
# TODO: add documentation here
try:
    import json
except ImportError:
    import simplejson as json
except:
    json_dep_found = False
else:
    json_dep_found = True

try:
    from cassandra.cluster import Cluster
    from cassandra.auth import PlainTextAuthProvider
    from cassandra.query import dict_factory
except ImportError:
    cassandra_dep_found = False
else:
    cassandra_dep_found = True


ALTER_KEYSPACE_FORMAT = 'alter keyspace {keyspace} with replication={config};'


def alter_keyspace(module, session, keyspace, strategy, topology):
    changed = True
    reasons = []

    # TODO: check the current state of the keyspace before changing and set the
    # changed/reasons vars for idempotency
    # Cassandra expects is to include the replication strategy alongside
    # the topology config
    topology['class'] = strategy
    # Small hack: cassandra expects a JSON-like structure, but with single
    # quotes instead of double quotes.
    config_stuff = json.dumps(topology).replace('"', '\'')
    cql = ALTER_KEYSPACE_FORMAT.format(keyspace=keyspace, config=config_stuff)

    session.execute(cql)

    return changed, reasons


def main():

    arg_spec = {
        'keyspace': {
            'type': 'str',
            'required': True,
        },
        'login_hosts': {
            'type': 'list',
            'required': True,
        },
        'strategy': {
            'type': 'str',
            'required': True,
        },
        'topology': {
            'type': 'dict',
            'required': True,
        },
        'login_user': {
            'type': 'str',
            'required': True,
        },
        'password': {
            'type': 'str',
            'required': True,
        },
        'login_port': {
            'type': 'int',
            'default': 9042,
            'required': False,
        },
    }

    module = AnsibleModule(argument_spec=arg_spec)

    keyspace = module.params['keyspace']
    login_hosts = module.params['login_hosts']
    login_port = module.params['login_port']
    strategy = module.params['strategy']
    topology = module.params['topology']
    login_user = module.params['login_user']
    password = module.params['password']

    if not cassandra_dep_found:
        module.fail_json(msg="the python cassandra-driver module is required")

    if not json_dep_found:
        module.fail_json(msg="the python json or simplejson module is required")

    try:
        if not login_user:
            cluster = Cluster(login_hosts, port=login_port)

        else:
            auth_provider = PlainTextAuthProvider(username=login_user,
                                                  password=password)
            cluster = Cluster(login_hosts, auth_provider=auth_provider,
                              protocol_version=2, port=login_port)
        session = cluster.connect()
        session.row_factory = dict_factory
    except Exception, e:
        module.fail_json(
            msg="unable to connect to cassandra, check login_user and " +
                "login_password are correct. Exception message: %s"
                % e)

    changed, reasons = alter_keyspace(module, session, keyspace, strategy,
                                      topology)

    module.exit_json(changed=changed, msg='OK', name=keyspace, reasons=reasons)

# Ansible "magic" (NOQA comments tells flake8 to ignore this line since it's
# bad Python, but required for Ansible)
from ansible.module_utils.basic import *  # NOQA
main()
