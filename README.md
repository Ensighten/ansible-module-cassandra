# Cassandra Ansible Module

Supplies modules for administering Cassandra roles and granting permissions to those roles.

## Pre-requisites

1. Enable authentication in Cassandra
1. Have `cassandra-driver` python package installed on the target machine

### Enable auth in Cassandra

E.g. set the following properties in `/etc/cassandra/cassandra.yml`:

    authenticator: PasswordAuthenticator
    authorizer: CassandraAuthorizer

Once this is updated and the cluster restarted a default user of `cassandra` with password `cassandra` will be required 
to login. 

This config change and restart **must be applied before you can add permissions**. 

### Install cassandra-driver

The package is: `cassandra-driver` and it can be install via `pip`. 

Docs: https://datastax.github.io/python-driver/api/cassandra/query.html

## Why is there no `cassandra_user` module?

In Cassandra's permissioning system, there are just roles.
However, roles can (optionally) login and roles can inherit other roles (so roles can be used in a very user-like way).

A suggested setup would be have 'role' roles which *can't login* (but are granted the keyspace permissions),
and 'user' roles which *can login* and inherit their permissions from roles.

e.g.
1. Create role `role_select_all` who can not login but is granted access to select anything from any keyspace/table.
1. Create 'pseudo-user' (a role which can login) and assign them the role `role_select_all`.

See `example-tasks` for how this can be done.

## Docs

Written in comments in `library/*`.
