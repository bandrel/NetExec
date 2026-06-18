"""Smoke tests for the WMI protocol database layer.

The WMI database is schema-only: it defines tables (credentials, hosts) but
implements no data-access methods beyond __init__ and reflect_tables().
These tests lock in the schema/parity floor.
"""
from sqlalchemy import func, select

import pytest


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("wmi")
    yield dbo
    dbo.clear_database()


def test_db_constructed(db):
    assert db is not None


def test_reflect_tables_populated(db):
    assert db.CredentialsTable is not None
    assert db.HostsTable is not None


def test_tables_are_empty(db, protocol_dbs):
    sess = protocol_dbs.session("wmi")
    for table in (db.HostsTable, db.CredentialsTable):
        count = sess.execute(select(func.count()).select_from(table)).scalar_one()
        assert count == 0
