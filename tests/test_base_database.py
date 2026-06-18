"""Tests for the shared BaseDB layer (nxc/database.py)."""
import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from nxc.database import delete_workspace


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("smb")
    yield dbo
    dbo.clear_database()


def test_db_execute_releases_lock_on_exception(db):
    # an execute() that raises must NOT leave the shared lock held (else the next
    # db_execute on this instance would deadlock the whole run)
    with pytest.raises(OperationalError):
        db.db_execute(text("SELECT * FROM table_that_does_not_exist"))
    assert db.lock.locked() is False
    # the db object must still be usable afterwards
    assert db.get_hosts() == []


def test_db_execute_releases_lock_on_success(db):
    db.add_host("127.0.0.1", "H", "D", "OS", False, True)
    assert db.lock.locked() is False
    assert len(db.get_hosts()) == 1


def test_delete_workspace_missing_is_noop():
    # deleting a workspace that does not exist must not raise
    delete_workspace("this_workspace_does_not_exist_xyz")
    delete_workspace("")
