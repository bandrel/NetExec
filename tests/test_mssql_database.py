"""Unit tests for the MSSQL protocol database layer.

Mirrors the LDAP/SMB database test suites for cross-protocol parity. Tests assert
the *intended* behavior; where the current source is buggy, the assertion is
marked xfail with a reason so the bug is documented and the test goes green once
the source is fixed.
"""
import pytest


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("mssql")
    yield dbo
    dbo.clear_database()


# --------------------------------------------------------------------------- #
# Hosts
# --------------------------------------------------------------------------- #
def test_add_host(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    hosts = db.get_hosts()
    assert len(hosts) == 1
    host = hosts[0]
    assert host.ip == "127.0.0.1"
    assert host.hostname == "DC01"
    assert host.domain == "TEST.DEV"
    assert host.os == "Windows Server 2022"
    assert host.instances == 1


def test_update_host(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2025", 3)
    hosts = db.get_hosts()
    assert len(hosts) == 1
    assert hosts[0].os == "Windows Server 2025"
    assert hosts[0].instances == 3


def test_is_host_valid(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    host_id = db.get_hosts()[0].id
    assert db.is_host_valid(host_id) is True
    assert db.is_host_valid(9999) is False


def test_get_hosts(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    db.add_host("127.0.0.2", "WS01", "OTHER.DEV", "Windows 11", 1)

    assert len(db.get_hosts()) == 2

    # by valid id (single-element list)
    host_id = db.get_hosts(filter_term="DC01")[0].id
    by_id = db.get_hosts(filter_term=host_id)
    assert len(by_id) == 1
    assert by_id[0].hostname == "DC01"

    # by ip/hostname
    by_host = db.get_hosts(filter_term="WS01")
    assert len(by_host) == 1
    assert by_host[0].hostname == "WS01"


def test_get_hosts_dc_does_not_crash(db):
    # mssql has no DC concept; "dc" should fall through to a normal search
    # and return a list without raising (empty is fine).
    result = db.get_hosts(filter_term="dc")
    assert isinstance(result, list)


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
def test_add_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1
    cred = creds[0]
    assert cred.credtype == "plaintext"
    assert cred.domain == "TEST.DEV"
    assert cred.username == "admin"
    assert cred.password == "Passw0rd!"

    # same domain/username/credtype updates instead of duplicating
    db.add_credential("plaintext", "TEST.DEV", "admin", "NewPassw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1
    assert creds[0].password == "NewPassw0rd!"


def test_add_credential_pillaged_from_persists(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    host_id = db.get_hosts()[0].id
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!", pillaged_from=host_id)
    cred = db.get_credentials()[0]
    assert cred.pillaged_from_hostid == host_id


def test_get_credentials(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_credential("hash", "TEST.DEV", "svc", "aad3b...")

    assert len(db.get_credentials()) == 2

    cred_id = db.get_credentials(cred_type="plaintext")[0].id
    by_id = db.get_credentials(filter_term=cred_id)
    assert len(by_id) == 1
    assert by_id[0].username == "admin"

    by_type = db.get_credentials(cred_type="hash")
    assert len(by_type) == 1
    assert by_type[0].username == "svc"

    by_name = db.get_credentials(filter_term="adm")
    assert len(by_name) == 1
    assert by_name[0].username == "admin"


def test_get_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    assert db.get_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!") == cred_id


def test_get_credential_missing_returns_none(db):
    # No matching credential exists; should return None rather than crashing.
    assert db.get_credential("plaintext", "TEST.DEV", "nope", "nope") is None


def test_is_credential_valid(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    valid_id = db.get_credentials()[0].id
    assert db.is_credential_valid(valid_id) is True
    assert db.is_credential_valid(9999) is False


def test_is_credential_valid_rejects_null_password(db):
    db.add_credential("plaintext", "TEST.DEV", "nopw", None)
    cred_id = db.get_credentials()[0].id
    assert db.is_credential_valid(cred_id) is False


def test_remove_single_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    db.remove_credentials([cred_id])
    assert len(db.get_credentials()) == 0


def test_remove_multiple_credentials(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_credential("plaintext", "TEST.DEV", "user", "Passw0rd!")
    ids = [c.id for c in db.get_credentials()]
    db.remove_credentials(ids)
    assert len(db.get_credentials()) == 0


# --------------------------------------------------------------------------- #
# Admin relations
# --------------------------------------------------------------------------- #
def test_add_admin_user_and_get_relations(db):
    # Add an extra host FIRST so the target host's id differs from the user's id.
    # This catches the cartesian-product bug where the wrong id was stored.
    db.add_host("127.0.0.9", "DECOY", "TEST.DEV", "Windows Server 2022", 1)
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    host_id = db.get_hosts(filter_term="DC01")[0].id
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    user_id = db.get_credentials()[0].id

    # Sanity: ids must differ, otherwise the test can't detect a swapped id.
    assert host_id != user_id

    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")

    relations = db.get_admin_relations()
    assert len(relations) == 1
    # The single relation must point at the REAL host id and REAL user id.
    assert relations[0].hostid == host_id
    assert relations[0].userid == user_id

    by_user = db.get_admin_relations(user_id=user_id)
    assert len(by_user) == 1
    assert by_user[0].userid == user_id
    assert by_user[0].hostid == host_id

    by_host = db.get_admin_relations(host_id=host_id)
    assert len(by_host) == 1
    assert by_host[0].hostid == host_id
    assert by_host[0].userid == user_id


def test_add_admin_user_dedup(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")

    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")

    assert len(db.get_admin_relations()) == 1


def test_remove_admin_relation_by_user(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    user_id = db.get_credentials()[0].id
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")
    assert len(db.get_admin_relations()) == 1

    db.remove_admin_relation(user_ids=[user_id])
    assert len(db.get_admin_relations()) == 0


def test_remove_admin_relation_by_host(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    host_id = db.get_hosts()[0].id
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")
    assert len(db.get_admin_relations()) == 1

    db.remove_admin_relation(host_ids=[host_id])
    assert len(db.get_admin_relations()) == 0


# --------------------------------------------------------------------------- #
# Logged-in relations
# --------------------------------------------------------------------------- #
def test_add_and_get_loggedin_relation(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    host_id = db.get_hosts()[0].id
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    user_id = db.get_credentials()[0].id

    db.add_loggedin_relation(user_id, host_id)

    relations = db.get_loggedin_relations()
    assert len(relations) == 1
    assert relations[0].userid == user_id
    assert relations[0].hostid == host_id

    by_user = db.get_loggedin_relations(user_id=user_id)
    assert len(by_user) == 1
    by_host = db.get_loggedin_relations(host_id=host_id)
    assert len(by_host) == 1


def test_add_loggedin_relation_dedup(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    host_id = db.get_hosts()[0].id
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    user_id = db.get_credentials()[0].id

    db.add_loggedin_relation(user_id, host_id)
    db.add_loggedin_relation(user_id, host_id)

    assert len(db.get_loggedin_relations()) == 1


def test_remove_loggedin_relations(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", 1)
    host_id = db.get_hosts()[0].id
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    user_id = db.get_credentials()[0].id
    db.add_loggedin_relation(user_id, host_id)
    assert len(db.get_loggedin_relations()) == 1

    db.remove_loggedin_relations(user_id=user_id)
    assert len(db.get_loggedin_relations()) == 0
