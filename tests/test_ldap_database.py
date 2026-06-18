"""Unit tests for the LDAP protocol database layer.

Mirrors the SMB database test suite for cross-protocol parity. Tests assert the
*intended* behavior; where the current source is buggy, the assertion is marked
xfail with a reason so the bug is documented and the test goes green once fixed.
"""
import pytest


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("ldap")
    yield dbo
    dbo.clear_database()


def test_add_host(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", True, "When Supported")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    host = hosts[0]
    assert host.ip == "127.0.0.1"
    assert host.hostname == "DC01"
    assert host.domain == "TEST.DEV"
    assert host.os == "Windows Server 2022"
    assert host.signing_required is True
    assert host.channel_binding == "When Supported"


def test_update_host(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", True, "Never")
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2025", False, "Always")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    assert hosts[0].os == "Windows Server 2025"
    assert hosts[0].signing_required is False
    assert hosts[0].channel_binding == "Always"


def test_is_host_valid(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", True, "Never")
    host_id = db.get_hosts()[0].id
    assert db.is_host_valid(host_id) is True
    assert db.is_host_valid(9999) is False


def test_get_hosts(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", True, "Never")
    db.add_host("127.0.0.2", "WS01", "OTHER.DEV", "Windows 11", False, "Never")

    assert len(db.get_hosts()) == 2

    # by valid id (single-element list)
    host_id = db.get_hosts(filter_term="DC01")[0].id
    by_id = db.get_hosts(filter_term=host_id)
    assert len(by_id) == 1
    assert by_id[0].hostname == "DC01"

    # by "domain <x>" filter
    by_domain = db.get_hosts(filter_term="domain TEST")
    assert len(by_domain) == 1
    assert by_domain[0].hostname == "DC01"

    # by ip/hostname
    by_host = db.get_hosts(filter_term="WS01")
    assert len(by_host) == 1
    assert by_host[0].hostname == "WS01"


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


def test_add_credential_invalid_pillaged_from(db):
    # pillaged_from referencing a nonexistent host is rejected (add is skipped)
    db.add_credential("plaintext", "TEST.DEV", "admin", "secret", pillaged_from=9999)
    assert len(db.get_credentials()) == 0


def test_add_credential_pillaged_from_persists(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", True, "Never")
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
    # get_credential for a non-existent credential returns None (no crash)
    assert db.get_credential("plaintext", "NOPE.DEV", "ghost", "nope") is None


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
