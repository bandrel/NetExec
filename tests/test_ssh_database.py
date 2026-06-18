"""Unit tests for the SSH protocol database layer.

Mirrors the LDAP/SMB database test suites for cross-protocol parity. Tests assert
the *intended* behavior; where the current source is buggy, the assertion is marked
xfail with a reason so the bug is documented and the test goes green once fixed.

SSH quirks compared to other protocols:
- credentials have no ``domain`` column: ``add_credential(credtype, username, password, key=None)``
- credentials may be keyed by an SSH key (``add_key`` / ``get_keys``)
- hosts use ``host``/``port``/``banner``/``os`` columns
"""
import pytest


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("ssh")
    yield dbo
    dbo.clear_database()


# ---------------------------------------------------------------------------
# hosts
# ---------------------------------------------------------------------------
def test_add_host(db):
    db.add_host("127.0.0.1", 22, "SSH-2.0-OpenSSH_9.6", "Ubuntu 24.04")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    host = hosts[0]
    assert host.host == "127.0.0.1"
    assert host.port == 22
    assert host.banner == "SSH-2.0-OpenSSH_9.6"
    assert host.os == "Ubuntu 24.04"


def test_add_host_defaults_null_banner_and_os(db):
    db.add_host("127.0.0.1", 22, None, None)
    host = db.get_hosts()[0]
    assert host.banner == ""
    assert host.os == ""


def test_update_host(db):
    db.add_host("127.0.0.1", 22, "SSH-2.0-OpenSSH_9.6", "Ubuntu 24.04")
    db.add_host("127.0.0.1", 2222, "SSH-2.0-OpenSSH_9.7", "Ubuntu 24.10")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    assert hosts[0].port == 2222
    assert hosts[0].banner == "SSH-2.0-OpenSSH_9.7"
    assert hosts[0].os == "Ubuntu 24.10"


def test_is_host_valid(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    assert db.is_host_valid(host_id) is True
    assert db.is_host_valid(9999) is False


def test_get_hosts(db):
    db.add_host("127.0.0.1", 22, "banner-a", "Ubuntu")
    db.add_host("127.0.0.2", 22, "banner-b", "Debian")

    assert len(db.get_hosts()) == 2

    # by valid id (single-element list)
    host_id = db.get_hosts(filter_term="127.0.0.1")[0].id
    by_id = db.get_hosts(filter_term=host_id)
    assert len(by_id) == 1
    assert by_id[0].host == "127.0.0.1"

    # by ip
    by_ip = db.get_hosts(filter_term="127.0.0.2")
    assert len(by_ip) == 1
    assert by_ip[0].host == "127.0.0.2"


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------
def test_add_credential(db):
    cred_id = db.add_credential("plaintext", "admin", "Passw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1
    cred = creds[0]
    assert cred.id == cred_id
    assert cred.credtype == "plaintext"
    assert cred.username == "admin"
    assert cred.password == "Passw0rd!"


def test_add_credential_updates_existing(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    # same username/credtype updates instead of duplicating
    db.add_credential("plaintext", "admin", "NewPassw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1
    assert creds[0].password == "NewPassw0rd!"


def test_add_credential_with_key(db):
    cred_id = db.add_credential("key", "admin", "passphrase", key="PRIVATE-KEY-DATA")
    creds = db.get_credentials()
    assert len(creds) == 1
    assert creds[0].id == cred_id

    keys = db.get_keys(cred_id=cred_id)
    assert len(keys) == 1
    assert keys[0].data == "PRIVATE-KEY-DATA"


def test_get_credentials(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    db.add_credential("key", "svc", "passphrase")

    assert len(db.get_credentials()) == 2

    cred_id = db.get_credentials(cred_type="plaintext")[0].id
    by_id = db.get_credentials(filter_term=cred_id)
    assert len(by_id) == 1
    assert by_id[0].username == "admin"

    by_type = db.get_credentials(cred_type="key")
    assert len(by_type) == 1
    assert by_type[0].username == "svc"

    by_name = db.get_credentials(filter_term="adm")
    assert len(by_name) == 1
    assert by_name[0].username == "admin"


def test_get_credential(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    assert db.get_credential("plaintext", "admin", "Passw0rd!") == cred_id
    # nonexistent returns None
    assert db.get_credential("plaintext", "nope", "nope") is None


def test_is_credential_valid(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    valid_id = db.get_credentials()[0].id
    assert db.is_credential_valid(valid_id) is True
    assert db.is_credential_valid(9999) is False


def test_is_credential_valid_rejects_null_password(db):
    # A non-key (plaintext) credential with a NULL password is not a usable
    # credential and should be rejected. Key-based creds may legitimately have a
    # null password, but a plaintext one with no secret should be invalid.
    db.add_credential("plaintext", "nopw", None)
    cred_id = db.get_credentials()[0].id
    assert db.is_credential_valid(cred_id) is False


def test_remove_single_credential(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    db.remove_credentials([cred_id])
    assert len(db.get_credentials()) == 0


def test_remove_multiple_credentials(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    db.add_credential("plaintext", "user", "Passw0rd!")
    ids = [c.id for c in db.get_credentials()]
    db.remove_credentials(ids)
    assert len(db.get_credentials()) == 0


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------
def test_add_key(db):
    cred_id = db.add_credential("plaintext", "admin", "Passw0rd!")
    key_id = db.add_key(cred_id, "KEY-DATA")
    keys = db.get_keys(cred_id=cred_id)
    assert len(keys) == 1
    assert keys[0].id == key_id
    assert keys[0].data == "KEY-DATA"


def test_add_key_deduplicates(db):
    cred_id = db.add_credential("plaintext", "admin", "Passw0rd!")
    db.add_key(cred_id, "KEY-DATA")
    # a key relation already exists for this cred, so a second add is a no-op
    assert db.add_key(cred_id, "OTHER-DATA") is None
    assert len(db.get_keys(cred_id=cred_id)) == 1


def test_get_keys(db):
    cred1 = db.add_credential("plaintext", "admin", "Passw0rd!")
    cred2 = db.add_credential("plaintext", "user", "Passw0rd!")
    k1 = db.add_key(cred1, "KEY-1")
    db.add_key(cred2, "KEY-2")

    assert len(db.get_keys()) == 2

    by_cred = db.get_keys(cred_id=cred2)
    assert len(by_cred) == 1
    assert by_cred[0].data == "KEY-2"

    by_key = db.get_keys(key_id=k1)
    assert len(by_key) == 1
    assert by_key[0].data == "KEY-1"


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------
def test_is_user_valid(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    assert db.is_user_valid(cred_id) is True
    assert db.is_user_valid(9999) is False


def test_get_users(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    db.add_credential("plaintext", "svc", "Passw0rd!")

    assert len(db.get_users()) == 2

    cred_id = db.get_credentials(filter_term="admin")[0].id
    by_id = db.get_users(filter_term=cred_id)
    assert len(by_id) == 1
    assert by_id[0].username == "admin"

    by_name = db.get_users(filter_term="adm")
    assert len(by_name) == 1
    assert by_name[0].username == "admin"


def test_get_user(db):
    db.add_credential("plaintext", "admin", "Passw0rd!")
    db.add_credential("plaintext", "svc", "Passw0rd!")
    # get_user matches by username (domain arg is ignored for SSH)
    found = db.get_user(None, "admin")
    assert len(found) == 1
    assert found[0].username == "admin"


# ---------------------------------------------------------------------------
# admin relations
# ---------------------------------------------------------------------------
def test_add_admin_user_and_get_relations(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "root", "toor")

    db.add_admin_user("plaintext", "root", "toor", host_id=host_id)
    relations = db.get_admin_relations()
    assert len(relations) == 1
    assert relations[0].credid == cred_id
    assert relations[0].hostid == host_id


def test_add_admin_user_deduplicates(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    db.add_credential("plaintext", "root", "toor")

    db.add_admin_user("plaintext", "root", "toor", host_id=host_id)
    db.add_admin_user("plaintext", "root", "toor", host_id=host_id)
    assert len(db.get_admin_relations()) == 1


def test_get_admin_relations_filters(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "root", "toor")
    db.add_admin_user("plaintext", "root", "toor", host_id=host_id)

    assert len(db.get_admin_relations(cred_id=cred_id)) == 1
    assert len(db.get_admin_relations(host_id=host_id)) == 1
    assert len(db.get_admin_relations(cred_id=9999)) == 0


def test_remove_admin_relation_by_cred(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "root", "toor")
    db.add_admin_user("plaintext", "root", "toor", host_id=host_id)

    db.remove_admin_relation(cred_ids=[cred_id])
    assert len(db.get_admin_relations()) == 0


def test_remove_admin_relation_by_host(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    db.add_credential("plaintext", "root", "toor")
    db.add_admin_user("plaintext", "root", "toor", host_id=host_id)

    db.remove_admin_relation(host_ids=[host_id])
    assert len(db.get_admin_relations()) == 0


# ---------------------------------------------------------------------------
# loggedin relations
# ---------------------------------------------------------------------------
def test_add_loggedin_relation(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "user", "Passw0rd!")

    rel_id = db.add_loggedin_relation(cred_id, host_id, shell=True)
    relations = db.get_loggedin_relations()
    assert len(relations) == 1
    assert relations[0].id == rel_id
    assert relations[0].credid == cred_id
    assert relations[0].hostid == host_id
    assert relations[0].shell is True


def test_add_loggedin_relation_deduplicates(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "user", "Passw0rd!")

    db.add_loggedin_relation(cred_id, host_id)
    db.add_loggedin_relation(cred_id, host_id)
    assert len(db.get_loggedin_relations()) == 1


def test_get_loggedin_relations_filters(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "user", "Passw0rd!")
    db.add_loggedin_relation(cred_id, host_id, shell=True)

    assert len(db.get_loggedin_relations(cred_id=cred_id)) == 1
    assert len(db.get_loggedin_relations(host_id=host_id)) == 1
    assert len(db.get_loggedin_relations(shell=True)) == 1
    assert len(db.get_loggedin_relations(cred_id=9999)) == 0


def test_remove_loggedin_relations_by_cred(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "user", "Passw0rd!")
    db.add_loggedin_relation(cred_id, host_id)

    db.remove_loggedin_relations(cred_id=cred_id)
    assert len(db.get_loggedin_relations()) == 0


def test_remove_loggedin_relations_by_host(db):
    db.add_host("127.0.0.1", 22, "banner", "os")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("plaintext", "user", "Passw0rd!")
    db.add_loggedin_relation(cred_id, host_id)

    db.remove_loggedin_relations(host_id=host_id)
    assert len(db.get_loggedin_relations()) == 0
