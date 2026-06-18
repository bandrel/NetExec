"""Unit tests for the FTP protocol database layer.

Mirrors the LDAP/SMB database test suites for cross-protocol parity. Tests assert
the *intended* behavior; where the current source is buggy, the assertion is
marked xfail with a reason so the bug is documented and the test goes green once
fixed.

FTP's credential model is simpler than LDAP's: add_credential(username, password)
has no credtype/domain and uses a CredentialsTable with just (id, username,
password).
"""
import pytest


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("ftp")
    yield dbo
    dbo.clear_database()


# ---------------------------------------------------------------------------
# hosts
# ---------------------------------------------------------------------------
def test_add_host(db):
    db.add_host("127.0.0.1", 21, "220 FTP Server ready")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    host = hosts[0]
    assert host.host == "127.0.0.1"
    assert host.port == 21
    assert host.banner == "220 FTP Server ready"


def test_update_host(db):
    db.add_host("127.0.0.1", 21, "220 Old banner")
    db.add_host("127.0.0.1", 2121, "220 New banner")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    assert hosts[0].port == 2121
    assert hosts[0].banner == "220 New banner"


def test_is_host_valid(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    host_id = db.get_hosts()[0].id
    assert db.is_host_valid(host_id) is True
    assert db.is_host_valid(9999) is False


def test_get_hosts(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    db.add_host("127.0.0.2", 21, "220 other")

    assert len(db.get_hosts()) == 2

    # by valid id (single-element list)
    host_id = db.get_hosts()[0].id
    by_id = db.get_hosts(filter_term=host_id)
    assert len(by_id) == 1
    assert by_id[0].id == host_id

    # by ip
    by_host = db.get_hosts(filter_term="127.0.0.2")
    assert len(by_host) == 1
    assert by_host[0].host == "127.0.0.2"


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------
def test_add_credential(db):
    db.add_credential("admin", "Passw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1
    cred = creds[0]
    assert cred.username == "admin"
    assert cred.password == "Passw0rd!"


def test_add_credential_no_duplicate(db):
    # same username/password should not produce a duplicate row
    db.add_credential("admin", "Passw0rd!")
    db.add_credential("admin", "Passw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1


def test_add_credential_returns_id(db):
    cred_id = db.add_credential("admin", "Passw0rd!")
    assert cred_id == db.get_credentials()[0].id


def test_get_credential(db):
    db.add_credential("admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    assert db.get_credential("admin", "Passw0rd!") == cred_id
    # nonexistent credential returns None
    assert db.get_credential("nobody", "nope") is None


def test_get_credentials(db):
    db.add_credential("admin", "Passw0rd!")
    db.add_credential("svc", "Secret123")

    assert len(db.get_credentials()) == 2

    # by valid id
    cred_id = db.get_credential("admin", "Passw0rd!")
    by_id = db.get_credentials(filter_term=cred_id)
    assert len(by_id) == 1
    assert by_id[0].username == "admin"

    # by username substring
    by_name = db.get_credentials(filter_term="adm")
    assert len(by_name) == 1
    assert by_name[0].username == "admin"


def test_is_credential_valid(db):
    db.add_credential("admin", "Passw0rd!")
    valid_id = db.get_credentials()[0].id
    assert db.is_credential_valid(valid_id) is True
    assert db.is_credential_valid(9999) is False


def test_is_credential_valid_rejects_null_password(db):
    db.add_credential("nopw", None)
    cred_id = db.get_credentials()[0].id
    assert db.is_credential_valid(cred_id) is False


def test_remove_single_credential(db):
    db.add_credential("admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    db.remove_credentials([cred_id])
    assert len(db.get_credentials()) == 0


def test_remove_multiple_credentials(db):
    db.add_credential("admin", "Passw0rd!")
    db.add_credential("user", "Passw0rd!")
    ids = [c.id for c in db.get_credentials()]
    db.remove_credentials(ids)
    assert len(db.get_credentials()) == 0


# ---------------------------------------------------------------------------
# users (alias view over the credentials table)
# ---------------------------------------------------------------------------
def test_is_user_valid(db):
    db.add_credential("admin", "Passw0rd!")
    cred_id = db.get_credentials()[0].id
    assert db.is_user_valid(cred_id) is True
    assert db.is_user_valid(9999) is False


def test_get_user(db):
    db.add_credential("admin", "Passw0rd!")
    db.add_credential("svc", "Secret123")
    # get_user matches on exact (case-insensitive) username
    users = db.get_user("ADMIN")
    assert len(users) == 1
    assert users[0].username == "admin"
    # nonexistent username returns empty
    assert db.get_user("nobody") == []


def test_get_users(db):
    db.add_credential("admin", "Passw0rd!")
    db.add_credential("svc", "Secret123")

    assert len(db.get_users()) == 2

    # by valid id
    cred_id = db.get_credentials()[0].id
    by_id = db.get_users(filter_term=cred_id)
    assert len(by_id) == 1
    assert by_id[0].id == cred_id

    # by username substring
    by_name = db.get_users(filter_term="adm")
    assert len(by_name) == 1
    assert by_name[0].username == "admin"


# ---------------------------------------------------------------------------
# loggedin relations
# ---------------------------------------------------------------------------
def test_add_loggedin_relation(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("admin", "Passw0rd!")

    rel_id = db.add_loggedin_relation(cred_id, host_id)
    assert rel_id is not None
    rels = db.get_loggedin_relations()
    assert len(rels) == 1
    assert rels[0].credid == cred_id
    assert rels[0].hostid == host_id


def test_add_loggedin_relation_no_duplicate(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("admin", "Passw0rd!")

    db.add_loggedin_relation(cred_id, host_id)
    db.add_loggedin_relation(cred_id, host_id)
    assert len(db.get_loggedin_relations()) == 1


def test_get_loggedin_relations(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    db.add_host("127.0.0.2", 21, "220 other")
    host_ids = [h.id for h in db.get_hosts()]
    cred_id = db.add_credential("admin", "Passw0rd!")

    db.add_loggedin_relation(cred_id, host_ids[0])
    db.add_loggedin_relation(cred_id, host_ids[1])

    assert len(db.get_loggedin_relations()) == 2
    assert len(db.get_loggedin_relations(cred_id=cred_id)) == 2
    assert len(db.get_loggedin_relations(host_id=host_ids[0])) == 1
    by_both = db.get_loggedin_relations(cred_id=cred_id, host_id=host_ids[1])
    assert len(by_both) == 1
    assert by_both[0].hostid == host_ids[1]


def test_remove_loggedin_relations_by_cred(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("admin", "Passw0rd!")
    db.add_loggedin_relation(cred_id, host_id)

    db.remove_loggedin_relations(cred_id=cred_id)
    assert len(db.get_loggedin_relations()) == 0


def test_remove_loggedin_relations_by_host(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("admin", "Passw0rd!")
    db.add_loggedin_relation(cred_id, host_id)

    db.remove_loggedin_relations(host_id=host_id)
    assert len(db.get_loggedin_relations()) == 0


# ---------------------------------------------------------------------------
# directory listings
# ---------------------------------------------------------------------------
def test_add_directory_listing(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("admin", "Passw0rd!")
    lir_id = db.add_loggedin_relation(cred_id, host_id)

    db.add_directory_listing(lir_id, "drwxr-xr-x 2 user group 4096 file.txt")
    listings = db.get_directory_listing()
    assert listings is not None
    assert len(listings) == 1
    assert listings[0].lir_id == lir_id
    assert listings[0].data == "drwxr-xr-x 2 user group 4096 file.txt"


def test_get_directory_listing_empty(db):
    listings = db.get_directory_listing()
    assert listings == []


def test_remove_directory_listing(db):
    db.add_host("127.0.0.1", 21, "220 ready")
    host_id = db.get_hosts()[0].id
    cred_id = db.add_credential("admin", "Passw0rd!")
    lir_id = db.add_loggedin_relation(cred_id, host_id)

    db.add_directory_listing(lir_id, "some data")
    db.remove_directory_listing()
    assert db.get_directory_listing() == []
