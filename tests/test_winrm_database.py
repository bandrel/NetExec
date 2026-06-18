"""Unit tests for the WinRM protocol database layer.

Mirrors the SMB/LDAP database test suites for cross-protocol parity. Tests assert
the *intended* behavior; where the current source is buggy, the assertion is
marked xfail with a reason so the bug is documented and the test goes green once
the source is fixed.
"""
import pytest


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("winrm")
    yield dbo
    dbo.clear_database()


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------
def test_add_host(db):
    db.add_host("127.0.0.1", 5985, "DC01", "TEST.DEV", "Windows Server 2022")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    host = hosts[0]
    assert host.ip == "127.0.0.1"
    assert host.port == 5985
    assert host.hostname == "DC01"
    assert host.domain == "TEST.DEV"
    assert host.os == "Windows Server 2022"


def test_add_host_default_os(db):
    db.add_host("127.0.0.2", 5985, "WS01", "TEST.DEV")
    host = db.get_hosts()[0]
    assert host.os is None


def test_update_host(db):
    db.add_host("127.0.0.1", 5985, "DC01", "TEST.DEV", "Windows Server 2022")
    db.add_host("127.0.0.1", 5986, "DC01", "TEST.DEV", "Windows Server 2025")
    hosts = db.get_hosts()
    assert len(hosts) == 1
    assert hosts[0].port == 5986
    assert hosts[0].os == "Windows Server 2025"


def test_is_host_valid(db):
    db.add_host("127.0.0.1", 5985, "DC01", "TEST.DEV", "Windows Server 2022")
    host_id = db.get_hosts()[0].id
    assert db.is_host_valid(host_id) is True
    assert db.is_host_valid(9999) is False


def test_get_hosts(db):
    db.add_host("127.0.0.1", 5985, "DC01", "TEST.DEV", "Windows Server 2022")
    db.add_host("127.0.0.2", 5985, "WS01", "OTHER.DEV", "Windows 11")

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


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
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
    db.add_host("127.0.0.1", 5985, "DC01", "TEST.DEV", "Windows Server 2022")
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
    """get_credential() returns None (not a crash) when no credential matches."""
    assert db.get_credential("plaintext", "TEST.DEV", "nobody", "nope") is None

    # also None when there are credentials but none match the filter
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    assert db.get_credential("plaintext", "TEST.DEV", "admin", "WrongPassword") is None


def test_is_credential_valid(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    valid_id = db.get_credentials()[0].id
    assert db.is_credential_valid(valid_id) is True
    assert db.is_credential_valid(9999) is False


def test_is_credential_valid_rejects_null_password(db):
    db.add_credential("plaintext", "TEST.DEV", "nopw", None)
    cred_id = db.get_credentials()[0].id
    assert db.is_credential_valid(cred_id) is False


def test_is_credential_local_intended(db):
    """A credential whose domain matches a host hostname is 'local'."""
    db.add_host("127.0.0.1", 5985, "DC01", "TEST.DEV", "Windows Server 2022")
    # local credential: domain equals the host's hostname
    db.add_credential("plaintext", "DC01", "admin", "Passw0rd!")
    # domain credential: domain matches no host hostname
    db.add_credential("plaintext", "TEST.DEV", "domainadmin", "Passw0rd!")

    local_id = db.get_credential("plaintext", "DC01", "admin", "Passw0rd!")
    domain_id = db.get_credential("plaintext", "TEST.DEV", "domainadmin", "Passw0rd!")

    assert db.is_credential_local(local_id) is True
    assert db.is_credential_local(domain_id) is False
    assert db.is_credential_local(9999) is None


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


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def test_is_user_valid(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    user_id = db.get_credentials()[0].id
    assert db.is_user_valid(user_id) is True
    assert db.is_user_valid(9999) is False


def test_get_users(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_credential("plaintext", "TEST.DEV", "svc", "Passw0rd!")

    assert len(db.get_users()) == 2

    # by valid id
    user_id = db.get_users()[0].id
    by_id = db.get_users(filter_term=user_id)
    assert len(by_id) == 1
    assert by_id[0].id == user_id

    # by username substring
    by_name = db.get_users(filter_term="adm")
    assert len(by_name) == 1
    assert by_name[0].username == "admin"


def test_get_user(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    users = db.get_user("TEST.DEV", "admin")
    assert len(users) == 1
    assert users[0].username == "admin"

    # case-insensitive
    assert len(db.get_user("test.dev", "ADMIN")) == 1

    # no match
    assert len(db.get_user("TEST.DEV", "nobody")) == 0


# ---------------------------------------------------------------------------
# Admin relations
# ---------------------------------------------------------------------------
def _seed_host_and_cred(db, domain="TEST", username="admin", password="Passw0rd!"):
    # add_admin_user() reduces the supplied domain to its short form via
    # domain.split(".")[0] before matching credentials, so credentials must be
    # stored with the short domain for the relation lookup to find them.
    db.add_host("127.0.0.1", 5985, "DC01", domain, "Windows Server 2022")
    db.add_credential("plaintext", domain, username, password)
    host_id = db.get_hosts()[0].id
    user_id = db.get_credentials()[0].id
    return host_id, user_id


def test_add_admin_user_and_get_relations(db):
    host_id, user_id = _seed_host_and_cred(db)
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")

    relations = db.get_admin_relations()
    assert len(relations) == 1
    assert relations[0].userid == user_id
    assert relations[0].hostid == host_id

    # filter by user / host
    assert len(db.get_admin_relations(user_id=user_id)) == 1
    assert len(db.get_admin_relations(host_id=host_id)) == 1
    assert len(db.get_admin_relations(user_id=9999)) == 0


def test_add_admin_user_links_real_ids(db):
    """The relation must reference the real host/user ids, not positionally zipped ids.

    Seed an extra host first so the matched host's id (2) differs from the
    matched user's id (1). A positional zip() would mispair them; correct nested
    loops link by the actual matched rows.
    """
    # extra host taking id 1, so the credential's user id and target host id diverge
    db.add_host("127.0.0.9", 5985, "OTHER", "TEST", "Windows Server 2022")
    db.add_host("127.0.0.1", 5985, "DC01", "TEST", "Windows Server 2022")
    db.add_credential("plaintext", "TEST", "admin", "Passw0rd!")

    host_id = db.get_hosts(filter_term="DC01")[0].id
    user_id = db.get_credentials()[0].id
    assert host_id != user_id  # guard: ids genuinely differ

    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")

    relations = db.get_admin_relations()
    assert len(relations) == 1
    assert relations[0].hostid == host_id
    assert relations[0].userid == user_id


def test_add_admin_user_mismatched_counts_no_valueerror(db):
    """A single matching user against multiple matching hosts must not raise.

    The legacy implementation used zip(users, hosts, strict=True), which raises
    ValueError whenever the user count and host count differ. Here one user
    matches but two hosts share the "TEST" domain, so a "domain TEST" host
    filter returns two hosts versus one user. The nested-loop implementation
    must link the user to both hosts without raising.
    """
    db.add_host("127.0.0.1", 5985, "DC01", "TEST", "Windows Server 2022")
    db.add_host("127.0.0.2", 5985, "DC02", "TEST", "Windows Server 2022")
    db.add_credential("plaintext", "TEST", "admin", "Passw0rd!")

    user_id = db.get_credentials()[0].id
    host_ids = sorted(h.id for h in db.get_hosts(filter_term="domain TEST"))
    assert len(host_ids) == 2  # guard: two hosts, one user -> count mismatch

    # Must not raise ValueError despite user count (1) != host count (2).
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "domain TEST")

    relations = db.get_admin_relations()
    assert sorted(r.hostid for r in relations) == host_ids
    assert all(r.userid == user_id for r in relations)


def test_add_admin_user_no_duplicate(db):
    _seed_host_and_cred(db)
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")
    assert len(db.get_admin_relations()) == 1


def test_remove_admin_relation(db):
    host_id, user_id = _seed_host_and_cred(db)
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")
    assert len(db.get_admin_relations()) == 1

    db.remove_admin_relation(user_ids=[user_id])
    assert len(db.get_admin_relations()) == 0


def test_remove_admin_relation_by_host(db):
    host_id, user_id = _seed_host_and_cred(db)
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", "127.0.0.1")
    assert len(db.get_admin_relations()) == 1

    db.remove_admin_relation(host_ids=[host_id])
    assert len(db.get_admin_relations()) == 0


# ---------------------------------------------------------------------------
# Logged-in relations
# ---------------------------------------------------------------------------
def test_add_loggedin_relation_and_get(db):
    host_id, user_id = _seed_host_and_cred(db)
    db.add_loggedin_relation(user_id, host_id)

    relations = db.get_loggedin_relations()
    assert len(relations) == 1
    assert relations[0].userid == user_id
    assert relations[0].hostid == host_id

    assert len(db.get_loggedin_relations(user_id=user_id)) == 1
    assert len(db.get_loggedin_relations(host_id=host_id)) == 1
    assert len(db.get_loggedin_relations(user_id=9999)) == 0


def test_add_loggedin_relation_no_duplicate(db):
    host_id, user_id = _seed_host_and_cred(db)
    db.add_loggedin_relation(user_id, host_id)
    db.add_loggedin_relation(user_id, host_id)
    assert len(db.get_loggedin_relations()) == 1


def test_remove_loggedin_relations_by_user(db):
    host_id, user_id = _seed_host_and_cred(db)
    db.add_loggedin_relation(user_id, host_id)
    assert len(db.get_loggedin_relations()) == 1

    db.remove_loggedin_relations(user_id=user_id)
    assert len(db.get_loggedin_relations()) == 0


def test_remove_loggedin_relations_by_host(db):
    host_id, user_id = _seed_host_and_cred(db)
    db.add_loggedin_relation(user_id, host_id)
    assert len(db.get_loggedin_relations()) == 1

    db.remove_loggedin_relations(host_id=host_id)
    assert len(db.get_loggedin_relations()) == 0
