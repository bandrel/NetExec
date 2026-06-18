import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from nxc.database import delete_workspace, create_workspace
from nxc.first_run import first_run_setup
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.logger import NXCAdapter
from nxc.paths import WORKSPACE_DIR
from sqlalchemy.dialects.sqlite import Insert


@pytest.fixture(scope="session")
def db_engine():
    db_path = os.path.join(WORKSPACE_DIR, "test/smb.db")
    db_engine = create_engine(f"sqlite:///{db_path}", isolation_level="AUTOCOMMIT", future=True)
    yield db_engine
    db_engine.dispose()


@pytest.fixture(scope="session")
def db_setup(db_engine):
    proto = "smb"
    logger = NXCAdapter()
    first_run_setup(logger)
    p_loader = ProtocolLoader()
    create_workspace("test", p_loader)

    protocol_db_path = p_loader.get_protocols()[proto]["dbpath"]
    protocol_db_object = p_loader.load_protocol(protocol_db_path).database

    database_obj = protocol_db_object(db_engine)
    database_obj.reflect_tables()
    yield database_obj
    database_obj.shutdown_db()
    delete_workspace("test")


@pytest.fixture
def db(db_setup):
    yield db_setup
    db_setup.clear_database()


@pytest.fixture(scope="session")
def sess(db_engine):
    session_factory = sessionmaker(bind=db_engine, expire_on_commit=True)
    Session = scoped_session(session_factory)
    sess = Session()
    yield sess
    sess.close()


def test_add_host(db):
    db.add_host(
        "127.0.0.1",
        "localhost",
        "TEST.DEV",
        "Windows Testing 2023",
        False,
        True,
        True,
        True,
        False,
        False,
    )
    inserted_host = db.get_hosts()
    assert len(inserted_host) == 1
    host = inserted_host[0]
    assert host.id == 1
    assert host.ip == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.os == "Windows Testing 2023"
    assert host.smbv1 is False
    assert host.signing is True
    assert host.spooler is True
    assert host.zerologon is True
    assert host.petitpotam is False
    assert host.dc is False


def test_update_host(db, sess):
    host = {
        "ip": "127.0.0.1",
        "hostname": "localhost",
        "domain": "TEST.DEV",
        "os": "Windows Testing 2023",
        "smbv1": True,
        "signing": False,
        "spooler": True,
        "zerologon": False,
        "petitpotam": False,
        "dc": False,
    }
    iq = Insert(db.HostsTable)
    sess.execute(iq, [host])
    db.add_host(
        "127.0.0.1",
        "localhost",
        "TEST.DEV",
        "Windows Testing 2023 Updated",
        False,
        True,
        False,
        False,
        False,
        False,
    )
    inserted_host = db.get_hosts()
    assert len(inserted_host) == 1
    host = inserted_host[0]
    assert host.id == 1
    assert host.ip == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.os == "Windows Testing 2023 Updated"
    assert host.smbv1 is False
    assert host.signing is True
    assert host.spooler is False
    assert host.zerologon is False
    assert host.petitpotam is False
    assert host.dc is False


def test_add_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1
    cred = creds[0]
    assert cred.credtype == "plaintext"
    assert cred.domain == "TEST.DEV"
    assert cred.username == "admin"
    assert cred.password == "Passw0rd!"

    # adding the same cred (same domain/username/credtype) updates instead of duplicating
    db.add_credential("plaintext", "TEST.DEV", "admin", "NewPassw0rd!")
    creds = db.get_credentials()
    assert len(creds) == 1
    assert creds[0].password == "NewPassw0rd!"

    # invalid group_id/pillaged_from causes the add to be skipped
    db.add_credential("plaintext", "TEST.DEV", "skipme", "secret", group_id=9999)
    assert len(db.get_credentials()) == 1


def test_update_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_host("127.0.0.1", "localhost", "TEST.DEV", "Windows Testing 2023", False, True)
    host_id = db.get_hosts()[0].id

    # updating with a valid pillaged_from host
    db.add_credential("plaintext", "TEST.DEV", "admin", "Updated!", pillaged_from=host_id)
    creds = db.get_credentials()
    assert len(creds) == 1
    assert creds[0].password == "Updated!"
    assert creds[0].pillaged_from_hostid == host_id


def test_remove_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_credential("plaintext", "TEST.DEV", "user", "Passw0rd!")
    cred_id = db.get_user("TEST.DEV", "admin")[0].id

    db.remove_credentials([cred_id])
    creds = db.get_credentials()
    assert len(creds) == 1
    assert creds[0].username == "user"


def test_add_admin_user(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_host("127.0.0.1", "localhost", "TEST.DEV", "Windows Testing 2023", False, True)
    host_id = db.get_hosts()[0].id

    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", host_id)
    relations = db.get_admin_relations()
    assert len(relations) == 1
    assert relations[0].hostid == host_id

    # adding the same admin relation again does not duplicate
    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", host_id)
    assert len(db.get_admin_relations()) == 1


def test_get_admin_relations(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_host("127.0.0.1", "localhost", "TEST.DEV", "Windows Testing 2023", False, True)
    host_id = db.get_hosts()[0].id
    user_id = db.get_credentials()[0].id

    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", host_id)

    assert len(db.get_admin_relations()) == 1
    assert len(db.get_admin_relations(user_id=user_id)) == 1
    assert len(db.get_admin_relations(host_id=host_id)) == 1
    assert len(db.get_admin_relations(user_id=9999)) == 0
    assert len(db.get_admin_relations(host_id=9999)) == 0


def test_remove_admin_relation(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_host("127.0.0.1", "localhost", "TEST.DEV", "Windows Testing 2023", False, True)
    host_id = db.get_hosts()[0].id
    user_id = db.get_credentials()[0].id

    db.add_admin_user("plaintext", "TEST.DEV", "admin", "Passw0rd!", host_id)
    assert len(db.get_admin_relations()) == 1

    db.remove_admin_relation(user_ids=[user_id])
    assert len(db.get_admin_relations()) == 0


def test_is_credential_valid(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    valid_id = db.get_credentials()[0].id
    assert db.is_credential_valid(valid_id) is True
    assert db.is_credential_valid(9999) is False

    # a credential with a NULL password must NOT be considered valid
    db.add_credential("plaintext", "TEST.DEV", "nopw", None)
    nopw_id = db.get_user("TEST.DEV", "nopw")[0].id
    assert db.is_credential_valid(nopw_id) is False


def test_get_credentials(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_credential("hash", "TEST.DEV", "svc", "aad3b...")

    # all credentials
    assert len(db.get_credentials()) == 2

    # by valid id
    cred_id = db.get_user("TEST.DEV", "admin")[0].id
    by_id = db.get_credentials(filter_term=cred_id)
    assert len(by_id) == 1
    assert by_id[0].username == "admin"

    # by cred_type
    by_type = db.get_credentials(cred_type="hash")
    assert len(by_type) == 1
    assert by_type[0].username == "svc"

    # by username substring
    by_name = db.get_credentials(filter_term="adm")
    assert len(by_name) == 1
    assert by_name[0].username == "admin"


def test_get_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    cred_id = db.get_user("TEST.DEV", "admin")[0].id
    assert db.get_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!") == cred_id


def test_is_credential_local(db):
    # a local account's "domain" is the machine name, so it matches a host hostname
    db.add_host("127.0.0.1", "WS01", "TEST.DEV", "Windows 11", False, True)
    db.add_credential("plaintext", "WS01", "localadmin", "Passw0rd!")
    db.add_credential("plaintext", "TEST.DEV", "domainadmin", "Passw0rd!")

    local_id = db.get_user("WS01", "localadmin")[0].id
    domain_id = db.get_user("TEST.DEV", "domainadmin")[0].id

    assert db.is_credential_local(local_id) is True
    assert db.is_credential_local(domain_id) is False

    # for a nonexistent credential there is no domain row, so it returns None
    assert db.is_credential_local(9999) is None


def test_is_host_valid(db):
    db.add_host("127.0.0.1", "localhost", "TEST.DEV", "Windows Testing 2023", False, True)
    host_id = db.get_hosts()[0].id
    assert db.is_host_valid(host_id) is True
    assert db.is_host_valid(9999) is False


def test_get_hosts(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", False, True, dc=True)
    db.add_host("127.0.0.2", "WS01", "OTHER.DEV", "Windows 11", False, False)

    # all hosts
    assert len(db.get_hosts()) == 2

    # by valid id (returns single-element list)
    host_id = db.get_hosts(filter_term="DC01")[0].id
    by_id = db.get_hosts(filter_term=host_id)
    assert len(by_id) == 1
    assert by_id[0].hostname == "DC01"

    # by signing (disabled)
    signing = db.get_hosts(filter_term="signing")
    assert len(signing) == 1
    assert signing[0].hostname == "WS01"

    # by domain filter term
    by_domain = db.get_hosts(filter_term="domain TEST")
    assert len(by_domain) == 1
    assert by_domain[0].hostname == "DC01"

    # by ip/hostname
    by_host = db.get_hosts(filter_term="WS01")
    assert len(by_host) == 1
    assert by_host[0].hostname == "WS01"


def test_is_group_valid(db):
    group_id = db.add_group("TEST.DEV", "Domain Admins")[0]
    assert db.is_group_valid(group_id) is True
    assert db.is_group_valid(9999) is False


def test_add_group(db):
    ids = db.add_group("TEST.DEV", "Domain Admins")
    assert len(ids) == 1
    group = db.get_groups(group_name="Domain Admins", group_domain="TEST.DEV")
    assert len(group) == 1
    assert group[0].name == "Domain Admins"

    # adding the same group again does not duplicate it
    db.add_group("TEST.DEV", "Domain Admins", rid="512")
    groups = db.get_groups(group_name="Domain Admins", group_domain="TEST.DEV")
    assert len(groups) == 1
    assert groups[0].rid == "512"


def test_get_groups(db):
    gid = db.add_group("TEST.DEV", "Domain Admins")[0]
    db.add_group("TEST.DEV", "Enterprise Admins")

    # all groups
    assert len(db.get_groups()) == 2

    # by valid id (single-element list)
    by_id = db.get_groups(filter_term=gid)
    assert len(by_id) == 1
    assert by_id[0].name == "Domain Admins"

    # by name + domain
    by_name_domain = db.get_groups(group_name="Domain Admins", group_domain="TEST.DEV")
    assert len(by_name_domain) == 1

    # by name substring
    by_name = db.get_groups(filter_term="Enterprise")
    assert len(by_name) == 1
    assert by_name[0].name == "Enterprise Admins"


def test_get_group_relations(db):
    gid = db.add_group("TEST.DEV", "Domain Admins")[0]
    # the relation is recorded on the initial insert of the credential
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!", group_id=gid)
    user_id = db.get_credentials()[0].id

    by_group = db.get_group_relations(group_id=gid)
    assert len(by_group) == 1
    assert by_group[0].userid == user_id
    assert by_group[0].groupid == gid

    # adding the same membership again does not duplicate it
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!", group_id=gid)
    assert len(db.get_group_relations(group_id=gid)) == 1

    # lookups by user id (and user id + group id) work
    assert len(db.get_group_relations(user_id=user_id)) == 1
    assert len(db.get_group_relations(user_id=user_id, group_id=gid)) == 1
    assert len(db.get_group_relations(user_id=9999)) == 0


def test_remove_group_relations(db):
    gid = db.add_group("TEST.DEV", "Domain Admins")[0]
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!", group_id=gid)
    user_id = db.get_credentials()[0].id

    assert len(db.get_group_relations(group_id=gid)) == 1
    db.remove_group_relations(user_id=user_id)
    assert len(db.get_group_relations(group_id=gid)) == 0


def test_is_user_valid(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    user_id = db.get_credentials()[0].id
    assert db.is_user_valid(user_id) is True
    assert db.is_user_valid(9999) is False


def test_get_users(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    db.add_credential("plaintext", "TEST.DEV", "svc", "Passw0rd!")

    user_id = db.get_user("TEST.DEV", "admin")[0].id
    by_id = db.get_users(filter_term=user_id)
    assert len(by_id) == 1
    assert by_id[0].username == "admin"

    by_name = db.get_users(filter_term="svc")
    assert len(by_name) == 1
    assert by_name[0].username == "svc"


def test_get_user(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    result = db.get_user("TEST.DEV", "admin")
    assert len(result) == 1
    assert result[0].username == "admin"
    # case-insensitive
    assert len(db.get_user("test.dev", "ADMIN")) == 1
    assert len(db.get_user("TEST.DEV", "nobody")) == 0


def test_set_host_dc(db):
    db.add_host(
        "127.0.0.1",
        "localhost",
        "TEST.DEV",
        "Windows Testing 2023",
        False,
        True,
    )
    host_id = db.get_hosts()[0].id
    assert db.get_hosts()[0].dc is None

    db.set_host_dc(host_id, True)
    assert db.get_hosts()[0].dc is True

    db.set_host_dc(host_id, False)
    assert db.get_hosts()[0].dc is False


def test_get_hosts_dc_filter(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", False, True, dc=True)
    db.add_host("127.0.0.2", "WS01", "TEST.DEV", "Windows 11", False, True, dc=False)
    db.add_host("127.0.0.3", "WS02", "TEST.DEV", "Windows 11", False, True)  # dc left as None

    dcs = db.get_hosts(filter_term="dc")
    assert len(dcs) == 1
    assert dcs[0].hostname == "DC01"
    assert dcs[0].dc is True


def test_get_domain_controllers(db):
    db.add_host("127.0.0.1", "DC01", "TEST.DEV", "Windows Server 2022", False, True, dc=True)
    db.add_host("127.0.0.2", "DC02", "OTHER.DEV", "Windows Server 2022", False, True, dc=True)
    db.add_host("127.0.0.3", "WS01", "TEST.DEV", "Windows 11", False, True, dc=False)

    all_dcs = db.get_domain_controllers()
    assert len(all_dcs) == 2

    test_dev_dcs = db.get_domain_controllers(domain="TEST.DEV")
    assert len(test_dev_dcs) == 1
    assert test_dev_dcs[0].hostname == "DC01"


def _setup_host_and_user(db):
    db.add_host("127.0.0.1", "localhost", "TEST.DEV", "Windows Testing 2023", False, True)
    db.add_credential("plaintext", "TEST.DEV", "admin", "Passw0rd!")
    host_id = db.get_hosts()[0].id
    user_id = db.get_credentials()[0].id
    return host_id, user_id


def test_is_share_valid(db):
    host_id, user_id = _setup_host_and_user(db)
    db.add_share(host_id, user_id, "C$", "Default share", True, False)
    share_id = db.get_shares()[0].id
    assert db.is_share_valid(share_id) is True
    assert db.is_share_valid(9999) is False


def test_add_share(db):
    host_id, user_id = _setup_host_and_user(db)
    db.add_share(host_id, user_id, "C$", "Default share", True, False)
    shares = db.get_shares()
    assert len(shares) == 1
    share = shares[0]
    assert share.name == "C$"
    assert share.remark == "Default share"
    assert share.read is True
    assert share.write is False

    # adding the same share (same host/user/name) does nothing
    db.add_share(host_id, user_id, "C$", "Default share", True, True)
    assert len(db.get_shares()) == 1


def test_get_shares(db):
    host_id, user_id = _setup_host_and_user(db)
    db.add_share(host_id, user_id, "C$", "Default share", True, False)
    db.add_share(host_id, user_id, "ADMIN$", "Admin share", True, True)

    # all shares
    assert len(db.get_shares()) == 2

    # by valid id
    share_id = db.get_shares()[0].id
    by_id = db.get_shares(filter_term=share_id)
    assert len(by_id) == 1

    # by name substring
    by_name = db.get_shares(filter_term="ADMIN")
    assert len(by_name) == 1
    assert by_name[0].name == "ADMIN$"


def test_get_shares_by_access(db):
    host_id, user_id = _setup_host_and_user(db)
    db.add_share(host_id, user_id, "C$", "Read only", True, False)
    db.add_share(host_id, user_id, "ADMIN$", "Read write", True, True)

    readable = db.get_shares_by_access("r")
    assert len(readable) == 2

    writable = db.get_shares_by_access("rw")
    assert len(writable) == 1
    assert writable[0].name == "ADMIN$"


def test_get_users_with_share_access(db):
    host_id, user_id = _setup_host_and_user(db)
    db.add_share(host_id, user_id, "ADMIN$", "Read write", True, True)

    readers = db.get_users_with_share_access(host_id, "ADMIN$", "r")
    assert len(readers) == 1
    assert readers[0].userid == user_id

    writers = db.get_users_with_share_access(host_id, "ADMIN$", "rw")
    assert len(writers) == 1

    none = db.get_users_with_share_access(host_id, "NOPE", "r")
    assert len(none) == 0


def test_add_domain_backupkey(db):
    db.add_domain_backupkey("test.dev", b"backupkeybytes")
    results = db.get_domain_backupkey("test.dev")
    assert len(results) == 1
    assert results[0][1] == "test.dev"
    assert results[0][2] == b"backupkeybytes"

    # adding again for the same domain does not duplicate
    db.add_domain_backupkey("test.dev", b"otherbytes")
    assert len(db.get_domain_backupkey("test.dev")) == 1


def test_get_domain_backupkey(db):
    db.add_domain_backupkey("test.dev", b"keyone")
    db.add_domain_backupkey("other.dev", b"keytwo")

    # all keys
    assert len(db.get_domain_backupkey()) == 2

    # by domain (case-insensitive), with pvk decoded back to bytes
    one = db.get_domain_backupkey("TEST.DEV")
    assert len(one) == 1
    assert one[0][2] == b"keyone"

    # nonexistent domain returns empty
    assert db.get_domain_backupkey("nope.dev") == []


def test_is_dpapi_secret_valid(db):
    db.add_dpapi_secrets("127.0.0.1", "CREDENTIAL", "winuser", "user", "pass", "http://url")
    secret_id = db.get_dpapi_secrets()[0].id
    assert db.is_dpapi_secret_valid(secret_id) is True
    assert db.is_dpapi_secret_valid(9999) is False


def test_add_dpapi_secrets(db):
    db.add_dpapi_secrets("127.0.0.1", "CREDENTIAL", "winuser", "user", "pass", "http://url")
    secrets = db.get_dpapi_secrets()
    assert len(secrets) == 1
    secret = secrets[0]
    assert secret.host == "127.0.0.1"
    assert secret.dpapi_type == "CREDENTIAL"
    assert secret.windows_user == "winuser"
    assert secret.username == "user"
    assert secret.password == "pass"
    assert secret.url == "http://url"

    # adding the same secret does not duplicate
    db.add_dpapi_secrets("127.0.0.1", "CREDENTIAL", "winuser", "user", "pass", "http://url")
    assert len(db.get_dpapi_secrets()) == 1


def test_get_dpapi_secrets(db):
    db.add_dpapi_secrets("127.0.0.1", "CREDENTIAL", "winuser", "user", "pass", "http://url")
    db.add_dpapi_secrets("127.0.0.2", "CHROME", "winuser2", "user2", "pass2", "http://url2")

    # all secrets
    assert len(db.get_dpapi_secrets()) == 2

    # filtering by a valid id returns the single matching secret
    secret_id = db.get_dpapi_secrets()[0].id
    by_id = db.get_dpapi_secrets(filter_term=secret_id)
    assert len(by_id) == 1
    assert by_id[0].id == secret_id

    # by host (single-element list)
    by_host = db.get_dpapi_secrets(host="127.0.0.2")
    assert len(by_host) == 1
    assert by_host[0].host == "127.0.0.2"

    # by dpapi_type
    by_type = db.get_dpapi_secrets(dpapi_type="CHROME")
    assert len(by_type) == 1
    assert by_type[0].dpapi_type == "CHROME"

    # by windows_user substring
    by_winuser = db.get_dpapi_secrets(windows_user="winuser2")
    assert len(by_winuser) == 1
    assert by_winuser[0].windows_user == "winuser2"


def test_add_loggedin_relation(db):
    host_id, user_id = _setup_host_and_user(db)
    relation_id = db.add_loggedin_relation(user_id, host_id)
    assert relation_id is not None

    relations = db.get_loggedin_relations()
    assert len(relations) == 1
    assert relations[0].userid == user_id
    assert relations[0].hostid == host_id

    # adding the same relation again does not duplicate (returns None)
    assert db.add_loggedin_relation(user_id, host_id) is None
    assert len(db.get_loggedin_relations()) == 1


def test_get_loggedin_relations(db):
    host_id, user_id = _setup_host_and_user(db)
    db.add_loggedin_relation(user_id, host_id)

    assert len(db.get_loggedin_relations()) == 1
    assert len(db.get_loggedin_relations(user_id=user_id)) == 1
    assert len(db.get_loggedin_relations(host_id=host_id)) == 1
    assert len(db.get_loggedin_relations(user_id=user_id, host_id=host_id)) == 1
    assert len(db.get_loggedin_relations(user_id=9999)) == 0


def test_remove_loggedin_relations(db):
    host_id, user_id = _setup_host_and_user(db)
    db.add_loggedin_relation(user_id, host_id)
    assert len(db.get_loggedin_relations()) == 1

    db.remove_loggedin_relations(user_id=user_id)
    assert len(db.get_loggedin_relations()) == 0
