"""Unit tests for the RDP protocol database layer.

Mirrors the other per-protocol database test suites for cross-protocol parity.
RDP is a host-only database (no credentials): it exposes add_host, get_hosts and
is_host_valid. Tests assert the *intended* behavior; where the current source is
buggy, the assertion is marked xfail with a reason so the bug is documented and
the test goes green once fixed.
"""
import pytest


@pytest.fixture
def db(protocol_dbs):
    dbo = protocol_dbs.db("rdp")
    yield dbo
    dbo.clear_database()


def test_add_host(db):
    db.add_host("127.0.0.1", 3389, "DC01", "TEST.DEV", "Windows Server 2022", True)
    hosts = db.get_hosts()
    assert len(hosts) == 1
    host = hosts[0]
    assert host.ip == "127.0.0.1"
    assert host.port == 3389
    assert host.hostname == "DC01"
    assert host.domain == "TEST.DEV"
    assert host.os == "Windows Server 2022"
    assert host.nla is True


def test_update_host(db):
    db.add_host("127.0.0.1", 3389, "DC01", "TEST.DEV", "Windows Server 2022", True)
    db.add_host("127.0.0.1", 3389, "DC01", "TEST.DEV", "Windows Server 2025", False)
    hosts = db.get_hosts()
    assert len(hosts) == 1
    assert hosts[0].os == "Windows Server 2025"
    assert hosts[0].nla is False


def test_is_host_valid(db):
    db.add_host("127.0.0.1", 3389, "DC01", "TEST.DEV", "Windows Server 2022", True)
    host_id = db.get_hosts()[0].id
    assert db.is_host_valid(host_id) is True
    assert db.is_host_valid(9999) is False


def test_get_hosts(db):
    db.add_host("127.0.0.1", 3389, "DC01", "TEST.DEV", "Windows Server 2022", True)
    db.add_host("127.0.0.2", 3389, "WS01", "OTHER.DEV", "Windows 11", False)

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

    by_ip = db.get_hosts(filter_term="127.0.0.1")
    assert len(by_ip) == 1
    assert by_ip[0].hostname == "DC01"


def test_get_hosts_nla_filter(db):
    # the "nla" filter term returns hosts where nla is disabled (the misconfiguration)
    db.add_host("127.0.0.1", 3389, "DC01", "TEST.DEV", "Windows Server 2022", True)
    db.add_host("127.0.0.2", 3389, "WS01", "OTHER.DEV", "Windows 11", False)

    by_nla = db.get_hosts(filter_term="nla")
    assert len(by_nla) == 1
    assert by_nla[0].hostname == "WS01"
    assert by_nla[0].nla is False
