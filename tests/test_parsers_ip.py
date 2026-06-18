import pytest

from nxc.parsers.ip import parse_targets


def test_single_ip():
    assert list(parse_targets("10.0.0.5")) == ["10.0.0.5"]


def test_cidr_expansion():
    assert list(parse_targets("10.0.0.0/30")) == [
        "10.0.0.0",
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]


def test_full_ip_range():
    assert list(parse_targets("192.168.1.1-192.168.1.3")) == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]


def test_short_octet_range():
    # End of range given as just the last octet
    assert list(parse_targets("192.168.1.1-3")) == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]


@pytest.mark.parametrize("hostname", ["example.com", "dc01", "not-an-ip"])
def test_hostname_passthrough(hostname):
    # Non-IP/non-range input is yielded verbatim
    assert list(parse_targets(hostname)) == [hostname]


def test_single_host_cidr_32():
    assert list(parse_targets("192.168.1.50/32")) == ["192.168.1.50"]


def test_ipv6_link_local_passthrough():
    target = "fe80::1"
    assert list(parse_targets(target)) == [target]
