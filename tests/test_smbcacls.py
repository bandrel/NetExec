from impacket.smb3structs import (
    FILE_READ_DATA, FILE_READ_EA, FILE_EXECUTE, FILE_READ_ATTRIBUTES,
    READ_CONTROL, SYNCHRONIZE, GENERIC_READ,
)
from nxc.helpers.ntsecuritydescriptor import decode_file_access_mask, SIDResolver


def test_decode_full_control():
    assert decode_file_access_mask(0x1F01FF) == ["FULL_CONTROL"]


def test_decode_read_and_execute():
    mask = FILE_READ_DATA | FILE_READ_EA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    assert decode_file_access_mask(mask) == [
        "READ_DATA", "READ_EA", "EXECUTE", "READ_ATTRIBUTES", "READ_CONTROL", "SYNCHRONIZE",
    ]


def test_decode_generic_read():
    assert decode_file_access_mask(GENERIC_READ) == ["GENERIC_READ"]


def test_decode_unknown_bits_returns_empty():
    assert decode_file_access_mask(0) == []


def test_resolver_well_known_sid():
    r = SIDResolver(lookup_func=None)
    assert r.resolve("S-1-5-18") == "Local System"


def test_resolver_uses_lookup_and_caches():
    calls = []

    def fake_lookup(sid):
        calls.append(sid)
        return "DOMAIN\\jsmith"

    r = SIDResolver(lookup_func=fake_lookup)
    assert r.resolve("S-1-5-21-1-2-3-1105") == "DOMAIN\\jsmith"
    assert r.resolve("S-1-5-21-1-2-3-1105") == "DOMAIN\\jsmith"
    assert calls == ["S-1-5-21-1-2-3-1105"]  # cached, looked up once


def test_resolver_falls_back_to_raw_sid_on_error():
    def boom(sid):
        raise RuntimeError("lsa down")

    r = SIDResolver(lookup_func=boom)
    sid = "S-1-5-21-9-9-9-1000"
    assert r.resolve(sid) == sid
    assert r.resolve("S-1-5-21-9-9-9-1001") == "S-1-5-21-9-9-9-1001"


def test_resolver_no_lookup_returns_raw_sid():
    r = SIDResolver(lookup_func=None)
    assert r.resolve("S-1-5-21-9-9-9-1000") == "S-1-5-21-9-9-9-1000"
