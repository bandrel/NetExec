from impacket.ldap import ldaptypes
from impacket.smb3structs import (
    FILE_READ_DATA, FILE_READ_EA, FILE_EXECUTE, FILE_READ_ATTRIBUTES,
    READ_CONTROL, SYNCHRONIZE, GENERIC_READ,
)
from nxc.helpers.ntsecuritydescriptor import decode_file_access_mask, SIDResolver, render_security_descriptor


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


def _make_sid(sid_string):
    sid = ldaptypes.LDAP_SID()
    sid.fromCanonical(sid_string)
    return sid


def _make_allowed_ace(sid_string, mask):
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = mask
    acedata["Sid"] = _make_sid(sid_string)
    ace["Ace"] = acedata
    return ace


def _build_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004  # SE_DACL_PRESENT | SE_SELF_RELATIVE
    sd["OwnerSid"] = _make_sid("S-1-5-32-544")  # Administrators
    sd["GroupSid"] = _make_sid("S-1-5-18")      # Local System
    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 2
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    read_exec = FILE_READ_DATA | FILE_READ_EA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    dacl["Data"] = [
        _make_allowed_ace("S-1-5-18", 0x1F01FF),
        _make_allowed_ace("S-1-5-21-1-2-3-1105", read_exec),
    ]
    sd["Dacl"] = dacl
    return sd


def test_render_owner_group_and_aces():
    sd = _build_sd()
    resolver = SIDResolver(lookup_func=lambda s: "DOMAIN\\jsmith" if s.endswith("1105") else None)
    lines = render_security_descriptor(sd, resolver)
    assert lines[0] == "OWNER: Administrators"
    assert lines[1] == "GROUP: Local System"
    assert any(line.startswith("ALLOWED") and "Local System" in line and "FULL_CONTROL" in line for line in lines)
    assert any(line.startswith("ALLOWED") and "DOMAIN\\jsmith" in line and "READ_DATA" in line for line in lines)
