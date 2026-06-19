from impacket.ldap import ldaptypes
from impacket.smb3structs import (
    FILE_READ_DATA, FILE_READ_EA, FILE_EXECUTE, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE,
)
from nxc.helpers.ntsecuritydescriptor import SIDResolver, security_descriptor_to_dict


def _make_sid(sid_string):
    sid = ldaptypes.LDAP_SID()
    sid.fromCanonical(sid_string)
    return sid


def _make_ace(ace_type, sid_string, mask, flags=0):
    ace = ldaptypes.ACE()
    ace["AceType"] = ace_type
    ace["AceFlags"] = flags
    if ace_type == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    else:
        acedata = ldaptypes.ACCESS_DENIED_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = mask
    acedata["Sid"] = _make_sid(sid_string)
    ace["Ace"] = acedata
    return ace


def _build_sd(with_dacl=True):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = _make_sid("S-1-5-32-544")  # Administrators
    sd["GroupSid"] = _make_sid("S-1-5-18")      # Local System
    if not with_dacl:
        sd["Dacl"] = None
        return sd
    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 2
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    read_exec = FILE_READ_DATA | FILE_READ_EA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    dacl["Data"] = [
        _make_ace(ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, "S-1-5-21-1-2-3-1105", read_exec, flags=ldaptypes.ACE.INHERITED_ACE),
        _make_ace(ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE, "S-1-5-7", FILE_READ_DATA),
    ]
    sd["Dacl"] = dacl
    return sd


def test_to_dict_owner_group_and_aces():
    sd = _build_sd()
    resolver = SIDResolver(lookup_func=lambda s: "DOMAIN\\jsmith" if s.endswith("1105") else None)
    result = security_descriptor_to_dict(sd, resolver)
    assert result["owner"] == "Administrators"
    assert result["group"] == "Local System"
    assert len(result["dacl"]) == 2
    allowed = result["dacl"][0]
    assert allowed["type"] == "ALLOWED"
    assert allowed["trustee"] == "DOMAIN\\jsmith"
    assert "READ_DATA" in allowed["rights"]
    assert allowed["inherited"] is True
    denied = result["dacl"][1]
    assert denied["type"] == "DENIED"
    assert denied["trustee"] == "Anonymous"  # S-1-5-7 well-known
    assert denied["inherited"] is False


def test_to_dict_no_dacl():
    sd = _build_sd(with_dacl=False)
    resolver = SIDResolver(lookup_func=None)
    result = security_descriptor_to_dict(sd, resolver)
    assert result["owner"] == "Administrators"
    assert result["group"] == "Local System"
    assert result["dacl"] == []
