from impacket.smb3structs import (
    FILE_READ_DATA, FILE_READ_EA, FILE_EXECUTE, FILE_READ_ATTRIBUTES,
    READ_CONTROL, SYNCHRONIZE, GENERIC_READ,
)
from nxc.helpers.ntsecuritydescriptor import decode_file_access_mask


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
