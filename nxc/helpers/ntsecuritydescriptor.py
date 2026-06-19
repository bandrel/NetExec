from impacket.smb3structs import (
    FILE_READ_DATA, FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_READ_EA, FILE_WRITE_EA,
    FILE_EXECUTE, FILE_DELETE_CHILD, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
    DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE,
    GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE,
)

# Standard (0x1F0000) + specific file rights (0x1FF) all set.
FULL_CONTROL = 0x1F01FF

_FILE_RIGHTS = [
    (FILE_READ_DATA, "READ_DATA"),
    (FILE_WRITE_DATA, "WRITE_DATA"),
    (FILE_APPEND_DATA, "APPEND_DATA"),
    (FILE_READ_EA, "READ_EA"),
    (FILE_WRITE_EA, "WRITE_EA"),
    (FILE_EXECUTE, "EXECUTE"),
    (FILE_DELETE_CHILD, "DELETE_CHILD"),
    (FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"),
    (FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"),
    (DELETE, "DELETE"),
    (READ_CONTROL, "READ_CONTROL"),
    (WRITE_DAC, "WRITE_DAC"),
    (WRITE_OWNER, "WRITE_OWNER"),
    (SYNCHRONIZE, "SYNCHRONIZE"),
]

_GENERIC_RIGHTS = [
    (GENERIC_ALL, "GENERIC_ALL"),
    (GENERIC_READ, "GENERIC_READ"),
    (GENERIC_WRITE, "GENERIC_WRITE"),
    (GENERIC_EXECUTE, "GENERIC_EXECUTE"),
]


def decode_file_access_mask(mask):
    """Decode an ACE access mask into a list of file-specific right names.

    Collapses the all-bits-set case to ["FULL_CONTROL"]. Generic bits are
    reported alongside any specific rights. Bits with no known meaning are
    ignored (callers fall back to hex when the result is empty).
    """
    generic = [name for bit, name in _GENERIC_RIGHTS if mask & bit == bit]
    specific_mask = mask & FULL_CONTROL
    if specific_mask == FULL_CONTROL:
        return ["FULL_CONTROL", *generic]
    specific = [name for bit, name in _FILE_RIGHTS if mask & bit == bit]
    return specific + generic
