import base64

import pytest

from nxc.helpers.powershell import replace_singles, encode_ps_command


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("it's", r"it\"s"),
        ("'quoted'", r"\"quoted\""),
        ("no quotes", "no quotes"),
        ("", ""),
    ],
)
def test_replace_singles(value, expected):
    assert replace_singles(value) == expected


def test_encode_ps_command_roundtrip():
    encoded = encode_ps_command("whoami")
    assert isinstance(encoded, str)
    # Decodes back from base64 + UTF-16LE to the original command
    assert base64.b64decode(encoded).decode("utf-16le") == "whoami"


def test_encode_ps_command_known_value():
    # Stable, deterministic encoding of a known input
    assert encode_ps_command("whoami") == "dwBoAG8AYQBtAGkA"


def test_encode_ps_command_empty():
    assert encode_ps_command("") == ""
