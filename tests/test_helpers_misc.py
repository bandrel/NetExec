import string

import pytest

from nxc.helpers.misc import (
    validate_ntlm,
    gen_random_string,
    detect_if_ip,
    d2b,
    convert,
    parse_argument,
)


@pytest.mark.parametrize(
    "value",
    [
        "aad3b435b51404eeaad3b435b51404ee",  # empty LM hash, valid hex 32
        "31D6CFE0D16AE931B73C59D7E0C089C0",  # uppercase valid
        "0123456789abcdef0123456789abcdef",
        # full LM:NT form
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    ],
)
def test_validate_ntlm_valid(value):
    assert validate_ntlm(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",  # empty
        "g" * 32,  # non-hex chars
        "abc123",  # too short
        "xyz3b435b51404eeaad3b435b51404ee",  # leading non-hex
    ],
)
def test_validate_ntlm_invalid(value):
    assert validate_ntlm(value) is False


def test_validate_ntlm_rejects_trailing_junk():
    # a valid 32-char hex prefix followed by junk must NOT validate
    assert validate_ntlm("0123456789abcdef0123456789abcdef-extra-junk") is False
    assert validate_ntlm("0123456789abcdef0123456789abcdef0") is False  # 33 chars


def test_gen_random_string_default_length():
    s = gen_random_string()
    assert isinstance(s, str)
    assert len(s) == 10
    assert all(c in string.ascii_letters for c in s)


@pytest.mark.parametrize("length", [1, 5, 26, 52])
def test_gen_random_string_custom_length(length):
    s = gen_random_string(length)
    assert len(s) == length
    assert all(c in string.ascii_letters for c in s)


def test_gen_random_string_unique_chars():
    # random.sample yields unique characters (no repeats)
    s = gen_random_string(52)
    assert len(set(s)) == len(s)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.1.1", True),
        ("10.0.0.0", True),
        ("::1", True),
        ("fe80::1", True),
        ("not-an-ip", False),
        ("", False),
        ("256.256.256.256", False),
        ("example.com", False),
    ],
)
def test_detect_if_ip(target, expected):
    assert detect_if_ip(target) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (255, "11111111"),
        (1, "000001"),
        (2, "000010"),
        (0, "000000"),
        (256, "100000000"),
    ],
)
def test_d2b(value, expected):
    # d2b pads small values to 6 bits, which is intentional: its consumers
    # (smb passpol pretty_print / ldap) map exactly 6 PasswordProperties flag
    # bits (values 0-63). Values needing more bits (e.g. 255) are returned at
    # their natural width.
    assert d2b(value) == expected


def test_convert_none():
    assert convert(0, 0) == "None"


def test_convert_not_set():
    assert convert(0, -0x8000_0000) == "Not Set"
    assert convert(0, -0x8000_0000_0000_0000) == "Not Set"


def test_convert_lockout_duration():
    result = convert(0, -600000000, lockout=True)
    assert result == "1 minute "


def test_convert_returns_human_readable():
    result = convert(0, -600000000)
    assert isinstance(result, str)
    assert "days" in result or "hours" in result or "minutes" in result


def test_parse_argument_plain_values():
    assert parse_argument(["admin", "  guest  "]) == ["admin", "guest"]


def test_parse_argument_reads_file(tmp_path):
    f = tmp_path / "users.txt"
    f.write_text("alice\nbob\n\n  carol  \n")
    result = parse_argument([str(f)])
    assert result == ["alice", "bob", "carol"]


def test_parse_argument_mixed(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("fromfile\n")
    result = parse_argument(["literal", str(f)])
    assert result == ["literal", "fromfile"]
