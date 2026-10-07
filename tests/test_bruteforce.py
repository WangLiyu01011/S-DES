"""第四关暴力破解测试。"""

import pytest

from sdes_app.bruteforce import brute_force_keys, parse_block_list
from sdes_app.core import encrypt_block


KEY = "1010000010"


def test_bruteforce_finds_known_key() -> None:
    plaintext = ("10111001", "00000000")
    ciphertext = tuple(encrypt_block(block, KEY) for block in plaintext)

    result = brute_force_keys(plaintext, ciphertext)

    assert result.checked_count == 1024
    assert KEY in result.matching_keys
    assert result.elapsed_seconds >= 0


def test_parse_block_list_accepts_common_separators() -> None:
    assert parse_block_list("10111001, 00000000\n11111111", "明文") == (
        "10111001",
        "00000000",
        "11111111",
    )


@pytest.mark.parametrize("value", ["", "101", "10111002"])
def test_parse_block_list_rejects_invalid_blocks(value: str) -> None:
    with pytest.raises(ValueError):
        parse_block_list(value, "明文")


def test_bruteforce_requires_equal_pair_counts() -> None:
    with pytest.raises(ValueError, match="数量"):
        brute_force_keys(("10111001",), ("00000110", "00000000"))
