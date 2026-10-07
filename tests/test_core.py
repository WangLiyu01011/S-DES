"""S-DES 核心算法测试。"""

import pytest

from sdes_app.constants import IP, IP_INVERSE
from sdes_app.core import (
    decrypt_block,
    encrypt_block,
    generate_subkeys,
    permute,
    trace_encrypt_block,
)


def test_assignment_key_schedule() -> None:
    """k2 从 k1 的左右半组继续执行 Shift² 生成。"""

    assert generate_subkeys("1010000010") == ("10100100", "01000011")


def test_known_assignment_variant_vector() -> None:
    assert encrypt_block("10111001", "1010000010") == "00000110"
    assert decrypt_block("00000110", "1010000010") == "10111001"


def test_trace_contains_every_first_gate_stage() -> None:
    trace = trace_encrypt_block("10111001", "1010000010")

    assert trace.after_ip == "00111110"
    assert trace.after_first_fk == "00011110"
    assert trace.after_swap == "11100001"
    assert trace.after_second_fk == "01000001"
    assert trace.output_bits == "00000110"


def test_ip_and_inverse_cancel_for_every_block() -> None:
    for value in range(256):
        bits = format(value, "08b")
        assert permute(permute(bits, IP), IP_INVERSE) == bits


@pytest.mark.parametrize(
    ("data", "key", "message"),
    [
        ("101", "1010000010", "明文必须恰好为 8 bit"),
        ("1011100x", "1010000010", "明文只能包含字符 0 和 1"),
        ("10111001", "1010", "密钥必须恰好为 10 bit"),
        ("10111001", "101000001x", "密钥只能包含字符 0 和 1"),
    ],
)
def test_invalid_input_is_rejected(data: str, key: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        encrypt_block(data, key)


def test_round_trip_for_every_block_with_representative_keys() -> None:
    keys = ("0000000000", "1010000010", "1111111111", "0101010101")
    for key in keys:
        for value in range(256):
            plaintext = format(value, "08b")
            assert decrypt_block(encrypt_block(plaintext, key), key) == plaintext

