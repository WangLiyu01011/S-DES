"""第三关 ASCII 文本模式测试。"""

import pytest

from sdes_app.text_cipher import (
    decrypt_ciphertext,
    encrypt_ascii_text,
    parse_ciphertext,
)


KEY = "1010000010"


def test_ascii_text_encrypt_and_decrypt_round_trip() -> None:
    encrypted = encrypt_ascii_text("This is a test", KEY)

    assert encrypted.block_count == 14
    assert encrypted.ciphertext_hex == (
        "22 68 C7 27 62 C7 27 62 BD 62 4E F8 27 4E"
    )
    assert len(encrypted.ciphertext_binary.split()) == 14

    decrypted = decrypt_ciphertext(encrypted.ciphertext_hex, KEY)
    assert decrypted.plaintext_display == "This is a test"
    assert decrypted.is_ascii


def test_binary_ciphertext_can_be_decrypted_with_whitespace() -> None:
    encrypted = encrypt_ascii_text("OK", KEY)
    binary = encrypted.ciphertext_binary.replace(" ", "\n")

    decrypted = decrypt_ciphertext(binary, KEY, "binary")

    assert decrypted.plaintext_display == "OK"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "ASCII 文本不能为空"),
        ("你好", "第三关文本模式只接受 ASCII 字符"),
    ],
)
def test_ascii_text_validation(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        encrypt_ascii_text(text, KEY)


@pytest.mark.parametrize(
    ("value", "representation", "message"),
    [
        ("A", "hex", "完整的两位字节"),
        ("GG", "hex", "只能包含 0-9、A-F"),
        ("0101", "binary", "8 bit 的整数倍"),
        ("0101010X", "binary", "只能包含 0 和 1"),
    ],
)
def test_ciphertext_format_validation(
    value: str, representation: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_ciphertext(value, representation)

