"""第三关：ASCII 文本的逐字节 S-DES 编解码。"""

from __future__ import annotations

from dataclasses import dataclass

from .core import decrypt_block, encrypt_block


@dataclass(frozen=True, slots=True)
class TextEncryptionResult:
    """ASCII 文本加密后的多种安全展示形式。"""

    plaintext: str
    key: str
    plaintext_bytes: bytes
    ciphertext_bytes: bytes

    @property
    def block_count(self) -> int:
        return len(self.plaintext_bytes)

    @property
    def ciphertext_hex(self) -> str:
        return _format_hex(self.ciphertext_bytes)

    @property
    def ciphertext_binary(self) -> str:
        return _format_binary(self.ciphertext_bytes)

    @property
    def escaped_ciphertext(self) -> str:
        return _format_escaped(self.ciphertext_bytes)


@dataclass(frozen=True, slots=True)
class TextDecryptionResult:
    """密文字节解密后的文本和字节视图。"""

    ciphertext_bytes: bytes
    plaintext_bytes: bytes
    plaintext_display: str
    is_ascii: bool

    @property
    def plaintext_hex(self) -> str:
        return _format_hex(self.plaintext_bytes)

    @property
    def plaintext_binary(self) -> str:
        return _format_binary(self.plaintext_bytes)


def _format_hex(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def _format_binary(data: bytes) -> str:
    return " ".join(f"{value:08b}" for value in data)


def _format_escaped(data: bytes) -> str:
    return "".join(f"\\x{value:02X}" for value in data)


def _validate_ascii_text(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("文本必须是字符串")
    if not text:
        raise ValueError("ASCII 文本不能为空")
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("第三关文本模式只接受 ASCII 字符") from error


def _bytes_to_blocks(data: bytes) -> list[str]:
    return [format(value, "08b") for value in data]


def encrypt_ascii_text(text: str, key: str) -> TextEncryptionResult:
    """将 ASCII 文本按 1 Byte 分组逐字节加密。"""

    plaintext_bytes = _validate_ascii_text(text)
    ciphertext = bytes(
        int(encrypt_block(block, key), 2)
        for block in _bytes_to_blocks(plaintext_bytes)
    )
    return TextEncryptionResult(text, key.strip(), plaintext_bytes, ciphertext)


def parse_ciphertext(value: str, representation: str) -> bytes:
    """解析十六进制或 8 bit 分组二进制密文。"""

    if not isinstance(value, str):
        raise TypeError("密文必须是字符串")
    compact = "".join(value.split())
    if not compact:
        raise ValueError("密文不能为空")

    if representation == "hex":
        if len(compact) % 2:
            raise ValueError("十六进制密文必须由完整的两位字节组成")
        if any(character not in "0123456789abcdefABCDEF" for character in compact):
            raise ValueError("十六进制密文只能包含 0-9、A-F")
        return bytes.fromhex(compact)

    if representation == "binary":
        if len(compact) % 8:
            raise ValueError("二进制密文长度必须是 8 bit 的整数倍")
        if any(character not in "01" for character in compact):
            raise ValueError("二进制密文只能包含 0 和 1")
        return bytes(
            int(compact[index : index + 8], 2)
            for index in range(0, len(compact), 8)
        )

    raise ValueError("不支持的密文表示方式")


def _display_bytes_as_text(data: bytes) -> tuple[str, bool]:
    """可读地显示恢复结果，避免控制字符破坏 GUI。"""

    is_ascii = all(value < 128 for value in data)
    parts: list[str] = []
    for value in data:
        if value in (9, 10, 13):
            parts.append(chr(value))
        elif 32 <= value <= 126:
            parts.append(chr(value))
        else:
            parts.append(f"\\x{value:02X}")
    return "".join(parts), is_ascii


def decrypt_ciphertext(
    ciphertext: str, key: str, representation: str = "hex"
) -> TextDecryptionResult:
    """按指定表示方式解析密文并逐字节解密。"""

    ciphertext_bytes = parse_ciphertext(ciphertext, representation)
    plaintext_bytes = bytes(
        int(decrypt_block(block, key), 2)
        for block in _bytes_to_blocks(ciphertext_bytes)
    )
    plaintext_display, is_ascii = _display_bytes_as_text(plaintext_bytes)
    return TextDecryptionResult(
        ciphertext_bytes=ciphertext_bytes,
        plaintext_bytes=plaintext_bytes,
        plaintext_display=plaintext_display,
        is_ascii=is_ascii,
    )

