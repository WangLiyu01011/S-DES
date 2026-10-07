"""不依赖 GUI 的 S-DES 核心算法。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .constants import (
    EP,
    IP,
    IP_INVERSE,
    LEFT_SHIFT_1,
    LEFT_SHIFT_2,
    P8,
    P10,
    S_BOX_1,
    S_BOX_2,
    SP,
)


@dataclass(frozen=True, slots=True)
class CipherTrace:
    """一次加密或解密的完整 8 bit 运算轨迹。"""

    mode: str
    input_bits: str
    key: str
    k1: str
    k2: str
    first_subkey_name: str
    second_subkey_name: str
    after_ip: str
    after_first_fk: str
    after_swap: str
    after_second_fk: str
    output_bits: str


def _validate_binary(value: str, length: int, field_name: str) -> str:
    """去除首尾空白并校验固定长度的二进制字符串。"""

    if not isinstance(value, str):
        raise TypeError(f"{field_name}必须是字符串")

    normalized = value.strip()
    if len(normalized) != length:
        raise ValueError(f"{field_name}必须恰好为 {length} bit")
    if any(bit not in "01" for bit in normalized):
        raise ValueError(f"{field_name}只能包含字符 0 和 1")
    return normalized


def permute(bits: str, positions: Sequence[int]) -> str:
    """按照从 1 开始的位置表重排字符串。"""

    if not positions:
        return ""
    if min(positions) < 1 or max(positions) > len(bits):
        raise ValueError("置换表包含超出输入范围的位置")
    return "".join(bits[position - 1] for position in positions)


def xor_bits(left: str, right: str) -> str:
    """对两个等长二进制字符串执行按位异或。"""

    if len(left) != len(right):
        raise ValueError("异或运算的两个输入长度必须相同")
    return "".join("0" if a == b else "1" for a, b in zip(left, right))


def generate_subkeys(key: str) -> tuple[str, str]:
    """按标准 S-DES 的连续移位流程生成 k1、k2。

    先对 P10(K) 拆分得到的 C0、D0 执行 LeftShift¹ 生成 k1，
    再以 C1、D1 为输入执行 LeftShift² 生成 k2。
    """

    key = _validate_binary(key, 10, "密钥")
    permuted = permute(key, P10)
    left, right = permuted[:5], permuted[5:]

    left_once = permute(left, LEFT_SHIFT_1)
    right_once = permute(right, LEFT_SHIFT_1)
    left_twice = permute(left_once, LEFT_SHIFT_2)
    right_twice = permute(right_once, LEFT_SHIFT_2)
    return permute(left_once + right_once, P8), permute(left_twice + right_twice, P8)


def _s_box_lookup(bits: str, box: Sequence[Sequence[int]]) -> str:
    """用外侧两位选行、中间两位选列，输出 2 bit。"""

    row = int(bits[0] + bits[3], 2)
    column = int(bits[1:3], 2)
    return format(box[row][column], "02b")


def round_function(right: str, subkey: str) -> str:
    """轮函数 F：EP、异或、S-Boxes、SP。"""

    right = _validate_binary(right, 4, "轮函数右半组")
    subkey = _validate_binary(subkey, 8, "轮密钥")
    mixed = xor_bits(permute(right, EP), subkey)
    substituted = _s_box_lookup(mixed[:4], S_BOX_1) + _s_box_lookup(
        mixed[4:], S_BOX_2
    )
    return permute(substituted, SP)


def fk(block: str, subkey: str) -> str:
    """S-DES 的 fk(L, R) = (L XOR F(R, k), R)。"""

    block = _validate_binary(block, 8, "轮输入")
    left, right = block[:4], block[4:]
    return xor_bits(left, round_function(right, subkey)) + right


def swap_halves(block: str) -> str:
    """交换 8 bit 分组的左右两个 4 bit 半组。"""

    block = _validate_binary(block, 8, "交换输入")
    return block[4:] + block[:4]


def _trace_transform(block: str, key: str, decrypt: bool) -> CipherTrace:
    block_name = "密文" if decrypt else "明文"
    block = _validate_binary(block, 8, block_name)
    key = _validate_binary(key, 10, "密钥")
    k1, k2 = generate_subkeys(key)

    first_key, second_key = (k2, k1) if decrypt else (k1, k2)
    first_name, second_name = ("k2", "k1") if decrypt else ("k1", "k2")

    after_ip = permute(block, IP)
    after_first_fk = fk(after_ip, first_key)
    after_swap = swap_halves(after_first_fk)
    after_second_fk = fk(after_swap, second_key)
    output_bits = permute(after_second_fk, IP_INVERSE)

    return CipherTrace(
        mode="decrypt" if decrypt else "encrypt",
        input_bits=block,
        key=key,
        k1=k1,
        k2=k2,
        first_subkey_name=first_name,
        second_subkey_name=second_name,
        after_ip=after_ip,
        after_first_fk=after_first_fk,
        after_swap=after_swap,
        after_second_fk=after_second_fk,
        output_bits=output_bits,
    )


def trace_encrypt_block(plaintext: str, key: str) -> CipherTrace:
    """加密 8 bit 明文并返回完整轨迹。"""

    return _trace_transform(plaintext, key, decrypt=False)


def trace_decrypt_block(ciphertext: str, key: str) -> CipherTrace:
    """解密 8 bit 密文并返回完整轨迹。"""

    return _trace_transform(ciphertext, key, decrypt=True)


def encrypt_block(plaintext: str, key: str) -> str:
    """加密单个 8 bit 明文分组。"""

    return trace_encrypt_block(plaintext, key).output_bits


def decrypt_block(ciphertext: str, key: str) -> str:
    """解密单个 8 bit 密文分组。"""

    return trace_decrypt_block(ciphertext, key).output_bits

