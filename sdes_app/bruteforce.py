"""第四关：已知明文/密文条件下的 S-DES 密钥空间遍历。"""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Callable, Sequence

from .core import encrypt_block


TOTAL_KEYS = 1 << 10


@dataclass(frozen=True, slots=True)
class BruteForceResult:
    """一次完整密钥遍历的结果。"""

    matching_keys: tuple[str, ...]
    checked_count: int
    elapsed_seconds: float


def parse_block_list(value: str, field_name: str) -> tuple[str, ...]:
    """解析一个或多个以空格、逗号或换行分隔的 8 bit 分组。"""

    if not isinstance(value, str):
        raise TypeError(f"{field_name}必须是字符串")

    tokens = value.replace(",", " ").split()
    if not tokens:
        raise ValueError(f"请至少输入一个{field_name}分组")

    blocks: list[str] = []
    for index, token in enumerate(tokens, start=1):
        if len(token) != 8 or any(bit not in "01" for bit in token):
            raise ValueError(f"{field_name}第 {index} 组必须是 8 bit 二进制")
        blocks.append(token)
    return tuple(blocks)


def key_matches_pairs(
    plaintext_blocks: Sequence[str],
    ciphertext_blocks: Sequence[str],
    key: str,
) -> bool:
    """判断一个 10 bit 密钥是否满足全部明文/密文对。"""

    return all(
        encrypt_block(plaintext, key) == ciphertext
        for plaintext, ciphertext in zip(plaintext_blocks, ciphertext_blocks)
    )


def brute_force_keys(
    plaintext_blocks: Sequence[str],
    ciphertext_blocks: Sequence[str],
    progress_callback: Callable[[int], None] | None = None,
) -> BruteForceResult:
    """遍历全部 1024 个 10 bit 密钥并返回所有匹配项。"""

    if not plaintext_blocks or not ciphertext_blocks:
        raise ValueError("明文和密文至少各需要一个分组")
    if len(plaintext_blocks) != len(ciphertext_blocks):
        raise ValueError("明文和密文分组数量必须一致")

    started_at = perf_counter()
    matches: list[str] = []
    for index in range(TOTAL_KEYS):
        key = format(index, "010b")
        if key_matches_pairs(plaintext_blocks, ciphertext_blocks, key):
            matches.append(key)
        if progress_callback is not None:
            progress_callback(index + 1)

    return BruteForceResult(tuple(matches), TOTAL_KEYS, perf_counter() - started_at)
