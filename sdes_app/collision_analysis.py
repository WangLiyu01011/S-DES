"""第五关：分析密文碰撞和主密钥等价类。"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from time import perf_counter
from typing import Callable

from .bruteforce import TOTAL_KEYS, brute_force_keys, parse_block_list
from .core import encrypt_block, generate_subkeys


@dataclass(frozen=True, slots=True)
class PairAnalysis:
    """单个明密文对对应的候选密钥。"""

    plaintext: str
    ciphertext: str
    matching_keys: tuple[str, ...]
    elapsed_seconds: float

    @property
    def candidate_count(self) -> int:
        return len(self.matching_keys)


@dataclass(frozen=True, slots=True)
class CollisionAnalysis:
    """固定明文时，1024 个主密钥到密文的映射统计。"""

    plaintext: str
    ciphertext_to_keys: tuple[tuple[str, tuple[str, ...]], ...]
    multiplicity_histogram: tuple[tuple[int, int], ...]
    elapsed_seconds: float

    @property
    def reachable_ciphertext_count(self) -> int:
        return len(self.ciphertext_to_keys)

    @property
    def unreachable_ciphertext_count(self) -> int:
        return 256 - self.reachable_ciphertext_count

    @property
    def collision_excess_keys(self) -> int:
        return TOTAL_KEYS - self.reachable_ciphertext_count


@dataclass(frozen=True, slots=True)
class KeyEquivalenceAnalysis:
    """按相同子密钥对分组得到的主密钥等价类。"""

    classes: tuple[tuple[str, ...], ...]

    @property
    def class_count(self) -> int:
        return len(self.classes)

    @property
    def class_size_histogram(self) -> tuple[tuple[int, int], ...]:
        return tuple(sorted(Counter(map(len, self.classes)).items()))


def _single_block(value: str, field_name: str) -> str:
    blocks = parse_block_list(value, field_name)
    if len(blocks) != 1:
        raise ValueError(f"{field_name}分析一次只能输入一个 8 bit 分组")
    return blocks[0]


def analyze_known_pair(plaintext: str, ciphertext: str) -> PairAnalysis:
    """分析一个明密文对，并保留全部候选主密钥。"""

    plain = _single_block(plaintext, "明文")
    cipher = _single_block(ciphertext, "密文")
    result = brute_force_keys((plain,), (cipher,))
    return PairAnalysis(plain, cipher, result.matching_keys, result.elapsed_seconds)


def analyze_plaintext_collisions(
    plaintext: str,
    progress_callback: Callable[[int], None] | None = None,
) -> CollisionAnalysis:
    """固定一个明文，统计全部主密钥产生的密文碰撞。"""

    plain = _single_block(plaintext, "明文")
    started_at = perf_counter()
    buckets: defaultdict[str, list[str]] = defaultdict(list)
    for index in range(TOTAL_KEYS):
        key = format(index, "010b")
        buckets[encrypt_block(plain, key)].append(key)
        if progress_callback is not None:
            progress_callback(index + 1)

    ordered_buckets = tuple(
        (ciphertext, tuple(keys)) for ciphertext, keys in sorted(buckets.items())
    )
    histogram = tuple(
        sorted(Counter(len(keys) for _, keys in ordered_buckets).items())
    )
    return CollisionAnalysis(
        plaintext=plain,
        ciphertext_to_keys=ordered_buckets,
        multiplicity_histogram=histogram,
        elapsed_seconds=perf_counter() - started_at,
    )


def analyze_key_equivalence() -> KeyEquivalenceAnalysis:
    """按子密钥对分组，识别对所有明文都等价的主密钥。"""

    groups: defaultdict[tuple[str, str], list[str]] = defaultdict(list)
    for index in range(TOTAL_KEYS):
        key = format(index, "010b")
        groups[generate_subkeys(key)].append(key)

    classes = tuple(sorted(tuple(keys) for keys in groups.values()))
    return KeyEquivalenceAnalysis(classes)
