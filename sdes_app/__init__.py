"""S-DES 教学实验程序。"""

from .core import (
    CipherTrace,
    decrypt_block,
    encrypt_block,
    generate_subkeys,
    trace_decrypt_block,
    trace_encrypt_block,
)
from .text_cipher import (
    TextDecryptionResult,
    TextEncryptionResult,
    decrypt_ciphertext,
    encrypt_ascii_text,
    parse_ciphertext,
)
from .bruteforce import BruteForceResult, brute_force_keys, parse_block_list
from .collision_analysis import (
    CollisionAnalysis,
    KeyEquivalenceAnalysis,
    PairAnalysis,
    analyze_key_equivalence,
    analyze_known_pair,
    analyze_plaintext_collisions,
)

__all__ = [
    "CipherTrace",
    "decrypt_block",
    "encrypt_block",
    "generate_subkeys",
    "trace_decrypt_block",
    "trace_encrypt_block",
    "TextDecryptionResult",
    "TextEncryptionResult",
    "decrypt_ciphertext",
    "encrypt_ascii_text",
    "parse_ciphertext",
    "BruteForceResult",
    "brute_force_keys",
    "parse_block_list",
    "CollisionAnalysis",
    "KeyEquivalenceAnalysis",
    "PairAnalysis",
    "analyze_key_equivalence",
    "analyze_known_pair",
    "analyze_plaintext_collisions",
]

