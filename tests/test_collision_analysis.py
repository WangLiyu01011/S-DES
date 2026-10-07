"""第五关封闭测试与碰撞分析测试。"""

from sdes_app.collision_analysis import (
    analyze_key_equivalence,
    analyze_known_pair,
    analyze_plaintext_collisions,
)


def test_known_pair_reports_all_candidates() -> None:
    result = analyze_known_pair("10111001", "00000110")

    assert result.candidate_count == 8
    assert "1010000010" in result.matching_keys
    assert result.elapsed_seconds >= 0


def test_plaintext_collision_histogram_matches_current_parameters() -> None:
    result = analyze_plaintext_collisions("10111001")

    assert result.reachable_ciphertext_count == 240
    assert result.unreachable_ciphertext_count == 16
    assert result.collision_excess_keys == 784
    assert result.multiplicity_histogram == (
        (1, 16),
        (2, 53),
        (3, 25),
        (4, 63),
        (5, 7),
        (6, 40),
        (7, 7),
        (8, 16),
        (9, 9),
        (10, 3),
        (12, 1),
    )


def test_key_equivalence_classes_are_unique() -> None:
    result = analyze_key_equivalence()

    assert result.class_count == 1024
    assert result.class_size_histogram == ((1, 1024),)
    assert ("1010000010",) in result.classes
