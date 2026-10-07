"""不打开可见窗口的 GUI 冒烟测试。"""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from sdes_app.gui import SDesWindow, create_application


def test_gui_encrypt_and_decrypt_workflow() -> None:
    app = create_application([])
    window = SDesWindow()

    window.data_input.setText("10111001")
    window.key_input.setText("1010000010")
    window.encrypt_button.click()

    assert window.output_caption.text() == "密文"
    assert window.output_field.text() == "00000110"
    assert window.trace_stages[-1].value_label.text() == "00000110"

    window.data_input.setText(window.output_field.text())
    window.decrypt_button.click()

    assert window.output_caption.text() == "明文"
    assert window.output_field.text() == "10111001"
    assert "解密完成" in window.status_label.text()

    window.close()
    app.processEvents()


def test_gui_reports_invalid_input() -> None:
    app = create_application([])
    window = SDesWindow()

    window.data_input.setText("101")
    window.key_input.setText("1010000010")
    window.encrypt_button.click()

    assert not window.output_field.text()
    assert "8 bit" in window.status_label.text()

    window.close()
    app.processEvents()


def test_gui_ascii_text_workflow() -> None:
    app = create_application([])
    window = SDesWindow()
    window.mode_tabs.setCurrentIndex(1)

    assert window.text_encrypt_status.text() == "请输入 ASCII 文本和 10 bit 密钥。"
    assert window.text_decrypt_status.text() == "等待密文输入。"
    assert [window.text_format_combo.itemText(index) for index in range(2)] == [
        "十六进制",
        "二进制分组",
    ]

    window.text_plain_input.setPlainText("This is a test")
    window.text_key_input.setText("1010000010")
    window.text_encrypt_button.click()

    assert window.text_hex_output.text() == (
        "22 68 C7 27 62 C7 27 62 BD 62 4E F8 27 4E"
    )
    assert len(window.text_binary_output.toPlainText().split()) == 14

    window.text_transfer_button.click()
    window.text_decrypt_button.click()

    assert window.text_plain_output.toPlainText() == "This is a test"
    assert "解密完成" in window.text_decrypt_status.text()

    window.close()
    app.processEvents()


def test_gui_bruteforce_workflow() -> None:
    app = create_application([])
    window = SDesWindow()
    window.mode_tabs.setCurrentIndex(2)
    window.brute_plain_input.setPlainText("10111001")
    window.brute_cipher_input.setPlainText("00000110")
    window.brute_start_button.click()

    deadline = time.monotonic() + 2
    while window.brute_timer.isActive() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)

    assert not window.brute_timer.isActive()
    assert window.brute_progress.value() == 1024
    assert "1010000010" in window.brute_keys_output.toPlainText()
    assert "破解完成" in window.brute_status_label.text()

    window.close()
    app.processEvents()


def test_gui_binary_transfer_uses_binary_output() -> None:
    app = create_application([])
    window = SDesWindow()
    window.mode_tabs.setCurrentIndex(1)

    window.text_plain_input.setPlainText("OK")
    window.text_key_input.setText("1010000010")
    window.text_encrypt_button.click()
    window.text_format_combo.setCurrentIndex(1)
    window.text_transfer_button.click()

    assert window.text_format_combo.currentData() == "binary"
    assert window.text_cipher_input.toPlainText() == window.text_binary_output.toPlainText()

    window.text_decrypt_button.click()
    assert window.text_plain_output.toPlainText() == "OK"

    window.close()
    app.processEvents()


def test_gui_closed_test_workflow() -> None:
    app = create_application([])
    window = SDesWindow()
    window.mode_tabs.setCurrentIndex(3)
    window.closed_example_button.click()
    window.closed_analyze_button.click()

    assert window.closed_pair_count_label.text() == "8 个候选"
    assert "1010000010" in window.closed_pair_output.toPlainText()
    assert window.closed_reachable_label.text() == "240 / 256"
    assert window.closed_class_count_label.text() == "1024 个等价类"
    assert "不同的 (k1, k2)" in window.closed_equivalence_output.text()

    window.close()
    app.processEvents()

