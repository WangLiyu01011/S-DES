"""生成第一关、第三关、第四关和第五关界面截图，供文档和视觉检查使用。"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from sdes_app.gui import SDesWindow, create_application


def main() -> None:
    app = create_application([])
    window = SDesWindow()
    window.resize(1240, 760)

    window.mode_tabs.setCurrentIndex(0)
    window.data_input.setText(window.EXAMPLE_DATA)
    window.key_input.setText(window.EXAMPLE_KEY)
    window.encrypt_button.click()
    window.show()
    app.processEvents()

    output_dir = PROJECT_ROOT / "docs/screenshots"
    output_dir.mkdir(parents=True, exist_ok=True)

    first_path = output_dir / "first_gate.png"
    if not window.grab().save(str(first_path)):
        raise RuntimeError(f"无法保存界面截图：{first_path}")
    print(first_path.resolve())

    window.mode_tabs.setCurrentIndex(1)
    window.text_plain_input.setPlainText("This is a test")
    window.text_key_input.setText(window.EXAMPLE_KEY)
    window.text_encrypt_button.click()
    window.text_transfer_button.click()
    window.text_decrypt_button.click()
    app.processEvents()

    third_path = output_dir / "third_gate.png"
    if not window.grab().save(str(third_path)):
        raise RuntimeError(f"无法保存界面截图：{third_path}")
    print(third_path.resolve())

    window.mode_tabs.setCurrentIndex(2)
    window.brute_plain_input.setPlainText("10111001\n00000000")
    window.brute_cipher_input.setPlainText("00000110\n00001110")
    window.brute_start_button.click()
    while window.brute_timer.isActive():
        app.processEvents()
        time.sleep(0.02)
    app.processEvents()

    fourth_path = output_dir / "fourth_gate.png"
    if not window.grab().save(str(fourth_path)):
        raise RuntimeError(f"无法保存界面截图：{fourth_path}")
    print(fourth_path.resolve())

    window.mode_tabs.setCurrentIndex(3)
    window.closed_example_button.click()
    window.closed_analyze_button.click()
    app.processEvents()

    fifth_path = output_dir / "fifth_gate.png"
    if not window.grab().save(str(fifth_path)):
        raise RuntimeError(f"无法保存界面截图：{fifth_path}")
    print(fifth_path.resolve())

    window.close()
    app.processEvents()


if __name__ == "__main__":
    main()

