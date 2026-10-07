"""S-DES 第一关至第五关的 PySide6 图形界面。"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from time import perf_counter

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .core import CipherTrace, trace_decrypt_block, trace_encrypt_block
from .bruteforce import TOTAL_KEYS, key_matches_pairs, parse_block_list
from .collision_analysis import (
    analyze_key_equivalence,
    analyze_known_pair,
    analyze_plaintext_collisions,
)
from .styles import APP_STYLE
from .text_cipher import decrypt_ciphertext, encrypt_ascii_text


@dataclass(slots=True)
class TraceStage:
    frame: QFrame
    name_label: QLabel
    value_label: QLabel


class SDesWindow(QMainWindow):
    """用于 8 bit 分组加解密和过程观察的主窗口。"""

    EXAMPLE_DATA = "10111001"
    EXAMPLE_KEY = "1010000010"

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("S-DES 密码实验台")
        self.setMinimumSize(1120, 700)
        self.resize(1240, 760)

        self._build_ui()
        self._connect_signals()
        self._reset_trace()

    def _build_ui(self) -> None:
        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_header())

        self.mode_tabs = QTabWidget(objectName="modeTabs")
        self.mode_tabs.addTab(self._build_block_page(), "第一关 · 单分组")
        self.mode_tabs.addTab(self._build_text_page(), "第三关 · ASCII 文本")
        self.mode_tabs.addTab(self._build_bruteforce_page(), "第四关 · 暴力破解")
        self.mode_tabs.addTab(self._build_closed_test_page(), "第五关 · 封闭测试")
        root_layout.addWidget(self.mode_tabs, 1)

    def _build_block_page(self) -> QWidget:
        page = QWidget()
        content_layout = QHBoxLayout(page)
        content_layout.setContentsMargins(28, 26, 28, 28)
        content_layout.setSpacing(22)
        content_layout.addWidget(self._build_input_panel(), 0)
        content_layout.addWidget(self._build_trace_panel(), 1)
        return page

    def _build_header(self) -> QFrame:
        header = QFrame(objectName="header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(30, 20, 30, 20)

        title_stack = QVBoxLayout()
        title_stack.setSpacing(3)
        title = QLabel("S-DES 密码实验台", objectName="appTitle")
        subtitle = QLabel(
            "信息安全导论 · 作业 1 · 单分组、ASCII 文本与密钥分析",
            objectName="appSubtitle",
        )
        title_stack.addWidget(title)
        title_stack.addWidget(subtitle)
        layout.addLayout(title_stack)
        layout.addStretch(1)

        spec = QLabel("8-bit BLOCK  /  10-bit KEY", objectName="specLabel")
        layout.addWidget(spec, 0, Qt.AlignmentFlag.AlignVCenter)
        return header

    def _build_input_panel(self) -> QFrame:
        panel = QFrame(objectName="inputPanel")
        panel.setFixedWidth(410)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 24, 24, 22)
        layout.setSpacing(12)

        layout.addWidget(QLabel("输入与控制", objectName="sectionTitle"))
        layout.addWidget(
            QLabel(
                "输入 8 bit 数据分组与 10 bit 主密钥，示例显示在输入框内。",
                objectName="sectionHint",
                wordWrap=True,
            )
        )
        layout.addSpacing(10)

        data_label_row = QHBoxLayout()
        data_label_row.addWidget(QLabel("数据分组", objectName="fieldLabel"))
        data_label_row.addStretch(1)
        self.data_counter = QLabel("0 / 8", objectName="counterLabel")
        data_label_row.addWidget(self.data_counter)
        layout.addLayout(data_label_row)

        self.data_input = QLineEdit(objectName="bitInput")
        self.data_input.setMaxLength(8)
        self.data_input.setPlaceholderText("例如：10111001")
        self.data_input.setAccessibleName("8 bit 数据分组")
        layout.addWidget(self.data_input)
        layout.addWidget(
            QLabel(
                "加密时作为明文，解密时作为密文。",
                objectName="fieldHint",
                wordWrap=True,
            )
        )

        layout.addSpacing(6)
        key_label_row = QHBoxLayout()
        key_label_row.addWidget(QLabel("主密钥", objectName="fieldLabel"))
        key_label_row.addStretch(1)
        self.key_counter = QLabel("0 / 10", objectName="counterLabel")
        key_label_row.addWidget(self.key_counter)
        layout.addLayout(key_label_row)

        self.key_input = QLineEdit(objectName="bitInput")
        self.key_input.setMaxLength(10)
        self.key_input.setPlaceholderText("例如：1010000010")
        self.key_input.setAccessibleName("10 bit 主密钥")
        layout.addWidget(self.key_input)
        layout.addWidget(
            QLabel(
                "子密钥 k1、k2 按标准 S-DES 连续移位规则生成。",
                objectName="fieldHint",
                wordWrap=True,
            )
        )

        layout.addSpacing(10)
        action_row = QHBoxLayout()
        action_row.setSpacing(10)
        self.encrypt_button = QPushButton("执行加密", objectName="primaryButton")
        self.decrypt_button = QPushButton("执行解密", objectName="secondaryButton")
        action_row.addWidget(self.encrypt_button)
        action_row.addWidget(self.decrypt_button)
        layout.addLayout(action_row)

        utility_row = QHBoxLayout()
        utility_row.setSpacing(10)
        self.example_button = QPushButton("载入示例", objectName="quietButton")
        self.clear_button = QPushButton("清空", objectName="quietButton")
        utility_row.addWidget(self.example_button)
        utility_row.addWidget(self.clear_button)
        layout.addLayout(utility_row)

        self.status_label = QLabel(objectName="statusLabel", wordWrap=True)
        layout.addWidget(self.status_label)
        layout.addWidget(
            QLabel("运算结果显示在右侧的输出区。", objectName="fieldHint", wordWrap=True)
        )
        layout.addItem(
            QSpacerItem(
                1,
                1,
                QSizePolicy.Policy.Minimum,
                QSizePolicy.Policy.Expanding,
            )
        )
        return panel

    def _build_trace_panel(self) -> QFrame:
        panel = QFrame(objectName="tracePanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        result_panel = QFrame(objectName="resultPanel")
        result_layout = QVBoxLayout(result_panel)
        result_layout.setContentsMargins(16, 13, 16, 15)
        result_layout.setSpacing(8)
        result_heading = QHBoxLayout()
        result_heading.addWidget(QLabel("输出结果", objectName="sectionTitle"))
        result_heading.addStretch(1)
        self.output_caption = QLabel("输出", objectName="fieldLabel")
        result_heading.addWidget(self.output_caption, 0, Qt.AlignmentFlag.AlignVCenter)
        self.copy_button = QPushButton("复制结果", objectName="resultCopyButton")
        self.copy_button.setFixedHeight(32)
        result_heading.addWidget(self.copy_button, 0, Qt.AlignmentFlag.AlignVCenter)
        result_layout.addLayout(result_heading)
        self.output_field = QLineEdit(objectName="bitOutput")
        self.output_field.setReadOnly(True)
        self.output_field.setAccessibleName("运算结果")
        result_layout.addWidget(self.output_field)
        layout.addWidget(result_panel)

        divider = QFrame(objectName="sectionDivider")
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFrameShadow(QFrame.Shadow.Plain)
        layout.addWidget(divider)

        heading_row = QHBoxLayout()
        heading_stack = QVBoxLayout()
        heading_stack.setSpacing(3)
        heading_stack.addWidget(QLabel("运算轨道", objectName="sectionTitle"))
        heading_stack.addWidget(
            QLabel(
                "每个节点显示完成该步骤后的 8 bit 状态",
                objectName="sectionHint",
            )
        )
        heading_row.addLayout(heading_stack)
        heading_row.addStretch(1)
        self.mode_label = QLabel("等待输入", objectName="modeLabel")
        heading_row.addWidget(self.mode_label, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(heading_row)

        self.key_strip = QFrame(objectName="keyStrip")
        key_layout = QGridLayout(self.key_strip)
        key_layout.setContentsMargins(16, 11, 16, 11)
        key_layout.setHorizontalSpacing(30)
        self.key_value_labels: dict[str, QLabel] = {}
        for column, key_name in enumerate(("K", "k1", "k2")):
            name = QLabel(key_name, objectName="keyName")
            value = QLabel("—", objectName="keyValue")
            key_layout.addWidget(name, 0, column)
            key_layout.addWidget(value, 1, column)
            self.key_value_labels[key_name] = value
        key_layout.setColumnStretch(0, 2)
        key_layout.setColumnStretch(1, 1)
        key_layout.setColumnStretch(2, 1)
        layout.addWidget(self.key_strip)

        self.trace_row = QHBoxLayout()
        self.trace_row.setSpacing(7)
        self.trace_stages: list[TraceStage] = []
        for index, name in enumerate(("IP", "fₖ₁", "SW", "fₖ₂", "IP⁻¹")):
            stage = self._make_trace_stage(name)
            self.trace_stages.append(stage)
            self.trace_row.addWidget(stage.frame, 1)
            if index < 4:
                self.trace_row.addWidget(QLabel("›", objectName="connector"))
        layout.addLayout(self.trace_row)

        layout.addStretch(1)

        note = QLabel(
            "算法参数以作业要求为准",
            objectName="sectionHint",
            wordWrap=True,
        )
        layout.addWidget(note)
        return panel

    def _build_text_page(self) -> QWidget:
        """构建第三关 ASCII 文本模式页面。"""

        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(28, 20, 28, 28)
        outer.setSpacing(16)

        key_band = QFrame(objectName="textKeyBand")
        key_layout = QHBoxLayout(key_band)
        key_layout.setContentsMargins(18, 12, 18, 12)
        key_layout.setSpacing(12)
        key_title = QLabel("文本模式主密钥", objectName="fieldLabel")
        key_layout.addWidget(key_title)
        self.text_key_input = QLineEdit(objectName="compactInput")
        self.text_key_input.setMaxLength(10)
        self.text_key_input.setPlaceholderText("例如：1010000010")
        self.text_key_input.setFixedWidth(245)
        self.text_key_input.setAccessibleName("文本模式 10 bit 主密钥")
        key_layout.addWidget(self.text_key_input)
        self.text_key_counter = QLabel("0 / 10", objectName="counterLabel")
        key_layout.addWidget(self.text_key_counter)
        key_layout.addSpacing(12)
        key_layout.addWidget(
            QLabel(
                "每个 ASCII 字符独立加密为一个 8 bit 密文分组",
                objectName="sectionHint",
            )
        )
        key_layout.addStretch(1)
        self.text_example_button = QPushButton("载入文本示例", objectName="quietButton")
        key_layout.addWidget(self.text_example_button)
        outer.addWidget(key_band)

        columns = QHBoxLayout()
        columns.setSpacing(22)
        columns.addWidget(self._build_text_encrypt_panel(), 1)
        columns.addWidget(self._build_text_decrypt_panel(), 1)
        outer.addLayout(columns, 1)

        return page

    def _build_text_encrypt_panel(self) -> QFrame:
        panel = QFrame(objectName="encryptTextPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(7)

        layout.addWidget(QLabel("ASCII 文本加密", objectName="sectionTitle"))
        layout.addWidget(
            QLabel(
                "只接受 ASCII 字符。密文用十六进制和 8 bit 分组同时呈现，避免控制字符破坏复制。",
                objectName="sectionHint",
                wordWrap=True,
            )
        )
        layout.addSpacing(5)

        layout.addWidget(QLabel("明文输入", objectName="fieldLabel"))
        self.text_plain_input = QPlainTextEdit(objectName="textInput")
        self.text_plain_input.setPlaceholderText("例如：This is a test")
        self.text_plain_input.setFixedHeight(52)
        self.text_plain_input.setAccessibleName("ASCII 明文输入")
        layout.addWidget(self.text_plain_input)

        self.text_encrypt_button = QPushButton("执行文本加密", objectName="primaryButton")
        self.text_encrypt_button.setFixedHeight(34)
        layout.addWidget(self.text_encrypt_button)

        hex_row = QHBoxLayout()
        hex_row.addWidget(QLabel("十六进制密文", objectName="fieldLabel"))
        hex_row.addStretch(1)
        self.copy_hex_button = QPushButton("复制", objectName="quietButton")
        self.copy_hex_button.setFixedHeight(30)
        hex_row.addWidget(self.copy_hex_button)
        layout.addLayout(hex_row)
        self.text_hex_output = QLineEdit(objectName="compactOutput")
        self.text_hex_output.setReadOnly(True)
        self.text_hex_output.setPlaceholderText("等待文本加密")
        layout.addWidget(self.text_hex_output)

        layout.addWidget(QLabel("二进制密文（每 8 bit 一组）", objectName="fieldLabel"))
        self.text_binary_output = QPlainTextEdit(objectName="binaryOutput")
        self.text_binary_output.setReadOnly(True)
        self.text_binary_output.setFixedHeight(56)
        self.text_binary_output.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.NoWrap
        )
        self.text_binary_output.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.text_binary_output.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.text_binary_output.setPlaceholderText("每个字符对应一个 8 bit 分组")
        layout.addWidget(self.text_binary_output)

        escaped_row = QHBoxLayout()
        escaped_row.addWidget(QLabel("转义字节", objectName="fieldLabel"))
        escaped_row.addStretch(1)
        self.copy_binary_button = QPushButton("复制二进制", objectName="quietButton")
        self.copy_binary_button.setFixedHeight(30)
        escaped_row.addWidget(self.copy_binary_button)
        layout.addLayout(escaped_row)
        self.text_escaped_output = QLineEdit(objectName="compactOutput")
        self.text_escaped_output.setReadOnly(True)
        self.text_escaped_output.setPlaceholderText("例如 \\x82\\x0C...")
        layout.addWidget(self.text_escaped_output)

        self.text_encrypt_status = QLabel(objectName="statusLabel", wordWrap=True)
        self.text_encrypt_status.setText("请输入 ASCII 文本和 10 bit 密钥。")
        layout.addWidget(self.text_encrypt_status)
        layout.addStretch(1)
        return panel

    def _build_text_decrypt_panel(self) -> QFrame:
        panel = QFrame(objectName="decryptTextPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(7)

        layout.addWidget(QLabel("密文还原", objectName="sectionTitle"))
        layout.addWidget(
            QLabel(
                "粘贴左侧生成的十六进制密文，或切换为 8 bit 分组二进制后再解密。",
                objectName="sectionHint",
                wordWrap=True,
            )
        )
        layout.addSpacing(5)

        format_row = QHBoxLayout()
        format_row.addWidget(QLabel("密文格式", objectName="fieldLabel"))
        self.text_format_combo = QComboBox(objectName="formatCombo")
        self.text_format_combo.addItem("十六进制", "hex")
        self.text_format_combo.addItem("二进制分组", "binary")
        format_row.addWidget(self.text_format_combo)
        format_row.addStretch(1)
        self.clear_text_button = QPushButton("清空本页", objectName="quietButton")
        self.clear_text_button.setFixedHeight(30)
        format_row.addWidget(self.clear_text_button)
        layout.addLayout(format_row)

        self.text_cipher_input = QPlainTextEdit(objectName="cipherInput")
        self.text_cipher_input.setPlaceholderText("例如：22 68 C7 27 ...")
        self.text_cipher_input.setFixedHeight(60)
        self.text_cipher_input.setAccessibleName("文本模式密文输入")
        layout.addWidget(self.text_cipher_input)

        action_row = QHBoxLayout()
        self.text_decrypt_button = QPushButton("执行文本解密", objectName="secondaryButton")
        self.text_transfer_button = QPushButton("使用左侧密文", objectName="quietButton")
        self.text_decrypt_button.setFixedHeight(34)
        self.text_transfer_button.setFixedHeight(34)
        action_row.addWidget(self.text_decrypt_button)
        action_row.addWidget(self.text_transfer_button)
        layout.addLayout(action_row)

        layout.addWidget(QLabel("恢复的 ASCII 文本", objectName="fieldLabel"))
        self.text_plain_output = QPlainTextEdit(objectName="textOutput")
        self.text_plain_output.setReadOnly(True)
        self.text_plain_output.setFixedHeight(52)
        self.text_plain_output.setPlaceholderText("等待文本解密")
        layout.addWidget(self.text_plain_output)

        output_hex_row = QHBoxLayout()
        output_hex_row.addWidget(QLabel("恢复字节（十六进制）", objectName="fieldLabel"))
        output_hex_row.addStretch(1)
        layout.addLayout(output_hex_row)
        self.text_plain_hex_output = QLineEdit(objectName="compactOutput")
        self.text_plain_hex_output.setReadOnly(True)
        layout.addWidget(self.text_plain_hex_output)

        self.text_decrypt_status = QLabel(objectName="statusLabel", wordWrap=True)
        self.text_decrypt_status.setText("等待密文输入。")
        layout.addWidget(self.text_decrypt_status)
        layout.addStretch(1)
        return panel

    def _build_bruteforce_page(self) -> QWidget:
        """构建第四关：已知明密文下的 10 bit 密钥暴力破解。"""

        page = QWidget()
        content_layout = QHBoxLayout(page)
        content_layout.setContentsMargins(28, 20, 28, 28)
        content_layout.setSpacing(22)
        content_layout.addWidget(self._build_bruteforce_input_panel(), 0)
        content_layout.addWidget(self._build_bruteforce_result_panel(), 1)

        self.brute_timer = QTimer(self)
        self.brute_timer.setInterval(16)
        self.brute_timer.timeout.connect(self._process_bruteforce_batch)
        self._brute_pairs: tuple[tuple[str, str], ...] = ()
        self._brute_next_index = 0
        self._brute_matches: list[str] = []
        self._brute_started_at = 0.0
        return page

    def _build_bruteforce_input_panel(self) -> QFrame:
        panel = QFrame(objectName="bruteInputPanel")
        panel.setFixedWidth(410)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(9)

        layout.addWidget(QLabel("已知明密文", objectName="sectionTitle"))
        layout.addWidget(
            QLabel(
                "输入同一主密钥下的一组或多组明文与密文，程序将遍历全部 10 bit 密钥。",
                objectName="sectionHint",
                wordWrap=True,
            )
        )
        layout.addSpacing(5)

        plain_label_row = QHBoxLayout()
        plain_label_row.addWidget(QLabel("明文 P", objectName="fieldLabel"))
        plain_label_row.addStretch(1)
        self.brute_plain_counter = QLabel("0 组", objectName="counterLabel")
        plain_label_row.addWidget(self.brute_plain_counter)
        layout.addLayout(plain_label_row)

        self.brute_plain_input = QPlainTextEdit(objectName="bruteInput")
        self.brute_plain_input.setPlaceholderText("例如：10111001\n00000000")
        self.brute_plain_input.setFixedHeight(72)
        self.brute_plain_input.setAccessibleName("暴力破解明文分组")
        layout.addWidget(self.brute_plain_input)
        layout.addWidget(
            QLabel(
                "每行一个 8 bit 分组，也可以用空格或逗号分隔。",
                objectName="fieldHint",
                wordWrap=True,
            )
        )

        cipher_label_row = QHBoxLayout()
        cipher_label_row.addWidget(QLabel("密文 C", objectName="fieldLabel"))
        cipher_label_row.addStretch(1)
        self.brute_cipher_counter = QLabel("0 组", objectName="counterLabel")
        cipher_label_row.addWidget(self.brute_cipher_counter)
        layout.addLayout(cipher_label_row)

        self.brute_cipher_input = QPlainTextEdit(objectName="bruteInput")
        self.brute_cipher_input.setPlaceholderText("例如：00000110\n00001110")
        self.brute_cipher_input.setFixedHeight(72)
        self.brute_cipher_input.setAccessibleName("暴力破解密文分组")
        layout.addWidget(self.brute_cipher_input)
        layout.addWidget(
            QLabel(
                "明文与密文按顺序一一对应，数量必须相同。",
                objectName="fieldHint",
                wordWrap=True,
            )
        )

        action_row = QHBoxLayout()
        action_row.setSpacing(10)
        self.brute_start_button = QPushButton("开始破解", objectName="primaryButton")
        self.brute_clear_button = QPushButton("清空", objectName="quietButton")
        action_row.addWidget(self.brute_start_button)
        action_row.addWidget(self.brute_clear_button)
        layout.addLayout(action_row)

        self.brute_status_label = QLabel(objectName="statusLabel", wordWrap=True)
        self.brute_status_label.setText("请输入明文和密文，然后开始破解。")
        layout.addWidget(self.brute_status_label)
        layout.addItem(
            QSpacerItem(
                1,
                1,
                QSizePolicy.Policy.Minimum,
                QSizePolicy.Policy.Expanding,
            )
        )
        return panel

    def _build_bruteforce_result_panel(self) -> QFrame:
        panel = QFrame(objectName="bruteResultPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        heading_row = QHBoxLayout()
        heading_stack = QVBoxLayout()
        heading_stack.setSpacing(3)
        heading_stack.addWidget(QLabel("暴力破解", objectName="sectionTitle"))
        heading_stack.addWidget(
            QLabel(
                "按作业要求遍历 0000000000 至 1111111111 的密钥空间",
                objectName="sectionHint",
            )
        )
        heading_row.addLayout(heading_stack)
        heading_row.addStretch(1)
        self.brute_run_label = QLabel("未开始", objectName="modeLabel")
        heading_row.addWidget(self.brute_run_label, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(heading_row)

        result_band = QFrame(objectName="bruteResultBand")
        result_layout = QVBoxLayout(result_band)
        result_layout.setContentsMargins(16, 13, 16, 14)
        result_layout.setSpacing(8)
        result_header = QHBoxLayout()
        result_header.addWidget(QLabel("候选密钥", objectName="sectionTitle"))
        result_header.addStretch(1)
        self.brute_match_count_label = QLabel("0 个", objectName="fieldLabel")
        result_header.addWidget(self.brute_match_count_label)
        result_layout.addLayout(result_header)
        self.brute_keys_output = QPlainTextEdit(objectName="bruteKeysOutput")
        self.brute_keys_output.setReadOnly(True)
        self.brute_keys_output.setFixedHeight(150)
        self.brute_keys_output.setPlaceholderText("破解完成后将在此列出所有候选密钥")
        self.brute_keys_output.setAccessibleName("候选密钥列表")
        result_layout.addWidget(self.brute_keys_output)
        layout.addWidget(result_band)

        progress_band = QFrame(objectName="bruteProgressBand")
        progress_layout = QVBoxLayout(progress_band)
        progress_layout.setContentsMargins(16, 13, 16, 14)
        progress_layout.setSpacing(9)
        progress_header = QHBoxLayout()
        progress_header.addWidget(QLabel("密钥空间搜索", objectName="fieldLabel"))
        progress_header.addStretch(1)
        self.brute_checked_label = QLabel("0 / 1024", objectName="counterLabel")
        progress_header.addWidget(self.brute_checked_label)
        self.brute_elapsed_label = QLabel("0.00 ms", objectName="counterLabel")
        progress_header.addWidget(self.brute_elapsed_label)
        progress_layout.addLayout(progress_header)
        self.brute_progress = QProgressBar(objectName="bruteProgress")
        self.brute_progress.setRange(0, TOTAL_KEYS)
        self.brute_progress.setValue(0)
        self.brute_progress.setTextVisible(False)
        self.brute_progress.setAccessibleName("暴力破解进度")
        progress_layout.addWidget(self.brute_progress)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(20)
        metrics.addWidget(QLabel("明密文对", objectName="counterLabel"), 0, 0)
        metrics.addWidget(QLabel("密钥空间", objectName="counterLabel"), 0, 1)
        metrics.addWidget(QLabel("搜索状态", objectName="counterLabel"), 0, 2)
        self.brute_pair_count_label = QLabel("0 组", objectName="metricValue")
        self.brute_space_label = QLabel("1024 个", objectName="metricValue")
        self.brute_state_label = QLabel("等待开始", objectName="metricValue")
        metrics.addWidget(self.brute_pair_count_label, 1, 0)
        metrics.addWidget(self.brute_space_label, 1, 1)
        metrics.addWidget(self.brute_state_label, 1, 2)
        metrics.setColumnStretch(0, 1)
        metrics.setColumnStretch(1, 1)
        metrics.setColumnStretch(2, 2)
        progress_layout.addLayout(metrics)
        layout.addWidget(progress_band)

        layout.addStretch(1)
        layout.addWidget(
            QLabel(
                "若出现多个候选密钥，说明这些密钥对当前明密文对表现等价；增加明密文分组可继续缩小候选范围。",
                objectName="sectionHint",
                wordWrap=True,
            )
        )
        return panel

    def _build_closed_test_page(self) -> QWidget:
        """构建第五关：密钥碰撞与等价密钥封闭测试。"""

        page = QScrollArea(objectName="closedPage")
        page.setWidgetResizable(True)
        page.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        page_palette = page.viewport().palette()
        page_palette.setColor(QPalette.ColorRole.Window, QColor("#F4F1EB"))
        page.viewport().setPalette(page_palette)
        page.viewport().setAutoFillBackground(True)
        content = QWidget()
        content_palette = content.palette()
        content_palette.setColor(QPalette.ColorRole.Window, QColor("#F4F1EB"))
        content.setPalette(content_palette)
        content.setAutoFillBackground(True)
        content.setMinimumHeight(620)
        page.setWidget(content)
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(28, 20, 28, 28)
        content_layout.setSpacing(22)
        content_layout.addWidget(self._build_closed_input_panel(), 0)
        content_layout.addWidget(self._build_closed_result_panel(), 1)
        return page

    def _build_closed_input_panel(self) -> QFrame:
        panel = QFrame(objectName="closedInputPanel")
        panel.setFixedWidth(410)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        layout.addWidget(QLabel("封闭测试", objectName="sectionTitle"))
        layout.addWidget(
            QLabel(
                "验证同一明密文对是否存在多个密钥，并分析固定明文的碰撞分布。",
                objectName="sectionHint",
                wordWrap=True,
            )
        )
        layout.addSpacing(6)

        layout.addWidget(QLabel("明文 P", objectName="fieldLabel"))
        self.closed_plain_input = QLineEdit(objectName="bitInput")
        self.closed_plain_input.setMaxLength(8)
        self.closed_plain_input.setPlaceholderText("例如：10111001")
        self.closed_plain_input.setAccessibleName("封闭测试明文")
        layout.addWidget(self.closed_plain_input)
        layout.addWidget(
            QLabel("固定一个 8 bit 明文，统计全部主密钥产生的密文。", objectName="fieldHint", wordWrap=True)
        )

        layout.addWidget(QLabel("密文 C", objectName="fieldLabel"))
        self.closed_cipher_input = QLineEdit(objectName="bitInput")
        self.closed_cipher_input.setMaxLength(8)
        self.closed_cipher_input.setPlaceholderText("例如：00000110")
        self.closed_cipher_input.setAccessibleName("封闭测试密文")
        layout.addWidget(self.closed_cipher_input)
        layout.addWidget(
            QLabel("先验证这一组明密文对的全部候选密钥。", objectName="fieldHint", wordWrap=True)
        )

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        self.closed_analyze_button = QPushButton("开始分析", objectName="primaryButton")
        self.closed_example_button = QPushButton("载入示例", objectName="quietButton")
        action_row.addWidget(self.closed_analyze_button)
        action_row.addWidget(self.closed_example_button)
        layout.addLayout(action_row)
        self.closed_clear_button = QPushButton("清空本页", objectName="quietButton")
        self.closed_clear_button.setFixedHeight(34)
        layout.addWidget(self.closed_clear_button)

        self.closed_status_label = QLabel(objectName="statusLabel", wordWrap=True)
        self.closed_status_label.setText("请输入明文和密文，然后开始分析。")
        layout.addWidget(self.closed_status_label)
        layout.addWidget(
            QLabel(
                "若候选密钥不止一个，不代表破解失败，而是说明当前算法参数存在密钥碰撞或等价类。",
                objectName="fieldHint",
                wordWrap=True,
            )
        )
        layout.addItem(
            QSpacerItem(
                1,
                1,
                QSizePolicy.Policy.Minimum,
                QSizePolicy.Policy.Expanding,
            )
        )
        return panel

    def _build_closed_result_panel(self) -> QFrame:
        panel = QFrame(objectName="closedResultPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(8)

        heading_row = QHBoxLayout()
        heading_stack = QVBoxLayout()
        heading_stack.setSpacing(3)
        heading_stack.addWidget(QLabel("碰撞结论", objectName="sectionTitle"))
        heading_stack.addWidget(
            QLabel(
                "固定明文后比较 1024 个主密钥的输出，并识别永久等价密钥",
                objectName="sectionHint",
            )
        )
        heading_row.addLayout(heading_stack)
        heading_row.addStretch(1)
        self.closed_run_label = QLabel("未开始", objectName="modeLabel")
        heading_row.addWidget(self.closed_run_label, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(heading_row)

        pair_band = QFrame(objectName="closedBand")
        pair_layout = QVBoxLayout(pair_band)
        pair_layout.setContentsMargins(16, 12, 16, 13)
        pair_layout.setSpacing(7)
        pair_header = QHBoxLayout()
        pair_header.addWidget(QLabel("单对明密文候选", objectName="fieldLabel"))
        pair_header.addStretch(1)
        self.closed_pair_count_label = QLabel("0 个候选", objectName="metricValue")
        pair_header.addWidget(self.closed_pair_count_label)
        pair_layout.addLayout(pair_header)
        self.closed_pair_output = QPlainTextEdit(objectName="closedOutput")
        self.closed_pair_output.setReadOnly(True)
        self.closed_pair_output.setFixedHeight(140)
        self.closed_pair_output.setPlaceholderText("分析后列出所有匹配的 10 bit 密钥")
        pair_layout.addWidget(self.closed_pair_output)
        layout.addWidget(pair_band)

        collision_band = QFrame(objectName="closedBand")
        collision_layout = QVBoxLayout(collision_band)
        collision_layout.setContentsMargins(16, 12, 16, 13)
        collision_layout.setSpacing(18)
        collision_header = QHBoxLayout()
        collision_header.addWidget(QLabel("固定明文的密文分布", objectName="fieldLabel"))
        collision_header.addStretch(1)
        self.closed_collision_time_label = QLabel("0.00 ms", objectName="counterLabel")
        collision_header.addWidget(self.closed_collision_time_label)
        collision_layout.addLayout(collision_header)
        self.closed_collision_output = QPlainTextEdit(objectName="closedOutput")
        self.closed_collision_output.setReadOnly(True)
        self.closed_collision_output.setPlaceholderText(
            "分析后显示各密钥重数对应的密文数量"
        )
        self.closed_collision_output.setFixedHeight(86)
        collision_layout.addWidget(self.closed_collision_output)

        layout.addWidget(collision_band)

        metrics_band = QFrame(objectName="closedMetrics")
        metrics_band_layout = QGridLayout(metrics_band)
        metrics_band_layout.setContentsMargins(16, 6, 16, 6)
        metrics_band_layout.setHorizontalSpacing(18)
        metrics_band_layout.addWidget(QLabel("可达密文", objectName="counterLabel"), 0, 0)
        metrics_band_layout.addWidget(QLabel("重复映射", objectName="counterLabel"), 0, 1)
        self.closed_reachable_label = QLabel("0 / 256", objectName="metricValue")
        self.closed_excess_label = QLabel("0 个", objectName="metricValue")
        metrics_band_layout.addWidget(self.closed_reachable_label, 1, 0)
        metrics_band_layout.addWidget(self.closed_excess_label, 1, 1)
        metrics_band_layout.setColumnStretch(0, 1)
        metrics_band_layout.setColumnStretch(1, 1)
        layout.addWidget(metrics_band)

        equivalence_band = QFrame(objectName="closedBand")
        equivalence_layout = QVBoxLayout(equivalence_band)
        equivalence_layout.setContentsMargins(16, 12, 16, 13)
        equivalence_layout.setSpacing(7)
        equivalence_header = QHBoxLayout()
        equivalence_header.addWidget(QLabel("等价密钥分析", objectName="fieldLabel"))
        equivalence_header.addStretch(1)
        self.closed_class_count_label = QLabel("0 个等价类", objectName="metricValue")
        equivalence_header.addWidget(self.closed_class_count_label)
        equivalence_layout.addLayout(equivalence_header)
        self.closed_equivalence_output = QLabel(
            "分析后说明相同的 (k1, k2) 如何导致主密钥等价。",
            objectName="closedConclusion",
            wordWrap=True,
        )
        equivalence_layout.addWidget(self.closed_equivalence_output)
        layout.addWidget(equivalence_band)

        layout.addStretch(1)
        layout.addWidget(
            QLabel(
                "当前作业要求参数下，每个主密钥对应唯一的 (k1, k2)；增加明密文对可以消除偶然碰撞。",
                objectName="sectionHint",
                wordWrap=True,
            )
        )
        return panel

    @staticmethod
    def _make_trace_stage(name: str) -> TraceStage:
        frame = QFrame(objectName="traceStage")
        frame.setMinimumWidth(104)
        frame.setMinimumHeight(100)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 13, 10, 13)
        layout.setSpacing(10)
        name_label = QLabel(name, objectName="stageName")
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label = QLabel("—", objectName="stageValue")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(name_label)
        layout.addWidget(value_label, 1)
        return TraceStage(frame, name_label, value_label)

    def _connect_signals(self) -> None:
        self.encrypt_button.clicked.connect(lambda: self._execute("encrypt"))
        self.decrypt_button.clicked.connect(lambda: self._execute("decrypt"))
        self.example_button.clicked.connect(self._load_example)
        self.clear_button.clicked.connect(self._clear_all)
        self.copy_button.clicked.connect(self._copy_result)
        self.text_example_button.clicked.connect(self._load_text_example)
        self.text_encrypt_button.clicked.connect(self._encrypt_text)
        self.text_decrypt_button.clicked.connect(self._decrypt_text)
        self.text_transfer_button.clicked.connect(self._transfer_text_cipher)
        self.copy_hex_button.clicked.connect(self._copy_text_hex)
        self.copy_binary_button.clicked.connect(self._copy_text_binary)
        self.clear_text_button.clicked.connect(self._clear_text_page)
        self.brute_start_button.clicked.connect(self._start_bruteforce)
        self.brute_clear_button.clicked.connect(self._clear_bruteforce)
        self.closed_analyze_button.clicked.connect(self._run_closed_analysis)
        self.closed_example_button.clicked.connect(self._load_closed_example)
        self.closed_clear_button.clicked.connect(self._clear_closed_analysis)
        self.data_input.textChanged.connect(
            lambda text: self.data_counter.setText(f"{len(text)} / 8")
        )
        self.key_input.textChanged.connect(
            lambda text: self.key_counter.setText(f"{len(text)} / 10")
        )
        self.text_key_input.textChanged.connect(
            lambda text: self.text_key_counter.setText(f"{len(text)} / 10")
        )
        self.brute_plain_input.textChanged.connect(
            lambda: self._update_brute_counter(
                self.brute_plain_input, self.brute_plain_counter
            )
        )
        self.brute_cipher_input.textChanged.connect(
            lambda: self._update_brute_counter(
                self.brute_cipher_input, self.brute_cipher_counter
            )
        )
        self.data_input.returnPressed.connect(self.encrypt_button.click)
        self.key_input.returnPressed.connect(self.encrypt_button.click)

    @staticmethod
    def _update_brute_counter(editor: QPlainTextEdit, label: QLabel) -> None:
        tokens = editor.toPlainText().replace(",", " ").split()
        label.setText(f"{len(tokens)} 组")

    def _start_bruteforce(self) -> None:
        try:
            plaintext_blocks = parse_block_list(
                self.brute_plain_input.toPlainText(), "明文"
            )
            ciphertext_blocks = parse_block_list(
                self.brute_cipher_input.toPlainText(), "密文"
            )
            if len(plaintext_blocks) != len(ciphertext_blocks):
                raise ValueError("明文与密文分组数量必须一致")
        except (TypeError, ValueError) as error:
            self._set_status(self.brute_status_label, str(error), "error")
            return

        if self.brute_timer.isActive():
            return

        self._brute_pairs = tuple(zip(plaintext_blocks, ciphertext_blocks))
        self._brute_next_index = 0
        self._brute_matches = []
        self._brute_started_at = perf_counter()
        self.brute_progress.setValue(0)
        self.brute_checked_label.setText(f"0 / {TOTAL_KEYS}")
        self.brute_elapsed_label.setText("0.00 ms")
        self.brute_match_count_label.setText("0 个")
        self.brute_keys_output.clear()
        self.brute_run_label.setText("破解中")
        self.brute_state_label.setText("正在遍历")
        self._set_status(self.brute_status_label, "正在遍历 1024 个 10 bit 密钥……", "normal")
        self.brute_start_button.setEnabled(False)
        self.brute_plain_input.setEnabled(False)
        self.brute_cipher_input.setEnabled(False)
        self.brute_pair_count_label.setText(f"{len(self._brute_pairs)} 组")
        self.brute_timer.start()

    def _process_bruteforce_batch(self) -> None:
        batch_size = 32
        end_index = min(self._brute_next_index + batch_size, TOTAL_KEYS)
        for index in range(self._brute_next_index, end_index):
            key = format(index, "010b")
            if all(
                key_matches_pairs((plaintext,), (ciphertext,), key)
                for plaintext, ciphertext in self._brute_pairs
            ):
                self._brute_matches.append(key)
        self._brute_next_index = end_index

        elapsed = perf_counter() - self._brute_started_at
        self.brute_progress.setValue(end_index)
        self.brute_checked_label.setText(f"{end_index} / {TOTAL_KEYS}")
        self.brute_elapsed_label.setText(f"{elapsed * 1000:.2f} ms")

        if end_index < TOTAL_KEYS:
            return

        self.brute_timer.stop()
        self.brute_start_button.setEnabled(True)
        self.brute_plain_input.setEnabled(True)
        self.brute_cipher_input.setEnabled(True)
        self.brute_match_count_label.setText(f"{len(self._brute_matches)} 个")
        self.brute_state_label.setText("已完成")
        self.brute_run_label.setText("破解完成")
        if self._brute_matches:
            self.brute_keys_output.setPlainText(
                "\n".join(
                    f"候选 {index}: {key}"
                    for index, key in enumerate(self._brute_matches, start=1)
                )
            )
            if len(self._brute_matches) == 1:
                message = "破解完成：找到 1 个候选密钥。"
            else:
                message = (
                    f"破解完成：找到 {len(self._brute_matches)} 个候选密钥，"
                    "可能存在等价密钥。"
                )
            self._set_status(self.brute_status_label, message, "success")
        else:
            self.brute_keys_output.setPlainText("未找到匹配的 10 bit 密钥。")
            self._set_status(
                self.brute_status_label,
                "遍历完成：当前明密文对没有匹配的密钥。",
                "error",
            )

    def _clear_bruteforce(self) -> None:
        self.brute_timer.stop()
        self._brute_pairs = ()
        self._brute_next_index = 0
        self._brute_matches = []
        self.brute_plain_input.clear()
        self.brute_cipher_input.clear()
        self.brute_keys_output.clear()
        self.brute_progress.setValue(0)
        self.brute_checked_label.setText(f"0 / {TOTAL_KEYS}")
        self.brute_elapsed_label.setText("0.00 ms")
        self.brute_match_count_label.setText("0 个")
        self.brute_pair_count_label.setText("0 组")
        self.brute_state_label.setText("等待开始")
        self.brute_run_label.setText("未开始")
        self.brute_start_button.setEnabled(True)
        self.brute_plain_input.setEnabled(True)
        self.brute_cipher_input.setEnabled(True)
        self._set_status(self.brute_status_label, "请输入明文和密文，然后开始破解。", "normal")

    def _run_closed_analysis(self) -> None:
        try:
            pair = analyze_known_pair(
                self.closed_plain_input.text(), self.closed_cipher_input.text()
            )
        except (TypeError, ValueError) as error:
            self._set_status(self.closed_status_label, str(error), "error")
            return

        self.closed_run_label.setText("分析中")
        self._set_status(self.closed_status_label, "正在统计候选密钥和碰撞分布……", "normal")
        QApplication.processEvents()

        collision = analyze_plaintext_collisions(pair.plaintext)
        equivalence = analyze_key_equivalence()

        self.closed_pair_count_label.setText(f"{pair.candidate_count} 个候选")
        self.closed_pair_output.setPlainText(
            "\n".join(
                f"候选 {index}: {key}"
                for index, key in enumerate(pair.matching_keys, start=1)
            )
            or "当前明密文对没有匹配的密钥。"
        )

        histogram_lines = [
            f"{multiplicity} 个密钥  →  {bucket_count} 种密文"
            for multiplicity, bucket_count in collision.multiplicity_histogram
        ]
        self.closed_collision_output.setPlainText("\n".join(histogram_lines))
        self.closed_collision_time_label.setText(
            f"{collision.elapsed_seconds * 1000:.2f} ms"
        )
        self.closed_reachable_label.setText(
            f"{collision.reachable_ciphertext_count} / 256"
        )
        self.closed_excess_label.setText(f"{collision.collision_excess_keys} 个")
        self.closed_class_count_label.setText(
            f"{equivalence.class_count} 个等价类"
        )

        example_class = next(
            (
                key_class
                for key_class in equivalence.classes
                if "1010000010" in key_class
            ),
            equivalence.classes[0],
        )
        if len(example_class) == 1:
            conclusion = (
                f"当前参数下每个等价类包含 1 个主密钥；示例：{example_class[0]}。"
                "不同主密钥对应不同的 (k1, k2)。"
            )
        else:
            conclusion = (
                f"每个等价类有 {len(example_class)} 个主密钥；示例："
                f"{' ↔ '.join(example_class)}，它们对应相同的 (k1, k2)。"
            )
        self.closed_equivalence_output.setText(conclusion)
        self.closed_run_label.setText("分析完成")
        if pair.candidate_count > 1:
            self._set_status(
                self.closed_status_label,
                f"分析完成：该明密文对有 {pair.candidate_count} 个候选密钥。",
                "success",
            )
        else:
            self._set_status(
                self.closed_status_label,
                "分析完成：该明密文对没有多个候选密钥。",
                "normal",
            )

    def _load_closed_example(self) -> None:
        self.closed_plain_input.setText(self.EXAMPLE_DATA)
        self.closed_cipher_input.setText("00000110")
        self._set_status(
            self.closed_status_label,
            "示例已载入，可以开始封闭测试。",
            "normal",
        )
        self.mode_tabs.setCurrentIndex(3)
        self.closed_plain_input.setFocus()

    def _clear_closed_analysis(self) -> None:
        self.closed_plain_input.clear()
        self.closed_cipher_input.clear()
        self.closed_pair_output.clear()
        self.closed_collision_output.clear()
        self.closed_pair_count_label.setText("0 个候选")
        self.closed_collision_time_label.setText("0.00 ms")
        self.closed_reachable_label.setText("0 / 256")
        self.closed_excess_label.setText("0 个")
        self.closed_class_count_label.setText("0 个等价类")
        self.closed_equivalence_output.setText(
            "分析后说明相同的 (k1, k2) 如何导致主密钥等价。"
        )
        self.closed_run_label.setText("未开始")
        self._set_status(
            self.closed_status_label,
            "请输入明文和密文，然后开始分析。",
            "normal",
        )
        self.closed_plain_input.setFocus()

    def _execute(self, mode: str) -> None:
        data = self.data_input.text()
        key = self.key_input.text()
        try:
            trace = (
                trace_encrypt_block(data, key)
                if mode == "encrypt"
                else trace_decrypt_block(data, key)
            )
        except (TypeError, ValueError) as error:
            self.output_field.clear()
            self._reset_trace()
            self._set_status(self.status_label, str(error), "error")
            return

        self._show_trace(trace)
        self.output_field.setText(trace.output_bits)
        if mode == "encrypt":
            self.output_caption.setText("密文")
            self._set_status(self.status_label, "加密完成：已生成 8 bit 密文。", "success")
        else:
            self.output_caption.setText("明文")
            self._set_status(self.status_label, "解密完成：已恢复 8 bit 明文。", "success")

    def _encrypt_text(self) -> None:
        try:
            result = encrypt_ascii_text(
                self.text_plain_input.toPlainText(), self.text_key_input.text()
            )
        except (TypeError, ValueError) as error:
            self._set_status(self.text_encrypt_status, str(error), "error")
            self._clear_text_outputs()
            return

        self.text_hex_output.setText(result.ciphertext_hex)
        binary_groups = result.ciphertext_binary.split()
        binary_display = "\n".join(
            " ".join(binary_groups[index : index + 5])
            for index in range(0, len(binary_groups), 5)
        )
        self.text_binary_output.setPlainText(binary_display)
        self.text_escaped_output.setText(result.escaped_ciphertext)
        self._set_status(
            self.text_encrypt_status,
            f"加密完成：{result.block_count} 个 ASCII 字符已转换为 {result.block_count} 个 8 bit 分组。",
            "success",
        )

    def _decrypt_text(self) -> None:
        try:
            result = decrypt_ciphertext(
                self.text_cipher_input.toPlainText(),
                self.text_key_input.text(),
                self.text_format_combo.currentData(),
            )
        except (TypeError, ValueError) as error:
            self._set_status(self.text_decrypt_status, str(error), "error")
            self.text_plain_output.clear()
            self.text_plain_hex_output.clear()
            return

        self.text_plain_output.setPlainText(result.plaintext_display)
        self.text_plain_hex_output.setText(result.plaintext_hex)
        if result.is_ascii:
            message = f"解密完成：已恢复 {len(result.plaintext_bytes)} 个 ASCII 字节。"
            self._set_status(self.text_decrypt_status, message, "success")
        else:
            self._set_status(
                self.text_decrypt_status,
                "解密完成，但结果包含非 ASCII 字节，已使用 \\xNN 转义显示。",
                "error",
            )

    def _transfer_text_cipher(self) -> None:
        representation = self.text_format_combo.currentData()
        if representation == "binary":
            value = self.text_binary_output.toPlainText()
            source_name = "二进制"
        else:
            value = self.text_hex_output.text()
            source_name = "十六进制"
        if not value:
            self._set_status(self.text_encrypt_status, "请先执行文本加密。", "error")
            return
        self.text_cipher_input.setPlainText(value)
        self._set_status(
            self.text_decrypt_status,
            f"左侧{source_name}密文已送入解密区。",
            "normal",
        )

    def _copy_text_hex(self) -> None:
        value = self.text_hex_output.text()
        if not value:
            self._set_status(self.text_encrypt_status, "当前没有可复制的十六进制密文。", "error")
            return
        QApplication.clipboard().setText(value)
        self._set_status(self.text_encrypt_status, "十六进制密文已复制。", "success")

    def _copy_text_binary(self) -> None:
        value = self.text_binary_output.toPlainText()
        if not value:
            self._set_status(self.text_encrypt_status, "当前没有可复制的二进制密文。", "error")
            return
        QApplication.clipboard().setText(value)
        self._set_status(self.text_encrypt_status, "二进制密文已复制。", "success")

    def _load_text_example(self) -> None:
        self.text_plain_input.setPlainText("This is a test")
        self.text_key_input.setText(self.EXAMPLE_KEY)
        self._set_status(self.text_encrypt_status, "文本示例已载入，可以执行加密。", "normal")
        self.mode_tabs.setCurrentIndex(1)
        self.text_plain_input.setFocus()

    def _clear_text_outputs(self) -> None:
        self.text_hex_output.clear()
        self.text_binary_output.clear()
        self.text_escaped_output.clear()

    def _clear_text_page(self) -> None:
        self.text_plain_input.clear()
        self.text_key_input.clear()
        self.text_cipher_input.clear()
        self.text_plain_output.clear()
        self.text_plain_hex_output.clear()
        self._clear_text_outputs()
        self._set_status(self.text_encrypt_status, "请输入 ASCII 文本和 10 bit 密钥。", "normal")
        self._set_status(self.text_decrypt_status, "等待密文输入。", "normal")
        self.text_plain_input.setFocus()

    def _show_trace(self, trace: CipherTrace) -> None:
        decrypting = trace.mode == "decrypt"
        self.mode_label.setText("解密轨道" if decrypting else "加密轨道")
        self.key_value_labels["K"].setText(trace.key)
        self.key_value_labels["k1"].setText(trace.k1)
        self.key_value_labels["k2"].setText(trace.k2)

        stage_names = (
            "IP",
            f"fₖ₂" if decrypting else "fₖ₁",
            "SW",
            f"fₖ₁" if decrypting else "fₖ₂",
            "IP⁻¹",
        )
        stage_values = (
            trace.after_ip,
            trace.after_first_fk,
            trace.after_swap,
            trace.after_second_fk,
            trace.output_bits,
        )
        for stage, name, value in zip(
            self.trace_stages, stage_names, stage_values
        ):
            stage.name_label.setText(name)
            stage.value_label.setText(value)

    def _reset_trace(self) -> None:
        self.mode_label.setText("等待输入")
        for label in self.key_value_labels.values():
            label.setText("—")
        default_names = ("IP", "fₖ₁", "SW", "fₖ₂", "IP⁻¹")
        for stage, name in zip(self.trace_stages, default_names):
            stage.name_label.setText(name)
            stage.value_label.setText("—")
        self._set_status(
            self.status_label,
            "请输入数据分组和密钥，然后选择加密或解密。",
            "normal",
        )

    def _load_example(self) -> None:
        self.data_input.setText(self.EXAMPLE_DATA)
        self.key_input.setText(self.EXAMPLE_KEY)
        self._set_status(
            self.status_label, "示例已载入，可以直接执行加密。", "normal"
        )
        self.data_input.setFocus()

    def _clear_all(self) -> None:
        self.data_input.clear()
        self.key_input.clear()
        self.output_field.clear()
        self.output_caption.setText("输出")
        self._reset_trace()
        self.data_input.setFocus()

    def _copy_result(self) -> None:
        result = self.output_field.text()
        if not result:
            self._set_status(self.status_label, "当前没有可复制的结果。", "error")
            return
        QApplication.clipboard().setText(result)
        self._set_status(self.status_label, "结果已复制到剪贴板。", "success")

    def _set_status(self, label: QLabel, text: str, kind: str) -> None:
        object_name = {
            "success": "statusSuccess",
            "error": "statusError",
        }.get(kind, "statusLabel")
        label.setObjectName(object_name)
        label.setText(text)
        label.style().unpolish(label)
        label.style().polish(label)


def create_application(argv: list[str] | None = None) -> QApplication:
    """创建或复用 QApplication，并应用统一样式。"""

    app = QApplication.instance() or QApplication(argv or sys.argv)
    app.setApplicationName("S-DES 密码实验台")
    app.setOrganizationName("信息安全导论课程小组")
    app.setStyle("Fusion")
    app_font = QFont()
    app_font.setFamilies(["Times New Roman", "SimSun"])
    app_font.setPointSize(10)
    app.setFont(app_font)
    app.setStyleSheet(APP_STYLE)

    # 提前查询字体列表，确保首次绘制时字体回退已就绪。
    QFontDatabase.families()
    return app


def run() -> int:
    """启动桌面程序。"""

    app = create_application()
    window = SDesWindow()
    window.show()
    return app.exec()

