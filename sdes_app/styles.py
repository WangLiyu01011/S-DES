"""S-DES 密码实验台的 Qt 样式。"""

APP_STYLE = """
QWidget {
    color: #202B33;
    font-family: "Times New Roman";
    font-size: 14px;
}

QMainWindow, QWidget#root {
    background: #F3F1EB;
}

QTabWidget#modeTabs::pane {
    border: none;
    background: #F3F1EB;
}

QTabBar::tab {
    min-width: 150px;
    padding: 10px 18px;
    color: #5D6B74;
    background: #E5E3DC;
    border: none;
    border-bottom: 3px solid transparent;
    font-weight: 600;
}

QTabBar::tab:hover {
    color: #11243A;
    background: #ECEAE4;
}

QTabBar::tab:selected {
    color: #11243A;
    background: #F3F1EB;
    border-bottom: 3px solid #D47732;
}

QFrame#header {
    background: #11243A;
    border: none;
}

QLabel#appTitle {
    color: #FFFFFF;
    font-size: 30px;
    font-weight: 700;
}

QLabel#appSubtitle {
    color: #B9C8D6;
    font-size: 13px;
}

QLabel#specLabel {
    color: #F3F1EB;
    background: #1B3A58;
    border: 1px solid #42637F;
    padding: 8px 12px;
    font-family: "Times New Roman";
    font-weight: 600;
}

QFrame#inputPanel, QFrame#tracePanel {
    background: #FCFBF8;
    border: 1px solid #D8D5CB;
}

QFrame#inputPanel {
    border-left: 5px solid #D47732;
}

QFrame#tracePanel {
    border-top: 5px solid #3D9CA8;
}

QFrame#bruteInputPanel, QFrame#bruteResultPanel {
    background: #FCFBF8;
    border: 1px solid #D8D5CB;
}

QFrame#bruteInputPanel {
    border-left: 5px solid #D47732;
}

QFrame#bruteResultPanel {
    border-top: 5px solid #3D9CA8;
}

QFrame#closedInputPanel, QFrame#closedResultPanel {
    background: #FCFBF8;
    border: 1px solid #D8D5CB;
}

QFrame#closedInputPanel {
    border-left: 5px solid #D47732;
}

QFrame#closedResultPanel {
    border-top: 5px solid #3D9CA8;
}

QScrollArea#closedPage {
    background: #F4F1EB;
    border: none;
}

QFrame#resultPanel {
    background: #F4F7F5;
    border: 1px solid #C9D8D4;
    border-left: 4px solid #3D9CA8;
}

QFrame#sectionDivider {
    max-height: 1px;
    color: #D8D5CB;
    background: #D8D5CB;
    border: none;
}

QLabel#sectionTitle {
    color: #11243A;
    font-size: 20px;
    font-weight: 700;
}

QLabel#sectionHint, QLabel#fieldHint, QLabel#counterLabel {
    color: #66747E;
    font-size: 12px;
}

QLabel#fieldLabel {
    color: #253847;
    font-size: 13px;
    font-weight: 600;
}

QLabel#metricValue {
    color: #11243A;
    font-size: 15px;
    font-weight: 700;
}

QLineEdit#bitInput {
    min-height: 50px;
    padding: 0 14px;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
    border-radius: 5px;
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 14px;
    font-weight: 400;
    letter-spacing: 0px;
    selection-background-color: #3D9CA8;
}

QLineEdit#bitOutput {
    min-height: 50px;
    padding: 0 14px;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
    border-radius: 5px;
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 23px;
    font-weight: 600;
    letter-spacing: 4px;
    selection-background-color: #3D9CA8;
}

QLineEdit#bitInput:focus {
    border: 2px solid #3D9CA8;
}

QLineEdit#bitOutput {
    background: #E9F1F0;
    border-color: #8DB5B5;
}

QLineEdit#compactInput {
    min-height: 36px;
    padding: 0 10px;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
    border-radius: 4px;
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 14px;
    font-weight: 400;
    letter-spacing: 0px;
}

QLineEdit#compactOutput {
    min-height: 36px;
    padding: 0 10px;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
    border-radius: 4px;
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 1px;
}

QLineEdit#compactInput:focus {
    border: 2px solid #3D9CA8;
}

QLineEdit#compactOutput {
    background: #E9F1F0;
    border-color: #8DB5B5;
}

QPlainTextEdit#textInput, QPlainTextEdit#cipherInput,
QPlainTextEdit#textOutput, QPlainTextEdit#binaryOutput {
    padding: 8px 10px;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
    border-radius: 4px;
    color: #11243A;
    font-size: 14px;
}

QPlainTextEdit#binaryOutput, QLineEdit#compactOutput {
    font-family: "Times New Roman";
    font-size: 11px;
    letter-spacing: 1px;
}

QPlainTextEdit#textInput:focus, QPlainTextEdit#cipherInput:focus {
    border: 2px solid #3D9CA8;
}

QPlainTextEdit#bruteInput, QPlainTextEdit#bruteKeysOutput {
    padding: 8px 10px;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
    border-radius: 4px;
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 14px;
}

QPlainTextEdit#bruteInput:focus {
    border: 2px solid #3D9CA8;
}

QPlainTextEdit#bruteKeysOutput {
    background: #E9F1F0;
    border-color: #8DB5B5;
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 1px;
}

QPlainTextEdit#closedOutput {
    padding: 8px 10px;
    background: #E9F1F0;
    border: 1px solid #8DB5B5;
    border-radius: 4px;
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 1px;
}

QFrame#textKeyBand {
    background: #E9E6DE;
    border-left: 5px solid #D47732;
}

QFrame#bruteResultBand, QFrame#bruteProgressBand {
    background: #F4F7F5;
    border: 1px solid #C9D8D4;
}

QFrame#bruteProgressBand {
    background: #F8F7F2;
}

QFrame#closedBand {
    background: #F4F7F5;
    border: 1px solid #C9D8D4;
}

QFrame#closedMetrics {
    background: #E9E6DE;
    border: 1px solid #D5D0C5;
}

QLabel#closedConclusion {
    color: #274558;
    font-size: 13px;
    line-height: 1.35;
}

QProgressBar#bruteProgress {
    min-height: 14px;
    max-height: 14px;
    border: 1px solid #B8C8C5;
    border-radius: 3px;
    background: #E9E6DE;
}

QProgressBar#bruteProgress::chunk {
    background: #3D9CA8;
    border-radius: 2px;
}

QFrame#encryptTextPanel, QFrame#decryptTextPanel {
    background: #FCFBF8;
    border: 1px solid #D8D5CB;
}

QFrame#encryptTextPanel {
    border-top: 5px solid #D47732;
}

QFrame#decryptTextPanel {
    border-top: 5px solid #3D9CA8;
}

QComboBox#formatCombo {
    min-height: 32px;
    padding: 0 8px;
    color: #253847;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
}

QComboBox#formatCombo:focus {
    border: 2px solid #3D9CA8;
}

QComboBox#formatCombo QAbstractItemView {
    color: #253847;
    background: #FFFFFF;
    border: 1px solid #A9B1B6;
    selection-color: #11243A;
    selection-background-color: #DCEBE8;
    outline: none;
}

QFrame#encryptTextPanel QPushButton, QFrame#decryptTextPanel QPushButton {
    min-height: 30px;
    padding: 0 12px;
}

QPushButton {
    min-height: 42px;
    padding: 0 18px;
    border-radius: 5px;
    font-weight: 600;
}

QPushButton#primaryButton {
    color: #FFFFFF;
    background: #D47732;
    border: 1px solid #B85E22;
}

QPushButton#primaryButton:hover {
    background: #E1843E;
}

QPushButton#primaryButton:pressed {
    background: #B85E22;
}

QPushButton#secondaryButton {
    color: #FFFFFF;
    background: #234C6C;
    border: 1px solid #173B58;
}

QPushButton#secondaryButton:hover {
    background: #2F628A;
}

QPushButton#quietButton {
    color: #33434E;
    background: transparent;
    border: 1px solid #AEB5B8;
}

QPushButton#quietButton:hover {
    background: #ECE9E1;
}

QPushButton#resultCopyButton {
    color: #33434E;
    background: transparent;
    border: 1px solid #AEB5B8;
    min-height: 32px;
    max-height: 32px;
    padding: 0 14px;
}

QPushButton#resultCopyButton:hover {
    background: #ECE9E1;
}

QPushButton:focus {
    outline: none;
    border: 2px solid #3D9CA8;
}

QLabel#statusLabel {
    min-height: 38px;
    padding: 8px 10px;
    background: #E8E6DF;
    border-left: 4px solid #8A969E;
    color: #46545D;
}

QLabel#statusSuccess {
    min-height: 38px;
    padding: 8px 10px;
    background: #E4EFEA;
    border-left: 4px solid #3D8B67;
    color: #245D45;
}

QLabel#statusError {
    min-height: 38px;
    padding: 8px 10px;
    background: #F6E5E1;
    border-left: 4px solid #B44E3D;
    color: #8D3428;
}

QFrame#keyStrip {
    background: #E9E6DE;
    border: none;
}

QLabel#keyName {
    color: #64717A;
    font-size: 12px;
    font-weight: 600;
}

QLabel#keyValue {
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 2px;
}

QFrame#traceStage {
    background: #FFFFFF;
    border: 1px solid #C7CBCB;
    border-bottom: 4px solid #3D9CA8;
}

QLabel#stageName {
    color: #274558;
    font-size: 13px;
    font-weight: 700;
}

QLabel#stageValue {
    color: #11243A;
    font-family: "Times New Roman";
    font-size: 17px;
    font-weight: 700;
    letter-spacing: 2px;
}

QLabel#connector {
    color: #8A969E;
    font-size: 20px;
    font-weight: 700;
}

QLabel#modeLabel {
    color: #FFFFFF;
    background: #3D9CA8;
    padding: 6px 10px;
    font-weight: 700;
}

QScrollBar:vertical {
    width: 12px;
    background: #E9E6DE;
    margin: 0;
    border-left: 1px solid #D5D0C5;
}

QScrollBar::handle:vertical {
    min-height: 42px;
    background: #B9D2D0;
    border: 1px solid #8DB5B5;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::handle:vertical:hover {
    background: #9FC2C0;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {
    background: #F4F1EB;
    border: none;
    height: 0;
}

QScrollBar:horizontal {
    height: 12px;
    background: #E9E6DE;
    margin: 0;
    border-top: 1px solid #D5D0C5;
}

QScrollBar::handle:horizontal {
    min-width: 42px;
    background: #B9D2D0;
    border: 1px solid #8DB5B5;
    border-radius: 5px;
    margin: 2px;
}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal,
QScrollBar::sub-page:horizontal {
    background: #F4F1EB;
    border: none;
    width: 0;
}

"""

