"""
GUI modules for VulnScan Pro.

Defines the shared dark-theme stylesheet and colour constants used
throughout the application.
"""
from __future__ import annotations

# ── Colour constants ───────────────────────────────────────────────────────────
BG_PRIMARY = "#0a0e1a"
BG_SECONDARY = "#0d1117"
BG_CARD = "#161b22"
BG_HOVER = "#1f2937"
BORDER = "#21262d"
BORDER_LIGHT = "#30363d"
ACCENT = "#00d4ff"
ACCENT_GREEN = "#00ff88"
ACCENT_ORANGE = "#ff8c00"
TEXT_PRIMARY = "#e6edf3"
TEXT_SECONDARY = "#8b949e"
TEXT_MUTED = "#484f58"

SEV_CRITICAL = "#ff0055"
SEV_HIGH = "#ff4444"
SEV_MEDIUM = "#ffb800"
SEV_LOW = "#00c853"
SEV_INFO = "#00d4ff"

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": SEV_CRITICAL,
    "HIGH": SEV_HIGH,
    "MEDIUM": SEV_MEDIUM,
    "LOW": SEV_LOW,
    "INFORMATIONAL": SEV_INFO,
}

DARK_STYLESHEET = f"""
/* ── Base ────────────────────────────────────────────────────────────── */
QMainWindow, QDialog, QWidget {{
    background-color: {BG_PRIMARY};
    color: {TEXT_PRIMARY};
    font-family: "Segoe UI", "SF Pro Display", Arial, sans-serif;
    font-size: 13px;
}}

/* ── Sidebar ─────────────────────────────────────────────────────────── */
#sidebar {{
    background-color: {BG_SECONDARY};
    border-right: 1px solid {BORDER};
    min-width: 220px;
    max-width: 220px;
}}
#sidebarTitle {{
    color: {ACCENT};
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 1px;
}}
#sidebarVersion {{
    color: {TEXT_MUTED};
    font-size: 10px;
}}
#navBtn {{
    background-color: transparent;
    color: {TEXT_SECONDARY};
    border: none;
    border-radius: 6px;
    padding: 10px 16px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}}
#navBtn:hover {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
}}
#navBtn[active="true"] {{
    background-color: {BG_HOVER};
    color: {ACCENT};
    border-left: 3px solid {ACCENT};
    padding-left: 13px;
}}

/* ── Cards ────────────────────────────────────────────────────────────── */
#card {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}
#pageTitle {{
    font-size: 20px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
}}
#pageSubtitle {{
    font-size: 12px;
    color: {TEXT_SECONDARY};
}}
#sectionTitle {{
    font-size: 13px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
    letter-spacing: 0.3px;
}}
#mutedLabel {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
}}

/* ── Tables ───────────────────────────────────────────────────────────── */
QTableWidget {{
    background-color: {BG_SECONDARY};
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: {BORDER};
    selection-background-color: #1f3a5f;
    selection-color: {TEXT_PRIMARY};
    alternate-background-color: {BG_CARD};
}}
QTableWidget::item {{
    padding: 6px 10px;
    border: none;
    border-bottom: 1px solid {BORDER};
}}
QTableWidget::item:selected {{
    background-color: #1f3a5f;
    color: {TEXT_PRIMARY};
}}
QHeaderView::section {{
    background-color: {BG_CARD};
    color: {TEXT_SECONDARY};
    border: none;
    border-bottom: 2px solid {ACCENT};
    padding: 8px 10px;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}}
QHeaderView::section:first {{
    border-top-left-radius: 8px;
}}

/* ── Input fields ─────────────────────────────────────────────────────── */
QLineEdit, QSpinBox, QDoubleSpinBox, QTextEdit, QPlainTextEdit {{
    background-color: {BG_SECONDARY};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 6px;
    padding: 7px 11px;
    color: {TEXT_PRIMARY};
    selection-background-color: #1f3a5f;
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus,
QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {ACCENT};
    background-color: {BG_CARD};
}}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{
    color: {TEXT_MUTED};
    background-color: {BG_PRIMARY};
}}

/* ── ComboBox ─────────────────────────────────────────────────────────── */
QComboBox {{
    background-color: {BG_SECONDARY};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 6px;
    padding: 7px 11px;
    color: {TEXT_PRIMARY};
    min-width: 120px;
}}
QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{
    border: none;
    width: 28px;
    subcontrol-position: right center;
}}
QComboBox::down-arrow {{
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {TEXT_SECONDARY};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 6px;
    selection-background-color: #1f3a5f;
    color: {TEXT_PRIMARY};
    padding: 4px;
}}

/* ── Buttons ──────────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 500;
    min-height: 32px;
}}
QPushButton:hover {{
    background-color: {BG_HOVER};
    border-color: {TEXT_SECONDARY};
}}
QPushButton:pressed {{ background-color: {BG_PRIMARY}; }}
QPushButton:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER}; }}
#primaryBtn {{
    background-color: {ACCENT};
    color: #0a0e1a;
    border: none;
    font-weight: 700;
    font-size: 13px;
}}
#primaryBtn:hover {{ background-color: #00b8e0; }}
#primaryBtn:pressed {{ background-color: #0099c0; }}
#primaryBtn:disabled {{ background-color: #1a3a4a; color: #2a5a6a; }}
#dangerBtn {{
    background-color: #da3633;
    color: white;
    border: none;
    font-weight: 600;
}}
#dangerBtn:hover {{ background-color: #b91c1c; }}
#successBtn {{
    background-color: #238636;
    color: white;
    border: none;
    font-weight: 600;
}}
#successBtn:hover {{ background-color: #2ea043; }}
#warnBtn {{
    background-color: #9e6a03;
    color: white;
    border: none;
    font-weight: 600;
}}
#warnBtn:hover {{ background-color: #bb8009; }}

/* ── Progress bar ─────────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {BORDER};
    border: none;
    border-radius: 5px;
    height: 10px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {ACCENT}, stop:1 {ACCENT_GREEN});
    border-radius: 5px;
}}

/* ── Scrollbars ───────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background-color: {BG_PRIMARY};
    width: 8px;
    border-radius: 4px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background-color: {BORDER_LIGHT};
    border-radius: 4px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background-color: {TEXT_SECONDARY}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background-color: {BG_PRIMARY};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background-color: {BORDER_LIGHT};
    border-radius: 4px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{ background-color: {TEXT_SECONDARY}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Tabs ─────────────────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    background-color: {BG_SECONDARY};
    top: -1px;
}}
QTabBar::tab {{
    background-color: {BG_PRIMARY};
    color: {TEXT_SECONDARY};
    border: 1px solid {BORDER};
    border-bottom: none;
    padding: 8px 18px;
    border-radius: 8px 8px 0 0;
    margin-right: 2px;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    background-color: {BG_SECONDARY};
    color: {ACCENT};
    border-bottom: 1px solid {BG_SECONDARY};
}}
QTabBar::tab:hover {{ background-color: {BG_CARD}; color: {TEXT_PRIMARY}; }}

/* ── Sliders ──────────────────────────────────────────────────────────── */
QSlider::groove:horizontal {{
    height: 4px;
    background-color: {BORDER_LIGHT};
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background-color: {ACCENT};
    width: 16px;
    height: 16px;
    border-radius: 8px;
    margin: -6px 0;
}}
QSlider::sub-page:horizontal {{
    background-color: {ACCENT};
    border-radius: 2px;
}}

/* ── CheckBox ─────────────────────────────────────────────────────────── */
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {BORDER_LIGHT};
    border-radius: 4px;
    background-color: {BG_SECONDARY};
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
    image: none;
}}
QCheckBox::indicator:checked::after {{
    content: "✓";
    color: black;
}}

/* ── GroupBox ─────────────────────────────────────────────────────────── */
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 12px;
    color: {TEXT_SECONDARY};
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    font-size: 11px;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}}

/* ── Splitter ─────────────────────────────────────────────────────────── */
QSplitter::handle {{ background-color: {BORDER}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

/* ── StatusBar ────────────────────────────────────────────────────────── */
QStatusBar {{
    background-color: {BG_SECONDARY};
    color: {TEXT_SECONDARY};
    border-top: 1px solid {BORDER};
    font-size: 11px;
}}
QStatusBar::item {{ border: none; }}

/* ── ToolTip ──────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}}

/* ── ListWidget ───────────────────────────────────────────────────────── */
QListWidget {{
    background-color: {BG_SECONDARY};
    border: 1px solid {BORDER};
    border-radius: 8px;
    color: {TEXT_PRIMARY};
}}
QListWidget::item {{
    padding: 6px 10px;
    border-bottom: 1px solid {BORDER};
}}
QListWidget::item:selected {{
    background-color: #1f3a5f;
    color: {TEXT_PRIMARY};
}}
QListWidget::item:hover {{
    background-color: {BG_CARD};
}}

/* ── TreeWidget ───────────────────────────────────────────────────────── */
QTreeWidget {{
    background-color: {BG_SECONDARY};
    border: 1px solid {BORDER};
    border-radius: 8px;
    color: {TEXT_PRIMARY};
    show-decoration-selected: 1;
}}
QTreeWidget::item {{
    padding: 4px 6px;
    border-bottom: 1px solid {BORDER};
}}
QTreeWidget::item:selected {{ background-color: #1f3a5f; }}
QTreeWidget::item:hover {{ background-color: {BG_CARD}; }}
QTreeWidget::branch {{ background-color: transparent; }}
"""
