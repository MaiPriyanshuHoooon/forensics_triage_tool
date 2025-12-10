# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Build Configuration
================================
Builds the forensic tool into a standalone Windows executable

Build command:
    pyinstaller forensic_tool.spec

Output:
    dist/ForensicTool.exe (standalone executable)
"""

block_cipher = None

a = Analysis(
    ['gui_launcher.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('assets', 'assets'),
        ('config', 'config'),
    ],
    hiddenimports=[
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
        'cryptography',
        'cryptography.fernet',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.backends',
        'requests',
        'pywin32',
        'win32com',
        'win32api',
        'win32con',
        'pywintypes',
        'wmi',
        'pytsk3',
        'PyPDF2',
        'python-docx',
        'openpyxl',
        'PIL',
        'pytesseract',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        '_ssl',
        '_tkinter',
        'tkinter',
        'unittest',
        'pydoc',
        'doctest',
        'test',
        'lib2to3',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ForensicTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window (GUI only)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico',  # Add your icon here
    version_file='version_info.txt',  # Windows version info
)
