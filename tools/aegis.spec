# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller-Spec fuer AEGIS — eine einzige ausfuehrbare App (onedir).

Baut dist/AEGIS/AEGIS.exe (windowed, kein Konsolenfenster). Dieselbe Binary
uebernimmt alle Rollen per Flag (--core/--watchdog/--restart/--setup/--repin)
— gesteuert von bin/aegis_app.py. Der Endnutzer doppelklickt NUR AEGIS.exe.

Build:
  py -m PyInstaller --noconfirm --clean tools/aegis.spec
"""
import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))   # noqa: F821  (SPECPATH von PyInstaller)


def _p(*parts):
    return os.path.join(ROOT, *parts)


# ── Daten, die zur Laufzeit relativ zu Path(__file__) gefunden werden muessen ──
datas = [
    (_p('aegis2', 'ui', 'web'),               'aegis2/ui/web'),
    (_p('aegis2', 'ui', 'assets'),            'aegis2/ui/assets'),
    (_p('aegis2', 'shared', 'knowledge_seed'), 'aegis2/shared/knowledge_seed'),
    (_p('CHANGELOG.md'),                       '.'),   # actions.py: parents[2]/CHANGELOG.md
]

# ── Alle aegis2-Submodule einschliessen (deckt dynamische/bedingte Importe ab) ──
hiddenimports = collect_submodules('aegis2')
hiddenimports += [
    'psutil',
    'win32timezone',        # pywin32-Eigenheit: dynamisch von win32-Modulen geladen
    # QtWebEngine-Stack (von app/window deferred importiert)
    'PyQt6.QtWebEngineWidgets',
    'PyQt6.QtWebEngineCore',
    'PyQt6.QtWebChannel',
    'PyQt6.QtNetwork',
    'PyQt6.QtPrintSupport',
]

a = Analysis(
    [_p('bin', 'aegis_app.py')],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'numpy.distutils',
        'PySide6', 'PyQt5', 'PySide2',          # keine konkurrierenden Qt-Bindings
        'PyQt6.QtQuick', 'PyQt6.QtQml', 'PyQt6.Qt3DCore',
        # Optionale Audio-Wake-Word-Libs: in recorder.py per try/except gekapselt
        # (HAS_AUDIO). Ausschliessen vermeidet den kaputten webrtcvad-Contrib-Hook
        # (Paket heisst 'webrtcvad-wheels' -> copy_metadata('webrtcvad') schlaegt fehl)
        # und haelt das Bundle schlank. Folge: kein Mikrofon-Wake-Word in der .exe.
        'webrtcvad', 'webrtcvad_wheels', '_webrtcvad', 'pyaudio', 'pvporcupine',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,        # onedir: Binaries in den COLLECT-Ordner
    name='AEGIS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,                # windowed — kein schwarzes Konsolenfenster
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_p('aegis2', 'ui', 'assets', 'aegis.ico'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='AEGIS',
)
