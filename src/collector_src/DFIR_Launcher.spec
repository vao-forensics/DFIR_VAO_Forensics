# -*- mode: python ; coding: utf-8 -*-
# Launcher only - the payload is NOT a data file any more. It is appended to this exe as an
# uncompressed zip overlay by build_v3.py, so PyInstaller has nothing large to unpack at start.

a = Analysis(
    ['C:/DFIR/pybuild/launcher_v3.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='DFIR_Launcher',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon='C:\\DFIR\\pybuild\\collector.ico',
)
