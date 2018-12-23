# -*- mode: python -*-

block_cipher = None


a = Analysis(['gui-thread.py'],
             pathex=['.'],
             binaries=[],
             datas=[
                 ('core/ieee_standards/*.*', 'core/ieee_standards'),
                 ('qt-gui/*.qml', 'qt-gui'),
                 ('qt-gui/images/*.*', 'qt-gui/images')
             ],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='sniffer',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          icon='qt-gui/images/icon.ico',
          console=False )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='sniffer')
