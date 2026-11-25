#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用 cx_Freeze 将 boot_counter.py 与 app.ico 打包为标准 Windows MSI 安装程序包 (.msi)
运行方式：在 Windows 上双击 build_msi.bat，或执行 python setup_msi.py bdist_msi
注：MSI 元数据与快捷方式名使用纯 ASCII，避免在英文/美版 Windows 下因 ANSI 编码导致打包失败（软件内界面仍为完整中文）。
"""

import os
import sys
import cx_Freeze
from cx_Freeze import Executable, setup

# 兼容 cx_Freeze 6.x / 7.x / 8.x 的无黑框 GUI base 参数
_ver_parts = tuple(int(x) for x in cx_Freeze.__version__.split(".")[:2] if x.isdigit())
if sys.platform == "win32":
    base = "gui" if _ver_parts >= (7, 2) else "Win32GUI"
else:
    base = None

ICON_FILE = "app.ico" if os.path.exists("app.ico") else None

build_exe_options = {
    "packages": ["tkinter", "xml.etree.ElementTree"],
    "excludes": ["unittest", "http", "urllib", "test", "pydoc"],
    "include_files": ["app.ico"] if ICON_FILE else [],
    "include_msvcr": True,
    "optimize": 2,
}

bdist_msi_options = {
    "add_to_path": False,
    "initial_target_dir": r"[ProgramFiles64Folder]\BootCounter",
    "upgrade_code": "{8B3C5A92-4D17-4E91-9A2F-7F10E3C6B421}",
    "summary_data": {
        "author": "BootCounter",
        "comments": "Windows Boot and Wake Audit Counter",
    },
}
if ICON_FILE:
    bdist_msi_options["install_icon"] = ICON_FILE

executables = [
    Executable(
        script="boot_counter.py",
        base=base,
        icon=ICON_FILE,
        target_name="BootCounter.exe",
        shortcut_name="BootCounter",
        shortcut_dir="DesktopFolder",
    )
]

setup(
    name="BootCounter",
    version="1.1.0",
    description="Windows Boot and Wake Audit Counter",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options,
    },
    executables=executables,
)
