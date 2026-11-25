#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 开机与唤醒防篡改审计记录器 (BootCounter Pro)
核心特性：
1. 全面捕获开机与唤醒事件（冷启动/重启 EventID 12、快速启动 EventID 27、合盖睡眠唤醒 EventID 1 + GetTickCount64 双重检测，60 秒去重）。
2. 不可清零的「累计清除/重置次数」计数器 + 6 位防重装 Emoji 指纹（由系统加密随机数 os.urandom(32) 生成安装 ID，原始 ID 仅存日志不显示在界面）。
3. 多种保护方式自由组合：
   - 管理密码（内置系统随机数强密码生成器，一键生成/复制）
   - 手机动态口令 TOTP（首次安装向导即可直接绑定，兼容 Google / Microsoft Authenticator）
   - Windows Hello / Windows 凭据（调用原生 WinRT UserConsentVerifier 支持指纹 / 面部 / PIN）
   - 支持「任一已启用的方式通过即可清除」或「全部已启用的方式同时通过才可清除」或「完全禁止清除 / 永久锁定」
4. Windows 11 Fluent Design 界面 + Per-Monitor V2 高分屏自适应 + 后台线程异步加载与平滑细进度条（彻底告别进入主界面卡顿）。
"""

import base64
import ctypes
import hashlib
import hmac
import json
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

IS_WINDOWS = sys.platform == "win32"
IS_FROZEN = bool(getattr(sys, "frozen", False) or "__compiled__" in globals())

LANG_AUTO = "auto"
LANG_ZH = "zh"
LANG_EN = "en"
VALID_LANGS = (LANG_AUTO, LANG_ZH, LANG_EN)


def detect_system_language() -> str:
    """检测系统语言：中文系统返回 'zh'，英文及其他非中文系统一律默认返回 'en'。"""
    override = os.environ.get("BOOTCOUNTER_LANG", "").strip().lower()
    if override in (LANG_ZH, LANG_EN):
        return override
    if IS_WINDOWS:
        try:
            k32 = ctypes.windll.kernel32
            k32.GetUserDefaultUILanguage.restype = ctypes.c_uint16
            lang_id = k32.GetUserDefaultUILanguage()
            # Primary language ID 0x04 = LANG_CHINESE
            return LANG_ZH if (lang_id & 0x3FF) == 0x04 else LANG_EN
        except Exception:
            return LANG_EN
    env_lang = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").lower()
    return LANG_ZH if env_lang.startswith("zh") else LANG_EN


CURRENT_LANG = detect_system_language()


def apply_language_preference(pref: str) -> str:
    global CURRENT_LANG
    if pref == LANG_ZH:
        CURRENT_LANG = LANG_ZH
    elif pref == LANG_EN:
        CURRENT_LANG = LANG_EN
    else:
        CURRENT_LANG = detect_system_language()
    return CURRENT_LANG


def tr(zh_text: str, en_text: str) -> str:
    return zh_text if CURRENT_LANG == LANG_ZH else en_text

if IS_WINDOWS:
    import winreg

APP_NAME = "BootCounter"
REG_RUN_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_APP_PATH = r"Software\BootCounter"
BOOT_TOLERANCE_SECONDS = 120
EVENT_MERGE_WINDOW_SECONDS = 60
CLOCK_JUMP_THRESHOLD_SECONDS = 300
PBKDF2_ITERATIONS = 120_000
HMAC_APP_SECRET = b"BootCounter-Integrity-Key-v3-2026"

# 清空逻辑模式：any=任一已启用方式通过即可清除；all=全部已启用方式同时通过才可清除；disabled=完全禁止清除
CLEAR_LOGIC_ANY = "any"
CLEAR_LOGIC_ALL = "all"
CLEAR_LOGIC_DISABLED = "disabled"
VALID_CLEAR_LOGICS = (CLEAR_LOGIC_ANY, CLEAR_LOGIC_ALL, CLEAR_LOGIC_DISABLED)

METHOD_PASSWORD = "password"
METHOD_TOTP = "totp"
METHOD_WINHELLO = "windows_hello"
ALL_METHODS = (METHOD_PASSWORD, METHOD_TOTP, METHOD_WINHELLO)

# 兼容旧版常量名（供回归测试与旧状态文件平滑迁移）
CLEAR_MODE_PASSWORD = "password"
CLEAR_MODE_TOTP = "totp"
CLEAR_MODE_BOTH = "password_and_totp"
CLEAR_MODE_DISABLED = "disabled"

AUTOSTART_SILENT = "silent"
AUTOSTART_GUI = "gui"
AUTOSTART_OFF = "off"
VALID_AUTOSTART_MODES = (AUTOSTART_SILENT, AUTOSTART_GUI, AUTOSTART_OFF)

# 64 个单码位、高视觉辨识度 Emoji（恰好 2^6，6 位共 36 bit ≈ 687 亿种组合）
EMOJI_POOL_64 = (
    "🐶", "🐱", "🦊", "🐼", "🐨", "🦁", "🐸", "🐙",
    "🦋", "🐢", "🐬", "🦉", "🦄", "🐝", "🦀", "🐳",
    "🍎", "🍌", "🍉", "🍇", "🍓", "🍒", "🍑", "🍍",
    "🍕", "🍔", "🍩", "🍪", "🍿", "🎂", "🍵", "🍺",
    "⚽", "🏀", "🎾", "🎸", "🎺", "🎯", "🎲", "🧩",
    "🚗", "🚀", "🚁", "🚢", "🚲", "⚓", "🧭", "⛺",
    "🌞", "🌙", "⭐", "🌈", "🔥", "💧", "⚡", "🌊",
    "🌵", "🌻", "🍀", "🍁", "💎", "🔑", "🔔", "🎈",
)
EMOJI_FINGERPRINT_LEN = 6


def enable_windows_high_dpi() -> None:
    if not IS_WINDOWS:
        return
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        return
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def generate_os_install_id() -> str:
    """调用操作系统加密级随机数生成器 (os.urandom -> Windows BCryptGenRandom) 生成 256 位随机安装 ID。"""
    return os.urandom(32).hex()



TPM_KEY_NAME = "BootCounter_InstallKey_v1"
TPM_PROVIDER_NAME = "Microsoft Platform Crypto Provider"


def compute_self_binary_sha256() -> str:
    """计算当前运行程序本体（BootCounter.exe 或源码）的 SHA-256 哈希，用于检测程序文件是否被替换篡改。"""
    target = sys.executable if IS_FROZEN else os.path.abspath(__file__)
    h = hashlib.sha256()
    try:
        with open(target, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def dpapi_protect(plaintext: str) -> str:
    """使用 Windows DPAPI (CryptProtectData) 加密敏感字符串，不以明文落盘。"""
    if not IS_WINDOWS:
        return ""
    try:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptProtectData.restype = ctypes.c_int
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p

        raw = plaintext.encode("utf-8")
        buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        in_blob = DATA_BLOB(len(raw), buf)
        out_blob = DATA_BLOB()
        # CRYPTPROTECT_UI_FORBIDDEN = 0x1
        if not crypt32.CryptProtectData(ctypes.byref(in_blob), "BootCounter", None, None, None, 0x1, ctypes.byref(out_blob)):
            return ""
        try:
            enc_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return base64.b64encode(enc_bytes).decode("ascii")
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return ""


def dpapi_unprotect(b64_cipher: str) -> str:
    """使用 Windows DPAPI (CryptUnprotectData) 解密字符串。"""
    if not IS_WINDOWS or not b64_cipher:
        return ""
    try:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptUnprotectData.restype = ctypes.c_int
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p

        enc_bytes = base64.b64decode(b64_cipher)
        buf = (ctypes.c_ubyte * len(enc_bytes)).from_buffer_copy(enc_bytes)
        in_blob = DATA_BLOB(len(enc_bytes), buf)
        out_blob = DATA_BLOB()
        if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0x1, ctypes.byref(out_blob)):
            return ""
        try:
            raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return raw.decode("utf-8")
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return ""


def _ncrypt_setup():
    nc = ctypes.windll.ncrypt
    nc.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_wchar_p, ctypes.c_uint32]
    nc.NCryptOpenStorageProvider.restype = ctypes.c_uint32
    nc.NCryptCreatePersistedKey.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_wchar_p,
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
    ]
    nc.NCryptCreatePersistedKey.restype = ctypes.c_uint32
    nc.NCryptOpenKey.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
    ]
    nc.NCryptOpenKey.restype = ctypes.c_uint32
    nc.NCryptFinalizeKey.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    nc.NCryptFinalizeKey.restype = ctypes.c_uint32
    nc.NCryptExportKey.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
    ]
    nc.NCryptExportKey.restype = ctypes.c_uint32
    nc.NCryptDeleteKey.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    nc.NCryptDeleteKey.restype = ctypes.c_uint32
    nc.NCryptSignHash.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
    ]
    nc.NCryptSignHash.restype = ctypes.c_uint32
    nc.NCryptVerifySignature.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
    ]
    nc.NCryptVerifySignature.restype = ctypes.c_uint32
    nc.NCryptFreeObject.argtypes = [ctypes.c_void_p]
    nc.NCryptFreeObject.restype = ctypes.c_uint32
    return nc


def tpm_create_hardware_key() -> str:
    """在主板 TPM 2.0 安全芯片中生成不可导出 ECDSA-P256 密钥，返回硬件公钥 SHA-256 指纹（失败返回空串）。"""
    if not IS_WINDOWS:
        return ""
    h_prov = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    try:
        nc = _ncrypt_setup()
        if nc.NCryptOpenStorageProvider(ctypes.byref(h_prov), TPM_PROVIDER_NAME, 0) != 0:
            return ""
        # NCRYPT_OVERWRITE_KEY_FLAG = 0x80；默认不设导出标志，私钥永不可导出
        if nc.NCryptCreatePersistedKey(h_prov, ctypes.byref(h_key), "ECDSA_P256", TPM_KEY_NAME, 0, 0x80) != 0:
            return ""
        if nc.NCryptFinalizeKey(h_key, 0) != 0:
            return ""
        out_len = ctypes.c_uint32(0)
        if nc.NCryptExportKey(h_key, None, "ECCPUBLICBLOB", None, None, 0, ctypes.byref(out_len), 0) != 0 or out_len.value == 0:
            return ""
        buf = (ctypes.c_ubyte * out_len.value)()
        if nc.NCryptExportKey(h_key, None, "ECCPUBLICBLOB", None, buf, out_len.value, ctypes.byref(out_len), 0) != 0:
            return ""
        return hashlib.sha256(bytes(buf[: out_len.value])).hexdigest()
    except Exception:
        return ""
    finally:
        try:
            nc = ctypes.windll.ncrypt
            if h_key.value:
                nc.NCryptFreeObject(h_key)
            if h_prov.value:
                nc.NCryptFreeObject(h_prov)
        except Exception:
            pass


def tpm_read_hardware_key_hash() -> str:
    """读取当前主板 TPM 2.0 芯片中专属密钥的公钥 SHA-256 指纹（不存在则返回空串）。"""
    if not IS_WINDOWS:
        return ""
    h_prov = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    try:
        nc = _ncrypt_setup()
        if nc.NCryptOpenStorageProvider(ctypes.byref(h_prov), TPM_PROVIDER_NAME, 0) != 0:
            return ""
        if nc.NCryptOpenKey(h_prov, ctypes.byref(h_key), TPM_KEY_NAME, 0, 0) != 0:
            return ""
        out_len = ctypes.c_uint32(0)
        if nc.NCryptExportKey(h_key, None, "ECCPUBLICBLOB", None, None, 0, ctypes.byref(out_len), 0) != 0 or out_len.value == 0:
            return ""
        buf = (ctypes.c_ubyte * out_len.value)()
        if nc.NCryptExportKey(h_key, None, "ECCPUBLICBLOB", None, buf, out_len.value, ctypes.byref(out_len), 0) != 0:
            return ""
        return hashlib.sha256(bytes(buf[: out_len.value])).hexdigest()
    except Exception:
        return ""
    finally:
        try:
            nc = ctypes.windll.ncrypt
            if h_key.value:
                nc.NCryptFreeObject(h_key)
            if h_prov.value:
                nc.NCryptFreeObject(h_prov)
        except Exception:
            pass


def tpm_destroy_hardware_key() -> bool:
    """卸载或清理测试数据时，仅销毁本软件专属的 TPM 2.0 密钥（不影响系统任何其他功能）。"""
    if not IS_WINDOWS:
        return False
    h_prov = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    try:
        nc = _ncrypt_setup()
        if nc.NCryptOpenStorageProvider(ctypes.byref(h_prov), TPM_PROVIDER_NAME, 0) != 0:
            return False
        if nc.NCryptOpenKey(h_prov, ctypes.byref(h_key), TPM_KEY_NAME, 0, 0) != 0:
            return False
        res = nc.NCryptDeleteKey(h_key, 0)
        h_key = ctypes.c_void_p()  # NCryptDeleteKey 成功后自动释放句柄
        return res == 0
    except Exception:
        return False
    finally:
        try:
            nc = ctypes.windll.ncrypt
            if h_key.value:
                nc.NCryptFreeObject(h_key)
            if h_prov.value:
                nc.NCryptFreeObject(h_prov)
        except Exception:
            pass




class BinaryTamperError(RuntimeError):
    """程序本体完整性校验失败（与用户配置文件分离，触发后直接阻止程序运行）。"""


def tpm_sign_hash(digest_hex: str) -> str:
    """使用主板 TPM 2.0 不可导出私钥对程序本体 SHA-256 摘要做硬件 ECDSA-P256 签名（返回 Base64）。"""
    if not IS_WINDOWS or not digest_hex:
        return ""
    h_prov = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    try:
        digest = bytes.fromhex(digest_hex)
        nc = _ncrypt_setup()
        if nc.NCryptOpenStorageProvider(ctypes.byref(h_prov), TPM_PROVIDER_NAME, 0) != 0:
            return ""
        if nc.NCryptOpenKey(h_prov, ctypes.byref(h_key), TPM_KEY_NAME, 0, 0) != 0:
            return ""
        hash_buf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        sig_len = ctypes.c_uint32(0)
        if nc.NCryptSignHash(h_key, None, hash_buf, len(digest), None, 0, ctypes.byref(sig_len), 0) != 0 or sig_len.value == 0:
            return ""
        sig_buf = (ctypes.c_ubyte * sig_len.value)()
        if nc.NCryptSignHash(h_key, None, hash_buf, len(digest), sig_buf, sig_len.value, ctypes.byref(sig_len), 0) != 0:
            return ""
        return base64.b64encode(bytes(sig_buf[: sig_len.value])).decode("ascii")
    except Exception:
        return ""
    finally:
        try:
            nc = ctypes.windll.ncrypt
            if h_key.value:
                nc.NCryptFreeObject(h_key)
            if h_prov.value:
                nc.NCryptFreeObject(h_prov)
        except Exception:
            pass


def tpm_verify_hash_signature(digest_hex: str, sig_b64: str) -> bool:
    """使用主板 TPM 2.0 硬件密钥验证程序本体 SHA-256 摘要的硬件签名。"""
    if not IS_WINDOWS or not digest_hex or not sig_b64:
        return False
    h_prov = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    try:
        digest = bytes.fromhex(digest_hex)
        sig = base64.b64decode(sig_b64)
        nc = _ncrypt_setup()
        if nc.NCryptOpenStorageProvider(ctypes.byref(h_prov), TPM_PROVIDER_NAME, 0) != 0:
            return False
        if nc.NCryptOpenKey(h_prov, ctypes.byref(h_key), TPM_KEY_NAME, 0, 0) != 0:
            return False
        hash_buf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        sig_buf = (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig)
        return nc.NCryptVerifySignature(h_key, None, hash_buf, len(digest), sig_buf, len(sig), 0) == 0
    except Exception:
        return False
    finally:
        try:
            nc = ctypes.windll.ncrypt
            if h_key.value:
                nc.NCryptFreeObject(h_key)
            if h_prov.value:
                nc.NCryptFreeObject(h_prov)
        except Exception:
            pass


def check_debugger_attached() -> str:
    """检测是否挂载了调试器或断点追踪器（IsDebuggerPresent / CheckRemoteDebuggerPresent / sys.gettrace）。"""
    if sys.gettrace() is not None:
        return tr("检测到 Python 调试器或断点追踪器", "Python debugger or breakpoint tracer detected")
    if IS_WINDOWS:
        try:
            k32 = ctypes.windll.kernel32
            k32.IsDebuggerPresent.restype = ctypes.c_int
            if k32.IsDebuggerPresent():
                return tr("检测到 Windows 用户态调试器附加", "Windows user-mode debugger attached")
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            k32.CheckRemoteDebuggerPresent.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            k32.CheckRemoteDebuggerPresent.restype = ctypes.c_int
            is_dbg = ctypes.c_int(0)
            if k32.CheckRemoteDebuggerPresent(k32.GetCurrentProcess(), ctypes.byref(is_dbg)) and is_dbg.value:
                return tr("检测到远程调试器附加", "Remote debugger attached")
        except Exception:
            pass
    return ""


def harden_process_anti_debug() -> None:
    """调用 NtSetInformationThread(ThreadHideFromDebugger) 隐藏当前线程以抵御附加调试与断点。"""
    if not IS_WINDOWS:
        return
    try:
        k32 = ctypes.windll.kernel32
        k32.GetCurrentThread.restype = ctypes.c_void_p
        ntdll = ctypes.windll.ntdll
        ntdll.NtSetInformationThread.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
        ntdll.NtSetInformationThread.restype = ctypes.c_uint32
        # ThreadHideFromDebugger = 0x11
        ntdll.NtSetInformationThread(k32.GetCurrentThread(), 0x11, None, 0)
    except Exception:
        pass


def generate_strong_password(length: int = 16) -> str:
    """使用操作系统加密随机数生成器生成强密码（含大小写字母、数字与易读符号，避开 0/O/1/l/I 混淆字符）。"""
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lower = "abcdefghijkmnopqrstuvwxyz"
    digits = "23456789"
    symbols = "!@#$%^&*-_=+"
    pool = upper + lower + digits + symbols

    def _pick(charset: str) -> str:
        # 拒绝采样避免取模偏差
        limit = (256 // len(charset)) * len(charset)
        while True:
            b = os.urandom(1)[0]
            if b < limit:
                return charset[b % len(charset)]

    chars = [_pick(upper), _pick(lower), _pick(digits), _pick(symbols)]
    while len(chars) < max(8, int(length)):
        chars.append(_pick(pool))

    # 使用系统随机字节进行 Fisher-Yates 洗牌
    for i in range(len(chars) - 1, 0, -1):
        j = int.from_bytes(os.urandom(2), "big") % (i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def derive_emoji_fingerprint(
    install_id: str, install_seal: str = "", tpm_pub_hash: str = "", count: int = EMOJI_FINGERPRINT_LEN
) -> str:
    digest = hashlib.sha256(f"BootCounter-Emoji-FP-v3:{install_id}:{install_seal}:{tpm_pub_hash}".encode("utf-8")).digest()
    bits_val = int.from_bytes(digest[:8], "big")
    return " ".join(EMOJI_POOL_64[(bits_val >> (i * 6)) & 0x3F] for i in range(count))


# =========================
# Windows Hello / Windows 凭据原生验证
# =========================
def check_windows_hello_available() -> tuple:
    """检测本机是否支持并配置了 Windows Hello。返回 (is_available: bool, detail: str)。"""
    if not IS_WINDOWS:
        return False, "非 Windows 系统"
    ps_script = (
        "[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null; "
        "$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync(); "
        "while ($op.Status -eq 'Started') { Start-Sleep -Milliseconds 50 }; "
        "Write-Output $op.GetResults()"
    )
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
            creationflags=creationflags,
        )
        res = (proc.stdout or "").strip()
        if "Available" in res:
            return True, "Windows Hello 已就绪（支持指纹 / 面部 / PIN）"
        return False, f"Windows Hello 当前不可用（状态：{res or '未配置'}）"
    except Exception as exc:
        return False, f"无法检测 Windows Hello：{exc}"


def verify_windows_hello(reason: str = "BootCounter 安全验证：请通过 Windows Hello验证身份") -> tuple:
    """弹出原生 Windows Hello 验证框。返回 (verified: bool, message: str)。"""
    if not IS_WINDOWS:
        return False, "当前非 Windows 系统，无法调用 Windows Hello。"
    safe_reason = reason.replace("'", "''").replace('"', "")
    ps_script = (
        "[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null; "
        f"$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('{safe_reason}'); "
        "while ($op.Status -eq 'Started') { Start-Sleep -Milliseconds 80 }; "
        "Write-Output $op.GetResults()"
    )
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=90,
            creationflags=creationflags,
        )
        res = (proc.stdout or "").strip()
        if res == "Verified":
            return True, "Windows Hello 验证通过"
        if "Canceled" in res:
            return False, "已取消 Windows Hello 验证。"
        if "NotConfiguredForUser" in res or "DeviceNotPresent" in res:
            return False, "本机未配置 Windows Hello（PIN / 指纹 / 面部），请在 Windows 设置 -> 账户 -> 登录选项中开启。"
        return False, f"Windows Hello 验证未通过（返回：{res or '未知错误'}）。"
    except subprocess.TimeoutExpired:
        return False, "Windows Hello 验证超时。"
    except Exception as exc:
        return False, f"调用 Windows Hello 失败：{exc}"


# =========================
# 加密与 RFC 6238 动态口令
# =========================
def generate_totp_secret(num_bytes: int = 20) -> str:
    return base64.b32encode(os.urandom(num_bytes)).decode("ascii").rstrip("=")


def _normalize_b32_secret(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    padding = (-len(cleaned)) % 8
    return base64.b32decode(cleaned + ("=" * padding), casefold=True)


def generate_totp_code(secret: str, for_time: float = None, interval: int = 30, digits: int = 6) -> str:
    ts = time.time() if for_time is None else float(for_time)
    counter = int(ts // interval)
    key = _normalize_b32_secret(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def verify_totp_code(secret: str, code: str, for_time: float = None, interval: int = 30, window: int = 1) -> bool:
    if not secret or not code:
        return False
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != 6:
        return False
    ts = time.time() if for_time is None else float(for_time)
    for step_offset in range(-window, window + 1):
        expected = generate_totp_code(secret, for_time=ts + step_offset * interval, interval=interval)
        if hmac.compare_digest(cleaned, expected):
            return True
    return False



# =========================
# 纯 Python 二维码生成 (ISO/IEC 18004, 零依赖)
# =========================
# GF(256) tables for Reed-Solomon (primitive polynomial 0x11d)
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    return 0 if (a == 0 or b == 0) else _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_gen_poly(deg: int) -> list:
    poly = [1]
    for i in range(deg):
        nxt = [0] * (len(poly) + 1)
        g = _GF_EXP[i]
        for j, c in enumerate(poly):
            nxt[j] ^= c
            nxt[j + 1] ^= _gf_mul(c, g)
        poly = nxt
    return poly


def _rs_encode(data: list, ecc_len: int) -> list:
    gen = _rs_gen_poly(ecc_len)
    res = list(data) + [0] * ecc_len
    for i in range(len(data)):
        coef = res[i]
        if coef != 0:
            for j in range(1, len(gen)):
                res[i + j] ^= _gf_mul(gen[j], coef)
    return res[len(data):]


# QR Versions 1..10 at ECC Level M:
# (version, total_data_codewords, ecc_per_block, g1_blocks, g1_data_cw, g2_blocks, g2_data_cw, alignment_centers)
_QR_M_SPECS = (
    (1, 16, 10, 1, 16, 0, 0, ()),
    (2, 28, 16, 1, 28, 0, 0, (6, 18)),
    (3, 44, 26, 1, 44, 0, 0, (6, 22)),
    (4, 64, 18, 2, 32, 0, 0, (6, 26)),
    (5, 86, 24, 2, 43, 0, 0, (6, 30)),
    (6, 108, 16, 4, 27, 0, 0, (6, 34)),
    (7, 124, 18, 4, 31, 0, 0, (6, 22, 38)),
    (8, 154, 22, 2, 38, 2, 39, (6, 24, 42)),
    (9, 182, 22, 3, 36, 2, 37, (6, 26, 46)),
    (10, 216, 26, 4, 43, 1, 44, (6, 28, 50)),
)


def _bch_format_bits(ecc_bits: int, mask_id: int) -> int:
    data = (ecc_bits << 3) | mask_id
    rem = data << 10
    for i in range(4, -1, -1):
        if rem & (1 << (i + 10)):
            rem ^= 0x537 << i
    return ((data << 10) | rem) ^ 0x5412


def _bch_version_bits(ver: int) -> int:
    rem = ver << 12
    for i in range(5, -1, -1):
        if rem & (1 << (i + 12)):
            rem ^= 0x1F25 << i
    return (ver << 12) | rem


def generate_qr_matrix(text: str) -> list:
    """纯 Python 生成标准 ISO/IEC 18004 二维码布尔矩阵（ECC Level M，支持 Version 1–10）。"""
    raw = text.encode("utf-8")
    spec = None
    for s in _QR_M_SPECS:
        ver, total_dc = s[0], s[1]
        count_bits = 8 if ver <= 9 else 16
        if (4 + count_bits + len(raw) * 8) <= total_dc * 8:
            spec = s
            break
    if spec is None:
        raise ValueError("二维码内容过长")

    ver, total_dc, ecc_len, g1_cnt, g1_dc, g2_cnt, g2_dc, aligns = spec
    size = ver * 4 + 17

    # 1. Encode byte-mode bitstream
    bits = []
    def _push(val: int, nbits: int):
        for k in range(nbits - 1, -1, -1):
            bits.append((val >> k) & 1)

    _push(0b0100, 4)  # Byte mode
    _push(len(raw), 8 if ver <= 9 else 16)
    for b in raw:
        _push(b, 8)
    rem_bits = total_dc * 8 - len(bits)
    _push(0, min(4, rem_bits))
    while len(bits) % 8 != 0:
        bits.append(0)
    codewords = []
    for i in range(0, len(bits), 8):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i + j]
        codewords.append(v)
    pad = (0xEC, 0x11)
    idx = 0
    while len(codewords) < total_dc:
        codewords.append(pad[idx & 1])
        idx += 1

    # 2. Split into RS blocks & interleave
    data_blocks = []
    ecc_blocks = []
    pos = 0
    for _ in range(g1_cnt):
        blk = codewords[pos : pos + g1_dc]
        pos += g1_dc
        data_blocks.append(blk)
        ecc_blocks.append(_rs_encode(blk, ecc_len))
    for _ in range(g2_cnt):
        blk = codewords[pos : pos + g2_dc]
        pos += g2_dc
        data_blocks.append(blk)
        ecc_blocks.append(_rs_encode(blk, ecc_len))

    final_bytes = []
    max_dc = max(len(b) for b in data_blocks)
    for i in range(max_dc):
        for blk in data_blocks:
            if i < len(blk):
                final_bytes.append(blk[i])
    for i in range(ecc_len):
        for blk in ecc_blocks:
            final_bytes.append(blk[i])

    # 3. Build function patterns
    mat = [[False] * size for _ in range(size)]
    is_func = [[False] * size for _ in range(size)]

    def _set_func(r: int, c: int, val: bool):
        mat[r][c] = val
        is_func[r][c] = True

    # Finder patterns + separators
    for fr, fc in ((0, 0), (0, size - 7), (size - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = fr + dr, fc + dc
                if 0 <= rr < size and 0 <= cc < size:
                    in_outer = 0 <= dr <= 6 and 0 <= dc <= 6
                    on_border = dr in (0, 6) or dc in (0, 6)
                    in_center = 2 <= dr <= 4 and 2 <= dc <= 4
                    _set_func(rr, cc, in_outer and (on_border or in_center))

    # Timing patterns
    for i in range(8, size - 8):
        _set_func(6, i, i % 2 == 0)
        _set_func(i, 6, i % 2 == 0)

    # Alignment patterns (skip only the 3 corners overlapping finder patterns)
    for ar in aligns:
        for ac in aligns:
            if (ar == aligns[0] and ac == aligns[0]) or (ar == aligns[0] and ac == aligns[-1]) or (ar == aligns[-1] and ac == aligns[0]):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    _set_func(ar + dr, ac + dc, max(abs(dr), abs(dc)) != 1)

    # Dark module & reserve format info
    _set_func(size - 8, 8, True)
    for i in range(9):
        if i != 6:
            is_func[8][i] = True
            is_func[i][8] = True
    for i in range(8):
        is_func[8][size - 1 - i] = True
        is_func[size - 1 - i][8] = True

    # Version info for V >= 7
    if ver >= 7:
        vbits = _bch_version_bits(ver)
        for i in range(18):
            bit = bool((vbits >> i) & 1)
            a, b = size - 11 + (i % 3), i // 3
            _set_func(a, b, bit)
            _set_func(b, a, bit)

    # 4. Place data bits (zigzag upward/downward)
    bit_idx = 0
    total_bits = len(final_bytes) * 8
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for r in rows:
            for dc in (0, -1):
                c = col + dc
                if not is_func[r][c]:
                    if bit_idx < total_bits:
                        bval = (final_bytes[bit_idx >> 3] >> (7 - (bit_idx & 7))) & 1
                        mat[r][c] = bool(bval)
                    else:
                        mat[r][c] = False
                    bit_idx += 1
        col -= 2
        upward = not upward

    # 5. Apply mask 0..7 and pick lowest penalty (mask 0..7)
    def _mask_cond(m: int, r: int, c: int) -> bool:
        if m == 0: return (r + c) % 2 == 0
        if m == 1: return r % 2 == 0
        if m == 2: return c % 3 == 0
        if m == 3: return (r + c) % 3 == 0
        if m == 4: return ((r // 2) + (c // 3)) % 2 == 0
        if m == 5: return ((r * c) % 2) + ((r * c) % 3) == 0
        if m == 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 == 0
        return (((r + c) % 2) + ((r * c) % 3)) % 2 == 0

    best_mat = None
    best_score = 10**18
    for m in range(8):
        cand = [row[:] for row in mat]
        for r in range(size):
            for c in range(size):
                if not is_func[r][c] and _mask_cond(m, r, c):
                    cand[r][c] = not cand[r][c]
        # Write format info (ECC M = 0b00)
        fbits = _bch_format_bits(0b00, m)
        # Copy 1 (around top-left finder): bits 14..0
        for i in range(6):
            cand[8][i] = bool((fbits >> (14 - i)) & 1)
        cand[8][7] = bool((fbits >> 8) & 1)
        cand[8][8] = bool((fbits >> 7) & 1)
        cand[7][8] = bool((fbits >> 6) & 1)
        for i in range(6):
            cand[5 - i][8] = bool((fbits >> (5 - i)) & 1)
        # Copy 2 (bottom-left vertical bits 14..8, top-right horizontal bits 7..0)
        for i in range(7):
            cand[size - 1 - i][8] = bool((fbits >> (14 - i)) & 1)
        for i in range(8):
            cand[8][size - 8 + i] = bool((fbits >> (7 - i)) & 1)

        # Simple penalty (runs + 2x2 blocks + balance)
        dark = sum(sum(1 for v in row if v) for row in cand)
        score = abs(dark * 20 - size * size * 10)
        for r in range(size - 1):
            for c in range(size - 1):
                if cand[r][c] == cand[r][c + 1] == cand[r + 1][c] == cand[r + 1][c + 1]:
                    score += 3
        if score < best_score:
            best_score = score
            best_mat = cand

    return best_mat

def build_otpauth_uri(secret: str, account_name: str = "BootCounter", issuer: str = "BootCounter") -> str:
    return f"otpauth://totp/{issuer}:{account_name}?secret={secret}&issuer={issuer}&digits=6&period=30"


def _derive_enc_keys(key_material: str, salt_hex: str):
    salt = bytes.fromhex(salt_hex)
    material = hashlib.pbkdf2_hmac("sha256", key_material.encode("utf-8"), salt + b":totp-enc", PBKDF2_ITERATIONS, dklen=64)
    return material[:32], material[32:]


def encrypt_secret(plaintext: str, key_material: str) -> dict:
    salt_hex = os.urandom(16).hex()
    nonce = os.urandom(16)
    enc_key, mac_key = _derive_enc_keys(key_material, salt_hex)
    data = plaintext.encode("utf-8")
    keystream = bytearray()
    block_idx = 0
    while len(keystream) < len(data):
        keystream.extend(hashlib.sha256(enc_key + nonce + struct.pack(">I", block_idx)).digest())
        block_idx += 1
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).hexdigest()
    return {
        "salt": salt_hex,
        "nonce": nonce.hex(),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
        "tag": tag,
    }


def decrypt_secret(enc_blob: dict, key_material: str) -> str:
    if not enc_blob or not isinstance(enc_blob, dict):
        raise ValueError("未找到加密密钥数据")
    salt_hex = enc_blob.get("salt", "")
    nonce = bytes.fromhex(enc_blob.get("nonce", ""))
    ciphertext = base64.b64decode(enc_blob.get("ct", ""))
    expected_tag = enc_blob.get("tag", "")
    enc_key, mac_key = _derive_enc_keys(key_material, salt_hex)
    actual_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise ValueError("密钥解密失败（凭据错误或数据已被篡改）")
    keystream = bytearray()
    block_idx = 0
    while len(keystream) < len(ciphertext):
        keystream.extend(hashlib.sha256(enc_key + nonce + struct.pack(">I", block_idx)).digest())
        block_idx += 1
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    return plaintext.decode("utf-8")


# 兼容旧函数名
encrypt_secret_with_password = encrypt_secret
decrypt_secret_with_password = decrypt_secret


# =========================
# 系统开机、唤醒与防篡改事件检测
# =========================
def get_system_boot_epoch() -> float:
    if IS_WINDOWS:
        kernel32 = ctypes.windll.kernel32
        kernel32.GetTickCount64.restype = ctypes.c_uint64
        uptime_ms = kernel32.GetTickCount64()
        return time.time() - (uptime_ms / 1000.0)
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            uptime_sec = float(f.read().split()[0])
        return time.time() - uptime_sec
    except OSError:
        return time.time()


def _parse_iso_utc_to_epoch(iso_str: str) -> float:
    s = iso_str.strip()
    if s.endswith("Z"):
        s = s[:-1]
    if "." in s:
        main_part, frac_part = s.split(".", 1)
        frac_part = (frac_part[:6]).ljust(6, "0")
        s = f"{main_part}.{frac_part}"
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
    else:
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _run_wevtutil_xml(xpath: str, max_events: int = 200, timeout: int = 10):
    if not IS_WINDOWS:
        return []
    cmd = ["wevtutil", "qe", "System", f"/q:{xpath}", "/f:xml", f"/c:{max_events}", "/rd:true"]
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            creationflags=creationflags,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        root = ET.fromstring(f"<Events>{proc.stdout}</Events>")
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        return root.findall("e:Event", ns)
    except (OSError, subprocess.SubprocessError, ET.ParseError):
        return []


def query_windows_system_events(since_epoch: float, since_record_id: int = 0, include_sleep_wake: bool = True) -> dict:
    result = {"power_events": [], "anomalies": [], "max_record_id": since_record_id}
    if not IS_WINDOWS:
        return result

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    power_conditions = [
        "(EventID=12 and Provider[@Name='Microsoft-Windows-Kernel-General'])",
        "(EventID=27 and Provider[@Name='Microsoft-Windows-Kernel-Boot'])",
        "(EventID=104 and Provider[@Name='Microsoft-Windows-Eventlog'])",
    ]
    if include_sleep_wake:
        power_conditions.append("(EventID=1 and Provider[@Name='Microsoft-Windows-Power-Troubleshooter'])")

    power_nodes = _run_wevtutil_xml(f"*[System[{' or '.join(power_conditions)}]]", max_events=300)
    clock_nodes = _run_wevtutil_xml(
        "*[System[(EventID=1 and Provider[@Name='Microsoft-Windows-Kernel-General'])]]",
        max_events=100,
    )

    for ev in power_nodes + clock_nodes:
        sys_node = ev.find("e:System", ns)
        if sys_node is None:
            continue
        provider_node = sys_node.find("e:Provider", ns)
        event_id_node = sys_node.find("e:EventID", ns)
        time_node = sys_node.find("e:TimeCreated", ns)
        rec_node = sys_node.find("e:EventRecordID", ns)
        if provider_node is None or event_id_node is None or time_node is None:
            continue

        provider = provider_node.attrib.get("Name", "")
        event_id = event_id_node.text.strip() if event_id_node.text else ""
        sys_time = time_node.attrib.get("SystemTime", "")
        record_id = int(rec_node.text.strip()) if (rec_node is not None and rec_node.text and rec_node.text.strip().isdigit()) else 0

        if record_id > result["max_record_id"]:
            result["max_record_id"] = record_id

        try:
            ev_epoch = _parse_iso_utc_to_epoch(sys_time)
        except ValueError:
            continue

        is_new = (ev_epoch > since_epoch) or (since_record_id > 0 and record_id > since_record_id)
        if not is_new:
            continue

        if provider == "Microsoft-Windows-Eventlog" and event_id == "104":
            result["anomalies"].append(
                {
                    "epoch": round(ev_epoch, 2),
                    "record_id": record_id,
                    "kind": "log_cleared",
                    "label": tr("严重异常：Windows 系统事件日志曾被人工清空（EventID 104）", "Critical Alert: Windows System Event Log was cleared (EventID 104)"),
                }
            )
            continue

        if provider == "Microsoft-Windows-Kernel-General" and event_id == "1":
            old_t = new_t = None
            ed = ev.find("e:EventData", ns)
            if ed is not None:
                for d in ed.findall("e:Data", ns):
                    name = d.attrib.get("Name", "")
                    if name == "OldTime" and d.text:
                        try:
                            old_t = _parse_iso_utc_to_epoch(d.text)
                        except ValueError:
                            pass
                    elif name == "NewTime" and d.text:
                        try:
                            new_t = _parse_iso_utc_to_epoch(d.text)
                        except ValueError:
                            pass
            if old_t is not None and new_t is not None and abs(new_t - old_t) >= CLOCK_JUMP_THRESHOLD_SECONDS:
                diff_min = int(abs(new_t - old_t) // 60)
                result["anomalies"].append(
                    {
                        "epoch": round(ev_epoch, 2),
                        "record_id": record_id,
                        "kind": "clock_tamper",
                        "label": tr(f"可疑异常：系统时间被手动修改（跳变约 {diff_min} 分钟）", f"Suspicious Alert: System clock changed manually (jump ~{diff_min} min)"),
                    }
                )
            continue

        if provider == "Microsoft-Windows-Power-Troubleshooter" and event_id == "1":
            kind, label = "sleep_wake", tr("睡眠/合盖唤醒", "Sleep / Lid Wake")
        elif provider == "Microsoft-Windows-Kernel-Boot" and event_id == "27":
            kind, label = "fast_boot", tr("关机后开机（含快速启动）", "Power On (Fast Startup)")
        else:
            kind, label = "cold_boot", tr("冷启动/重启开机", "Cold Boot / Restart")

        result["power_events"].append(
            {"epoch": round(ev_epoch, 2), "record_id": record_id, "kind": kind, "label": label}
        )

    result["power_events"].sort(key=lambda x: (x["record_id"], x["epoch"]))
    result["anomalies"].sort(key=lambda x: (x["record_id"], x["epoch"]))
    return result


def get_latest_system_record_id() -> int:
    if not IS_WINDOWS:
        return 0
    nodes = _run_wevtutil_xml("*", max_events=1, timeout=4)
    if not nodes:
        return 0
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    sys_node = nodes[0].find("e:System", ns)
    if sys_node is None:
        return 0
    rec_node = sys_node.find("e:EventRecordID", ns)
    if rec_node is not None and rec_node.text and rec_node.text.strip().isdigit():
        return int(rec_node.text.strip())
    return 0


def format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return dk.hex()


# =========================
# Windows 开机自启与资源路径管理
# =========================
def get_executable_command(mode: str = AUTOSTART_SILENT) -> str:
    if mode not in (AUTOSTART_SILENT, AUTOSTART_GUI):
        raise ValueError("无效的自启命令模式")
    flag = " --boot" if mode == AUTOSTART_SILENT else ""
    if IS_FROZEN:
        return f'"{sys.executable}"{flag}'
    script_path = os.path.abspath(__file__)
    pythonw = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable
    return f'"{pythonw}" "{script_path}"{flag}'


def get_registered_autostart_command() -> str:
    if not IS_WINDOWS:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_NAME)
            return str(val or "")
    except OSError:
        return ""


def get_autostart_mode() -> str:
    cmd = get_registered_autostart_command()
    if not cmd:
        return AUTOSTART_OFF
    if "--boot" in cmd:
        return AUTOSTART_SILENT
    return AUTOSTART_GUI


def set_autostart_mode(mode: str) -> bool:
    if mode not in VALID_AUTOSTART_MODES:
        raise ValueError("无效的开机自启模式")
    if not IS_WINDOWS:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0, winreg.KEY_SET_VALUE) as key:
            if mode == AUTOSTART_OFF:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, get_executable_command(mode))
        return True
    except OSError:
        return False


def refresh_autostart_path_if_needed(preferred_mode: str = AUTOSTART_SILENT) -> None:
    if not IS_WINDOWS or preferred_mode == AUTOSTART_OFF:
        return
    expected_cmd = get_executable_command(preferred_mode)
    current_cmd = get_registered_autostart_command()
    if current_cmd != expected_cmd:
        set_autostart_mode(preferred_mode)


def get_resource_path(filename: str) -> str:
    candidates = []
    if IS_FROZEN:
        candidates.append(os.path.dirname(sys.executable))
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(meipass)
    candidates.append(os.path.dirname(os.path.abspath(__file__)))
    for base in candidates:
        full = os.path.join(base, filename)
        if os.path.exists(full):
            return full
    return ""


def get_install_seal() -> str:
    """读取每次安装时由安装程序写入安装目录的独立封条（重装后封条必变，防止备份 state.json 覆盖绕过）。"""
    seal_path = get_resource_path("install_seal.dat")
    if seal_path:
        try:
            with open(seal_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            pass
    return ""


def get_default_data_path() -> str:
    if IS_WINDOWS:
        base_dir = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base_dir, APP_NAME, "state.json")
    return os.path.join(os.path.expanduser("~"), ".boot_counter", "state.json")


class BootCounterStore:
    """防篡改开机与唤醒审计状态管理（支持多保护方式组合：密码 / TOTP / Windows Hello）。"""

    def __init__(self, data_path: str = None, use_registry: bool = IS_WINDOWS):
        self.data_path = data_path or get_default_data_path()
        self.log_path = os.path.join(os.path.dirname(self.data_path), "audit.log")
        self.use_registry = use_registry and IS_WINDOWS
        self.state = None
        self.tampered = False
        self.tamper_reasons = []

    @staticmethod
    def _compute_hmac(payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hmac.new(HMAC_APP_SECRET, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _compute_entry_hash(prev_hash: str, entry: dict) -> str:
        raw = f"{prev_hash}|{entry.get('time')}|{entry.get('event')}|{entry.get('count_after')}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def _verify_hash_chain(self, history: list, base_hash: str = "GENESIS") -> bool:
        prev = base_hash or "GENESIS"
        for item in history:
            if "hash" not in item:
                continue
            expected = self._compute_entry_hash(prev, item)
            if not hmac.compare_digest(item.get("hash", ""), expected):
                return False
            prev = item["hash"]
        return True

    def _totp_enc_key(self) -> str:
        """基于本机安装 ID 与应用密钥派生的加密口令，避免 TOTP 密钥明文落盘，同时支持独立 TOTP 验证。"""
        iid = self._get_effective_install_id()
        return f"{iid}:{HMAC_APP_SECRET.decode('ascii')}"

    def _write_audit_log(self, action: str, detail: str = "") -> None:
        if not self.state:
            return
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        line = (
            f"[{format_timestamp(time.time())}] "
            f"INSTALL_ID={self._get_effective_install_id() or '-'} | "
            f"EMOJI={self.get_emoji_fingerprint()} | "
            f"BOOT_COUNT={self.state.get('boot_count', 0)} | "
            f"RESET_COUNT={self.state.get('reset_count', 0)} | "
            f"ACTION={action}"
            + (f" | {detail}" if detail else "")
            + "\n"
        )
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass

    def _get_effective_install_id(self, data: dict = None) -> str:
        d = data if data is not None else (self.state or {})
        if d.get("install_id_dpapi") and IS_WINDOWS:
            plain = dpapi_unprotect(d["install_id_dpapi"])
            if plain:
                return plain
        return d.get("install_id", "")

    def get_emoji_fingerprint(self) -> str:
        if not self.state:
            return ""
        iid = self._get_effective_install_id()
        if not iid:
            return ""
        seal = get_install_seal() or self.state.get("install_seal", "")
        tpm_h = self.state.get("tpm_pub_hash", "")
        return derive_emoji_fingerprint(iid, seal, tpm_h)

    def verify_binary_integrity_or_raise(self) -> None:
        """严格校验程序本体 SHA-256（含 DPAPI 解密与 TPM 2.0 硬件签名验签）。仅程序本体被篡改时抛 BinaryTamperError 阻止运行，不影响修改密码等配置操作。"""
        if not self.state:
            return
        cur_sha = compute_self_binary_sha256()
        if not cur_sha:
            return
        stored_dpapi = self.state.get("app_binary_sha256_dpapi", "")
        stored_plain = self.state.get("app_binary_sha256", "")
        stored_tpm_sig = self.state.get("app_binary_tpm_sig", "")

        expected_sha = dpapi_unprotect(stored_dpapi) if (stored_dpapi and IS_WINDOWS) else stored_plain
        if stored_dpapi and IS_WINDOWS and not expected_sha:
            self._write_audit_log("BINARY_TAMPER_BLOCKED", "DPAPI 程序哈希解密失败")
            raise BinaryTamperError(tr("程序完整性校验失败：无法解密已绑定的程序 SHA-256 指纹，已停止运行。", "Integrity check failed: unable to decrypt bound binary SHA-256. Execution halted."))

        if expected_sha and not hmac.compare_digest(expected_sha, cur_sha):
            self._write_audit_log("BINARY_TAMPER_BLOCKED", f"expected={expected_sha[:16]} actual={cur_sha[:16]}")
            raise BinaryTamperError(tr("程序完整性校验失败：检测到程序本体文件已被修改或替换，已拒绝运行。", "Integrity check failed: application binary has been modified or replaced. Execution halted."))

        if stored_tpm_sig and IS_WINDOWS:
            if not tpm_verify_hash_signature(cur_sha, stored_tpm_sig):
                self._write_audit_log("BINARY_TAMPER_BLOCKED", "TPM 2.0 硬件签名验签失败")
                raise BinaryTamperError(tr("程序完整性校验失败：主板 TPM 2.0 硬件签名验证未通过，程序可能已被篡改，已停止运行。", "Integrity check failed: TPM 2.0 hardware signature verification failed. Execution halted."))

    def exists(self) -> bool:
        return os.path.exists(self.data_path)

    def _save_registry_anchor(self) -> None:
        if not self.use_registry or not self.state:
            return
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_APP_PATH) as key:
                winreg.SetValueEx(key, "InstallID", 0, winreg.REG_SZ, hashlib.sha256(self._get_effective_install_id().encode("utf-8")).hexdigest()[:32])
                winreg.SetValueEx(key, "BootCount", 0, winreg.REG_DWORD, max(0, int(self.state.get("boot_count", 0))))
                winreg.SetValueEx(key, "ResetCount", 0, winreg.REG_DWORD, max(0, int(self.state.get("reset_count", 0))))
                winreg.SetValueEx(key, "LastRecordID", 0, winreg.REG_SZ, str(self.state.get("last_event_record_id", 0)))
                winreg.SetValueEx(key, "Signature", 0, winreg.REG_SZ, str(self.state.get("integrity", "")))
        except OSError:
            pass

    def _read_registry_anchor(self) -> dict:
        if not self.use_registry:
            return {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_APP_PATH, 0, winreg.KEY_READ) as key:
                res = {}
                for field in ("InstallID", "BootCount", "ResetCount", "LastRecordID", "Signature"):
                    try:
                        val, _ = winreg.QueryValueEx(key, field)
                        res[field] = val
                    except OSError:
                        pass
                return res
        except OSError:
            return {}

    def has_orphan_registry_anchor(self) -> bool:
        if self.exists():
            return False
        anchor = self._read_registry_anchor()
        return bool(anchor.get("InstallID") or anchor.get("Signature"))

    def _encode_state_file(self, wrapped: dict) -> str:
        raw_json = json.dumps(wrapped, ensure_ascii=False, separators=(",", ":"))
        if IS_WINDOWS:
            dpapi_ct = dpapi_protect(raw_json)
            if dpapi_ct:
                return "BCENC1:" + dpapi_ct
        enc_blob = encrypt_secret(raw_json, HMAC_APP_SECRET.decode("ascii"))
        return "BCENC2:" + base64.b64encode(json.dumps(enc_blob, separators=(",", ":")).encode("utf-8")).decode("ascii")

    def _decode_state_file(self, raw_text: str) -> dict:
        text = raw_text.strip()
        if text.startswith("BCENC1:"):
            plain = dpapi_unprotect(text[7:])
            if not plain:
                raise ValueError("DPAPI 配置文件解密失败")
            return json.loads(plain)
        if text.startswith("BCENC2:"):
            blob = json.loads(base64.b64decode(text[7:]).decode("utf-8"))
            plain = decrypt_secret(blob, HMAC_APP_SECRET.decode("ascii"))
            return json.loads(plain)
        # 兼容旧版明文 JSON（下次保存会自动升级为全密文）
        return json.loads(text)

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.data_path), exist_ok=True)
        payload = {k: v for k, v in self.state.items() if k != "integrity"}
        sig = self._compute_hmac(payload)
        wrapped = dict(payload)
        wrapped["integrity"] = sig
        encoded = self._encode_state_file(wrapped)
        tmp_path = self.data_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(encoded)
        os.replace(tmp_path, self.data_path)
        self.state = wrapped
        self._save_registry_anchor()

    def _migrate_legacy_policy(self, data: dict) -> None:
        """将旧版 clear_mode 平滑迁移为新版 clear_logic + clear_methods。"""
        if "clear_logic" in data and "clear_methods" in data:
            return
        legacy = data.get("clear_mode", CLEAR_MODE_PASSWORD)
        if legacy == CLEAR_MODE_DISABLED:
            data["clear_logic"] = CLEAR_LOGIC_DISABLED
            data["clear_methods"] = [METHOD_PASSWORD]
        elif legacy == CLEAR_MODE_BOTH:
            data["clear_logic"] = CLEAR_LOGIC_ALL
            data["clear_methods"] = [METHOD_PASSWORD, METHOD_TOTP]
        elif legacy == CLEAR_MODE_TOTP:
            data["clear_logic"] = CLEAR_LOGIC_ANY
            data["clear_methods"] = [METHOD_TOTP]
        else:
            data["clear_logic"] = CLEAR_LOGIC_ANY
            data["clear_methods"] = [METHOD_PASSWORD]

    def load(self, external_anchor: dict = None) -> bool:
        self.tampered = False
        self.tamper_reasons = []
        if not os.path.exists(self.data_path):
            return False
        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = self._decode_state_file(f.read())
            stored_sig = data.get("integrity", "")
            payload = {k: v for k, v in data.items() if k != "integrity"}
            expected_sig = self._compute_hmac(payload)
            if not hmac.compare_digest(stored_sig, expected_sig):
                self.tampered = True
                self.tamper_reasons.append("状态文件 HMAC 签名校验失败（文件曾被外部修改）")

            if not self._verify_hash_chain(data.get("boot_history", []), data.get("history_base_hash", "GENESIS")):
                self.tampered = True
                self.tamper_reasons.append("历史记录哈希链断裂（历史条目曾被篡改或删减）")

            cur_seal = get_install_seal()
            stored_seal = data.get("install_seal", "")
            if cur_seal and stored_seal and cur_seal != stored_seal:
                self.tampered = True
                self.tamper_reasons.append("检测到程序被重新安装且有人覆盖了旧状态文件（安装封条不匹配）")

            # 校验程序本体 SHA-256 完整性（防止替换伪造程序）
            stored_bin_hash = data.get("app_binary_sha256", "")
            cur_bin_hash = compute_self_binary_sha256()
            if stored_bin_hash and cur_bin_hash and not hmac.compare_digest(stored_bin_hash, cur_bin_hash):
                self.tampered = True
                self.tamper_reasons.append("程序本体文件 SHA-256 校验不匹配（疑似程序文件被替换或修改）")

            # 校验 TPM 2.0 硬件不可导出密钥
            stored_tpm = data.get("tpm_pub_hash", "")
            if stored_tpm and IS_WINDOWS:
                live_tpm = tpm_read_hardware_key_hash()
                if not live_tpm or not hmac.compare_digest(stored_tpm, live_tpm):
                    self.tampered = True
                    self.tamper_reasons.append("主板 TPM 2.0 硬件密钥缺失或不匹配（疑似卸载重装或跨机复制）")

            eff_iid = self._get_effective_install_id(data)
            if data.get("install_id_dpapi") and IS_WINDOWS and not eff_iid:
                self.tampered = True
                self.tamper_reasons.append("DPAPI 加密安装密钥解密失败（疑似跨账户或跨设备复制）")

            if eff_iid and data.get("emoji_fingerprint"):
                expected_fp = derive_emoji_fingerprint(eff_iid, cur_seal or stored_seal, stored_tpm)
                if not hmac.compare_digest(
                    data["emoji_fingerprint"].encode("utf-8"), expected_fp.encode("utf-8")
                ):
                    self.tampered = True
                    self.tamper_reasons.append("Emoji 指纹与当前安装实例不匹配（程序可能被重装或指纹被篡改）")

            anchor = external_anchor if external_anchor is not None else self._read_registry_anchor()
            if anchor:
                reg_sig = anchor.get("Signature")
                reg_id = anchor.get("InstallID")
                reg_rec = int(anchor.get("LastRecordID", 0) or 0)
                reg_reset = int(anchor.get("ResetCount", 0) or 0)
                file_rec = int(data.get("last_event_record_id", 0) or 0)
                file_reset = int(data.get("reset_count", 0) or 0)
                eff_id_hash = hashlib.sha256(eff_iid.encode("utf-8")).hexdigest()[:32] if eff_iid else ""
                if reg_id and eff_iid and reg_id not in (eff_iid, eff_id_hash):
                    self.tampered = True
                    self.tamper_reasons.append("安装标识与注册表锚点不匹配（疑似覆盖了其他状态文件）")
                elif reg_reset > file_reset:
                    self.tampered = True
                    self.tamper_reasons.append("检测到「累计清除/重置次数」被回滚篡改")
                elif reg_rec > file_rec:
                    self.tampered = True
                    self.tamper_reasons.append("检测到状态文件被回滚到更早的备份版本")
                elif reg_sig and not hmac.compare_digest(str(reg_sig), stored_sig):
                    self.tampered = True
                    self.tamper_reasons.append("状态文件签名与注册表锚点不一致")

            data.setdefault("install_id", generate_os_install_id())
            data.setdefault("emoji_fingerprint", derive_emoji_fingerprint(data["install_id"]))
            data.setdefault("reset_count", 0)
            data.setdefault("count_sleep_wake", True)
            data.setdefault("totp_enc", None)
            data.setdefault("totp_enc_mode", "password")
            data.setdefault("totp_secret", "")
            data.setdefault("autostart_mode", AUTOSTART_SILENT)
            data.setdefault("last_event_epoch", data.get("last_boot_epoch", 0.0))
            data.setdefault("last_event_record_id", 0)
            data.setdefault("history_base_hash", "GENESIS")
            data.setdefault("language", LANG_AUTO)
            apply_language_preference(data.get("language", LANG_AUTO))
            data.setdefault("security_anomalies", [])
            self._migrate_legacy_policy(data)
            self.state = data
            return True
        except (OSError, ValueError, TypeError):
            self.tampered = True
            self.tamper_reasons.append("状态文件格式损坏，无法解析")
            return False

    def initialize(
        self,
        password: str,
        clear_mode: str = CLEAR_MODE_PASSWORD,
        clear_logic: str = None,
        clear_methods: list = None,
        count_sleep_wake: bool = True,
        autostart_mode: str = AUTOSTART_SILENT,
        totp_secret: str = "",
        boot_epoch: float = None,
        now_epoch: float = None,
        initial_record_id: int = None,
        had_orphan_anchor: bool = False,
    ) -> dict:
        if autostart_mode not in VALID_AUTOSTART_MODES:
            raise ValueError("无效的开机自启模式")
        if not password or len(password) < 4:
            raise ValueError("管理密码长度不能少于 4 位")

        # 解析保护方式组合（兼容旧参数 clear_mode 与新参数 clear_logic/clear_methods）
        if clear_logic is None:
            if clear_mode == CLEAR_MODE_DISABLED:
                clear_logic = CLEAR_LOGIC_DISABLED
                clear_methods = [METHOD_PASSWORD]
            elif clear_mode == CLEAR_MODE_BOTH:
                clear_logic = CLEAR_LOGIC_ALL
                clear_methods = [METHOD_PASSWORD, METHOD_TOTP]
            else:
                clear_logic = CLEAR_LOGIC_ANY
                clear_methods = [METHOD_PASSWORD]
        if clear_logic not in VALID_CLEAR_LOGICS:
            raise ValueError("无效的清空策略逻辑")

        methods = [m for m in (clear_methods or [METHOD_PASSWORD]) if m in ALL_METHODS]
        if clear_logic != CLEAR_LOGIC_DISABLED and not methods:
            raise ValueError("请至少勾选一种清空验证方式，或选择「完全禁止清除」")
        if METHOD_TOTP in methods and not totp_secret:
            raise ValueError("启用动态口令 前，请先完成手机验证器绑定")

        now = time.time() if now_epoch is None else float(now_epoch)
        boot_ts = get_system_boot_epoch() if boot_epoch is None else float(boot_epoch)
        rec_id = get_latest_system_record_id() if initial_record_id is None else int(initial_record_id)
        salt_hex = os.urandom(16).hex()
        pwd_hash = hash_password(password, salt_hex)

        install_id = generate_os_install_id()
        install_seal = get_install_seal()
        tpm_pub_hash = tpm_create_hardware_key()
        dpapi_blob = dpapi_protect(install_id) if IS_WINDOWS else ""
        key_storage_mode = "TPM 2.0 + DPAPI" if (tpm_pub_hash and dpapi_blob) else ("TPM 2.0" if tpm_pub_hash else ("DPAPI" if dpapi_blob else "Local"))
        bin_sha256 = compute_self_binary_sha256()
        bin_tpm_sig = tpm_sign_hash(bin_sha256) if tpm_pub_hash else ""
        bin_sha256_dpapi = dpapi_protect(bin_sha256) if (IS_WINDOWS and bin_sha256) else ""
        emoji_fp = derive_emoji_fingerprint(install_id, install_seal, tpm_pub_hash)

        first_entry = {
            "time": format_timestamp(now),
            "recorded_at": format_timestamp(now),
            "event": tr("软件安装并首次运行（计为第 1 次）", "Initial installation and first run (Count: 1)"),
            "count_after": 1,
        }
        first_entry["hash"] = self._compute_entry_hash("GENESIS", first_entry)

        anomalies = []
        if had_orphan_anchor:
            anomalies.append(
                {
                    "time": format_timestamp(now),
                    "kind": "reinstall_detected",
                    "label": "严重异常：初始化前检测到旧注册表锚点残留（疑似原状态文件被删除重装）",
                }
            )

        self.state = {
            "version": 8,
            "install_id": "" if dpapi_blob else install_id,
            "install_id_dpapi": dpapi_blob,
            "tpm_pub_hash": tpm_pub_hash,
            "key_storage_mode": key_storage_mode,
            "app_binary_sha256": "" if bin_sha256_dpapi else bin_sha256,
            "app_binary_sha256_dpapi": bin_sha256_dpapi,
            "app_binary_tpm_sig": bin_tpm_sig,
            "install_seal": install_seal,
            "emoji_fingerprint": emoji_fp,
            "installed_at": format_timestamp(now),
            "boot_count": 1,
            "reset_count": 0,
            "last_boot_epoch": round(boot_ts, 2),
            "last_event_epoch": round(now, 2),
            "last_event_record_id": rec_id,
            "count_sleep_wake": bool(count_sleep_wake),
            "autostart_mode": autostart_mode,
            "language": LANG_AUTO,
            "clear_logic": clear_logic,
            "clear_methods": methods,
            "clear_mode": CLEAR_MODE_DISABLED if clear_logic == CLEAR_LOGIC_DISABLED else CLEAR_MODE_PASSWORD,
            "permanent_lock": False,
            "password_salt": salt_hex,
            "password_hash": pwd_hash,
            "totp_enc": None,
            "totp_enc_mode": "install",
            "history_base_hash": "GENESIS",
            "boot_history": [first_entry],
            "security_anomalies": anomalies,
        }
        if totp_secret:
            self.state["totp_enc"] = encrypt_secret(totp_secret.strip(), self._totp_enc_key())
            self.state["totp_enc_mode"] = "install"

        self.tampered = bool(had_orphan_anchor)
        self.tamper_reasons = [anomalies[0]["label"]] if had_orphan_anchor else []
        self.save()
        self._write_audit_log("INSTALL_INIT", f"首次安装完成 logic={clear_logic} methods={','.join(methods)}")
        return self.state

    def _append_history(self, event_epoch: float, label: str, now_epoch: float = None) -> None:
        now = time.time() if now_epoch is None else float(now_epoch)
        history = self.state.setdefault("boot_history", [])
        base_h = self.state.get("history_base_hash", "GENESIS")
        prev_hash = history[-1].get("hash", base_h) if history else base_h
        entry = {
            "time": format_timestamp(event_epoch),
            "recorded_at": format_timestamp(now),
            "event": label,
            "count_after": self.state["boot_count"],
        }
        entry["hash"] = self._compute_entry_hash(prev_hash, entry)
        history.append(entry)
        if len(history) > 500:
            dropped = history[:-500]
            self.state["history_base_hash"] = dropped[-1].get("hash", "GENESIS")
            self.state["boot_history"] = history[-500:]

    def sync_power_events(
        self,
        external_result: dict = None,
        boot_epoch: float = None,
        now_epoch: float = None,
    ) -> tuple:
        if self.state is None:
            raise RuntimeError("尚未初始化状态")

        now = time.time() if now_epoch is None else float(now_epoch)
        last_event = float(self.state.get("last_event_epoch", 0.0))
        last_rec_id = int(self.state.get("last_event_record_id", 0) or 0)
        include_sleep = bool(self.state.get("count_sleep_wake", True))

        if external_result is None:
            query_res = query_windows_system_events(
                since_epoch=last_event,
                since_record_id=last_rec_id,
                include_sleep_wake=include_sleep,
            )
        else:
            query_res = external_result

        power_events = query_res.get("power_events", [])
        anomalies = query_res.get("anomalies", [])
        max_rec_id = max(last_rec_id, int(query_res.get("max_record_id", 0) or 0))

        added_boots = 0
        latest_recorded = last_event
        prev_counted_ts = last_event
        for ev in power_events:
            if not include_sleep and ev.get("kind") == "sleep_wake":
                continue
            ev_ts = float(ev["epoch"])
            ev_rid = int(ev.get("record_id", 0) or 0)
            is_new_by_id = last_rec_id > 0 and ev_rid > last_rec_id
            if ev_ts <= last_event and not is_new_by_id:
                continue
            if abs(ev_ts - prev_counted_ts) <= EVENT_MERGE_WINDOW_SECONDS:
                continue
            self.state["boot_count"] = int(self.state.get("boot_count", 0)) + 1
            prev_counted_ts = ev_ts
            latest_recorded = max(latest_recorded, ev_ts)
            added_boots += 1
            self._append_history(ev_ts, ev.get("label", "开机/唤醒事件"), now_epoch=now)

        added_anomalies = 0
        stored_anomalies = self.state.setdefault("security_anomalies", [])
        existing_keys = {(a.get("time"), a.get("kind"), a.get("record_id")) for a in stored_anomalies}
        for an in anomalies:
            ev_rid = int(an.get("record_id", 0) or 0)
            ev_ts = float(an["epoch"])
            t_str = format_timestamp(ev_ts)
            key = (t_str, an.get("kind"), ev_rid)
            if key in existing_keys:
                continue
            stored_anomalies.append(
                {
                    "time": t_str,
                    "record_id": ev_rid,
                    "kind": an.get("kind", "anomaly"),
                    "label": an.get("label", "未知安全异常"),
                }
            )
            existing_keys.add(key)
            added_anomalies += 1

        cur_boot = get_system_boot_epoch() if boot_epoch is None else float(boot_epoch)
        last_boot = float(self.state.get("last_boot_epoch", 0.0))
        if abs(cur_boot - last_boot) > BOOT_TOLERANCE_SECONDS:
            if abs(cur_boot - prev_counted_ts) > EVENT_MERGE_WINDOW_SECONDS:
                self.state["boot_count"] = int(self.state.get("boot_count", 0)) + 1
                latest_recorded = max(latest_recorded, cur_boot)
                added_boots += 1
                self._append_history(cur_boot, "系统开机/重启（运行时间检测）", now_epoch=now)
            self.state["last_boot_epoch"] = round(cur_boot, 2)

        if added_boots > 0 or added_anomalies > 0 or max_rec_id > last_rec_id or latest_recorded > last_event:
            self.state["last_event_epoch"] = round(max(latest_recorded, last_event), 2)
            self.state["last_event_record_id"] = max_rec_id
            self.save()
            if added_boots > 0 or added_anomalies > 0:
                self._write_audit_log("SYNC_EVENTS", f"新增开机/唤醒 {added_boots} 次，新增安全异常 {added_anomalies} 条")
        return added_boots, added_anomalies

    def verify_password(self, password: str) -> bool:
        if self.state is None or not password:
            return False
        salt_hex = self.state.get("password_salt", "")
        expected = self.state.get("password_hash", "")
        if not salt_hex or not expected:
            return False
        actual = hash_password(password, salt_hex)
        return hmac.compare_digest(actual, expected)

    def has_totp(self) -> bool:
        return bool(self.state and (self.state.get("totp_enc") or self.state.get("totp_secret")))

    def _get_totp_secret(self, password: str = "") -> str:
        enc = self.state.get("totp_enc")
        if enc:
            if self.state.get("totp_enc_mode") == "install":
                return decrypt_secret(enc, self._totp_enc_key())
            if not password:
                raise ValueError("解密旧版动态口令密钥需要管理密码。")
            return decrypt_secret(enc, password)
        return self.state.get("totp_secret", "")

    def verify_totp(self, totp_code: str, password: str = "", for_time: float = None) -> bool:
        if not self.has_totp():
            return False
        try:
            secret = self._get_totp_secret(password)
        except ValueError:
            return False
        return verify_totp_code(secret, totp_code, for_time=for_time)

    def bind_totp(self, password: str, new_secret: str, verify_code: str, for_time: float = None) -> None:
        if self.state is None:
            raise RuntimeError("尚未初始化状态")
        if not self.verify_password(password):
            raise ValueError("管理密码错误。")
        if not verify_totp_code(new_secret, verify_code, for_time=for_time):
            raise ValueError("6 位动态口令校验失败，请检查手机时间或重新输入。")
        self.state["totp_enc"] = encrypt_secret(new_secret.strip(), self._totp_enc_key())
        self.state["totp_enc_mode"] = "install"
        self.state.pop("totp_secret", None)
        self.save()
        self._write_audit_log("BIND_TOTP", "已加密绑定手机动态口令")

    def set_clear_policy(self, logic: str, methods: list, password: str, permanent: bool = False) -> None:
        """设置多保护方式组合策略（any=任一方式即可清除 / all=全部方式同时通过 / disabled=完全禁止）。"""
        if self.state is None:
            raise RuntimeError("尚未初始化状态")
        if logic not in VALID_CLEAR_LOGICS:
            raise ValueError("无效的清空策略逻辑")
        if self.state.get("permanent_lock"):
            raise PermissionError("已开启「永久锁定禁止清除」，无法再修改清空策略。")
        if not self.verify_password(password):
            raise ValueError("管理密码错误，无法修改清空策略。")

        clean_methods = [m for m in methods if m in ALL_METHODS]
        if logic != CLEAR_LOGIC_DISABLED and not clean_methods:
            raise ValueError("请至少勾选一种清除验证方式。")
        if METHOD_TOTP in clean_methods and not self.has_totp():
            raise ValueError("请先完成「绑定手机动态口令」，再勾选动态口令。")

        self.state["clear_logic"] = logic
        self.state["clear_methods"] = clean_methods
        self.state["clear_mode"] = CLEAR_MODE_DISABLED if logic == CLEAR_LOGIC_DISABLED else CLEAR_MODE_PASSWORD
        if permanent and logic == CLEAR_LOGIC_DISABLED:
            self.state["permanent_lock"] = True
        self.save()
        self._write_audit_log("SET_CLEAR_POLICY", f"logic={logic}, methods={','.join(clean_methods)}, permanent={permanent}")

    def set_clear_mode(self, new_mode: str, password: str, permanent: bool = False) -> None:
        """兼容旧版调用接口。"""
        if new_mode == CLEAR_MODE_DISABLED:
            self.set_clear_policy(CLEAR_LOGIC_DISABLED, [METHOD_PASSWORD], password, permanent=permanent)
        elif new_mode == CLEAR_MODE_BOTH:
            self.set_clear_policy(CLEAR_LOGIC_ALL, [METHOD_PASSWORD, METHOD_TOTP], password, permanent=False)
        elif new_mode == CLEAR_MODE_TOTP:
            self.set_clear_policy(CLEAR_LOGIC_ANY, [METHOD_TOTP], password, permanent=False)
        else:
            self.set_clear_policy(CLEAR_LOGIC_ANY, [METHOD_PASSWORD], password, permanent=False)

    def clear_count(
        self,
        password: str = "",
        totp_code: str = "",
        winhello_verified: bool = False,
        for_time: float = None,
    ) -> None:
        """
        按照当前多方式保护策略校验并清空开机计数（累计清除/重置次数永久 +1）：
        - logic == 'any'：只需满足已启用方式中的任意一种即可清除
        - logic == 'all'：必须同时满足所有已启用的方式才可清除
        """
        if self.state is None:
            raise RuntimeError("尚未初始化状态")
        logic = self.state.get("clear_logic", CLEAR_LOGIC_ANY)
        methods = self.state.get("clear_methods", [METHOD_PASSWORD])
        if self.state.get("permanent_lock") or logic == CLEAR_LOGIC_DISABLED:
            raise PermissionError("当前处于「完全禁止清除」模式，不允许清空记录的次数。")

        passed = []
        if METHOD_PASSWORD in methods and password and self.verify_password(password):
            passed.append("管理密码")
        if METHOD_TOTP in methods and totp_code and self.verify_totp(totp_code, password=password, for_time=for_time):
            passed.append("动态口令")
        if METHOD_WINHELLO in methods and winhello_verified:
            passed.append("Windows Hello")

        if logic == CLEAR_LOGIC_ANY:
            if not passed:
                raise ValueError("验证未通过：请至少通过一种已启用的保护方式（密码 / 动态口令 / Windows Hello）。")
            method_desc = " / ".join(passed)
        elif logic == CLEAR_LOGIC_ALL:
            missing = []
            if METHOD_PASSWORD in methods and "管理密码" not in passed:
                missing.append("管理密码")
            if METHOD_TOTP in methods and "动态口令" not in passed:
                missing.append("动态口令")
            if METHOD_WINHELLO in methods and "Windows Hello" not in passed:
                missing.append("Windows Hello")
            if missing:
                raise ValueError(f"未通过全部必选验证（缺少或错误：{'、'.join(missing)}）。")
            method_desc = " + ".join(passed)
        else:
            raise ValueError("未知清空策略。")

        now = time.time() if for_time is None else float(for_time)
        self.state["boot_count"] = 0
        self.state["reset_count"] = int(self.state.get("reset_count", 0)) + 1
        self.state["last_event_epoch"] = round(now, 2)
        self._append_history(
            now,
            f"通过【{method_desc}】清空计数（归零，累计第 {self.state['reset_count']} 次清除）",
            now_epoch=now,
        )
        self.save()
        self._write_audit_log("CLEAR_COUNT", f"method={method_desc}, reset_count={self.state['reset_count']}")

    def dismiss_tamper_alerts(
        self,
        password: str = "",
        totp_code: str = "",
        winhello_verified: bool = False,
        for_time: float = None,
    ) -> None:
        """通过已启用的验证方式消除界面上的红色防篡改告警，同时在日志与审计报告中永久记录消除时间与方式。"""
        if self.state is None:
            raise RuntimeError("尚未初始化状态")
        logic = self.state.get("clear_logic", CLEAR_LOGIC_ANY)
        methods = self.state.get("clear_methods", [METHOD_PASSWORD])
        if logic == CLEAR_LOGIC_DISABLED:
            # 若处于禁止清除模式，消除告警仍允许使用管理密码验证
            methods = [METHOD_PASSWORD]
            logic = CLEAR_LOGIC_ANY

        passed = []
        if METHOD_PASSWORD in methods and password and self.verify_password(password):
            passed.append("管理密码")
        if METHOD_TOTP in methods and totp_code and self.verify_totp(totp_code, password=password, for_time=for_time):
            passed.append("动态口令")
        if METHOD_WINHELLO in methods and winhello_verified:
            passed.append("Windows Hello")

        if logic == CLEAR_LOGIC_ANY:
            if not passed:
                raise ValueError("身份验证未通过，无法消除告警。")
            method_desc = " / ".join(passed)
        else:
            missing = []
            if METHOD_PASSWORD in methods and "管理密码" not in passed:
                missing.append("管理密码")
            if METHOD_TOTP in methods and "动态口令" not in passed:
                missing.append("动态口令")
            if METHOD_WINHELLO in methods and "Windows Hello" not in passed:
                missing.append("Windows Hello")
            if missing:
                raise ValueError(f"未通过全部验证（缺少或错误：{'、'.join(missing)}）。")
            method_desc = " + ".join(passed)

        now = time.time() if for_time is None else float(for_time)
        t_str = format_timestamp(now)
        dismissed_items = list(self.tamper_reasons) + [a.get("label", "") for a in self.state.get("security_anomalies", [])]
        dismiss_log = self.state.setdefault("dismissed_alerts", [])
        dismiss_log.append(
            {
                "time": t_str,
                "method": method_desc,
                "count": len(dismissed_items),
                "details": dismissed_items,
            }
        )
        self.state["security_anomalies"] = []
        cur_seal = get_install_seal()
        if cur_seal:
            self.state["install_seal"] = cur_seal
        cur_bin = compute_self_binary_sha256()
        if cur_bin:
            if IS_WINDOWS and self.state.get("app_binary_sha256_dpapi"):
                new_dp = dpapi_protect(cur_bin)
                if new_dp:
                    self.state["app_binary_sha256_dpapi"] = new_dp
                    self.state["app_binary_sha256"] = ""
            else:
                self.state["app_binary_sha256"] = cur_bin
        self.state["emoji_fingerprint"] = self.get_emoji_fingerprint()
        self.tampered = False
        self.tamper_reasons = []
        self._append_history(now, f"通过【{method_desc}】消除界面安全告警（共 {len(dismissed_items)} 项）", now_epoch=now)
        self.save()
        self._write_audit_log("DISMISS_ALERTS", f"method={method_desc}, count={len(dismissed_items)}, items={'; '.join(dismissed_items)}")

    def set_language(self, lang_pref: str) -> str:
        if self.state is None:
            raise RuntimeError(tr("尚未初始化状态", "State not initialized"))
        if lang_pref not in VALID_LANGS:
            raise ValueError(tr("无效的语言设置", "Invalid language setting"))
        self.state["language"] = lang_pref
        active = apply_language_preference(lang_pref)
        self.save()
        self._write_audit_log("SET_LANGUAGE", f"pref={lang_pref}, active={active}")
        return active

    def set_autostart_preference(self, mode: str, password: str) -> None:
        if self.state is None:
            raise RuntimeError("尚未初始化状态")
        if mode not in VALID_AUTOSTART_MODES:
            raise ValueError("无效的开机自启模式")
        if not self.verify_password(password):
            raise ValueError("管理密码错误，无法修改开机自启设置。")
        self.state["autostart_mode"] = mode
        self.save()
        self._write_audit_log("SET_AUTOSTART", f"mode={mode}")

    def set_count_sleep_wake(self, enabled: bool, password: str) -> None:
        if self.state is None:
            raise RuntimeError("尚未初始化状态")
        if not self.verify_password(password):
            raise ValueError("管理密码错误，无法修改睡眠唤醒统计设置。")
        self.state["count_sleep_wake"] = bool(enabled)
        self.save()
        self._write_audit_log("SET_SLEEP_WAKE", f"enabled={enabled}")

    def change_password(self, old_password: str, new_password: str) -> None:
        if self.state is None:
            raise RuntimeError("尚未初始化状态")
        if not self.verify_password(old_password):
            raise ValueError("原管理密码错误。")
        if not new_password or len(new_password) < 4:
            raise ValueError("新管理密码长度不能少于 4 位。")
        if self.state.get("totp_enc") and self.state.get("totp_enc_mode") != "install":
            plain_totp = decrypt_secret(self.state["totp_enc"], old_password)
            self.state["totp_enc"] = encrypt_secret(plain_totp, self._totp_enc_key())
            self.state["totp_enc_mode"] = "install"
        salt_hex = os.urandom(16).hex()
        self.state["password_salt"] = salt_hex
        self.state["password_hash"] = hash_password(new_password, salt_hex)
        self.save()
        self._write_audit_log("CHANGE_PASSWORD", "管理密码已修改")

    def format_policy_summary(self) -> str:
        st = self.state or {}
        if st.get("permanent_lock"):
            return tr("永久锁定禁止清除", "Permanently Locked")
        logic = st.get("clear_logic", CLEAR_LOGIC_ANY)
        if logic == CLEAR_LOGIC_DISABLED:
            return tr("完全禁止清除", "Clear Disabled")
        labels = {METHOD_PASSWORD: tr("密码", "Password"), METHOD_TOTP: tr("动态口令", "TOTP"), METHOD_WINHELLO: "Windows Hello"}
        m_text = " / ".join(labels[m] for m in st.get("clear_methods", [METHOD_PASSWORD]) if m in labels)
        return tr(f"任一可清({m_text})", f"Any ({m_text})") if logic == CLEAR_LOGIC_ANY else tr(f"全部需验({m_text.replace(' / ', '+')})", f"All ({m_text.replace(' / ', '+')})")

    def build_audit_report(self) -> str:
        st = self.state or {}
        anomalies = st.get("security_anomalies", [])
        lines = [
            "========================================",
            tr("   BootCounter 开机与唤醒防篡改审计报告", "   BootCounter Tamper-Evident Audit Report"),
            "========================================",
            tr(f"生成时间：{format_timestamp(time.time())}", f"Generated At: {format_timestamp(time.time())}"),
            tr(f"安装防伪 Emoji 指纹（6位）：{self.get_emoji_fingerprint()}", f"Install Emoji Fingerprint (6): {self.get_emoji_fingerprint()}"),
            tr(f"底层随机安装 ID（仅日志可见）：{self._get_effective_install_id() or '-'}", f"Internal Random Install ID: {self._get_effective_install_id() or '-'}"),
            tr(f"密钥安全存储方式：{st.get('key_storage_mode', 'Local')}", f"Key Protection Mode: {st.get('key_storage_mode', 'Local')}"),
            tr(f"程序本体 SHA-256：{(dpapi_unprotect(st.get('app_binary_sha256_dpapi', '')) if IS_WINDOWS else '') or st.get('app_binary_sha256', '') or compute_self_binary_sha256() or '-'}", f"Binary SHA-256: {(dpapi_unprotect(st.get('app_binary_sha256_dpapi', '')) if IS_WINDOWS else '') or st.get('app_binary_sha256', '') or compute_self_binary_sha256() or '-'}"),
            tr(f"安装时间：{st.get('installed_at', '-')}", f"Installed At: {st.get('installed_at', '-')}"),
            tr(f"累计开机/唤醒次数：{st.get('boot_count', 0)} 次", f"Total Boot / Wake Count: {st.get('boot_count', 0)}"),
            tr(f"累计清除/重置次数：{st.get('reset_count', 0)} 次", f"Total Reset Count (Permanent): {st.get('reset_count', 0)}"),
            tr(f"合盖睡眠唤醒统计：{'开启' if st.get('count_sleep_wake', True) else '关闭'}", f"Sleep / Lid Wake Tracking: {'Enabled' if st.get('count_sleep_wake', True) else 'Disabled'}"),
            tr(f"清空保护策略：{self.format_policy_summary()}", f"Clear Protection Policy: {self.format_policy_summary()}"),
            tr(f"文件与哈希链完整性：{'异常！' if self.tampered else '正常（通过）'}", f"File & Hash Chain Integrity: {'TAMPERED!' if self.tampered else 'OK (Verified)'}"),
        ]
        if self.tamper_reasons:
            lines.append(tr("完整性告警详情：", "Integrity Alert Details:"))
            for r in self.tamper_reasons:
                lines.append(f"  - {r}")
        dismissed = st.get("dismissed_alerts", [])
        lines.append(tr(f"当前未消除异常数：{len(anomalies)} 条（历史已消除告警：{len(dismissed)} 次）", f"Active Security Alerts: {len(anomalies)} (Historically Dismissed: {len(dismissed)})"))
        if dismissed:
            lines.append(tr("历史告警消除记录（永久留痕）：", "Dismissed Alert History (Permanent):"))
            for d in dismissed:
                lines.append(tr(f"  - [{d.get('time')}] 通过【{d.get('method')}】消除了 {d.get('count')} 项告警", f"  - [{d.get('time')}] Dismissed {d.get('count')} alert(s) via [{d.get('method')}]"))
        if anomalies:
            lines.append(tr("系统异常明细（清日志/改时间/重装）：", "System Security Alerts:"))
            for a in anomalies:
                lines.append(f"  - [{a.get('time')}] {a.get('label')}")
        lines.append("----------------------------------------")
        lines.append(tr("开机与唤醒记录（按时间顺序）：", "Boot & Wake History (Chronological):"))
        for idx, item in enumerate(st.get("boot_history", []), start=1):
            lines.append(
                tr(f"  {idx}. [{item.get('time')}] {item.get('event')} -> 累计 {item.get('count_after')} 次 (Hash: {item.get('hash', '-')})", f"  {idx}. [{item.get('time')}] {item.get('event')} -> Total {item.get('count_after')} (Hash: {item.get('hash', '-')})")
            )
        lines.append("========================================")
        return "\n".join(lines)


# =========================
# Windows 11 Fluent Design 界面
# =========================

def set_windows_app_id() -> None:
    """设置 AppUserModelID，确保 Windows 11 任务栏正确显示 app.ico 而非默认羽毛图标。"""
    if not IS_WINDOWS:
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("BootCounter.Audit.App.1")
    except Exception:
        pass


class Win32TrayIcon:
    """零外部依赖的原生 64 位安全 Windows 系统托盘图标（ctypes + Shell_NotifyIconW）。"""

    WM_USER = 0x0400
    WM_TRAYICON = WM_USER + 20
    WM_COMMAND = 0x0111
    WM_DESTROY = 0x0002
    WM_LBUTTONUP = 0x0202
    WM_LBUTTONDBLCLK = 0x0203
    WM_RBUTTONUP = 0x0205
    NIM_ADD = 0x00000000
    NIM_MODIFY = 0x00000001
    NIM_DELETE = 0x00000002
    NIF_MESSAGE = 0x00000001
    NIF_ICON = 0x00000002
    NIF_TIP = 0x00000004
    IMAGE_ICON = 1
    LR_LOADFROMFILE = 0x00000010
    LR_DEFAULTSIZE = 0x00000040
    MF_STRING = 0x00000000
    MF_SEPARATOR = 0x00000800
    TPM_LEFTALIGN = 0x0000
    TPM_BOTTOMALIGN = 0x0020
    TPM_RIGHTBUTTON = 0x0002

    ID_SHOW = 1001
    ID_SYNC = 1002
    ID_EXIT = 1003

    def __init__(self, ico_path: str, tooltip: str, action_queue: queue.Queue):
        self.ico_path = ico_path
        self.tooltip = tooltip[:120]
        self._last_tooltip = self.tooltip
        self.action_queue = action_queue
        self.hwnd = None
        self.hicon = None
        self._thread = None
        self._wndproc_ref = None
        self._running = False

    def start(self) -> None:
        if not IS_WINDOWS or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def update_tooltip(self, tooltip: str) -> None:
        tip = tooltip[:120]
        if tip == self._last_tooltip:
            return
        self.tooltip = tip
        self._last_tooltip = tip
        if not IS_WINDOWS or not self.hwnd or not self._running:
            return
        try:
            nid = self._make_nid()
            shell32 = ctypes.windll.shell32
            shell32.Shell_NotifyIconW.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
            shell32.Shell_NotifyIconW.restype = ctypes.c_int
            shell32.Shell_NotifyIconW(self.NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            pass

    def stop(self) -> None:
        self._running = False
        if not IS_WINDOWS or not self.hwnd:
            return
        try:
            nid = self._make_nid()
            shell32 = ctypes.windll.shell32
            shell32.Shell_NotifyIconW.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
            shell32.Shell_NotifyIconW.restype = ctypes.c_int
            shell32.Shell_NotifyIconW(self.NIM_DELETE, ctypes.byref(nid))
            user32 = ctypes.windll.user32
            user32.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
            user32.PostMessageW.restype = ctypes.c_int
            user32.PostMessageW(self.hwnd, self.WM_DESTROY, 0, 0)
        except Exception:
            pass

    def _make_nid(self):
        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint32),
                ("hWnd", ctypes.c_void_p),
                ("uID", ctypes.c_uint32),
                ("uFlags", ctypes.c_uint32),
                ("uCallbackMessage", ctypes.c_uint32),
                ("hIcon", ctypes.c_void_p),
                ("szTip", ctypes.c_wchar * 128),
            ]

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
        nid.uCallbackMessage = self.WM_TRAYICON
        nid.hIcon = self.hicon
        nid.szTip = self.tooltip
        return nid

    def _run(self) -> None:
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            shell32 = ctypes.windll.shell32

            WNDPROCTYPE = ctypes.WINFUNCTYPE(
                ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t
            )

            # 显式声明 64 位安全的 Win32 API 签名，避免 64 位句柄被截断为 32 位 c_int
            kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            kernel32.GetModuleHandleW.restype = ctypes.c_void_p
            user32.DefWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
            user32.DefWindowProcW.restype = ctypes.c_ssize_t
            user32.CreatePopupMenu.argtypes = []
            user32.CreatePopupMenu.restype = ctypes.c_void_p
            user32.AppendMenuW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_wchar_p]
            user32.AppendMenuW.restype = ctypes.c_int
            user32.GetCursorPos.argtypes = [ctypes.c_void_p]
            user32.GetCursorPos.restype = ctypes.c_int
            user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
            user32.SetForegroundWindow.restype = ctypes.c_int
            user32.TrackPopupMenu.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            user32.TrackPopupMenu.restype = ctypes.c_int
            user32.DestroyMenu.argtypes = [ctypes.c_void_p]
            user32.DestroyMenu.restype = ctypes.c_int
            user32.PostQuitMessage.argtypes = [ctypes.c_int]
            user32.PostQuitMessage.restype = None
            user32.RegisterClassW.argtypes = [ctypes.c_void_p]
            user32.RegisterClassW.restype = ctypes.c_uint16
            user32.CreateWindowExW.argtypes = [
                ctypes.c_uint32, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ]
            user32.CreateWindowExW.restype = ctypes.c_void_p
            user32.LoadImageW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
            user32.LoadImageW.restype = ctypes.c_void_p
            user32.LoadIconW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            user32.LoadIconW.restype = ctypes.c_void_p
            user32.GetMessageW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
            user32.GetMessageW.restype = ctypes.c_int
            user32.TranslateMessage.argtypes = [ctypes.c_void_p]
            user32.TranslateMessage.restype = ctypes.c_int
            user32.DispatchMessageW.argtypes = [ctypes.c_void_p]
            user32.DispatchMessageW.restype = ctypes.c_ssize_t
            shell32.Shell_NotifyIconW.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
            shell32.Shell_NotifyIconW.restype = ctypes.c_int

            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", ctypes.c_uint),
                    ("lpfnWndProc", WNDPROCTYPE),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.c_void_p),
                    ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_wchar_p),
                    ("lpszClassName", ctypes.c_wchar_p),
                ]

            def wnd_proc(hwnd, msg, wparam, lparam):
                if msg == self.WM_TRAYICON:
                    if lparam in (self.WM_LBUTTONUP, self.WM_LBUTTONDBLCLK):
                        self.action_queue.put("show")
                        return 0
                    elif lparam == self.WM_RBUTTONUP:
                        hmenu = user32.CreatePopupMenu()
                        user32.AppendMenuW(hmenu, self.MF_STRING, self.ID_SHOW, tr("打开 BootCounter", "Open BootCounter"))
                        user32.AppendMenuW(hmenu, self.MF_STRING, self.ID_SYNC, tr("立即同步日志", "Sync Logs Now"))
                        user32.AppendMenuW(hmenu, self.MF_SEPARATOR, 0, None)
                        user32.AppendMenuW(hmenu, self.MF_STRING, self.ID_EXIT, tr("退出程序", "Exit"))
                        pt = POINT()
                        user32.GetCursorPos(ctypes.byref(pt))
                        user32.SetForegroundWindow(hwnd)
                        user32.TrackPopupMenu(
                            hmenu, self.TPM_LEFTALIGN | self.TPM_BOTTOMALIGN | self.TPM_RIGHTBUTTON,
                            pt.x, pt.y, 0, hwnd, None,
                        )
                        user32.DestroyMenu(hmenu)
                        return 0
                elif msg == self.WM_COMMAND:
                    cmd_id = wparam & 0xFFFF
                    if cmd_id == self.ID_SHOW:
                        self.action_queue.put("show")
                    elif cmd_id == self.ID_SYNC:
                        self.action_queue.put("sync")
                    elif cmd_id == self.ID_EXIT:
                        self.action_queue.put("exit")
                    return 0
                elif msg == self.WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            self._wndproc_ref = WNDPROCTYPE(wnd_proc)
            hinst = kernel32.GetModuleHandleW(None)
            cls_name = f"BootCounterTrayClass_{os.getpid()}"
            wc = WNDCLASSW()
            wc.lpfnWndProc = self._wndproc_ref
            wc.hInstance = hinst
            wc.lpszClassName = cls_name
            user32.RegisterClassW(ctypes.byref(wc))

            self.hwnd = user32.CreateWindowExW(0, cls_name, "BootCounterTray", 0, 0, 0, 0, 0, None, None, hinst, None)

            if self.ico_path and os.path.exists(self.ico_path):
                self.hicon = user32.LoadImageW(
                    None, self.ico_path, self.IMAGE_ICON, 0, 0, self.LR_LOADFROMFILE | self.LR_DEFAULTSIZE
                )
            if not self.hicon:
                self.hicon = user32.LoadIconW(None, ctypes.c_void_p(32512))

            nid = self._make_nid()
            shell32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(nid))

            class MSG(ctypes.Structure):
                _fields_ = [
                    ("hwnd", ctypes.c_void_p),
                    ("message", ctypes.c_uint),
                    ("wParam", ctypes.c_size_t),
                    ("lParam", ctypes.c_ssize_t),
                    ("time", ctypes.c_uint32),
                    ("pt", POINT),
                ]

            m = MSG()
            while self._running and user32.GetMessageW(ctypes.byref(m), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(m))
                user32.DispatchMessageW(ctypes.byref(m))
        except Exception:
            pass


def _center_window(win, width: int, height: int) -> None:
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    w = min(width, int(sw * 0.90))
    h = min(height, int(sh * 0.88))
    x = max(0, (sw - w) // 2)
    y = max(0, (sh - h) // 2)
    win.geometry(f"{w}x{h}+{x}+{y}")


def _apply_win11_window_style(win, ico_path: str) -> None:
    if not IS_WINDOWS:
        return
    if ico_path:
        try:
            win.iconbitmap(ico_path)
        except Exception:
            pass
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(2)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(val), ctypes.sizeof(val))
    except Exception:
        pass


def launch_gui(store: BootCounterStore) -> None:
    enable_windows_high_dpi()
    set_windows_app_id()
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk

    BG_MICA = "#F3F3F3"
    BG_CARD = "#FFFFFF"
    BORDER_CARD = "#E5E5E5"
    ACCENT = "#0067C0"
    ACCENT_SOFT = "#EFF6FC"
    TEXT_PRIMARY = "#1B1B1B"
    TEXT_SECONDARY = "#5C5C5C"
    DANGER = "#C42B1C"
    DANGER_BG = "#FDE7E9"
    SUCCESS = "#107C10"
    SUCCESS_BG = "#DFF6DD"
    FONT_UI = "Microsoft YaHei UI" if CURRENT_LANG == LANG_ZH else "Segoe UI"

    root = tk.Tk()
    root.title(tr("BootCounter — 开机与唤醒审计", "BootCounter — Boot & Wake Audit"))
    root.configure(bg=BG_MICA)

    dpi_scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
    sc = lambda px: int(round(px * dpi_scale))
    _ico = get_resource_path("app.ico")
    if _ico and IS_WINDOWS:
        try:
            root.iconbitmap(default=_ico)
        except Exception:
            pass

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure(
        "Win11.Treeview",
        background=BG_CARD,
        fieldbackground=BG_CARD,
        foreground=TEXT_PRIMARY,
        borderwidth=0,
        rowheight=sc(28),
        font=(FONT_UI, 9),
    )
    style.configure(
        "Win11.Treeview.Heading",
        background="#F9F9F9",
        foreground=TEXT_SECONDARY,
        relief="flat",
        font=(FONT_UI, 9, "bold"),
        padding=(sc(6), sc(6)),
    )
    style.map("Win11.Treeview", background=[("selected", ACCENT_SOFT)], foreground=[("selected", ACCENT)])
    style.configure(
        "Win11.Horizontal.TProgressbar",
        troughcolor="#E5E5E5",
        background=ACCENT,
        borderwidth=0,
        thickness=sc(4),
    )

    def make_card(parent, padx=16, pady=12):
        outer = tk.Frame(parent, bg=BORDER_CARD, bd=0)
        inner = tk.Frame(outer, bg=BG_CARD, padx=sc(padx), pady=sc(pady))
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        return outer, inner

    def make_btn(parent, text, command, primary=False, danger=False, compact=False):
        if primary:
            bg, fg, active = ACCENT, "#FFFFFF", "#005A9E"
        elif danger:
            bg, fg, active = DANGER, "#FFFFFF", "#A4262C"
        else:
            bg, fg, active = BG_CARD, TEXT_PRIMARY, "#EAEAEA"
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active,
            activeforeground=fg,
            relief="solid" if not (primary or danger) else "flat",
            bd=1 if not (primary or danger) else 0,
            highlightthickness=0,
            font=(FONT_UI, 8 if compact else 9, "bold" if primary else "normal"),
            padx=sc(8 if compact else 12),
            pady=sc(3 if compact else 6),
            cursor="hand2",
        )

    def open_totp_bind_modal(parent_win, on_success):
        """通用 TOTP 动态口令绑定弹窗（内置二维码，支持 iPhone 相机 / 自带密码 App / 各类验证器直接扫码）。"""
        new_secret = generate_totp_secret()
        uri = build_otpauth_uri(new_secret)

        t_win = tk.Toplevel(parent_win)
        t_win.title(tr("绑定动态口令", "Bind Authenticator (TOTP)"))
        t_win.configure(bg=BG_MICA)
        _center_window(t_win, sc(460), sc(560))
        t_win.minsize(sc(420), sc(500))
        t_win.grab_set()
        _apply_win11_window_style(t_win, _ico)

        tk.Label(
            t_win,
            text=tr("使用 iPhone 相机 / 自带「密码」App 或手机验证器扫描下方二维码：", "Scan this QR code with iPhone Camera / Passwords or any Authenticator app:"),
            bg=BG_MICA,
            fg=TEXT_PRIMARY,
            justify="left",
            font=(FONT_UI, 9, "bold"),
        ).pack(padx=sc(18), pady=(sc(14), sc(8)), anchor="w")

        # 渲染纯矢量标准二维码（4 格静区，高 DPI 下锐利清晰）
        qr_mat = generate_qr_matrix(uri)
        n = len(qr_mat)
        cell = max(3, int(round(sc(185) / (n + 8))))
        quiet = 4
        canvas_px = (n + quiet * 2) * cell
        qr_card = tk.Frame(t_win, bg=BORDER_CARD, bd=0)
        qr_card.pack(pady=(0, sc(8)))
        qr_canvas = tk.Canvas(qr_card, width=canvas_px, height=canvas_px, bg="#FFFFFF", highlightthickness=0)
        qr_canvas.pack(padx=1, pady=1)
        for r in range(n):
            y0 = (r + quiet) * cell
            for c in range(n):
                if qr_mat[r][c]:
                    x0 = (c + quiet) * cell
                    qr_canvas.create_rectangle(x0, y0, x0 + cell, y0 + cell, fill="#000000", outline="")

        tk.Label(t_win, text=tr("或手动输入密钥：", "Or enter setup key manually:"), bg=BG_MICA, fg=TEXT_SECONDARY, font=(FONT_UI, 8)).pack(
            padx=sc(18), pady=(sc(2), sc(2)), anchor="w"
        )
        sec_entry = tk.Entry(t_win, font=("Consolas", 10, "bold"), justify="center")
        sec_entry.insert(0, new_secret)
        sec_entry.configure(state="readonly")
        sec_entry.pack(fill="x", padx=sc(18), pady=sc(2))

        cp_row = tk.Frame(t_win, bg=BG_MICA)
        cp_row.pack(pady=sc(4))
        make_btn(
            cp_row,
            tr("复制密钥", "Copy Key"),
            lambda: (root.clipboard_clear(), root.clipboard_append(new_secret), messagebox.showinfo(tr("已复制", "Copied"), tr("Base32 密钥已复制。", "Base32 secret key copied."), parent=t_win)),
            compact=True,
        ).pack(side="left", padx=sc(4))
        make_btn(
            cp_row,
            tr("复制 otpauth 链接", "Copy otpauth URI"),
            lambda: (root.clipboard_clear(), root.clipboard_append(uri), messagebox.showinfo(tr("已复制", "Copied"), tr("otpauth 链接已复制。", "otpauth URI copied."), parent=t_win)),
            compact=True,
        ).pack(side="left", padx=sc(4))

        tk.Label(t_win, text=tr("扫码添加后，输入手机显示的 6 位验证码完成绑定：", "Enter the 6-digit code from your phone to verify:"), bg=BG_MICA, fg=TEXT_PRIMARY, font=(FONT_UI, 9)).pack(
            padx=sc(18), pady=(sc(8), sc(4)), anchor="w"
        )
        code_var = tk.StringVar()
        tk.Entry(t_win, textvariable=code_var, font=("Consolas", 12), justify="center").pack(fill="x", padx=sc(18))

        def do_verify():
            code = code_var.get().strip()
            if not verify_totp_code(new_secret, code):
                messagebox.showerror(tr("校验失败", "Verification Failed"), tr("6 位动态口令不正确或已过期，请检查手机时间后重试。", "Invalid or expired 6-digit TOTP code. Check phone time and try again."), parent=t_win)
                return
            on_success(new_secret, code)
            t_win.destroy()

        make_btn(t_win, tr("验证并绑定", "Verify & Bind"), do_verify, primary=True).pack(pady=sc(10))

    # =========================
    # 首次安装初始化向导（含强密码生成 + TOTP 绑定 + Windows Hello + 多方式选择 + 平滑进度条）
    # =========================
    if not store.exists():
        had_orphan = store.has_orphan_registry_anchor()
        setup_win = tk.Toplevel(root)
        setup_win.title(tr("BootCounter 首次安装设置", "BootCounter Initial Setup"))
        setup_win.configure(bg=BG_MICA)
        _center_window(setup_win, sc(540), sc(680))
        setup_win.minsize(sc(480), sc(580))
        setup_win.grab_set()
        _apply_win11_window_style(setup_win, _ico)
        root.withdraw()

        tk.Label(setup_win, text=tr("欢迎安装 BootCounter", "Welcome to BootCounter"), bg=BG_MICA, fg=TEXT_PRIMARY, font=(FONT_UI, 14, "bold")).pack(
            anchor="w", padx=sc(20), pady=(sc(14), sc(2))
        )
        tk.Label(
            setup_win,
            text=tr("首次配置完成后，本次开机将记为第 1 次。", "After setup, this session will be recorded as boot #1."),
            bg=BG_MICA,
            fg=TEXT_SECONDARY,
            font=(FONT_UI, 9),
        ).pack(anchor="w", padx=sc(20), pady=(0, sc(8)))

        if had_orphan:
            tk.Label(
                setup_win,
                text=tr("⚠ 检测到旧注册表锚点残留（疑似原文件被删除重装），已记入审计异常", "⚠ Leftover registry anchor detected (suspected reinstall). Logged as security alert."),
                bg=DANGER_BG,
                fg=DANGER,
                font=(FONT_UI, 9, "bold"),
                padx=sc(10),
                pady=sc(6),
            ).pack(fill="x", padx=sc(20), pady=(0, sc(8)))

        card_out, frm = make_card(setup_win, padx=16, pady=12)
        card_out.pack(fill="both", expand=True, padx=sc(20), pady=(0, sc(8)))

        # 1. 管理密码 + 一键生成强密码 + 显示/复制
        pwd_hdr = tk.Frame(frm, bg=BG_CARD)
        pwd_hdr.pack(fill="x")
        tk.Label(pwd_hdr, text=tr("管理密码", "Admin Password"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 9, "bold")).pack(side="left")

        pwd1_var = tk.StringVar()
        pwd2_var = tk.StringVar()
        show_pwd = {"v": False}

        def on_gen_pwd():
            gp = generate_strong_password(16)
            pwd1_var.set(gp)
            pwd2_var.set(gp)
            show_pwd["v"] = True
            e_pwd1.configure(show="")
            e_pwd2.configure(show="")
            btn_eye.configure(text=tr("隐藏", "Hide"))
            root.clipboard_clear()
            root.clipboard_append(gp)
            messagebox.showinfo(tr("已生成强密码", "Strong Password Generated"), tr(f"已使用系统随机数生成 16 位强密码并复制到剪贴板：\n\n{gp}\n\n请务必妥善保存！", f"Generated a 16-char strong password and copied to clipboard:\n\n{gp}\n\nPlease save it securely!"), parent=setup_win)

        def on_toggle_eye():
            show_pwd["v"] = not show_pwd["v"]
            ch = "" if show_pwd["v"] else "*"
            e_pwd1.configure(show=ch)
            e_pwd2.configure(show=ch)
            btn_eye.configure(text=tr("隐藏", "Hide") if show_pwd["v"] else tr("显示", "Show"))

        btn_eye = make_btn(pwd_hdr, tr("显示", "Show"), on_toggle_eye, compact=True)
        btn_eye.pack(side="right", padx=(sc(4), 0))
        make_btn(pwd_hdr, tr("🎲 生成强密码", "🎲 Generate"), on_gen_pwd, compact=True).pack(side="right")

        e_pwd1 = tk.Entry(frm, textvariable=pwd1_var, show="*", font=("Consolas", 10))
        e_pwd1.pack(fill="x", pady=(sc(4), sc(6)))
        tk.Label(frm, text=tr("确认管理密码", "Confirm Password"), bg=BG_CARD, fg=TEXT_SECONDARY, font=(FONT_UI, 8)).pack(anchor="w")
        e_pwd2 = tk.Entry(frm, textvariable=pwd2_var, show="*", font=("Consolas", 10))
        e_pwd2.pack(fill="x", pady=(sc(2), sc(10)))

        # 2. TOTP 动态口令（初次启动即可绑定）
        totp_holder = {"secret": ""}
        totp_row = tk.Frame(frm, bg=ACCENT_SOFT, padx=sc(10), pady=sc(6))
        totp_row.pack(fill="x", pady=(0, sc(10)))
        totp_lbl = tk.Label(
            totp_row,
            text=tr("动态口令：未绑定", "Authenticator (TOTP): Not bound"),
            bg=ACCENT_SOFT,
            fg=TEXT_PRIMARY,
            font=(FONT_UI, 9),
        )
        totp_lbl.pack(side="left")

        def on_setup_bind_totp():
            def _bound(sec, _code):
                totp_holder["secret"] = sec
                totp_lbl.configure(text=tr("动态口令：已绑定", "Authenticator (TOTP): Bound"), fg=SUCCESS)
                m_totp_var.set(True)

            open_totp_bind_modal(setup_win, _bound)

        make_btn(totp_row, tr("绑定验证器", "Bind TOTP"), on_setup_bind_totp, compact=True).pack(side="right")

        # 3. 多种保护方式组合（支持多选 + 任一可清 / 全部需验 / 完全禁止）
        tk.Label(frm, text=tr("清空验证方式", "Reset Verification Methods"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 9, "bold")).pack(
            anchor="w"
        )
        m_pwd_var = tk.BooleanVar(value=True)
        m_totp_var = tk.BooleanVar(value=False)
        m_hello_var = tk.BooleanVar(value=False)

        m_row = tk.Frame(frm, bg=BG_CARD)
        m_row.pack(fill="x", pady=(sc(2), sc(4)))
        tk.Checkbutton(m_row, text=tr("管理密码", "Admin Password"), variable=m_pwd_var, bg=BG_CARD).pack(side="left", padx=(0, sc(10)))
        tk.Checkbutton(m_row, text=tr("动态口令", "TOTP"), variable=m_totp_var, bg=BG_CARD).pack(side="left", padx=(0, sc(10)))
        tk.Checkbutton(m_row, text="Windows Hello", variable=m_hello_var, bg=BG_CARD).pack(side="left")

        logic_var = tk.StringVar(value=CLEAR_LOGIC_ANY)
        tk.Radiobutton(frm, text=tr("任意一种方式通过即可清除", "Any selected method can clear"), variable=logic_var, value=CLEAR_LOGIC_ANY, bg=BG_CARD).pack(anchor="w")
        tk.Radiobutton(frm, text=tr("全部勾选方式均需通过", "All selected methods required"), variable=logic_var, value=CLEAR_LOGIC_ALL, bg=BG_CARD).pack(anchor="w")
        tk.Radiobutton(frm, text=tr("完全禁止清除计数", "Disable clearing completely"), variable=logic_var, value=CLEAR_LOGIC_DISABLED, bg=BG_CARD).pack(anchor="w")

        # 4. 统计范围与开机自启
        sleep_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            frm,
            text=tr("计入合盖睡眠与休眠唤醒", "Count sleep / lid-open wakes"),
            variable=sleep_var,
            bg=BG_CARD,
            font=(FONT_UI, 9),
        ).pack(anchor="w", pady=(sc(8), sc(4)))

        auto_var = tk.StringVar(value=AUTOSTART_SILENT)
        auto_row = tk.Frame(frm, bg=BG_CARD)
        auto_row.pack(fill="x")
        tk.Label(auto_row, text=tr("开机自启：", "Autostart:"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 9, "bold")).pack(side="left")
        tk.Radiobutton(auto_row, text=tr("静默自启", "Silent"), variable=auto_var, value=AUTOSTART_SILENT, bg=BG_CARD).pack(side="left", padx=(0, sc(6)))
        tk.Radiobutton(auto_row, text=tr("开机弹窗", "Show Window"), variable=auto_var, value=AUTOSTART_GUI, bg=BG_CARD).pack(side="left", padx=(0, sc(6)))
        tk.Radiobutton(auto_row, text=tr("关闭", "Off"), variable=auto_var, value=AUTOSTART_OFF, bg=BG_CARD).pack(side="left")

        init_done = {"ok": False, "busy": False}
        setup_prog_frame = tk.Frame(setup_win, bg=BG_MICA)
        tk.Label(
            setup_prog_frame,
            text=tr("正在生成防伪指纹并建立系统日志基线，请稍候...", "Generating hardware fingerprint & event log baseline..."),
            bg=BG_MICA,
            fg=ACCENT,
            font=(FONT_UI, 8),
            anchor="w",
        ).pack(fill="x", pady=(0, sc(3)))
        setup_pbar = ttk.Progressbar(setup_prog_frame, mode="indeterminate", style="Win11.Horizontal.TProgressbar")
        setup_pbar.pack(fill="x")

        def on_confirm():
            if init_done["busy"]:
                return
            p1, p2 = pwd1_var.get().strip(), pwd2_var.get().strip()
            if len(p1) < 4:
                messagebox.showwarning("提示", "管理密码长度不能少于 4 位。", parent=setup_win)
                return
            if p1 != p2:
                messagebox.showwarning("提示", "两次输入的密码不一致。", parent=setup_win)
                return
            chosen_logic = logic_var.get()
            chosen_methods = []
            if m_pwd_var.get():
                chosen_methods.append(METHOD_PASSWORD)
            if m_totp_var.get():
                if not totp_holder["secret"]:
                    messagebox.showwarning("提示", "已勾选「动态口令」，请先点击上方「绑定验证器」。", parent=setup_win)
                    return
                chosen_methods.append(METHOD_TOTP)
            if m_hello_var.get():
                chosen_methods.append(METHOD_WINHELLO)
            if chosen_logic != CLEAR_LOGIC_DISABLED and not chosen_methods:
                messagebox.showwarning("提示", "请至少勾选一种清空验证方式，或选择「完全禁止清除计数」。", parent=setup_win)
                return

            chosen_auto = auto_var.get()
            chosen_sleep = sleep_var.get()
            chosen_totp = totp_holder["secret"]

            init_done["busy"] = True
            btn_ok.configure(state="disabled", text=tr("正在初始化...", "Initializing..."))
            btn_cancel.configure(state="disabled")
            setup_prog_frame.pack(fill="x", padx=sc(20), pady=(0, sc(4)), before=btn_row)
            setup_pbar.start(12)

            res_q = queue.Queue()

            def _worker():
                try:
                    store.initialize(
                        password=p1,
                        clear_logic=chosen_logic,
                        clear_methods=chosen_methods,
                        count_sleep_wake=chosen_sleep,
                        autostart_mode=chosen_auto,
                        totp_secret=chosen_totp,
                        had_orphan_anchor=had_orphan,
                    )
                    set_autostart_mode(chosen_auto)
                    res_q.put((True, None))
                except Exception as exc:
                    res_q.put((False, exc))

            def _poll_init():
                if init_done.get("cancelled"):
                    return
                try:
                    ok_flag, err = res_q.get_nowait()
                except queue.Empty:
                    setup_win.after(80, _poll_init)
                    return
                setup_pbar.stop()
                setup_prog_frame.pack_forget()
                init_done["busy"] = False
                if not ok_flag:
                    btn_ok.configure(state="normal", text=tr("完成安装并生成防伪指纹", "Finish Setup"))
                    btn_cancel.configure(state="normal")
                    messagebox.showerror("初始化失败", str(err), parent=setup_win)
                    return
                fp = store.get_emoji_fingerprint()
                messagebox.showinfo(
                    tr("安装完成 — 请记录安装指纹", "Setup Complete — Save Your Fingerprint"),
                    f"本次安装已生成唯一防伪指纹：\n\n"
                    f"        {fp}\n\n"
                    f"请拍照或记下这 6 个 Emoji！\n"
                    f"若日后软件被卸载重装，这 6 个 Emoji 会完全改变；\n"
                    f"底层随机安装 ID 仅保存在日志中。",
                    parent=setup_win,
                )
                init_done["ok"] = True
                setup_win.destroy()

            threading.Thread(target=_worker, daemon=True).start()
            setup_win.after(80, _poll_init)

        def on_cancel():
            init_done["cancelled"] = True
            try:
                setup_pbar.stop()
            except Exception:
                pass
            setup_win.destroy()
            root.destroy()

        btn_row = tk.Frame(setup_win, bg=BG_MICA)
        btn_row.pack(fill="x", padx=sc(20), pady=sc(8))
        btn_cancel = make_btn(btn_row, tr("取消", "Cancel"), on_cancel)
        btn_cancel.pack(side="right", padx=(sc(8), 0))
        btn_ok = make_btn(btn_row, tr("完成安装并生成防伪指纹", "Finish Setup"), on_confirm, primary=True)
        btn_ok.pack(side="right")

        setup_win.protocol("WM_DELETE_WINDOW", on_cancel)
        root.wait_window(setup_win)
        if not init_done["ok"]:
            return
        root.deiconify()
    else:
        if not store.load():
            messagebox.showerror(
                "数据文件损坏或被篡改",
                f"无法读取状态文件：\n{store.data_path}\n\n请检查是否被外部修改，审计日志位于：\n{store.log_path}",
            )
            root.destroy()
            return
        try:
            store.verify_binary_integrity_or_raise()
        except BinaryTamperError as exc:
            messagebox.showerror("安全拦截 — 程序本体完整性异常", str(exc))
            root.destroy()
            sys.exit(1)
        refresh_autostart_path_if_needed(store.state.get("autostart_mode", AUTOSTART_SILENT))

    _center_window(root, sc(630), sc(650))
    root.minsize(sc(550), sc(530))
    _apply_win11_window_style(root, _ico)

    # =========================
    # 一级主界面：简洁、醒目、异步进度条平滑同步
    # =========================
    container = tk.Frame(root, bg=BG_MICA)
    container.pack(fill="both", expand=True, padx=sc(18), pady=sc(14))

    audit_bar = tk.Frame(container, bg=SUCCESS_BG, padx=sc(12), pady=sc(7))
    audit_bar.pack(fill="x", pady=(0, sc(6)))
    audit_banner = tk.Label(audit_bar, text="", bg=SUCCESS_BG, fg=SUCCESS, font=(FONT_UI, 9, "bold"), anchor="w")
    audit_banner.pack(side="left", fill="x", expand=True)
    btn_dismiss_alert = make_btn(audit_bar, tr("消除告警", "Dismiss"), lambda: on_dismiss_alerts(), compact=True)

    sync_bar_frame = tk.Frame(container, bg=BG_MICA)
    tk.Label(
        sync_bar_frame,
        text=tr("正在后台同步 Windows 系统开机与安全日志...", "Syncing Windows boot & security event logs..."),
        bg=BG_MICA,
        fg=ACCENT,
        font=(FONT_UI, 8),
        anchor="w",
    ).pack(fill="x", pady=(0, sc(2)))
    sync_pbar = ttk.Progressbar(sync_bar_frame, mode="indeterminate", style="Win11.Horizontal.TProgressbar")
    sync_pbar.pack(fill="x")
    sync_state = {"running": False}

    hero_out, hero = make_card(container, padx=18, pady=14)
    hero_out.pack(fill="x", pady=(0, sc(12)))

    kpi_row = tk.Frame(hero, bg=BG_CARD)
    kpi_row.pack(fill="x", pady=(0, sc(12)))

    left_kpi = tk.Frame(kpi_row, bg=BG_CARD)
    left_kpi.pack(side="left", expand=True, fill="x")
    tk.Label(left_kpi, text=tr("累计开机 / 唤醒次数", "Total Boots / Wakes"), bg=BG_CARD, fg=TEXT_SECONDARY, font=(FONT_UI, 10)).pack()
    count_var = tk.StringVar()
    tk.Label(left_kpi, textvariable=count_var, bg=BG_CARD, fg=ACCENT, font=(FONT_UI, 32, "bold")).pack(pady=(sc(2), 0))

    tk.Frame(kpi_row, bg=BORDER_CARD, width=1).pack(side="left", fill="y", padx=sc(14), pady=sc(4))

    right_kpi = tk.Frame(kpi_row, bg=BG_CARD)
    right_kpi.pack(side="left", expand=True, fill="x")
    tk.Label(right_kpi, text=tr("累计重置次数", "Total Resets"), bg=BG_CARD, fg=TEXT_SECONDARY, font=(FONT_UI, 10)).pack()
    reset_count_var = tk.StringVar()
    reset_count_lbl = tk.Label(right_kpi, textvariable=reset_count_var, bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 32, "bold"))
    reset_count_lbl.pack(pady=(sc(2), 0))

    fp_box = tk.Frame(hero, bg=ACCENT_SOFT, padx=sc(14), pady=sc(8))
    fp_box.pack(fill="x", pady=(0, sc(10)))
    tk.Label(fp_box, text=tr("安装指纹", "Install Fingerprint"), bg=ACCENT_SOFT, fg=TEXT_SECONDARY, font=(FONT_UI, 9)).pack(side="left")
    emoji_fp_var = tk.StringVar()
    tk.Label(fp_box, textvariable=emoji_fp_var, bg=ACCENT_SOFT, fg=TEXT_PRIMARY, font=("Segoe UI Emoji", 15)).pack(side="right")

    meta_var = tk.StringVar()
    tk.Label(hero, textvariable=meta_var, bg=BG_CARD, fg=TEXT_SECONDARY, font=(FONT_UI, 8), anchor="w").pack(fill="x")

    action_bar = tk.Frame(container, bg=BG_MICA)
    action_bar.pack(fill="x", pady=(0, sc(12)))

    hist_out, hist_card = make_card(container, padx=12, pady=10)
    hist_out.pack(fill="both", expand=True)

    tk.Label(hist_card, text=tr("近期开机与唤醒记录", "Recent Boot & Wake History"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 10, "bold")).pack(
        anchor="w", pady=(0, sc(6))
    )

    tree_wrap = tk.Frame(hist_card, bg=BG_CARD)
    tree_wrap.pack(fill="both", expand=True)
    cols = ("time", "event", "count")
    tree = ttk.Treeview(tree_wrap, columns=cols, show="headings", style="Win11.Treeview")
    tree.heading("time", text=tr("发生时间", "Timestamp"))
    tree.heading("event", text=tr("事件类型", "Event"))
    tree.heading("count", text=tr("当时累计", "Count"))
    tree.column("time", width=sc(145), minwidth=sc(120), anchor="center")
    tree.column("event", width=sc(300), minwidth=sc(180), anchor="w")
    tree.column("count", width=sc(80), minwidth=sc(65), anchor="center")
    scrollbar = ttk.Scrollbar(tree_wrap, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def refresh_ui():
        st = store.state
        count_var.set(tr(f"{st['boot_count']} 次", str(st['boot_count'])))
        rc = int(st.get("reset_count", 0))
        reset_count_var.set(tr(f"{rc} 次", str(rc)))
        reset_count_lbl.configure(fg=DANGER if rc > 0 else TEXT_PRIMARY)
        emoji_fp_var.set(store.get_emoji_fingerprint())

        actual_auto = get_autostart_mode() if IS_WINDOWS else st.get("autostart_mode", AUTOSTART_SILENT)
        auto_short = {AUTOSTART_SILENT: tr("静默自启", "Silent"), AUTOSTART_GUI: tr("开机弹窗", "Window"), AUTOSTART_OFF: tr("已关闭", "Off")}.get(actual_auto, "-")
        meta_var.set(tr(f"安装时间：{st['installed_at']}   ·   自启：{auto_short}   ·   清空策略：{store.format_policy_summary()}", f"Installed: {st['installed_at']}   ·   Autostart: {auto_short}   ·   Policy: {store.format_policy_summary()}"))

        anomalies = st.get("security_anomalies", [])
        total_issues = len(store.tamper_reasons) + len(anomalies)
        if store.tampered or anomalies:
            audit_bar.configure(bg=DANGER_BG)
            audit_banner.configure(
                bg=DANGER_BG,
                fg=DANGER,
                text=tr(f"⚠ 检测到 {total_issues} 项安全异常（点击「导出审计报告」查看详情）", f"⚠ {total_issues} security alert(s) detected (Export Audit Report for details)"),
            )
            btn_dismiss_alert.pack(side="right", padx=(sc(8), 0))
        else:
            audit_bar.configure(bg=SUCCESS_BG)
            audit_banner.configure(
                bg=SUCCESS_BG,
                fg=SUCCESS,
                text=tr("✔ 状态正常", "✔ All Checks Passed"),
            )
            btn_dismiss_alert.pack_forget()

        is_disabled = st.get("clear_logic") == CLEAR_LOGIC_DISABLED or bool(st.get("permanent_lock"))
        if is_disabled:
            btn_clear.configure(state="disabled", text=tr("清空计数（已禁止）", "Reset Disabled"), bg="#E0E0E0", fg="#8A8A8A")
        else:
            btn_clear.configure(state="normal", text=tr("清空计数", "Reset Count"), bg=BG_CARD, fg=DANGER)

        for row in tree.get_children():
            tree.delete(row)
        for item in reversed(st.get("boot_history", [])):
            tree.insert("", "end", values=(item.get("time", ""), item.get("event", ""), tr(f"{item.get('count_after', 0)} 次", str(item.get('count_after', 0)))))

    def run_async_sync(show_popup: bool = False):
        if sync_state["running"]:
            return
        sync_state["running"] = True
        sync_bar_frame.pack(fill="x", pady=(0, sc(8)), before=hero_out)
        sync_pbar.start(12)
        btn_sync.configure(state="disabled", text=tr("同步中...", "Syncing..."))

        sync_q = queue.Queue()

        def _worker():
            try:
                ab, aa = store.sync_power_events()
                sync_q.put((ab, aa, None))
            except Exception as exc:
                sync_q.put((0, 0, exc))

        def _poll_sync():
            try:
                added_b, added_a, err = sync_q.get_nowait()
            except queue.Empty:
                root.after(80, _poll_sync)
                return
            sync_pbar.stop()
            sync_bar_frame.pack_forget()
            sync_state["running"] = False
            btn_sync.configure(state="normal", text=tr("立即同步日志", "Sync Logs"))
            refresh_ui()
            if show_popup:
                if err is not None:
                    messagebox.showerror("同步失败", str(err), parent=root)
                else:
                    messagebox.showinfo("同步完成", f"已同步系统日志：新增 {added_b} 次开机/唤醒，新增 {added_a} 条安全异常。", parent=root)

        threading.Thread(target=_worker, daemon=True).start()
        root.after(80, _poll_sync)

    def on_clear_count():
        logic = store.state.get("clear_logic", CLEAR_LOGIC_ANY)
        methods = store.state.get("clear_methods", [METHOD_PASSWORD])

        def _do_clear(pwd="", totp="", wh_ok=False):
            try:
                store.clear_count(password=pwd, totp_code=totp, winhello_verified=wh_ok)
                refresh_ui()
                messagebox.showinfo(
                    "已清空",
                    f"开机/唤醒次数已归零。\n当前累计重置次数：{store.state['reset_count']} 次。",
                    parent=root,
                )
            except (ValueError, PermissionError) as exc:
                messagebox.showerror("清空失败", str(exc), parent=root)

        if logic == CLEAR_LOGIC_ANY and len(methods) > 1:
            # 多种方式任选其一：弹出 Win11 风格验证方式选择器
            pick = tk.Toplevel(root)
            pick.title("选择清空验证方式")
            pick.configure(bg=BG_MICA)
            _center_window(pick, sc(380), sc(260))
            pick.grab_set()
            _apply_win11_window_style(pick, _ico)

            tk.Label(pick, text="请选择任意一种已启用的方式验证身份", bg=BG_MICA, fg=TEXT_PRIMARY, font=(FONT_UI, 10, "bold")).pack(
                pady=(sc(16), sc(4))
            )
            tk.Label(pick, text="清空后将归零开机次数并记录一次重置", bg=BG_MICA, fg=TEXT_SECONDARY, font=(FONT_UI, 8)).pack(
                pady=(0, sc(12))
            )

            def _by_pwd():
                pick.destroy()
                p = simpledialog.askstring("管理密码验证", "请输入管理密码：", show="*", parent=root)
                if p is not None:
                    _do_clear(pwd=p)

            def _by_totp():
                pick.destroy()
                c = simpledialog.askstring("动态口令验证", "请输入手机验证器当前的 6 位动态口令：", parent=root)
                if c is not None:
                    _do_clear(totp=c)

            def _by_hello():
                pick.destroy()
                ok, msg = verify_windows_hello("BootCounter：请验证 Windows Hello 以清空开机计数")
                if not ok:
                    messagebox.showerror("Windows Hello 验证失败", msg, parent=root)
                    return
                _do_clear(wh_ok=True)

            if METHOD_WINHELLO in methods:
                make_btn(pick, "使用 Windows Hello 验证", _by_hello, primary=True).pack(fill="x", padx=sc(24), pady=sc(4))
            if METHOD_PASSWORD in methods:
                make_btn(pick, "使用管理密码验证", _by_pwd).pack(fill="x", padx=sc(24), pady=sc(4))
            if METHOD_TOTP in methods:
                make_btn(pick, "使用 6 位动态口令 验证", _by_totp).pack(fill="x", padx=sc(24), pady=sc(4))
            return

        # 单一方式 或 全部方式同时验证 (CLEAR_LOGIC_ALL)
        pwd, totp, wh_ok = "", "", False
        if METHOD_PASSWORD in methods:
            pwd = simpledialog.askstring("管理密码验证", "请输入管理密码：", show="*", parent=root)
            if pwd is None:
                return
        if METHOD_TOTP in methods:
            totp = simpledialog.askstring("动态口令验证", "请输入手机验证器当前的 6 位动态口令：", parent=root)
            if totp is None:
                return
        if METHOD_WINHELLO in methods:
            ok, msg = verify_windows_hello("BootCounter：请验证 Windows Hello 以清空开机计数")
            if not ok:
                messagebox.showerror("Windows Hello 验证失败", msg, parent=root)
                return
            wh_ok = True
        _do_clear(pwd=pwd, totp=totp, wh_ok=wh_ok)

    def on_dismiss_alerts():
        logic = store.state.get("clear_logic", CLEAR_LOGIC_ANY)
        methods = store.state.get("clear_methods", [METHOD_PASSWORD])
        if logic == CLEAR_LOGIC_DISABLED:
            logic = CLEAR_LOGIC_ANY
            methods = [METHOD_PASSWORD]

        def _do_dismiss(pwd="", totp="", wh_ok=False):
            try:
                store.dismiss_tamper_alerts(password=pwd, totp_code=totp, winhello_verified=wh_ok)
                refresh_ui()
                messagebox.showinfo("告警已消除", "界面告警已关闭，消除时间与验证方式已记入日志。", parent=root)
            except ValueError as exc:
                messagebox.showerror("验证失败", str(exc), parent=root)

        if logic == CLEAR_LOGIC_ANY and len(methods) > 1:
            pick = tk.Toplevel(root)
            pick.title("验证身份以消除告警")
            pick.configure(bg=BG_MICA)
            _center_window(pick, sc(360), sc(240))
            pick.grab_set()
            _apply_win11_window_style(pick, _ico)

            tk.Label(pick, text="选择验证方式以消除界面告警", bg=BG_MICA, fg=TEXT_PRIMARY, font=(FONT_UI, 10, "bold")).pack(
                pady=(sc(16), sc(10))
            )

            def _by_pwd():
                pick.destroy()
                p = simpledialog.askstring("管理密码验证", "请输入管理密码：", show="*", parent=root)
                if p is not None:
                    _do_dismiss(pwd=p)

            def _by_totp():
                pick.destroy()
                c = simpledialog.askstring("动态口令验证", "请输入 6 位动态口令：", parent=root)
                if c is not None:
                    _do_dismiss(totp=c)

            def _by_hello():
                pick.destroy()
                ok, msg = verify_windows_hello("BootCounter：验证身份以消除安全告警")
                if not ok:
                    messagebox.showerror("Windows Hello 验证失败", msg, parent=root)
                    return
                _do_dismiss(wh_ok=True)

            if METHOD_WINHELLO in methods:
                make_btn(pick, "使用 Windows Hello 验证", _by_hello, primary=True).pack(fill="x", padx=sc(24), pady=sc(4))
            if METHOD_PASSWORD in methods:
                make_btn(pick, "使用管理密码验证", _by_pwd).pack(fill="x", padx=sc(24), pady=sc(4))
            if METHOD_TOTP in methods:
                make_btn(pick, "使用动态口令验证", _by_totp).pack(fill="x", padx=sc(24), pady=sc(4))
            return

        pwd, totp, wh_ok = "", "", False
        if METHOD_PASSWORD in methods:
            pwd = simpledialog.askstring("管理密码验证", "请输入管理密码以消除告警：", show="*", parent=root)
            if pwd is None:
                return
        if METHOD_TOTP in methods:
            totp = simpledialog.askstring("动态口令验证", "请输入 6 位动态口令：", parent=root)
            if totp is None:
                return
        if METHOD_WINHELLO in methods:
            ok, msg = verify_windows_hello("BootCounter：验证身份以消除安全告警")
            if not ok:
                messagebox.showerror("Windows Hello 验证失败", msg, parent=root)
                return
            wh_ok = True
        _do_dismiss(pwd=pwd, totp=totp, wh_ok=wh_ok)

    def on_export_report():
        refresh_ui()
        report_text = store.build_audit_report()
        save_path = filedialog.asksaveasfilename(
            title="导出防篡改自证审计报告",
            defaultextension=".txt",
            initialfile=f"BootCounter_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("文本文件", "*.txt")],
            parent=root,
        )
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            messagebox.showinfo("导出成功", f"审计报告已保存至：\n{save_path}", parent=root)

    # =========================
    # 二级菜单窗口：⚙ 高级设置
    # =========================
    def open_settings_dialog():
        dlg = tk.Toplevel(root)
        dlg.title(tr("高级设置 — BootCounter", "Settings — BootCounter"))
        dlg.configure(bg=BG_MICA)
        _center_window(dlg, sc(560), sc(650))
        dlg.minsize(sc(500), sc(560))
        dlg.grab_set()
        _apply_win11_window_style(dlg, _ico)

        wrap = tk.Frame(dlg, bg=BG_MICA)
        wrap.pack(fill="both", expand=True, padx=sc(18), pady=sc(14))

        tk.Label(wrap, text=tr("高级设置与多方式安全策略", "Settings & Security Policy"), bg=BG_MICA, fg=TEXT_PRIMARY, font=(FONT_UI, 13, "bold")).pack(
            anchor="w", pady=(0, sc(2))
        )
        tk.Label(wrap, text=tr("修改以下配置需验证管理密码", "Admin password is required to change security settings"), bg=BG_MICA, fg=TEXT_SECONDARY, font=(FONT_UI, 8)).pack(
            anchor="w", pady=(0, sc(10))
        )

        # 卡片 A：统计范围 & Windows Hello 状态
        c1_out, c1 = make_card(wrap, padx=14, pady=10)
        c1_out.pack(fill="x", pady=(0, sc(10)))
        tk.Label(c1, text=tr("统计与运行详情", "Tracking & Status"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 10, "bold")).pack(anchor="w")
        tk.Label(
            c1,
            text=f"本次系统启动：{format_timestamp(get_system_boot_epoch())}   |   动态口令：{'已绑定' if store.has_totp() else '未绑定'}",
            bg=BG_CARD,
            fg=TEXT_SECONDARY,
            font=(FONT_UI, 8),
        ).pack(anchor="w", pady=(sc(2), sc(6)))

        sleep_var = tk.BooleanVar(value=bool(store.state.get("count_sleep_wake", True)))

        def on_toggle_sleep():
            desired = sleep_var.get()
            pwd = simpledialog.askstring("密码验证", "修改「睡眠唤醒统计」需要验证管理密码：", show="*", parent=dlg)
            if pwd is None:
                sleep_var.set(not desired)
                return
            try:
                store.set_count_sleep_wake(desired, pwd)
                refresh_ui()
            except ValueError as exc:
                sleep_var.set(not desired)
                messagebox.showerror("验证失败", str(exc), parent=dlg)

        tk.Checkbutton(
            c1,
            text=tr("计入合盖睡眠与休眠唤醒", "Count sleep / lid-open wakes"),
            variable=sleep_var,
            command=on_toggle_sleep,
            bg=BG_CARD,
            font=(FONT_UI, 9),
        ).pack(anchor="w")

        # 卡片 B：Windows 开机自启
        c2_out, c2 = make_card(wrap, padx=14, pady=10)
        c2_out.pack(fill="x", pady=(0, sc(10)))
        tk.Label(c2, text=tr("Windows 开机自启", "Windows Autostart"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 10, "bold")).pack(anchor="w", pady=(0, sc(4)))
        actual_auto = get_autostart_mode() if IS_WINDOWS else store.state.get("autostart_mode", AUTOSTART_SILENT)
        auto_var = tk.StringVar(value=actual_auto)
        auto_row = tk.Frame(c2, bg=BG_CARD)
        auto_row.pack(fill="x")
        tk.Radiobutton(auto_row, text=tr("静默自启", "Silent"), variable=auto_var, value=AUTOSTART_SILENT, bg=BG_CARD).pack(side="left", padx=(0, sc(8)))
        tk.Radiobutton(auto_row, text=tr("开机弹出窗口", "Show Window"), variable=auto_var, value=AUTOSTART_GUI, bg=BG_CARD).pack(side="left", padx=(0, sc(8)))
        tk.Radiobutton(auto_row, text=tr("关闭自启", "Disabled"), variable=auto_var, value=AUTOSTART_OFF, bg=BG_CARD).pack(side="left")

        def on_save_auto():
            chosen = auto_var.get()
            pwd = simpledialog.askstring("密码验证", "修改开机自启设置需要验证管理密码：", show="*", parent=dlg)
            if pwd is None:
                return
            try:
                store.set_autostart_preference(chosen, pwd)
                set_autostart_mode(chosen)
                refresh_ui()
                messagebox.showinfo("已更新", "Windows 开机自启设置已保存。", parent=dlg)
            except ValueError as exc:
                messagebox.showerror("失败", str(exc), parent=dlg)

        make_btn(auto_row, tr("应用", "Apply"), on_save_auto, primary=True, compact=True).pack(side="right")

        # 卡片 C：多种清空保护方式自由组合
        c3_out, c3 = make_card(wrap, padx=14, pady=10)
        c3_out.pack(fill="x", pady=(0, sc(10)))
        tk.Label(c3, text=tr("清空保护方式", "Reset Protection Methods"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 10, "bold")).pack(
            anchor="w", pady=(0, sc(4))
        )

        is_perm = bool(store.state.get("permanent_lock"))
        cur_methods = set(store.state.get("clear_methods", [METHOD_PASSWORD]))
        cb_pwd = tk.BooleanVar(value=METHOD_PASSWORD in cur_methods)
        cb_totp = tk.BooleanVar(value=METHOD_TOTP in cur_methods)
        cb_hello = tk.BooleanVar(value=METHOD_WINHELLO in cur_methods)

        cb_row = tk.Frame(c3, bg=BG_CARD)
        cb_row.pack(fill="x", pady=(0, sc(4)))
        tk.Checkbutton(cb_row, text=tr("管理密码", "Admin Password"), variable=cb_pwd, bg=BG_CARD, state="disabled" if is_perm else "normal").pack(side="left", padx=(0, sc(8)))
        tk.Checkbutton(cb_row, text=tr("动态口令", "TOTP"), variable=cb_totp, bg=BG_CARD, state="disabled" if is_perm else "normal").pack(side="left", padx=(0, sc(8)))
        tk.Checkbutton(cb_row, text="Windows Hello", variable=cb_hello, bg=BG_CARD, state="disabled" if is_perm else "normal").pack(side="left")

        logic_var = tk.StringVar(value=store.state.get("clear_logic", CLEAR_LOGIC_ANY))
        for val, lbl in (
            (CLEAR_LOGIC_ANY, "任意一种方式通过即可清除"),
            (CLEAR_LOGIC_ALL, "全部勾选方式均需通过"),
            (CLEAR_LOGIC_DISABLED, "完全禁止清除计数"),
        ):
            tk.Radiobutton(c3, text=lbl, variable=logic_var, value=val, bg=BG_CARD, state="disabled" if is_perm else "normal").pack(anchor="w")

        def on_save_policy():
            ms = []
            if cb_pwd.get():
                ms.append(METHOD_PASSWORD)
            if cb_totp.get():
                ms.append(METHOD_TOTP)
            if cb_hello.get():
                ms.append(METHOD_WINHELLO)
            pwd = simpledialog.askstring("密码验证", "请输入管理密码以保存清空策略：", show="*", parent=dlg)
            if pwd is None:
                return
            try:
                store.set_clear_policy(logic_var.get(), ms, pwd, permanent=False)
                refresh_ui()
                messagebox.showinfo("成功", "清空保护策略已更新。", parent=dlg)
            except (ValueError, PermissionError) as exc:
                messagebox.showerror("失败", str(exc), parent=dlg)

        def on_bind_totp():
            pwd = simpledialog.askstring("身份验证", "请输入管理密码以绑定/更换动态口令：", show="*", parent=dlg)
            if pwd is None:
                return
            if not store.verify_password(pwd):
                messagebox.showerror("失败", "管理密码错误。", parent=dlg)
                return

            def _bound(sec, code):
                store.bind_totp(pwd, sec, code)
                cb_totp.set(True)
                refresh_ui()
                messagebox.showinfo("绑定成功", "动态口令已加密绑定，别忘了点击「保存策略」生效。", parent=dlg)

            open_totp_bind_modal(dlg, _bound)

        def on_test_hello():
            avail, detail = check_windows_hello_available()
            if not avail:
                messagebox.showwarning("Windows Hello 不可用", detail, parent=dlg)
                return
            ok, msg = verify_windows_hello("BootCounter：测试 Windows Hello 身份验证")
            if ok:
                messagebox.showinfo("测试通过", "Windows Hello（指纹 / 面部 / PIN）验证成功！", parent=dlg)
            else:
                messagebox.showerror("测试未通过", msg, parent=dlg)

        def on_perm_lock():
            if not messagebox.askyesno(
                "高危确认：永久锁定",
                "开启「永久锁定禁止清除」后将永远无法清空计数，也无法切回其他模式。\n确定继续吗？",
                icon="warning",
                parent=dlg,
            ):
                return
            pwd = simpledialog.askstring("密码验证", "请输入管理密码以确认永久锁定：", show="*", parent=dlg)
            if pwd is None:
                return
            try:
                store.set_clear_policy(CLEAR_LOGIC_DISABLED, [METHOD_PASSWORD], pwd, permanent=True)
                refresh_ui()
                messagebox.showinfo("已锁定", "已永久锁定为「禁止清除」模式。", parent=dlg)
                dlg.destroy()
            except (ValueError, PermissionError) as exc:
                messagebox.showerror("失败", str(exc), parent=dlg)

        def on_change_pwd():
            old_p = simpledialog.askstring("修改密码", "请输入原管理密码：", show="*", parent=dlg)
            if old_p is None:
                return
            if not store.verify_password(old_p):
                messagebox.showerror("失败", "原管理密码错误。", parent=dlg)
                return
            use_gen = messagebox.askyesno("生成强密码", "是否由系统随机数自动生成 16 位强密码？\n选「否」则手动输入新密码。", parent=dlg)
            if use_gen:
                new_p = generate_strong_password(16)
                root.clipboard_clear()
                root.clipboard_append(new_p)
                store.change_password(old_p, new_p)
                messagebox.showinfo("修改成功", f"已生成并启用新强密码（已复制到剪贴板）：\n\n{new_p}", parent=dlg)
                return
            new_p = simpledialog.askstring("修改密码", "请输入新管理密码：", show="*", parent=dlg)
            if new_p is None:
                return
            new_p2 = simpledialog.askstring("修改密码", "请再次输入新管理密码：", show="*", parent=dlg)
            if new_p2 is None:
                return
            if new_p != new_p2:
                messagebox.showerror("失败", "两次输入的新密码不一致。", parent=dlg)
                return
            try:
                store.change_password(old_p, new_p)
                messagebox.showinfo("成功", "管理密码已修改。", parent=dlg)
            except ValueError as exc:
                messagebox.showerror("失败", str(exc), parent=dlg)

        p_btns = tk.Frame(c3, bg=BG_CARD)
        p_btns.pack(fill="x", pady=(sc(8), 0))
        b_save = make_btn(p_btns, tr("保存策略", "Save Policy"), on_save_policy, primary=True, compact=True)
        b_save.pack(side="left", padx=(0, sc(6)))
        make_btn(p_btns, tr("绑定动态口令", "Bind TOTP"), on_bind_totp, compact=True).pack(side="left", padx=(0, sc(6)))
        make_btn(p_btns, tr("测试 Windows Hello", "Test Hello"), on_test_hello, compact=True).pack(side="left", padx=(0, sc(6)))
        b_lock = make_btn(p_btns, tr("永久锁定", "Permanent Lock"), on_perm_lock, danger=True, compact=True)
        b_lock.pack(side="left")
        if is_perm:
            b_save.configure(state="disabled")
            b_lock.configure(state="disabled", text=tr("已永久锁定", "Locked"))

        # 卡片 D：界面语言切换（支持自动跟随系统 / 简体中文 / English）
        c4_out, c4 = make_card(wrap, padx=14, pady=8)
        c4_out.pack(fill="x", pady=(0, sc(10)))
        lang_row = tk.Frame(c4, bg=BG_CARD)
        lang_row.pack(fill="x")
        tk.Label(lang_row, text=tr("界面语言 / Language", "Language"), bg=BG_CARD, fg=TEXT_PRIMARY, font=(FONT_UI, 9, "bold")).pack(
            side="left", padx=(0, sc(10))
        )
        lang_var = tk.StringVar(value=store.state.get("language", LANG_AUTO))
        tk.Radiobutton(lang_row, text=tr("跟随系统", "Auto"), variable=lang_var, value=LANG_AUTO, bg=BG_CARD).pack(side="left", padx=(0, sc(8)))
        tk.Radiobutton(lang_row, text="简体中文", variable=lang_var, value=LANG_ZH, bg=BG_CARD).pack(side="left", padx=(0, sc(8)))
        tk.Radiobutton(lang_row, text="English", variable=lang_var, value=LANG_EN, bg=BG_CARD).pack(side="left")

        def on_save_lang():
            store.set_language(lang_var.get())
            refresh_ui()
            messagebox.showinfo(
                tr("语言已更新", "Language Updated"),
                tr("语言偏好已保存，重新打开程序即可完整生效。", "Language saved. Please reopen BootCounter for all labels to update."),
                parent=dlg,
            )

        make_btn(lang_row, tr("应用", "Apply"), on_save_lang, compact=True).pack(side="right")

        foot = tk.Frame(wrap, bg=BG_MICA)
        foot.pack(fill="x", pady=(sc(4), 0))
        make_btn(foot, tr("修改管理密码", "Change Password"), on_change_pwd).pack(side="left")
        make_btn(foot, tr("关闭", "Close"), dlg.destroy).pack(side="right")

    make_btn(action_bar, tr("导出审计报告", "Export Report"), on_export_report, primary=True).pack(side="left", padx=(0, sc(8)))
    btn_sync = make_btn(action_bar, tr("立即同步日志", "Sync Logs"), lambda: run_async_sync(show_popup=True))
    btn_sync.pack(side="left", padx=(0, sc(8)))
    btn_clear = make_btn(action_bar, tr("清空计数", "Reset Count"), on_clear_count)
    btn_clear.pack(side="left", padx=(0, sc(8)))
    make_btn(action_bar, tr("⚙ 高级设置", "⚙ Settings"), open_settings_dialog).pack(side="right")

    tray_q = queue.Queue()
    tray = Win32TrayIcon(_ico, tr(f"BootCounter — 累计开机 {store.state.get('boot_count', 0)} 次", f"BootCounter — Total Boots: {store.state.get('boot_count', 0)}"), tray_q)
    tray.start()

    def _poll_tray():
        try:
            while True:
                act = tray_q.get_nowait()
                if act == "show":
                    root.deiconify()
                    root.state("normal")
                    root.lift()
                    root.focus_force()
                elif act == "sync":
                    root.deiconify()
                    run_async_sync(show_popup=True)
                elif act == "exit":
                    tray.stop()
                    root.destroy()
                    return
        except queue.Empty:
            pass
        if store.state:
            tray.update_tooltip(tr(f"BootCounter — 累计开机 {store.state.get('boot_count', 0)} 次", f"BootCounter — Total Boots: {store.state.get('boot_count', 0)}"))
        root.after(200, _poll_tray)

    def _on_close_to_tray():
        if IS_WINDOWS:
            root.withdraw()
        else:
            tray.stop()
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close_to_tray)
    refresh_ui()
    root.after(120, lambda: run_async_sync(show_popup=False))
    root.after(200, _poll_tray)
    root.mainloop()
    tray.stop()


def main():
    if "--destroy-tpm-key" in sys.argv:
        tpm_destroy_hardware_key()
        return
    dbg_reason = check_debugger_attached()
    if dbg_reason:
        if IS_WINDOWS:
            try:
                ctypes.windll.user32.MessageBoxW(None, tr(f"安全拦截：{dbg_reason}，程序已停止运行。", f"Security Block: {dbg_reason}. Execution halted."), tr("BootCounter 安全保护", "BootCounter Security"), 0x10)
            except Exception:
                pass
        sys.exit(1)
    harden_process_anti_debug()
    store = BootCounterStore()
    if "--boot" in sys.argv:
        if store.exists() and store.load():
            store.sync_power_events()
        return
    launch_gui(store)


if __name__ == "__main__":
    main()
