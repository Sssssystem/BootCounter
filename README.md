[English](README_EN.md) | 简体中文

# BootCounter — Windows 开机与唤醒防篡改审计记录器

一款符合 Windows 11 Fluent Design 规范的桌面开机与唤醒审计工具，零第三方运行依赖，适用于记录设备自安装以来的真实开机、重启及合盖睡眠唤醒次数，并提供完整的防篡改与防重装核验能力。

## 功能一览

### 1. 开机与唤醒全场景记录

* **首次安装即计为 1 次**：安装并完成初始化后立即记录第 1 次。

* **全面覆盖多种开机方式**：结合 Windows 内核 `System` 事件日志（`Kernel-General 12` 冷启动/重启、`Kernel-Boot 27` Win10/11 快速启动、`Power-Troubleshooter 1` 睡眠与合盖唤醒）以及 64 位 `GetTickCount64()`，自动对 60 秒内的重复底层事件去重。

* **独立双通道日志查询**：开机/唤醒/清日志查询与系统时间跳变查询分离，避免日常 NTP 对时日志挤掉历史开机记录。

* **Windows 开机自启**：支持「静默自启」「开机弹窗」「关闭」三种模式，程序目录移动后自动更新注册表路径。

### 2. 防篡改与反卸载重装机制

* **不可清零的「累计重置次数」**：每次清空开机计数都会永久 `+1`，无法归零，并同步写入 Windows 注册表锚点防回滚。

* **类 Telegram 6 位防重装 Emoji 指纹**：首次安装调用操作系统加密随机数生成器（`os.urandom(32)` / Windows `BCryptGenRandom`）生成 256 位独立安装 ID（界面隐藏，仅存于 `audit.log` 与导出报告中），并结合每次安装独立生成的 `install_seal.dat` 安装封条，经 SHA-256 确定性派生 6 个高辨识度 Emoji（$64^6 \approx 687$ 亿种组合）。卸载重装或覆盖旧备份都会立刻导致指纹变化并触发告警。

* **硬件级密钥保护与本体完整性校验（v1.1 新增）**：

  * 优先在主板 **TPM 2.0 安全芯片**（`Microsoft Platform Crypto Provider`）中创建不可导出 ECDSA-P256 硬件私钥并绑定 6 位 Emoji 指纹；卸载时自动销毁该专属硬件密钥，防止备份还原。

  * 整份配置文件 `state.json` 全文通过 Windows **DPAPI** 加密存储（记事本打开全为密文，不以任何明文落盘），不支持 TPM 的设备自动降级至 DPAPI 保护。

  * 启动时校验程序本体文件 **SHA-256** 哈希并使用主板 **TPM 2.0 硬件私钥签名验签**（配合 DPAPI 加密存储），程序本体被修改则直接报错停止运行；用户配置文件（改密码、记录次数等）与之严格分离，正常修改不受影响。

  * 内置**反调试保护**（`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtSetInformationThread(ThreadHideFromDebugger)` 与 Python 断点追踪检测），支持通过 Nuitka 编译为原生 C/C++ 机器码。

* **系统级异常监测**：

  * 监测 Windows 系统事件日志是否被人工清空（`EventID 104`）

  * 监测系统时间是否被大幅手动修改（`EventID 1`，跳变超过 5 分钟）

  * 单调递增 `EventRecordID` 追踪，防止回拨系统时间绕过统计

  * 历史记录首尾相连哈希链（支持超 500 条裁剪基线锚定）+ HMAC 签名 + 注册表防回滚锚点

* **验证消除界面告警（永久留痕）**：可通过已启用的验证方式关闭界面上的红色告警条，但消除时间、验证方式与原告警详情会永久写入 `audit.log`、历史时间线及导出的审计报告中。

### 3. 多种验证保护方式自由组合

* **管理密码**：使用 `PBKDF2-HMAC-SHA256` 加盐哈希存储，内置基于操作系统随机数的 16 位**强密码生成器**（一键生成并复制到剪贴板）。

* **手机动态口令（TOTP）**：内置 RFC 6238 标准实现与纯矢量二维码生成，首次安装向导即可直接显示二维码，支持 iPhone 相机 / 自带「密码」App（Face ID 保护）、Google / Microsoft Authenticator 等扫码即绑，本地密钥加密存储。

* **Windows Hello**：调用 Windows 10/11 原生 `UserConsentVerifier` 接口，支持本机已配置的指纹、面部识别或 PIN 验证。

* **灵活组合策略**：支持「任意一种勾选方式通过即可清除」「全部勾选方式均需通过」「完全禁止清除」以及不可逆的「永久锁定禁止清除」。修改睡眠统计、开机自启与清空策略均需验证管理密码。

### 4. Windows 11 界面与体验优化

* **Per-Monitor V2 高分屏适配**：在 2K/4K 及 125%–200% 缩放下文字与图标锐利清晰，窗口支持自由缩放并自动按屏幕比例居中。

* **双层极简信息架构**：一级主界面仅突出核心计数、累计重置次数、6 位安装指纹、状态条与近期记录；所有详细设置收纳至「高级设置」二级窗口。

* **系统托盘常驻与异步加载**：关闭主窗口可最小化至右下角系统托盘（支持左键呼出、右键菜单与实时计数悬停提示）；初始化与日志同步在后台线程执行并配合细进度条平滑过渡，杜绝界面卡顿。

## 仓库目录结构

```
BootCounter/
├── app.ico                          # Windows 11 Fluent 风格多分辨率透明图标
├── boot_counter.py                  # 主程序源码（Python 3 + Tkinter，零第三方运行依赖）
├── setup_msi.py                     # cx_Freeze 应用冻结配置
├── BootCounter_Setup.iss            # Inno Setup 6 现代多语言安装程序脚本
├── ChineseSimplified.isl            # 安装程序简体中文语言包
├── build_installer.bat              # Windows 本地快速构建安装包脚本（cx_Freeze）
├── build_nuitka_installer.bat       # Windows 原生 C/C++ 机器码编译与打包脚本（Nuitka）
├── reset_for_testing.bat            # 开发测试专用：一键彻底清除本机记录与 TPM/注册表锚点
├── README.md                        # 中文说明文档
├── README_EN.md                     # 英文说明文档
└── .github/
    └── workflows/
        └── release-msi.yml          # GitHub Actions 云端自动构建并发布到 Releases

```

## 安装与构建

### 方式一：直接下载安装包

前往本仓库右侧 [**Releases**](https://www.google.com/search?q=https://github.com/Sssssystem/BootCounter/releases) 页面，下载最新版的 `BootCounter_Setup_1.1.0_amd64.exe` 双击安装即可（自动跟随系统语言，支持选择「为所有用户安装」或「仅为我安装」）。

### 方式二：在 Windows 本地构建安装包

1. 安装 [Python 3](https://www.python.org/downloads/)（勾选 `Add Python to PATH`）。

2. 将仓库文件放在同一目录：

   * **原生 C/C++ 机器码编译（推荐）**：双击运行 `build_nuitka_installer.bat`（自动安装 Nuitka 编译为原生机器码并用 Inno Setup 6 封装）。

   * **快速冻结打包**：双击运行 `build_installer.bat`（使用 `cx_Freeze` + Inno Setup 6 快速打包）。

3. 构建完成后在 `dist\` 目录生成 `BootCounter_Setup_1.1.0_amd64.exe`。

### 测试清理说明

如需在自己的测试机上彻底清除历史记录、日志、TPM 测试密钥和注册表锚点以重新体验全新首次安装，可先卸载软件，再双击运行 `reset_for_testing.bat`。

## 致谢

Powered by Google Gemini

## 许可证

MIT License