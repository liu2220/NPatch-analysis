# 847 构建与公开源码（tag v1.0.9 / dev）差异清单

> 对比对象：`NPatch-v1.0.9-847-release.zip`（manager dex + assets/npatch/loader.bin + libnpatch.so）
> vs `7723mod/NPatch` tag `v1.0.9`（a9dc461945）与 dev 分支（2026-10-18）
> 工具：androguard 4.1.4（dex 反汇编/字符串）、源码 grep

## 1. 确认的差异（逆向实证）

| # | 差异 | 证据 | 影响 |
|---|---|---|---|
| 1 | **sigBypass Level 5「Stealth」整体缺失于公开源码** | 847 管理器 dex CLI 帮助串含 `5: Stealth. Stealth requires --manager`；loader.bin 有 `enableStealthSignatureBypass`/`stealthModeActive`/`enableGotRedirect`/`refreshGotRedirect`/`disableOpenatHook`；`Constants.java`（tag+dev）仅定义到 `SIGBYPASS_SECCOMP=4` | 闭源新增，详见 stealth-reversed.md |
| 2 | 847 loader 的 `SigBypass` 类有 59 方法+13 内部类（tag 源码同文件 ~30 方法/少量内部类，`effectiveHookLevel` 仅处理 4→3） | androguard 类/方法清单 + `effectiveHookLevel` 字节码（847：`4,5→3`；tag：仅 `4→3`） | Stealth 分支 |
| 3 | 847 `doSigBypass` 含 `isStealth` 分支与 `return` 提前退出 | 字节码控制流还原 | 同上 |
| 4 | 管理器 dex 中修补器类位于 `top.nkbe.npatch.patch.NPatch`（R8 重定位包名），源码为 `top.nkbe.patch.NPatch` | androguard 类清单 | 仅打包差异，无行为差异 |
| 5 | 管理器 App 大量类被 R8 混淆（`ShizukuService extends 喵喵喵猫喵喵...`、`MainActivity extends 貓喵...`、`ZipMaker$alignmentRule$1 extends 喵喵...`） | 类清单 super 名 | 管理器开启 R8 混淆（喵系字典），与 Vector 桥的喵系类名同源（构建链共用混淆配置） |
| 6 | loader.bin 内含 `fpa_app.key` 同级的 `keystore`/`mtprovider.dex`/`npatch.key` 管理器资产（jar 模块），847 与 tag 一致 | jar/src/main/assets | 无差异 |

## 2. 一致性确认（847 与源码行为吻合的部分）

- 修补管线（manifest 修改点、metaloader 注入为 classes.dex、origin.apk zip-link、V2+V3 签名、`-npa/-fpa` XOR 0x5A 密钥混淆）——管理器 dex 内 `NPatch`/`nza.*` 类结构与源码一一对应。
- 运行时引导链（`LSPApplication.onLoad` 日志串逐条出现在 loader.bin：`Loaded patch config for ...`、`Initialize service client`、`Success update LoadedModule scope from Manager`、`NPatch bootstrap completed` 等）。
- `XposedBridge.FRAMEWORK_NAME="NPatch"`、`XPOSED_BRIDGE_VERSION=93`。
- 诊断导出（`NPatchCrash` tag、`Uncaught exception in main`、collection-report）与 `DiagnosticLogExporter` 源码对应。
- Vector legacy 桥链（`LSPHooker_.forName` → `VectorNativeHooker` → `LegacyDelegateImpl.processLegacyHook`）与 HSSkyBoy/Vector@6d6c28a3 源码一致（设备崩溃栈逐帧吻合）。

## 3. 版本推断

847 构建基于 v1.0.9 tag 之后的私有开发版（Stealth 特性未推送公开分支）。用户设备日志（`Stealth: bhook GOT/PLT redirect enabled`）与 847 管理器资产逐字吻合，可确认设备上修补所用 NPatch 即此构建系列。
