# NPatch 1.0.9-847 深度逆向分析

对 **NPatch v1.0.9-847**（免 Root Xposed 框架，LSPatch 复刻 + 内嵌 Vector）的完整逆向分析工程。

## 内容

| 目录 | 说明 |
|---|---|
| `docs/NPatch-1.0.9-847-深度逆向分析报告.md` | **主报告**：修补管线、引导链、模块加载、服务通道、SigBypass 0–4 全量还原 |
| `docs/stealth-reversed.md` | **Stealth（sigBypass Level 5）专项还原**——公开源码中不存在，字节码级逆向（bhook GOT/PLT 重定向 + Runtime.loadLibrary0/load0 GOT 刷新钩子） |
| `docs/apk-vs-source-diff.md` | 847 构建与公开源码差异清单 |
| `docs/multi-framework-compat.md` | 多框架兼容矩阵（LSPosed/Vector/LSPatch/NPatch/ShimmerPatch）与回归测试要点 |
| `source/NPatch-v1.0.9/` | 官方 v1.0.9 tag 全量源码（7723mod/NPatch @a9dc461945） |
| `source/Vector-core-6d6c28a3/` | 内嵌 Vector 框架源码（NPatch core submodule 精确 commit：HSSkyBoy/Vector @6d6c28a3） |
| `decompiled/` | 管理器 APK 与运行时 loader.bin 的 androguard 逆向产物（类/字段/方法清单、字符串池、关键方法字节码还原件） |

## 核心结论（TL;DR）

1. 847 构建**领先于公开源码**：独有 sigBypass Level 5「Stealth」——用字节跳动 [bhook](https://github.com/bytedance/bhook) 做 GOT/PLT 表重定向（不修改代码段），配合 `Runtime.loadLibrary0/load0` 钩子对晚加载 native 库做 GOT 刷新；Java 侧装满签名查询钩子（High+Extreme 的签名面）但**不装** openat inline hook / svc / seccomp。
2. 免 Root 加载链：`appComponentFactory` 存根静态块 → 内存 loader.dex → 落盘并加载 `libnpatch.so` → native bootstrap（消费 dex 后清零防 dump）→ `LSPApplication.onLoad`（服务选择/Vector 初始化/模块加载/签名绕过/延迟构建宿主 ClassLoader）。
3. 修补管线亮点：entry-hook 模式（保留宿主 appComponentFactory 名、注入同名 shim，反静态扫描）、origin.apk **zip 虚拟链接**（不复制数据）、内置密钥口令 Base64⊕0x5A 混淆、`--injectdex` 子进程支持。
4. 对 [gty_lsposed](https://github.com/liu2220/Gty_Lsposed) 模块的根因闭环：WebView 崩溃 = Vector legacy 桥破坏 `Class.forName(String)` 调用方敏感性；修复见该仓库 v1.5.2（域救援三通道），本仓库 `docs/multi-framework-compat.md` 论证其对 LSPosed/LSPatch/ShimmerPatch 零回归。

## 复现

```bash
# 字符串证据
strings assets/npatch/loader.bin | grep -i stealth
# 字节码还原（androguard 4.1.4）
python3 -c "from androguard.core.dex import DEX; d=DEX(open('assets/npatch/loader.bin','rb').read())"
```

分析工具：REA（morluto/rea）+ JADX headless + androguard 4.1.4。

> 仅供安全研究与互操作性分析使用；源码版权归原作者（7723mod / HSSkyBoy / JingMatrix）所有。
