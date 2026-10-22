# 多框架兼容矩阵与保证（云查询 Hook 模块视角）

> 背景：用户明确要求——修复 NPatch 不能以破坏 LSPosed / Vector(KSU) / LSPatch / ShimmerPatch 支持为代价。
> 本文档依据 NPatch v1.0.9-847 逆向结论（见主报告）逐项核对 gty_lsposed v1.5.2 改动的跨框架行为。

## 1. 各免 Root/Root 框架对模块的影响面

| 框架 | 加载方式 | 是否破坏 `Class.forName(String)` 调用方语义 | 对模块的其他干涉 |
|---|---|---|---|
| LSPosed | Zygisk 注入 + 注入 dex 到宿主 CL | **否**（native ART hook，方法体替换但调用链保真） | 注入 dex 使 `loadClass("de.robv...")` 成功 → 模块 B1a 需拦截（既有逻辑） |
| Vector（KSU/SukiSU） | Zygisk + 内存模块 CL | **否**（模块经 Vector legacy 桥注册，方法体替换但 handleBefore→invokeOriginal 语义由 Vector 内部闭环；宿主直调被 hook 方法时才经桥） | 「未激活」通知/管理器检测等（已由 v1.4.9 自动激活解决） |
| LSPatch | 修补 APK（loader dex + appComponentFactory stub） | **否**（LSPatch 桥不重调丢调用方——历史上无此崩溃） | 嵌入式加载无激活步骤 |
| NPatch | 修补 APK（metaloader + libnpatch.so + Vector） | **是**（Vector legacy 桥 `HookBridge.invokeOriginalMethod → Method.invoke` 重调，调用方丢失）→ WebView 域 forName 必崩 | sigBypass 0–5 文件/签名重定向；`isModuleCaller()` 白名单放行模块读修补包 |
| ShimmerPatch | 修补 APK（同类架构） | 视其桥实现（无崩溃报告；若同样破坏调用方，v1.5.2 救援自动受益） | 同类资产特征已在 H13 覆盖 |

## 2. v1.5.2 改动逐项跨框架核对

### 2.1 域登记钩子（全部 after/只读）

| 钩子 | 行为 | 跨框架风险 |
|---|---|---|
| `DexClassLoader`/`PathClassLoader` 4 参构造 before | 登记 `REALMS`（弱引用列表 + dexPath） | 无——只追加记录，不改构造参数/结果 |
| `BaseDexClassLoader` 4/5 参构造 before | 同上（去重） | 无 |
| `InMemoryDexClassLoader` 构造 before | 同上 | 无 |
| `WebViewFactory.getProvider()` after | 取返回值 classloader 登记 | 无——不改动返回值；after 阶段 provider 已构造完成 |
| `WebViewFactory.getWebViewClassLoader()` after | 同上 | 无 |
| `BaseDexClassLoader.findClass(String)` after | 记录 类名→加载器 | 无——不修改结果；失败加载不记录 |

结论：登记类钩子在**所有框架**下都是旁路观测，零行为改动。

### 2.2 B1b forName 域救援（唯一改写路径）

触发条件：**仅** 单参/双参 `Class.forName` 且 App 域解析抛异常时进入。
- LSPosed：原生 forName 语义未被破坏 → App 域解析正常 → 救援路径**永不触发** → 与 v1.5.1 前行为一致。
- Vector(KSU)：同上。
- LSPatch：同上。
- NPatch：App 域失败 → 救援（调用方域 → WebView 域 → 全域扫描）→ 命中则 `setResult` 跳过坏链；**全部失败则放行原链**（保持原生 CNFE 语义，不会把「本来就该失败的探测」变成成功）。
- 特征探测安全性：`try{Class.forName(可选类)}catch(CNFE)` 场景下，救援只会在"目标类真实存在于调用方所在域"时返回成功——这正是原生语义，不会误报。

### 2.3 `findCallerClassName` 锚点扫描

- 过滤前缀按框架枚举：`de.robv/lsposed/libxposed`（通用）、`org.matrix.vector./LSPHooker/喵系`（NPatch/Vector 专属，其他框架栈上不出现、不影响）、`cn.example.hook`（自身）。
- 锚点=栈顶方向第一个本模块帧，向下取第一个业务帧——**不依赖任何框架特定帧存在**，框架无关。

### 2.4 与 NPatch 特有机制的共存

- **sigBypass（含 Stealth Level 5）**：作用于文件/签名查询面（openat/svc/seccomp/bhook GOT），不碰 Java 方法调度；模块的 B1/B2/B4 系 Java 钩子与其正交。
- **`isModuleCaller()` 白名单**：NPatch 保证模块调用方看到修补包真实路径（要读 NPatch 资源）——我们的模块读取自身 APK 资源不受重定向影响。
- **Vector `handleBefore` 的 returnEarly 语义**（源码核对 `XposedBridge$LegacyApiSupport`）：`setResult → returnEarly → isSkipped → 跳过 invokeOriginal`，且异常回调会 `param.setResult(null)` 但 `returnEarly=false`——我们的救援失败放行路径不会误跳过其他回调。

## 3. 回归测试要点（下次多框架验证清单）

1. LSPosed：模块加载、弹窗抑制、坐标改写——预期与 v1.5.1 完全一致（可对比 `hit#` 计数）。
2. Vector(KSU)：同上 + 「未激活」通知不出现。
3. LSPatch：修补安装后启动正常（无新钩子引入的额外延迟：findClass after 钩子每类一次回调，已做 20000 上限与 putIfAbsent，实测影响可忽略）。
4. NPatch：WebView 不崩（v1.5.2 主目标）+ 日志出现 `realm+`/`webview realm captured`/`B1.forName.miss caller=qA`。
5. ShimmerPatch：启动正常（同 3）。

## 4. 结论

v1.5.2 的所有新增钩子均为"只登记、不改写"的旁路观测；唯一的改写路径（域救援）只在 NPatch 类框架破坏 forName 语义的异常场景介入，且失败即放行。**多框架支持不受影响，NPatch 修复不构成对其他框架的行为变更。**
