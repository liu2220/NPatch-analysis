# NPatch 847 构建「Stealth」（sigBypass Level 5）专项还原

> 来源：`NPatch-v1.0.9-847-release.zip` 内嵌 `assets/npatch/loader.bin`（运行时 dex，464,888 B，509 类）
> 方法：androguard 4.1.4 字节码级还原（DEX 反汇编）；native 侧（libnpatch.so）未开源，行为由 Java 调用面 + 日志串推导
> 结论：**该级别不存在于任何公开分支**（tag v1.0.9 / dev 均无），为 847 构建闭源新增

---

## 1. 定位证据

- 管理器主 dex（classes.dex）CLI 帮助串：
  `"Signature bypass mode. 0: None, 1: Basic, 2: High, 3: Extreme, 4: Seccomp, 5: Stealth. Stealth requires --manager. default 1"`
  及 `"Stealth signature bypass mode cannot be used in integrated mode"`
- loader.bin 字符串：`https://github.com/bytedance/bhook`、`enableStealthSignatureBypass`、`stealthModeActive`、6 条 `Stealth: ...` 日志串
- 设备侧实证（云查询宿主诊断日志 2026-10-22）：
  `[I/NPatch-SigBypass] Stealth: bhook GOT/PLT redirect enabled` —— 与还原代码路径逐字吻合

## 2. 847 版 `doSigBypass` 完整控制流（字节码还原伪代码）

```java
static void doSigBypass(Context ctx, int level, boolean hideLibs) {
    activeSigBypassLevel = Math.max(activeSigBypassLevel, level);
    boolean isStealth = (level == 5);
    stealthModeActive = stealthModeActive || isStealth;          // 幂等
    int hookLevel = effectiveHookLevel(level);                    // 4→3, 5→3, 其余原样
    String currentApkPath = (visibleApkPath != null) ? visibleApkPath : ctx.getPackageResourcePath();
    boolean nativeable = hideLibs && hookLevel >= 1;

    if (hookLevel >= 1 && redirectApkPath == null)
        redirectApkPath = extractOriginalApk(ctx);                // assets/npatch/origin.apk → code_cache/<crc>.apk

    if (!isStealth) {                                             // ===== Level 0–4 原路径 =====
        if (hookLevel >= 1 && redirectApkPath != null) {
            hookJavaIO(currentApkPath, redirectApkPath);
            hookJavaFilePathAccessors();
            boolean skipOpenat = (level == 4);                    // seccomp 独占 openat
            useMinimalNativeFileHook |= is360ProtectedApk(redirectApkPath);
            if (useMinimalNativeFileHook)
                SigBypass.enableOpenatHookMinimal(currentApkPath, redirectApkPath, ctx.getPackageName(), nativeable, skipOpenat);
            else
                SigBypass.enableOpenatHook       (currentApkPath, redirectApkPath, ctx.getPackageName(), nativeable, skipOpenat);
            nativeOpenatEnabled = !skipOpenat;
            libHideEnabled = nativeable;
        }
    } else {                                                      // ===== Level 5 Stealth =====
        enableStealthSignatureBypass(ctx);                        // ① 装满签名查询面（见 §3）
        if (redirectApkPath == null) {
            XLog.w(TAG, "Stealth: original APK unavailable, GOT redirect disabled"); return;
        }
        boolean ok = SigBypass.enableGotRedirect(                 // ② native bhook GOT/PLT 重定向
                currentApkPath, redirectApkPath, ctx.getPackageName(),
                hostNativeLibraryRoots(ctx));
        if (ok) {
            if (!gotRedirectEnabled) { XLog.i(TAG, "Stealth: bhook GOT/PLT redirect enabled"); gotRedirectEnabled = true; }
            hookRuntimeLibraryLoadForGotRefresh();                // ③ 晚加载库的 GOT 刷新钩子
        } else {
            XLog.w(TAG, "Stealth: bhook registration failed");
        }
        return;                                                   // ★ 不装 openat inline / svc / seccomp
    }

    if (hookLevel >= 2) { hookPackageArchiveInfo(ctx); hookHasSigningCertificate(ctx);
                          hookGetApplicationInfo(ctx); hookApkPathAccessors(ctx); }
    if (hookLevel >= 3) { /* PackageInfo 构造/Parcel/parser/appInfoCtor/getPackageInfo + svc redirect */ }
    if (level == 4)       { /* FunPatch.enableSeccompV2Redirect */ }
    ...
}
```

## 3. `enableStealthSignatureBypass` —— 签名查询面全装

字节码还原（等价于 High+Extreme 两级全部**签名类** Java 钩子）：

```java
static void enableStealthSignatureBypass(Context ctx) {
    hookPackageArchiveInfo(ctx);                    // getPackageArchiveInfo 路径偷换+重签
    hookHasSigningCertificate(ctx);                 // 原始证书匹配 → true
    if (!hookPackageInfoConstructor(ctx))           // PackageInfo 构造器/Parcel
        hookPackageInfoCreator(ctx);
    hookPackageParserGeneratePackageInfo(ctx);      // PackageParser.generatePackageInfo
    hookGetPackageInfo(ctx);                        // getPackageInfo
}
```

注意：**不含** `hookGetApplicationInfo` / `hookApkPathAccessors`（路径面由 native GOT 层接管，Java 路径钩子少装一层——比 Extreme 更少 Java 钩子、更隐蔽）。

## 4. native 桥新方法（847 loader.bin vs tag 源码）

| native 方法 | tag v1.0.9 | 847 | 作用 |
|---|---|---|---|
| `enableOpenatHook(String,String,String,Z,Z)V` | ✅ | ✅ | openat inline 重定向 |
| `enableOpenatHookMinimal(...)` | ✅ | ✅ | 360 壳最小模式 |
| `enableSvcRedirect(String,String,String)Z` | ✅ | ✅ | svc #0 指令级拦截 |
| `setModuleNativeLibraryRoots([Ljava/lang/String;)V` | ✅ | ✅ | 模块 native 库根 |
| **`enableGotRedirect(String,String,String,[String;)Z`** | ❌ | ✅ | **bhook GOT/PLT 重定向**（Stealth 核心） |
| **`refreshGotRedirect()Z`** | ❌ | ✅ | 刷新已加载 ELF 的 GOT 映射 |
| **`disableOpenatHook()V`** | ❌ | ✅ | 卸载 openat hook（模式间切换/清理） |

`enableGotRedirect` 第 4 参 = `hostNativeLibraryRoots(ctx)`：`LinkedHashSet{ nativeLibraryDir, dataDir }`——告诉 bhook 扫描哪些目录下的 ELF。

## 5. 晚加载库 GOT 刷新（`hookRuntimeLibraryLoadForGotRefresh`）

```java
static void hookRuntimeLibraryLoadForGotRefresh() {
    if (gotRefreshHookInstalled) return;
    XC_MethodHook h = new SigBypass$13();               // after: refreshGotRedirect()
    boolean a = hookAllMethodsQuietly(Runtime.class, "loadLibrary0", h);
    boolean b = hookAllMethodsQuietly(Runtime.class, "load0", h);   // 覆盖新旧 ART 两套 Runtime 实现
    gotRefreshHookInstalled = a || b;
    if (!gotRefreshHookInstalled)
        XLog.w(TAG, "Stealth: late-loaded native libraries cannot trigger a GOT refresh");
}
```

对应失败分支日志：`Stealth: GOT refresh failed after loading a native library`、`Stealth: GOT refresh reported no updated mappings`（native 侧 `refreshGotRedirect` 返回值语义）。

## 6. 与 Level 1–4 的对比

| 维度 | 1 Basic | 2 High | 3 Extreme | 4 Seccomp | **5 Stealth** |
|---|---|---|---|---|---|
| Java 签名钩子 | — | 4 个 | 8 个 | 8 个 | **8 个**（无路径面 2 个） |
| 文件重定向 | openat inline hook | 同左 | + svc 指令拦截 | seccomp trap-replay | **bhook GOT/PLT 表重定向** |
| 代码段修改 | 有（inline hook） | 有 | 有（指令级） | 无（seccomp filter） | **无（只改数据表 GOT）** |
| 晚加载库覆盖 | 部分库已加载后失效 | 同左 | 同左 | 全部（内核态） | **Runtime.loadLibrary0/load0 钩子主动刷新** |
| 对 CRC/代码完整性检测 | 可被检出 | 同左 | 可被检出 | 隐蔽 | **最隐蔽**（GOT 是数据段） |
| 要求 --manager | 否 | 否 | 是 | 是 | **是** |

## 7. 对云查询 Hook 模块（gty_lsposed）的意义

1. 用户设备正处于 Level 5：模块调用的 `ClassLoader.loadClass` 等若被宿主加固壳经 GOT 层监视，行为与 inline hook 场景一致——我们的 B1 系钩子不受影响（挂 Java 层方法，不碰 GOT）。
2. WebView 崩溃根因与 Stealth 无关（崩溃链在 Vector legacy 桥 forName 调用方丢失），Stealth 只负责文件/签名面。v1.5.2 域救援方案与 Level 5 共存无冲突。
3. 若 NPatch 未来版本变更 `enableGotRedirect` 对模块库根的覆盖（`setModuleNativeLibraryRoots`），模块自身的 native 库加载路径也在其中——模块不要依赖"从修补包路径读文件"的行为（NPatch 明确保证模块调用方看到真实修补包路径，`isModuleCaller()` 白名单机制）。
