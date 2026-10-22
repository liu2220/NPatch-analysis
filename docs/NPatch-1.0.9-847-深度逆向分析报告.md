# NPatch v1.0.9-847 深度逆向分析报告

> 分析对象：`NPatch-v1.0.9-847-release.zip`（管理器 APK，包名 `top.nkbe.npatch`，versionCode 847，minSdk 28，targetSdk 37）
> 参照源码：[7723mod/NPatch](https://github.com/7723mod/NPatch) tag `v1.0.9`（a9dc461945）+ 内嵌框架 [HSSkyBoy/Vector](https://github.com/HSSkyBoy/Vector) commit `6d6c28a3`
> 分析工具：REA（morluto/rea）+ JADX（headless）+ androguard 4.1.4 + 源码逐行核对
> 分析日期：2026-10-22

---

## 0. 最重要的结论（先看这里）

1. **847 构建比公开源码新**：APK 内嵌 dex 中存在 **sigBypass Level 5「Stealth」**（基于字节跳动 [bhook](https://github.com/bytedance/bhook) 的 GOT/PLT 重定向），公开仓库（tag v1.0.9 与 dev 分支）均无此实现——`Constants.java` 两处都只定义到 `SIGBYPASS_SECCOMP = 4`。Stealth 只能通过逆向 APK 还原，本报告给出已还原的行为面（§7）。
2. **NPatch = LSPatch 复刻 + Vector 内嵌**：修补贴（patcher）管线结构承袭 LSPatch，但运行时框架从 LSPosed 的 LSPD 换成了 **Vector**（`includeBuild("core")`，依赖替换 `vector:core→:xposed`、`vector:legacy→:legacy`、`vector:bridge→:hiddenapi:bridge`）。模块兼容性由此由 Vector 的 legacy 桥决定。
3. **免 Root 加载原理**：修补 APK 把 metaloader dex 注为 `classes.dex`，`appComponentFactory` 指向存根类；存根静态块拉起 native bootstrap（`libnpatch.so`），native 层完成 Vector 注入与模块加载，再把 `ApplicationInfo` 换回"缓存的原始 APK"以通过签名/完整性检测。
4. **签名绕过是分层武器库**（Level 0–5）：Java 层 PM 钩子 → native openat 重定向 → `svc #0` 内联拦截 → seccomp trap-replay → bhook GOT/PLT 重定向，逐级对抗越来越深的自校验（§6/§7）。
5. **对本项目（云查询 Hook 模块）的直接影响**：用户设备日志中的 `Stealth: bhook GOT/PLT redirect enabled` 即 Level 5；WebView 崩溃根因在 Vector legacy 桥（详见 §8 与 gty_lsposed 仓库 v1.5.2 修复）。

---

## 1. 仓库与模块地图

```
NPatch/
├── jar/               # 修补器资源：内置签名密钥(npatch.key/fpa_app.key) + MT管理器provider dex
├── patch/             # 修补器本体（可独立 CLI 运行）：top.nkbe.patch.NPatch（826 行）
├── meta-loader/       # 引导存根：LSPAppComponentFactoryStub（classes.dex 的唯一内容）
├── patch-loader/      # 运行时加载器：LSPApplication/LSPLoader/SigBypass/GmsRedirector/服务通道
├── manager/           # 管理器 App（top.nkbe.npatch）：模块作用域管理、修补 UI、诊断导出
├── share/java+android # 两端共享：Constants、PatchConfig、LSPConfig、远端服务桥
├── remote-api/        # （空占位）
└── core/              # git submodule → HSSkyBoy/Vector @6d6c28a3（构建期 includeBuild）
```

`settings.gradle.kts` 的依赖替换表（理解 NPatch↔Vector 边界的关键）：

| Vector 逻辑坐标 | 实际工程 |
|---|---|
| `vector:core` | `:xposed`（Xposed API 实现 + HookBridge） |
| `vector:legacy` | `:legacy`（旧版 XC_MethodHook 兼容层，LegacyDelegateImpl 所在） |
| `vector:bridge` | `:hiddenapi:bridge`（HiddenApiBridge） |
| `vector:axml` | `:external:axml` |
| `vector:daemon-service` | `:services:daemon-service` |

Vector 内部模块：`xposed`（核心）、`legacy`、`native`（C++：core/elf/jni）、`hiddenapi`、`services`、`daemon`、`dex2oat`。

## 2. 修补管线（patch/NPatch.java 逐段还原）

### 2.1 CLI 参数全集（管理器 UI 亦走同一入口）

| 参数 | 作用 | 备注 |
|---|---|---|
| `-o/-f/-v` | 输出目录/覆盖/详细 | 输出名 `<原名>-<LSPConfig.VERSION_CODE>-npatched.apk` |
| `-p --newpackage` | 改包名 | 同时重映射所有 Provider authority（`remapAuthority`：前缀替换） |
| `-d --debuggable` | manifest debuggable | |
| `-l --sigbypasslv` | 签名绕过级别 0–5 | **APK 内帮助文本：5=Stealth，需 --manager**；源码里仅 0–4 |
| `--provider` | 注入 MT 管理器 DocumentsProvider | 写 `assets/npatch/mtprovider.dex` + manifest provider（authority=`<pkg>.MTDataFilesProvider`） |
| `--useMicroG` | GMS 重定向 | manifest 写 `fake-signature` 元数据 + `FAKE_PACKAGE_SIGNATURE` 权限；运行时 `GmsRedirector.activate` |
| `--hidelibs` | 隐藏 ART/敏感系统库可见性 | 仅 sigBypass>0 时生效 |
| `--cleartext` | 强制 usesCleartextTraffic=true | |
| `--name` | 改启动器标签 | |
| `--extract-libs` | 强制 extractNativeLibs=true | 兼容压缩存储 so 的宿主 |
| `-k` / `-npa` / `-fpa` | 自定义密钥 / 内置 NPatch 密钥 / 内置 FPA 密钥 | **内置密钥口令混淆：Base64 ⊕ 0x5A**（`NPATCH_KEYSTORE_PASSWORD_ENC="a2hpbm9s"` → `khinol`…） |
| `--manager` | 管理器模式（与 -m 互斥） | Extreme/Seccomp/Stealth 强制要求 |
| `--injectdex` | 物理注入 loader 到主 dex 序列 | **子进程/isolated 进程支持**（默认 stub 方案不覆盖子进程）；检测到 isolated/multiProcess 组件时打印提示 |
| `-r --allowdown` | versionCode 降为 1 允许降级装 | 运行时通过元数据取回真实版本 |
| `--override-target-sdk` | 改 targetSdk（默认 28） | 绕 targetSdk>=29 的限制 |
| `-m --embed` | 嵌入模块 APK | 存 `assets/npatch/modules/<pkg>.apk`，同包名去重 |

### 2.2 处理顺序（单 APK 非 split 分支）

1. **解析 manifest**（自研 `ManifestParser`）：取 packageName/minSdk/appComponentFactory/splitName/权限/authorities；统计 isolated|multiProcess 组件数。
2. **选签名密钥**：默认内置 NPatch 密钥；V2+V3 双签名，minSdk 抬到 ≥28。
3. **改 manifest**（`modifyManifestFile`）：
   - minSdk<28 → 抬 28；debuggable；cleartext；label；extractNativeLibs；
   - **appComponentFactory**：宿主未声明 → 直接改为存根 `top.nkbe.npatch.metaloader.LSPAppComponentFactoryStub`；宿主已声明（**entry-hook 模式**）→ *不改 manifest*，改为注入同名 shim dex（§2.3）——避免静态扫描看到"外来工厂类 IOC"；
   - 嵌入模块时补 `xposedmodule=true`/`xposeddescription`/`xposedminversion=93`；
   - 写 `npatch` 元数据 = **Base64(Gson(PatchConfig))**（含 useManager/sigBypassLevel/originalSignature/appComponentFactory/useMicroG/hideLibs/newPackage…）；
   - MicroG：`fake-signature` 原始签名；manager 模式加 `QUERY_ALL_PACKAGES`。
4. **写 config**：`assets/npatch/config.json`（明文 PatchConfig JSON）。
5. **metaloader dex**：`assets/npatch/metaloader.dex` → **覆盖写为 `classes.dex`**（`--injectdex` 时改追加为 `classesN+1.dex`）。
6. **entry-hook shim**：`DexShimBuilder.buildFactoryShim(宿主工厂名, 存根名)` 生成小 dex，**必须紧跟 metaloader 的下一个连续 classesN.dex**（框架按序枚举 multidex，有空档 shim 不会加载）。
7. **loader dex**：`assets/npatch/loader.bin`（完整运行时 dex）。
8. **native lib**：`assets/npatch/so/{arm64-v8a,x86_64}/libnpatch.so`（STORED 不压缩）。仅两架构。
9. **嵌入模块**（非 manager 模式）。
10. **嵌套原始 APK**：`assets/npatch/origin.apk`，用 `ZipMaker.putNextHostEntry` 做 **zip 虚拟链接**——其余原始条目以 `putNextVirtualEntry` 链接进宿主 zip，**不复制数据**（对比 LSPatch 的整包复制，体积优势明显）。
11. **复制剩余条目**：跳过原 dex（除非 --injectdex）；`.so`/`resources.arsc` 强制 STORED 保持 mmap。
12. **V2+V3 签名**（自研 `top.nkbe.nza.*`：ZipFile/ZipMaker/V2V3SchemeSigner + BouncyCastle）。

> split APK 分支：仅改 manifest（versionCode/targetSdk/extractNativeLibs/包名）+ 原样复制，不注入任何 loader——**NPatch 只把 base.apk 作为修补对象**。

## 3. 引导链（进程启动时刻）

```
zygote fork
 → AppComponentFactory 实例化（manifest 指向存根，或 entry-hook shim 同名类）
 → LSPAppComponentFactoryStub.<clinit>（meta-loader）
    ├─ VMRuntime.setHiddenApiExemptions("L")（失败退 HiddenApiBypass）
    ├─ 读 config.json：hideLibs / sigBypassLevel
    ├─ 读 loader.bin → 静态字段 byte[] dex（内存暂存）
    ├─ libnpatch.so 解到 <dataDir>/cache/npatch/libnpatch-*.so（只读，按 uid 分目录）
    ├─ System.load(libnpatch.so)   ← native bootstrap 消费 dex/hideLibs 静态字段
    └─ 清零 dex 缓冲（防内存 dump）；失败仅记日志、类初始化不抛（防毒化）→ App 裸跑
 → （native 侧完成 Vector 注入，最终回调 Java）
 → LSPApplication.onLoad()
    ├─ isolated 进程直接跳过（uid%100000 >= 90000）
    ├─ createLoadedApkWithContext()：偷换 mBoundApplication.info（stub LoadedApk→app LoadedApk）
    │   · sigBypass≥1 时 appInfo.sourceDir 指向 **缓存原始 APK**（OriginApkHelper.prepareOriginApk）
    │   · resolveOriginalAppComponentFactory()：**直读 dex 字符串池**探测宿主原工厂是否真实存在
    │     （不建 ClassLoader——Android 16 禁止对 app 私有目录 APK 建 loader、也避免工厂 <clinit> 反篡改门提前运行）
    ├─ 服务选择：useManager→RemoteApplicationService（连管理器 Binder，失败降级）
    │           ↓ 无管理器：有嵌入模块→IntegrApplicationService；否则→NeoLocalApplicationService（读 SharedPreferences "npatch"/"modules" 缓存）
    ├─ Startup.initXposed(false,...) + bootstrapXposed(false)  ← Vector 框架初始化
    ├─ LSPLoader.initModules(appLoadedApk)（§4）
    ├─ SigBypass.registerModuleCallerPrefixes（模块包名/入口类前缀登记 → isModuleCaller 判定）
    ├─ SigBypass.doSigBypass(level, hideLibs)（§6/§7）
    ├─ disableProfile()：清空并只读化 ART profile（阻止基于 profile 的 AOT 使 hook 失效）
    ├─ realizeLoadedApk()：此时才构建宿主 ClassLoader
    │   · createAppFactory 钩子在工厂实例化**前**触发 onPackageLoaded（pre-<clinit>）
    │   · createOrUpdateClassLoaderLocked 返回时触发 onPackageReady + legacy handleLoadPackage
    │   · provider.dex 按 --injectProvider 追加进 dexElements；修正 ActivityClientRecord.packageInfo
    ├─ 非 manager 模式：向嵌入模块的 XposedServiceHelper.onBinderReceived 投递 EmbeddedXposedService
    ├─ CacheCleaner.sweepModuleNativeCache / switchAllClassLoader()
    └─ useMicroG → GmsRedirector.activate(context, originalSignature)
```

关键设计点（与 LSPatch 的差异）：
- **ClassLoader 延迟构建**：宿主类加载器刻意推迟到全部钩子/模块/签名绕过就绪后才构建——防加固壳把工厂 `<clinit>` 做成原生反篡改门。
- **`loadedPackagesInProcess` 延迟认领**：包生命周期只由 `LoadedApkCreateCLHooker` 在派发时认领一次（注释明确：曾有二次派发导致 native 模块 inline hook 重复安装直接 tombstone）。
- **LoadedApk 资源一致性**：mResDir 必须与创建它的 APK 配对，混用修补包/原始包资源表会引发 `Resources$NotFoundException`。

## 4. 模块加载（patch-loader/LSPLoader.java）

- `initModules`：设置 `XposedBridge.FRAMEWORK_NAME="NPatch"`、`XPOSED_BRIDGE_VERSION=93`，然后 **完全委托 Vector** 的 `XposedInit.loadModules(ActivityThread)`（读模块清单 → 每模块独立 ClassLoader → 从内存执行，"zero disk footprint"）。
- `NativeModuleFilteringService`：把 `IFrameworkService` 用动态代理/Stub 包装，native 侧查询模块清单时过滤。
- **模块自路径兼容**：hook `ApplicationPackageManager.getApplicationInfo(AsUser)/getPackageInfo`——当调用方是模块（`SigBypass.isModuleCallerForCompat()`）且查询的是模块自己的包时，返回预构建的 `runtimeAppInfo`（指向模块真实 APK 路径）。注释明确：模块的 ZIP/File 读取**不能**被重定向到 origin.apk（模块需要读修补包里的 NPatch 资源）。
- 模块运行时 ApplicationInfo 缓存 `moduleRuntimeAppInfos`；`getActiveModuleApkPaths` 供缓存清理。

## 5. 进程间服务（patch-loader/service/）

| 服务 | 角色 |
|---|---|
| `RemoteApplicationService` | manager 模式：Binder 连管理器 `ManagerService`，取 legacy+modern 模块清单；结果同步写 `SharedPreferences("npatch")` 作为离线缓存 |
| `IntegrApplicationService` | 集成模式：直接读 `assets/npatch/modules/*.apk` |
| `NeoLocalApplicationService` | 无模块/离线兜底：读共享首选项缓存 |
| `NPatchProcessChannel` | 进程通道 |
| `EmbeddedXposedService` | 给嵌入模块暴露 XposedService API（新 API 模块的 `onBinderReceived`） |
| `FallbackModuleServiceWrapper` / `IntegrApplicationService` | 服务降级包装 |

管理器侧对应：`ManagerService`（Binder 服务端）、`ConfigProvider`（跨进程配置）、`NeoPackageManager`（扫描模块 APK 元数据）、Room 数据库（`Module`/`Scope` DAO）——**作用域（scope）数据由此下发**，即设备日志中的 `Updated local module scope cache: [{"path":...,"packageName":"cn.example.hook"}]`。

## 6. 签名绕过 Level 0–4（源码完整还原，SigBypass.java 931 行）

统一入口 `doSigBypass(context, sigBypassLevel, hideLibs)`；`effectiveHookLevel`：**Seccomp(4) 的 Java 钩子按 Extreme(3) 装**（seccomp 独占 openat）。

| 级别 | 名称 | 机制 |
|---|---|---|
| 0 | None | 不做 |
| 1 | Basic | ① 从 `assets/npatch/origin.apk` 解出原始 APK → `<cacheDir>/code_cache/<crc>.apk`（只读）② native `enableOpenatHook`：openat 读修补包路径 → 重定向到缓存原始包（`should_redirect_apk_contents`）③ Java 侧 hook `ZipFile`/`FileInputStream` 构造器（重定向对修补包的读取，**模块调用方除外**）④ `java.io.File` 路径访问器 ⑤ hideLibs（ART/敏感库可见性清洗，native） |
| 2 | High | + hook `getPackageArchiveInfo`（把查询路径偷换成原始包后重签结果）、`hasSigningCertificate`（匹配原始证书直接 true）、`getApplicationInfo(AsUser)`（非模块调用方返回原始签名 info）、`Context.getPackageCodePath/getPackageResourcePath`、`LoadedApk.getResDir` |
| 3 | Extreme | + `PackageInfo` Parcel/CREATOR 构造钩子、`PackageParser.generatePackageInfo`、`ApplicationInfo` 构造器、`getPackageInfo`；**svc redirect**（arm64）：对绕过 libc 直接 `svc #0` 内联系统调用的加固壳做指令级拦截（`svc_bypass.cpp`，源码注释） |
| 4 | Seccomp | Java 层=Extreme；native 层 `FunPatch.enableSeccompV2Redirect`：**seccomp 陷阱-重放**独占 openat（与 inline hook 互斥，注释说明双机制叠加只有风险没有收益） |
| 5 | Stealth | **仅存在于 847 构建，公开源码无**。见 §7 |

辅助机制：
- `isModuleCaller()`：栈扫描，调用方前缀 ∈ 已登记模块前缀集合 → 模块看到**修补包真实路径**（要读 NPatch 资源），App 看到**原始包**。
- 360 加固检测（`is360ProtectedApk`）→ `enableOpenatHookMinimal` 最小化 native 钩子。
- 双路径映射表 `mapToRedirectPath/mapToVisiblePath`（含 `path + " (deleted)"` 与 `zip://...!/` 前缀形态）。

## 7. Stealth（Level 5）——APK 逆向还原（源码缺失部分）

公开仓库无 Level 5 实现。以下从 847 管理器 APK 内嵌 dex/loader.bin 字符串与代码结构还原（详见 docs/stealth-reversed.md）：

- CLI 帮助串：`"Signature bypass mode. 0: None, 1: Basic, 2: High, 3: Extreme, 4: Seccomp, 5: Stealth. Stealth requires --manager. default 1"`；集成模式禁止："Stealth signature bypass mode cannot be used in integrated mode"。
- loader.bin 内符号：`enableStealthSignatureBypass`、`stealthModeActive`、以及日志串：
  - `Stealth: bhook GOT/PLT redirect enabled`（设备日志实证已生效）
  - `Stealth: bhook registration failed`
  - `Stealth: GOT refresh failed after loading a native library`
  - `Stealth: GOT refresh reported no updated mappings`
  - `Stealth: late-loaded native libraries cannot trigger a GOT refresh`
  - `Stealth: original APK unavailable, GOT redirect disabled`
- 依赖库：字符串 `https://github.com/bytedance/bhook`——**ByteHook**（字节跳动 PLT/GOT hook 框架）。
- 行为模型（由日志串语义 + bhook 机制推导）：
  1. 注册 bhook（`bh_linker_hook` 系）对所有已加载 ELF 的 **GOT/PLT 表项**做重定向——openat/stat/readlink/access 等文件系统符号在 **PLT 跳板层**就被改写，比 Level 1 的 inline openat hook 更早、且覆盖面=每个 ELF 的导入表；
  2. **GOT refresh**：加载新 native 库（`System.loadLibrary`）后刷新其 GOT 映射（故有"late-loaded native libraries cannot trigger a GOT refresh"的失败分支——延迟加载的库可能错过刷新窗口）；
  3. 效果：加固壳调用 libc 读自身 APK 时拿到的都是原始包内容；由于不 patch 代码段、只改数据表（GOT），对 CRC/inline-hook 检测更隐蔽（"Stealth"得名）。
- 与本项目的关系：用户设备即运行 Level 5；`NPatch-SigBypass` TAG + `Stealth: bhook GOT/PLT redirect enabled` 与 847 构建完全吻合。

## 8. Vector legacy 桥与 WebView 崩溃（对云查询模块的根因闭环）

- NPatch 运行时框架 = Vector（HSSkyBoy fork）。Vector 对 `Class.forName` 装旧版桥：`LSPHooker_.forName` → `VectorNativeHooker.callback` → `VectorChain.proceed` → `LegacyDelegateImpl.processLegacyHook` → `handleBefore()`（迭代全部 legacy 回调）→ 若无回调 setResult → `HookBridge.invokeOriginalMethod`（native）→ `Method.invoke` 重调原始方法 → **调用方丢失**（VM 视角调用方=框架类）→ 单参 `Class.forName(String)` 按错误域解析。
- chromium 胶水层（`chromium-TrichromeWebViewGoogle.apk` 的独立 DexClassLoader 域）调用方必抛 CNFE → `WebViewDialog` inflate WebView 闪退（20261022 两份诊断日志实证，崩溃栈与本报告 §3/Vector 源码链完全吻合）。
- 修复见 gty_lsposed v1.5.2（域救援三通道 + 锚点栈回溯）；机制依据：`LegacyApiSupport.handleBefore` 见 `param.returnEarly` 即跳过 `invokeOriginal`（`syncronizeApi` 回写 `callback.setResult`）。

## 9. 管理器 App（manager/）功能清单

| 组件 | 功能 |
|---|---|
| `ManagerService` | Binder 服务端：给修补应用下发模块清单/作用域 |
| `Patcher.kt` | 修补 UI 的执行器：封装 `top.nkbe.patch.Natch` CLI 参数拼装（含 Shizuku 提权安装） |
| `ConfigProvider` | 跨进程配置读取 |
| `ModuleActivationController` / `HotReloadRegistry` | 模块激活/热重载 |
| `DiagnosticLogExporter` | **生成 npatch-diagnostics-*.zip**（设备日志即其产物：app/<pkg>/<date>.log + logcat.log + collection-report.txt） |
| `ManagerIntegrity` / `ManagerCacheCleaner` | 自完整性/缓存清理 |
| `ApkInstallSet` + `SystemPackageInstaller`/`ThirdPartyPackageInstaller` | 系统安装器/Shizuku/会话安装多通道 |
| `ShizukuApi`/`ShizukuService` | Shizuku 提权（免 root 装卸） |
| Room DB（Module/Scope） | 模块与作用域持久化 |
| `MyKeyStore`/`ConfigManager`/`ThemeConfig` | 密钥/配置/主题 |

（清单经源码核对；APK 反编译比对见 docs/apk-vs-source-diff.md——重点差异：Stealth 级别、loader.bin 内新增符号。）

## 10. 多框架兼容性结论（gty_lsposed 模块视角）

**v1.5.2 域救援改动对其他框架零回归**，理由：

| v1.5.2 改动 | LSPosed(LSPosed) | Vector(KSU) | LSPatch | NPatch | ShimmerPatch |
|---|---|---|---|---|---|
| BaseDexClassLoader/DexClassLoader/PathClassLoader/InMemoryDexClassLoader 构造钩子（注册域） | ✅ 无害（仅登记，不改行为） | ✅ | ✅ | ✅（主目标） | ✅ |
| WebViewFactory.getProvider/getWebViewClassLoader after 钩子（登记 WebView 域） | ✅ after 只读登记 | ✅ | ✅ | ✅ | ✅ |
| BaseDexClassLoader.findClass after 登记 | ✅ | ✅ | ✅ | ✅ | ✅ |
| findCallerClassName 锚点扫描（跳过 Vector/NPatch/LSPHooker/喵系帧） | ✅（LSPosed 帧已被 isFrameworkFrame 覆盖） | ✅ | ✅（LSPatch 桥不破坏 forName，救援路径本身不触发） | ✅ | ✅ |
| B1b forName 域救援（setResult 跳过原链） | 不触发（LSPosed 不改 forName 语义） | 不触发 | 不触发 | **触发并修复** | 不触发（若其桥同样破坏调用方则自动受益） |

设计上的"零回归"本质：**所有 v1.5.2 新钩子都是"只登记、不改写"**（after 钩子记录映射；before 救援仅在 App 域解析失败这一异常路径介入，且失败时放行原链保持原生 CNFE 语义）。任何框架下正常路径行为与 v1.5.1 前完全一致。

---

## 附：文件索引

- `source/NPatch-v1.0.9/` — 官方 v1.0.9 tag 全量源码（含 gradle 工程）
- `source/Vector-core-6d6c28a3/` — 内嵌 Vector 框架源码（NPatch core submodule 精确 commit）
- `decompiled/` — 847 管理器 APK 反编译产物（jadx 输出 + dex 字符串清单）
- `docs/apk-vs-source-diff.md` — APK 与源码差异清单（Stealth 等 847 独有内容）
- `docs/stealth-reversed.md` — Stealth(Level 5) 专项还原
- `docs/multi-framework-compat.md` — 多框架兼容矩阵与测试要点
