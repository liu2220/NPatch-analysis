# 宿主 云查询-负责人端 v5.043 深度分析（聚焦 WebView 崩溃链）

> 分析对象：`260915_200054_v5.043_release.apk`（101.6MB，`com.geoway.cloudquery_leader` versionCode 10，minSdk 26，targetSdk 28，compileSdk 34）
> 工具：androguard 4.1.4（5 个 dex 共 ~44MB：classes.dex 8.8M / classes2 9.8M / classes3 8.9M / classes4 7.2M / classes5 7.9M）+ aapt2
> 关联：NPatch 分析见本仓库主报告；修复见 gty_lsposed v1.5.3

## 1. 崩溃现场还原（与逆向结果闭环）

```
SplashActivity.onStart (Unknown Source:48)
 → WebViewDialog.show → onCreate → setContentView(webview_dialog_layout)
 → LayoutInflater: line #11 = <android.webkit.WebView>   ← 崩溃点（系统 WebView 构造）
 → WebViewFactory.getProvider()（已返回，provider 走 PostTask 异步 init）
 → WebViewChromium.init(74) → PostTask.b → Ku.run → s8.run → WebViewChromium.a(7)
 → AwContents.<init> → AwContents.Q/R → rA.<init> → qA.b → qA.a(3)
 → Class.forName("org.chromium.build.BuildHooksAndroidImpl")   ← 单参调用方敏感
 → [NPatch/Vector 桥重调后调用方丢失 → 落到 App 域] → ClassNotFoundException → 闪退
```

- 布局 `webview_dialog_layout` 第 11 行即系统 `android.webkit.WebView` 元素（资源名被 AndResGuard 混淆为 `res/-X.xml`，经 arsc 映射还原）。
- `WebViewDialog`（`com.geoway.cloudquery_leader.view.WebViewDialog`）结构简单：`Dialog` 子类 + 内部 `WebViewClient`（`$a`），无自定义 WebView 实现——**崩溃 100% 发生在系统 WebView（Trichrome）初始化链，与宿主代码无关**。

## 2. 宿主 WebView 使用面（全量扫描）

- **全部基于系统 WebView**，不含自带 chromium/WebView APK：
  - 继承 `android.webkit.WebView` 的类：`BaseXWebView`（com.yhongm.xwebview，XWebView JS 桥框架，242 类）、`KingoitWebView`、`JzHelperView`、`HawkeyeView`；
  - `WebViewClient`/`WebChromeClient` 子类 28+ 个（WebActivity、WebIMActivity、InfoSiteH5UiActivity、WorkH5UiActivity、WebViewActivity×2、CloudServiceLargeModelMgr 等）；
  - native 侧仅 `libyhmXWebView.so`（401KB，XWebView 桥的 JNI 部分），**不是** WebView 内核。
- 结论：宿主 WebView 崩溃面 = 系统 WebView 域（设备 `chromium-TrichromeWebViewGoogle.apk-stable-410410683`，WebView 130 系），修复点唯一在模块侧域救援（gty_lsposed v1.5.3），宿主无需任何改动。

## 3. 宿主自身类加载与崩溃的关联性核查

- 宿主全部业务类位于 App 域（5 个 dex 同一 PathClassLoader）——`Class.forName` 即便被 Vector 桥破坏调用方，B1b 的「直接用 App 域解析」路径全部命中，**宿主自身代码不会复现同类崩溃**；唯一受影响域是 WebView 域（系统 Trichrome APK），即本次崩溃。
- 宿主 dex 中 chromium 相关字符串仅 `org.chromium.arc`（Arc 兼容探测串），无 `BuildHooksAndroidImpl` 直接引用——该类只存在于 WebView 域内部加载链。
- 多进程：`:core` 进程（日志实证同样被 NPatch 修补且正常初始化）不受 WebView 崩溃影响；崩溃仅在主进程首次 inflate WebView 时发生。

## 4. 宿主检测面（v5.043，与既往分析一致，供完整性归档）

| 家族 | 入口 | 模块对策（gty_lsposed） |
|---|---|---|
| 栈扫描 | `com.geoway.base.util.x.y()` | B4 getStackTrace 过滤 |
| loadClass 探测 | `x.z()` | B1a loadClass 拦截 |
| disableHooks 反射 | `x.A()` | B2/B3 |
| root 探测 | `x.u()/v()`、`lahm.e.f()` | H2 文件/执行伪装 |
| 开发者模式 | `x.n()/q()`（Settings） | B5 全 getter 覆盖 |
| mock 定位 | `C15214b`/`isFromMockProvider` | B6 |
| 反调试 | `libantitrace.so`（休眠） | D14/D15 建档 |

（详细行为见 gty_lsposed 仓库 `docs/04-反检测与自适配.md`。）

## 5. 对修复的最终确认

1. **崩溃修复 = 模块侧 v1.5.3 域救援**（构造器注册表 ∪ WebViewFactory 直取域 ∪ loadClass 记录通道，三通道并集扫描），宿主 APK 无需修改；
2. NPatch 修补参数建议保持 `--manager` + sigBypass 级别不变（Stealth 只作用于文件/签名面，与 Java 方法钩子正交）；
3. 修补后验证要点：主进程 `SplashActivity → WebViewDialog` 弹出即证明 WebView 域 forName 已被救援；若仍崩溃，抓取 NPatch 诊断包中 `B1.forName.miss` 行的 `realms/wv/clmap/cand` 四值即可定位空通道。
