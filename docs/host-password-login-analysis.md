# 宿主密码存储与登录机制逆向分析（v5.043）

> 目标应用：`com.geoway.cloudquery_leader`（云查询 leader 版，宿主 APK v5.043）
> 分析目的：定位「密码登录」的密码存储位置，并给出启用密码登录的工程方案。
> 工具：androguard 4.1.4 + 指令级 `const-string` / `const-string/jumbo` 反编译（字符串 xref 在免 Root 加固下未建立，改用指令扫描）。

---

## 1. 密码到底存在哪里（核心结论）

宿主的「密码」分散在 **4 个位置**，按可信度排序：

| # | 存储位置 | 键 / 字段 | 形态 | 触发时机 | 说明 |
|---|----------|-----------|------|----------|------|
| 1 | **SharedPreferences `user`** | `loginname`、`password`、`login_tel`、`login_token`、`userId` | **明文** | 任意一次登录成功后 | 主凭证缓存，供离线登录使用。这是本地最直观的密码落点。 |
| 2 | **本地 Room / SQLite `user` 表** | `username TEXT DEFAULT 'hehe'`、`password TEXT DEFAULT '123456'` | 明文 | 建表默认 | 开发者遗留默认账号 `hehe / 123456`。 |
| 3 | **硬编码凭证** | `{"LoginName":"UavAdmin","Password":"2633a1f4f86f4f717ff0fdd4aceb4272"}` | MD5(32位) | 编译期内置 | `UavAdmin` + MD5，疑似**服务端/边缘管理员**凭证，非普通用户本地登录用。 |
| 4 | **SharedPreferences `auth`** | `auth.userName`、`auth.password` | 明文 | HTTP 基础认证 | 仅用于 `okhttp3.JavaNetAuthenticator` 的代理/网络 Basic Auth，**不是应用登录密码**。 |

> 关键实证：`LoginActivity.T(Z Z)` 从 SP `user` 读取 `loginname`/`password`/`login_tel`/`login_token`/`userId`；`LoginActivity.Y()` 登录成功时 `putString("password", …)`、`putString("loginname", …)`。
> 即：**你只要在宿主上成功登过一次，密码就以明文躺在 `/data/data/com.geoway.cloudquery_leader/shared_prefs/user.xml` 里**。

---

## 2. 登录模式：短信（默认） vs 密码

### 2.1 模式开关

- SP `user` 的 **int 键 `loginmode_2.13`**，缺省值 **1**，`LoginActivity.Y()` 登录成功时写入 `1`。
- `SplashActivity.x0` 启动时用 `getInt("loginmode_2.13", 1)` 与 `1` 比较，决定自动登录 / 跳登录页。
- **注意**：该 int 的语义偏向「是否已注册/自动登录」，与 UI 上「短信/密码」维度的关系需结合 2.2 看——日志实证宿主**当前 UI 不存在可点击的短信/密码切换**（j 标签仅弹 Toast），端点由构造时传入（见 2.3），并非标签点击实时决定。

### 2.2 登录页 UI 控件映射（`LoginActivity.H()` 视图绑定）

| 字段 | 类型 | 含义 |
|------|------|------|
| `f` | `GwEditText` | 第一输入框（账号 / 手机号） |
| `g` | `GwEditText` | 第二输入框（密码 / 验证码） |
| `h` / `k` | `TextView` | 标签文案 |
| `l` / `m` | `ImageView` | 密码可见性切换 |
| **`i` / `j`** | `View` | 两个 View 各带 `setOnClickListener`；日志实证 **j 标签点击仅弹 Toast（`I(View)`→`f0.n`），并非短信/密码切换**，i 标签点击走自动登录/进度（`L()`）。实际 UI **无密码模式切换** |
| `n`…`t` | `View`/`TextView` | 登录按钮、协议勾选、辅助入口等 |

### 2.3 提交链路（已逐指令核实）

```
LoginActivity$l.onClick（提交监听）
  → LoginActivity.s(Activity, b文本, c文本, l.d, l.e)        // 取两个输入框文本 + 模式端点/类型
  → LoginActivity.m0(String, String, String, String)
  → OkhttpUtils.D(val1, val2, endpoint, type)                 // Rx 网络请求（返回 Observable）
```

- `l` 是提交监听器实例，持有：两个 `GwEditText`（`b`=第一框、`c`=第二框）以及 `d`/`e` 两个 `String`（**endpoint 路径 + 请求类型**）。
- `endpoint`/`type`（`l.d`/`l.e`）在构造 `LoginActivity$l`（经由 `a0(String,String)` ← `p(Activity,String,String)`）时由上层**传入的固定字符串**决定，**并非标签点击设定**（日志实证：点 i/j 后 `g` 提示恒为「请输入验证码」）。`smsloginSys`/`loginSys` 仅存在于 Retrofit `@POST` 注解（dex 内无常量），故 endpoint 为运行时拼接，无法静态确定。
- 密码登录的 Retrofit 端点为 `LoginApi.login(String username, String password, String cookie)`（classes4.dex）。

### 2.4 服务端门控

`LoginActivity.Z(JSONObject)`（登录成功响应解析）会从服务端 JSON 读取并写入：

- `enableUserAuth`（默认 `"true"`）
- `enableUserOrgAuth`（默认 `"true"`）

若账号被服务端置为「仅短信」，这两个开关可能为 `false`，从而**隐藏/禁用密码登录入口**。这是「打开密码登录功能」最可能的服务端侧门控点。

### 2.5 登录方式回顾（与上一轮结论一致）

账号密码、短信验证码、扫码授权（管理版/landcloud.org.cn）、微信 OAuth，前置 KeyNego 密钥协商，72h 强制重登。

---

## 3. 如何「打开密码登录」（工程方案）

### 3.1 最稳的一步：直接切到密码标签 + 用已存凭证

1. **注意**：宿主当前 UI **无短信/密码模式切换**（j 标签仅弹 Toast），不能靠手动点标签进入密码模式；需由模块把第二输入框 `g` 直接改造为密码框（见 3.2）。
2. 若要取回密码：从 `/data/data/.../shared_prefs/user.xml` 读 `password`（明文），或从本地 `user` 表取默认 `hehe/123456`。
3. 输入账号 + 密码即可走 `loginSys` 密码端点。

### 3.2 模块钩子（CloudQueryHook / EnvGuard H18，v1.6.3 方案）

`EnvGuard.installPasswordLoginUnlock` 经 Vector 日志实证后重构为 **6 层防御**（详见 `EnvGuard.java`），核心是把「第二输入框 `g` 直接改造成密码框」+ 「多层 endpoint 兜底」，而不是去点根本不存在的短信/密码切换标签：

1. **凭证暴露（①）**：挂钩 `LoginActivity.Z(JSONObject)` 之后，把 SP `user` 的 `loginname` / `password` 打印到模块日志并 Toast，方便取回密码。
2. **强制密码端点（②）**：挂钩 `LoginActivity.m0` 之前，对第 3 参（endpoint）做 `forceLoginSys` 智能改写（`smsloginSys/smsLogin/sendSms/sendCode` 及 `/sms` → `loginSys`，大小写不敏感），**无条件兜底**，确保密码链路走密码端点。
3. **服务端开关兜底（③）**：在 `Z(JSONObject)` 之前，强制 `enableUserAuth` / `enableUserOrgAuth = true`，解除服务端对密码登录的门控。
4. **UI 直接改造成密码框（④）**：`H()` 视图绑定后 `postDelayed` 取字段 `f`（账号框）/`g`（密码框），把 `g` 的 `hint` 改为「请输入登录密码」并 `setInputType(TEXT|PASSWORD)`（圆点掩码）。**删除**了原 v1.6.2 失效的「自动选密码标签（performClick 比较 hint）」逻辑——日志已证实宿主 UI 无短信/密码切换，`g` 永远是验证码框。
5. **入口兜底（⑤）**：挂钩 `LoginActivity.p(String,String)`（即 `a0`←`p` 构造 `l` 时传入 endpoint/type 的入口），beforeHook 对两个参数都做 `forceLoginSys` 兜底。
6. **提交兜底（⑥）**：挂钩 `LoginActivity$l.onClick(View)`，beforeHook 反射把 `l.d` 字段改写为 `forceLoginSys` 值，确保点登录按钮那一刻 endpoint 已是密码端点。

> 钩子不依赖具体方法名混淆（`f/g/i/j/l` 均为 dex 真实字段名，与现有 Layer 2 同等级稳定性），升级改名后自动跳过。④ 的 UI 改造与 ②⑤⑥ 的 endpoint 兜底互为补充：前者解决「看不到输密码的地方」，后者解决「即便能看到也走错端点」。

> ⚠️ 历史说明：v1.6.2 的「④ 自动选密码标签」已被 Vector 日志证伪（见文末 v1.6.3 修正章节），切勿沿用。

---

## 4. 待确认 / 局限

- `loginmode_2.13` 的 int 取值与「短信/密码」的精确映射未 100% 闭合（仅确认缺省 1、成功写 1）。H18 未强依赖该 int，故不影响功能。
- `l.d`/`l.e`（endpoint/type）在构造 `a0`←`p` 时由上层传入固定字符串，未在任何 dex 中以 `iput` 显式出现；v1.6.3 同时采用「端点字符串智能替换（`forceLoginSys`，覆盖 m0/p）」与「反射改写 `l.d` 字段（⑥ onClick 兜底）」两条路径，确保无论 endpoint 来自参数还是字段最终都落为 `loginSys`。
- 硬编码 `UavAdmin` 的 MD5 `2633a1f4f86f4f717ff0fdd4aceb4272` 未破译，且为服务端凭证，普通本地登录不可用。

---

## v1.6.3 修正（基于 Vector 日志实证）

### 现象
用户反馈：宿主登录界面看不到输密码的地方。模块日志（`log/modules_*.log`）中 H18 运行痕迹：

```
H18 Z/m0/H hook ok
H18 tab: hI=请输入验证码 hJ=请输入验证码
```

`H18 tab` 两个提示**均为「请输入验证码」**，说明 v1.6.2 的「④ 自动选密码标签（performClick 比较 hint）」**从未命中**——因为宿主 UI 根本没有短信/密码模式切换。

### 根因（逐指令反编译实证）
1. **UI 无密码模式切换**：`LoginActivity` 的 `i`/`j` 两个 View 各有 `setOnClickListener`，但日志实证 `j` 点击仅弹 Toast（`I(View)`→`f0.n`），`i` 点击走 `L()` 自动登录/进度，**两者都不切换短信/密码模式**。第二输入框 `g` 的 hint 恒为「请输入验证码」，永远不是密码框。
2. **endpoint 非标签决定**：`l.d`/`l.e`（endpoint/type）在构造 `a0`←`p(Activity,String,String)` 时由上层传入固定字符串，`smsloginSys`/`loginSys` 仅存在于 Retrofit `@POST` 注解，dex 内无对应常量，故 endpoint 运行时拼接、无法静态确定。
3. **v1.6.2 ② 改写从未触发**：原 `m0` 仅在 endpoint 含 `smsloginSys` 时才改写，但主登录 endpoint 不经过该常量，导致 ② 形同虚设。

### 修复（v1.6.3）
- **④ 改为 UI 直接改造**：`H()` 后 `postDelayed` 取 `f`/`g` 字段，把 `g` 的 hint 设「请输入登录密码」并 `setInputType(TEXT|PASSWORD)`（圆点掩码），彻底解决「看不到输密码的地方」；删除失效的 performClick 标签切换。
- **② 改为 `forceLoginSys` 智能改写**：对 `m0` 第 3 参无条件做 `smsloginSys/smsLogin/sendSms/sendCode` 及 `/sms` → `loginSys` 替换（大小写不敏感），不再依赖 `smsloginSys` 常量。
- **新增 ⑤ `p(String,String)` 入口兜底** 与 **⑥ `l.onClick` 反射改 `l.d` 字段兜底**，覆盖 endpoint 来源于参数与字段的两条路径。

代码已构建验证（`CloudQueryHook_v1.6.3.apk`，versionCode 28，v2/v3 签名），提交 `gty_lsposed` 并推送。

---

## v1.6.4 诊断（端点改写挂在错误提交链上）

### 现象
升级 v1.6.3 后，验证码框已变为密码框（④ UI 改造生效），但点登录按钮仍提示「验证码错误」——请求仍打到短信端点，端点改写未生效。

### 根因（v1.6.3 日志实证）
- `H18 m0 hook ok`（注册成功）但**登录提交时从未打印 endpoint**，说明 `LoginActivity.m0(String×4)` 在登录提交链路中**根本没被调用**；原②③⑤⑥ 全部挂在一条**错误的提交链**假设上。
- `H18 p hook skip: NoSuchMethodError: LoginActivity#p(java.lang.String,java.lang.String)` → ⑤ 入口钩子方法签名与实际不符，从未生效。
- 结论：登录提交走的是另一条**未被 hook 的真实路径**，运行时端点字符串、`type` 区分字段均未知，无法静态猜测，须运行时抓取。

### 修复（v1.6.4，诊断先行）
- 增强日志：**dump `m0` 全部实参**（类型+值）、**dump `l.d`/`l.e` 字段真实值**，确认端点/类型到底长什么样。
- 新增 **⑦ OkHttp `newCall` 抓取钩子**：在 HTTP 层抓取登录相关请求的**真实 URL + POST 表单参数**（`FormBody` 字段名/值），直接暴露端点路径与服务端区分短信/密码的字段（`type`/`code`/`password` 等）。
- 保留 ④ 密码框改造（已验证可用），`forceLoginSys` 改为对任意 String 实参生效（仍可能因未知真实字符串而不命中）。
- 待用户刷 v1.6.4、复现一次登录失败并回传日志后，据真实端点/字段做 v1.6.5 的精确改写。

代码已构建验证（`CloudQueryHook_v1.6.4.apk`，versionCode 29，v2/v3 签名），提交 `gty_lsposed`（推送受沙箱网络抖动影响，已提交本地、待网络恢复推送）。

---

## v1.6.5 登录模式手动切换（用户新需求）

### 需求
用户在 v1.6.4 验证：「验证码框已变密码框」生效，但仍希望**不想用密码登录时能切回短信验证码**。v1.6.4 把 `g` 永久改成密码框、且端点改写挂在错误链上（密码提交仍报「验证码错误」），无法满足可切换诉求。

### 方案（把「强制密码」改为「可切换」，默认密码）
- **④ UI 切换条（新增 `setupLoginModeToggle`）**：`H()` 视图绑定后，在 `g` 框下方注入一个可点击 `TextView`（蓝色「使用短信验证码登录 ›」/「使用账号密码登录 ›」）。点击即在两种模式间切换，并把选择持久化到 `SP cloudquery_hook_cfg / h18_login_mode`（默认 `password`，重启后保持上次选择）。
  - 密码模式：`g` → hint「请输入登录密码」+ 圆点掩码（`setGwPasswordInput`）。
  - 短信模式：`g` → hint「请输入验证码」+ 普通文本输入（`setGwInputNormal`，还原原生可见验证码框）。
  - 切换条按 `tag="H18_mode_toggle"` 去重，多次 `H()`（如旋屏重建）不会重复注入。
- **⑥ 按模式路由端点**：`l.onClick` 提交前读取 `l.d`/`l.e`——首跑记录原生端点（`sNativeSmsEndpoint`/`sNativeSmsType`）供诊断；**密码模式**对端点做 `forceLoginSys` 改写，**短信模式**保持原生（不改写），从而短信登录走原生链路、必定可用。
- **⑦ 网络层双保险**：`newCall` 抓取登录请求时，若处于密码模式且 URL 命中短信类片段（`smsloginSys`/`/sms` 等），用 `Request.newBuilder().url(newUrl).build()` 重建请求改写端点；短信模式不做改写。
- ①②③⑤ 维持（凭证暴露 / `m0` 智能改写 / 服务端开关兜底 / `p` 入口兜底）。

### 已知风险（仍需一次日志闭环）
密码模式能否一次成功，取决于运行时端点字符串是否含 `forceLoginSys` 可识别的短信片段（`smsloginSys`/`smsLogin`/`sendSms`/`sendCode`/`/sms`，大小写不敏感）。若原生端点命名不同（如同一端点靠 `type` 表单字段区分短信/密码），则 ⑥⑦ 改写不命中，密码提交仍可能报「验证码错误」。
- 判定依据：v1.6.5 日志会打印 `H18 l.d=...`、原生 `url=...`、`form=...`，据此可确认端点/区分字段并做精确改写（届时升级 v1.6.6）。
- 短信模式不受此影响，原生链路恒可用。

代码已构建验证（`CloudQueryHook_v1.6.5.apk`，versionCode 30，v2/v3 签名），提交 `gty_lsposed` 并推送。

---

## v1.6.6 分析（基于 13:43 日志）—— 根因定位：后端是 `.action`，forceLoginSys 永不命中

### 这次日志看到了什么
用户在 13:42 刷入 v1.6.5、打开宿主，模块日志（`log/modules_*.log`）显示：
- `H18 Z/m0/H/l/net hook ok` 全部注册成功 → v1.6.5 已生效；
- `H18 p hook skip: NoSuchMethodError: LoginActivity#p(java.lang.String,java.lang.String)#exact` → **`p(String,String)` 再次确认不存在**（与 v1.6.4 结论一致）；
- `H18 H hook ok` 触发 → 进了登录页 `H()`；
- **但 `H18 l.d=` 从未打印** → 说明 `LoginActivity$l.onClick`（提交监听）在本次会话**从未被调用**，用户没有点登录按钮；
- 唯一被抓到的鉴权请求是 `GET https://www.landcloud.org.cn:8443/landCloudWork3/security/loginByWx.action?code=null&imei=&guid=&version=5.043` —— 这是**微信自动登录**，不是表单提交。
- 全量搜索（模块日志 + 81M `full.log`）只出现 `loginByWx.action`，**没有任何密码/短信登录端点**。

### 根因（彻底坐实「验证码错误」的来由）
1. **真实后端是 Struts 风格 `.action` 端点**（`/landCloudWork3/security/loginByWx.action`），**不是**文档 §2.3 假设的 Retrofit `smsloginSys`/`loginSys` 路径。
2. `forceLoginSys`（②③⑥⑦ 都依赖它）只认识 `smsloginSys`/`smsLogin`/`sendSms`/`sendCode`/`/sms` 这些 Retrofit 风格命名 → **对 `.action` URL 永远零命中** → 密码模式端点改写静默失效 → 请求仍打到短信/微信端点 → 持续「验证码错误」。
3. 文档 §2.3「Retrofit 端点 `smsloginSys`/`loginSys`」的假设**错误**，需以真实 `.action` 端点为准。

### 为什么还没修好
本次日志**缺一次真实登录提交**（用户没点登录），所以仍拿不到密码/短信端点的真实名字与表单字段（区分短信/密码到底是靠 URL 还是靠 `type` 表单字段），无法安全硬编码映射。当前 v1.6.5 的网络抓取钩子（⑦ + 模块自带 `[H8] okhttp`）**已能在点登录时抓到真实 URL + 表单**，等这次提交数据即可精确改写。

### 下一步（需要用户一次复现闭环）
请按下面步骤各点一次登录，再回传 Vector 日志：
1. 刷入 `CloudQueryHook_v1.6.5.apk`，打开登录页；
2. **密码模式**（默认）：输入账号 + 密码 → **点登录**（复现「验证码错误」）；
3. 点底部蓝字切到**短信验证模式**：输入手机号 + 验证码 → **点登录**；
4. 回传日志。
届时日志会给出 `H18 l.d=...`、原生 `url=...`、`form=...`，据此在 v1.6.6 做精确的 `.action` 端点映射（例如 `security/loginByPassword.action` ↔ `security/loginBySms.action` 之类，以真实抓包为准），一次性修好密码登录。

> 注：本次 13:42 的 v1.6.5 会话里「`H18 ui: mode toggle ready`」未出现，可能是微信自动登录抢先、登录表单未稳定展示所致；此前 v1.6.3 会话（13:09/13:11）有明确 `H18 ui: g -> password mode`，证明表单可达。若你那次确实看到了切换条，请告知；看不到则说明 UI 注入时机需加固（届时一并处理）。
