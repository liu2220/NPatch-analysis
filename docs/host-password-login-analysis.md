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
- **注意**：该 int 的语义偏向「是否已注册/自动登录」，UI 上的「短信/密码」切换是另一个维度（见 2.2），由标签点击实时决定。

### 2.2 登录页 UI 控件映射（`LoginActivity.H()` 视图绑定）

| 字段 | 类型 | 含义 |
|------|------|------|
| `f` | `GwEditText` | 第一输入框（账号 / 手机号） |
| `g` | `GwEditText` | 第二输入框（密码 / 验证码） |
| `h` / `k` | `TextView` | 标签文案 |
| `l` / `m` | `ImageView` | 密码可见性切换 |
| **`i` / `j`** | `View` | **两个登录模式标签（短信 / 密码）**，各自带 `setOnClickListener` |
| `n`…`t` | `View`/`TextView` | 登录按钮、协议勾选、辅助入口等 |

### 2.3 提交链路（已逐指令核实）

```
LoginActivity$l.onClick（提交监听）
  → LoginActivity.s(Activity, b文本, c文本, l.d, l.e)        // 取两个输入框文本 + 模式端点/类型
  → LoginActivity.m0(String, String, String, String)
  → OkhttpUtils.D(val1, val2, endpoint, type)                 // Rx 网络请求（返回 Observable）
```

- `l` 是提交监听器实例，持有：两个 `GwEditText`（`b`=第一框、`c`=第二框）以及 `d`/`e` 两个 `String`（**endpoint 路径 + 请求类型**）。
- `endpoint`/`type`（`l.d`/`l.e`）由**模式标签点击**时设定：
  - 短信：`.../user/smsloginSys`
  - 密码：`.../user/loginSys`（classes4.dex 中存在的 `loginSys` 令牌；另有 `loginQRCode` 扫码登录）
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

1. 打开宿主登录页，**手动点击密码模式标签**（`i`/`j` 之一，使第二输入框 `g` 变为密码类型）。
2. 若要取回密码：从 `/data/data/.../shared_prefs/user.xml` 读 `password`（明文），或从本地 `user` 表取默认 `hehe/123456`。
3. 输入账号 + 密码即可走 `loginSys` 密码端点。

### 3.2 模块钩子（CloudQueryHook / EnvGuard H18）

已在 `EnvGuard` 新增 `installPasswordLoginUnlock`，做四件事（详见 `EnvGuard.java`）：

1. **凭证暴露**：挂钩 `LoginActivity.Z(JSONObject)` 之后，把 SP `user` 的 `loginname` / `password` 打印到模块日志并 Toast，方便取回密码。
2. **强制密码端点**：挂钩 `LoginActivity.m0` 之前，把 endpoint 参数里的 `smsloginSys` 改写为 `loginSys`，确保密码链路始终走密码端点（兜底，避免短信端点误用）。
3. **服务端开关兜底**：在 `Z(JSONObject)` 之前，强制 `enableUserAuth` / `enableUserOrgAuth = true`，解除服务端对密码登录的门控。
4. **自动选密码标签（尽力而为）**：`H()` 视图绑定后，比较两标签点击后第二输入框 `g` 的提示文案，凡出现「密码 / pwd」者即密码模式，默认选中。失败不影响其余逻辑。

> 钩子不依赖具体方法名混淆（`f/g/i/j/l` 均为 dex 真实字段名，与现有 Layer 2 同等级稳定性），升级改名后自动跳过。

---

## 4. 待确认 / 局限

- `loginmode_2.13` 的 int 取值与「短信/密码」的精确映射未 100% 闭合（仅确认缺省 1、成功写 1）。H18 未强依赖该 int，故不影响功能。
- `l.d`/`l.e`（endpoint/type）由标签点击经构造/字段注入，未在任何 dex 中以 `iput` 显式出现，故 H18 采用「端点字符串替换」而非「改写 d/e 字段」的更稳方案。
- 硬编码 `UavAdmin` 的 MD5 `2633a1f4f86f4f717ff0fdd4aceb4272` 未破译，且为服务端凭证，普通本地登录不可用。
