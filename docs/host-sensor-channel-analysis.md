# 宿主原始传感器数据通道分析（v5.043 · rea/JADX + androguard 联合）

> 分析工具：rea 6.7.0（jadx-headless-mcp 0.7.1 引擎首次完整运行，`inspect-android-method` 直接出 Java 伪码）+ androguard 字节码交叉引用
> 结论：**是，宿主存在一条完全绕过 FiveParams 的原始传感器数据通道**（CameraX 自主相机链路）

## 1. 通道全貌（数据流）

```
硬件传感器（TYPE_MAGNETIC_FIELD 磁力计 + TYPE_ACCELEROMETER 加速度计）
  └─ com.geoway.cloudquery_leader.util.SensorHelper
       registerListener → onSensorChanged(SensorEvent)
       → SensorManager.getRotationMatrix / remapCoordinateSystem / getOrientation
       → m_lastAzimuth / m_lastTilt / m_lastRoll（含滑动平均 m_lastAve*、阈值 THRESHOLD_VALUE）
       → OnHandleCallback.onGetAzimuth(F) / onGetPitch(F) / onGetRoll(F)
            ├─ ConfigTaskSelfCameraActivity$d      （configtask 相机）
            ├─ SelfKotlinCameraActivity$onCreate$3 （gallery camerax 相机）
            └─ SimpleSelfCameraActivity$j          （news 相机）
                 → Activity 字段 mAzimuthDeg / mPitch / mRoll（+logcat "azimuth=" 调试）
                      ↓ 拍照
                 CameraXFragment.addWaterMark(Uri, float mAzimuthDeg, double mPitch,
                                              double mRoll, Location mCurLocation)
                 （rea 反编译还原的完整签名）
                      ↓ 协程 addWaterMark$1.invokeSuspend
                      ├─① CameraXUtil.addBitmapWatermark + getBitmapWithWordWaterMark
                      │    → 原始传感器方位角【烧录进照片像素水印】
                      └─② CameraListener.onTakePictureEnd(F, D, D, Location)
                           → BaseCameraXActivity / CameraXActivity
                           → Media bean（configtask.db.bean.Media）
                                setAzimuth / setPitch / setRoll + setLon/setLat
                                （坐标经 com.geoway.base.util.i.f()/d() 纠偏转换）
                           → 数据库记录 → 随媒体上传流程上报
```

## 2. 关键证据

| 证据 | 来源 |
|---|---|
| SensorHelper 注册磁力计+加速度计，getOrientation 计算方位角 | 字节码（getValue/start 方法） |
| 三个 OnHandleCallback 实现均把回调值写入 Activity 的 mAzimuthDeg/mPitch/mRoll | 接口实现扫描 + 回调体字节码 |
| `addWaterMark(Uri, float mAzimuthDeg, double mPitch, double mRoll, Location)` | **rea/JADX 反编译 CameraXFragment.addWaterMark 直接出 Java 签名** |
| 水印协程把 mAzimuthDeg 烧入位图，并 `onTakePictureEnd(F,D,D,Location)` 回传 | addWaterMark$1.invokeSuspend 字节码（调试串 "13:17_addWaterMark_961: mAzimuthDeg:"） |
| Media bean（上传媒体记录）被写入原始传感器值 | BaseCameraXActivity.onTakePictureEnd：Media.setAzimuth/setPitch/setRoll×多处 |

## 3. 对本模块（H11 固定坐标/方位角）的影响

- **主拍摄链（MultiMediaActivity，kingoit ksdkmultimedia）**：方位角/坐标全部经 `FiveParams` getter —— H11 类级 hook 覆盖，面板固定值全链生效（EXIF、校验码、顶栏、克隆对象均自洽）；
- **CameraX 自主相机链路（上述 3 个 Activity）**：完全**不经过** FiveParams —— H11 不生效，水印像素与 Media 记录用的是真实传感器值；
- 通道**内部自洽**（水印与 Media 记录同源，均为真实传感器值）→ 服务端单看这条链路无技术破绽；
- 风险仅在跨链路语义不一致：主链路照片方位角是固定值、CameraX 链路是实时值。
- 坐标：Media 记录坐标来自进程内构造的 `Location` 对象（H4 构造器钩子已覆盖）。

## 4. 可选对策（H17，未实施）

在 `CaptureHook` 的 fixed/azimuthOverride 激活时，追加两类钩子把固定值统一到 CameraX 链路：
1. `SensorHelper` 回调层：hook 三个 `OnHandleCallback.onGetAzimuth/onGetPitch/onGetRoll` 实现，命中时 `setResult(固定值)`；
2. 兜底层：hook `Media.setAzimuth/setPitch/setRoll` 与 `CameraXUtil.addBitmapWatermark` 的方位角参数。

需要时说一声即可实施（预计半小时内含构建交付）。
