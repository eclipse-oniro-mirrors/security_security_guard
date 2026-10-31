# 支持阻断服务使用者接入阻断框架 · dev 设计

> 状态：正式稿 v9（v8 + T5 增量迭代：移除服务端超时跟踪/超时处置/超时打点——超时属另一需求；会话关联重构为「会话即远端对象」方案 D——主接口仅追加 CreatAuthEventClient 1 方法下发 session 代理，新增独立 AuthEventSession IDL，删除 clientId 全链路；错误码场景全量梳理）
> v9 变更：① **移除服务端事件超时判断**（本需求只做会话管理）：删除 pendingResults_ 超时跟踪表、CheckAuthResultTimeout、AUTH_RESULT_TIMEOUT_MS=400、~~timeoutAllowFlag~~、seqNum 的 metadata 填充与解析、AUTH_RESULT_TIMEOUT 打点；保留结果表 authResults_、NotifyAuthEvent 分发（不再分配 eventIndex）、AUTH_BLOCK_RESULT 打点。【修订：timeoutAllowFlag 参数保留——IDL/SDK/会话链路携带并随会话保存，本需求仅保存不消费，供超时需求（另一需求）届时按会话读取】② **会话关联改方案 D（会话即远端对象）**：主接口 IDL 5 方法缩减为 1 方法 `CreatAuthEventClient([in] IRemoteObject cb, [in] boolean timeoutAllowFlag, [out] IRemoteObject session)`（实测 IDL 支持 [out] IRemoteObject：proxy `reply.ReadRemoteObject()` / stub `SUCCEEDED(errCode)` 时 `WriteRemoteObject`）；新增独立 `AuthEventSession.idl`（Subscribe/Unsubscribe/SetAuthResult/Destroy 四方法）；服务端 `AuthEventSessionService`（stub 实例）即会话本体——每会话对象自带 pid/uid/callback/eventIds/timeoutAllowFlag，方法直落对象、零会话查表；SDK 持 session 代理直调、零身份参数；clientId、ConstructClientId、会话查重/空判/死亡反查遍历全部删除。③ 用户裁决：Unsubscribe 未订阅 eventId 幂等 SUCCESS；同一 cb 重复 CreatAuthEventClient → BAD_PARAM；Destroy 幂等 SUCCESS，销毁后调其他方法 → BAD_PARAM。④ 错误码场景全量梳理（见 4.9）。⑤ **对外头文件回归标准位置、声明常驻**（修订：初版曾迁 frameworks/ 由 public_configs 条件暴露，因 binarys 预编译消费拿不到头、且宏包裹导致外部 include 为空，改回）：5 个对外头（auth_event.h、i_auth_event_callback.h、auth_event_callback_service.h、auth_event_callback_stub.h、auth_event_subscribe_client.h）位于 `interfaces/inner_api/collect/include/`（bundle.json header_base 登记，源码树与 binarys 发布链路天然可用）；**声明不做功能宏包裹（常驻），符号有无由 so 按 gni 决定**——未开启设备上调用方编译通过、链接报 undefined symbol（对齐 syscap 裁剪常规形态）；头内注释声明"仅特定设备开放"。
> v8 变更：分发索引不再作为 AuthEvent 独立字段（eventIndex_ 删除，parcelable 回归三字段），改为以 JSON 键 `seqNum` 填充在 metadata 中传输（服务端分发时 nlohmann 合并写入，客户端回填时解析；pending 内部键仍为 (clientId, eventIndex) 整数）。【v9 已随超时特性整体移除，仅存档】
> v7 变更：① 新增 HA 打点（AUTH_BLOCK_RESULT，适配层 AuthEventReporter，`ha_client_lite_api.h` 依赖未进仓先日志兜底）；② 整个需求经 gni 开关 `security_guard_auth_event_enable`（默认 false）+ 宏 `SECURITY_GUARD_AUTH_EVENT_ENABLE` 隔离；③ 会话操作前置双轨校验；④ Subscribe 增加事件配置校验（GetEventConfig 未命中 → BAD_PARAM）；⑤ clientId 改回客户端生成（IDL 入参）【v9 已删除 clientId，改 session 对象下发】；⑥ CreatClient 超时处置策略 timeoutAllowFlag【v9 已删除】。
> v6 变更（T3 Review 落地）：① libsg_collect_sdk sources 编入 auth_event.cpp（so 符号自包含）；② sg_collect_sdk.map 导出 AuthEventSubscribeClient 5 方法与 AuthEvent 序列化/vtable/VTT 符号；③ HandleDeath 改为对齐 event_subscribe_client 的退避自动重连（{1,5,15,30,60×5}，重建后更新服务端新 clientId 并重订阅快照）；④ 新增 deleted_ 标志防护 DeleteClient/Deleter 与在途重连的会话复活竞态；⑤ Deleter 补 RemoveDeathRecipient；⑥ 影响面修正：bundle.json 无需修改（inner_kits 为 header_files 空数组 + header_base 目录登记，新头自动暴露，对齐仓库现状）。
> v5 变更（T2 Review 落地）：① 管理器实现路径 sa/（无 src/ 子目录，对齐仓库惯例）；② 会话操作（Subscribe/Unsubscribe/Destory）绑定 callerPid，不匹配返回 BAD_PARAM；③ 新增集合容量上限（单会话订阅数/结果表 1024，超限 FILTER_EXCEED_LIMIT）；④ uid 白名单改为管理器成员（空清单占位，补值即生效）；⑤ GetAuthResult(eventId, allowFlag) 作为预留读取口；⑥ clientId 日志 %{private}s。
> v4 变更：`CreatAuthEventClient` 的 clientId 改为服务端生成（时间戳 + 原子计数器）经 `[out]` 参数回传；SDK 删除客户端侧 `ConstructClientId` 自构造，保存服务端返回的 id 并在后续 Subscribe/Unsubscribe/Destory/SetAuthResult 中使用。
> v3 变更：新增 `SetAuthResult(AuthEvent, bool allowFlag)` IPC 与 SDK 接口——订阅者（服务使用者）作为决策方向框架回填某事件的阻断/放行结果；allowFlag 流向为 订阅者→框架，不随 OnAuthEvent 回调下发。
> v2 变更：`AuthEventSubscribeClient` 改为会话模式（CreatClient/Subscribe/Unsubscribe/DeleteClient + clientId），IDL 扩为多方法，取消 `AuthEventSubscribeInfo` 批量订阅结构，新增配额规格（进程 ≤2、设备 ≤16）。

## 1. 需求

### 1.1 目标

在 security_guard 仓库内新建"阻断服务使用者管理框架"：外部服务使用者（系统 SA / HAP 应用）通过 inner_api 客户端接入框架、订阅阻断（AuthEvent）事件通知，框架管理客户端会话与订阅关系、校验接入合法性、执行配额限制、向订阅者分发阻断事件。

### 1.2 范围边界

- 做：
  - 客户端会话管理 inner_api（挂 SA 3524 data_collect）：创建/销毁客户端会话、按 eventId 订阅/退订——**会话关联采用方案 D「会话即远端对象」**：服务端创建会话对象（AuthEventSessionService）并将代理下发给客户端，SDK 的 client 对象持有 session 代理直调，零身份参数（详见第 3 节）；
  - HA 打点：AUTH_BLOCK_RESULT（阻断结果回填，allowFlag=false 时），适配层 `AuthEventReporter` 单点接入 HA lite 客户端；
  - 服务端会话与订阅管理（eventId 匹配分发、订阅者死亡清理）；
  - 配额限制：一个进程最多 2 个客户端，一个设备最多 16 个客户端（用户规格）；
  - 接入校验：SA 应用（native token）按硬编码 uid 清单校验；HAP 应用按权限名 `ohos.permission.kernel.AUTH_AUDIT_EVENT` 校验；
  - 结果回填：`SetAuthResult(AuthEvent, bool allowFlag)`——订阅者向框架设置某事件的阻断/放行结果（allowFlag 由订阅者下发，SDK 暴露，同套双轨校验）；
  - 客户端 SDK：新增 `AuthEventSubscribeClient` 类（含 SetAuthResult），编入 libsg_collect_sdk；
  - 整需求编译隔离：gni 开关 `security_guard_auth_event_enable`（默认 false，仅特定设备开启）。
- 不做：
  - **服务端事件超时判断/超时跟踪/超时处置/超时打点（AUTH_RESULT_TIMEOUT）**——属另一需求，本需求服务端只做会话管理（用户明确）；
  - 阻断事件"产生源"（决策引擎、模型联动）——`SetAuthResult` 仅接收订阅者回填的处理结果，不做策略决策；服务端内部 `NotifyAuthEvent` 仍为预留注入口；
  - HiSysEvent 审计事件（打点走 HA 通道而非 HiSysEvent）；
  - 回填结果的下游消费链路（如内核同步取回结果的机制）——本期仅内存记录，预留读取口；
  - JS API；
  - 会话/订阅关系/回填结果持久化（不落库）；
  - 独立裁剪开关（随 security_guard_enable 整体裁剪）；
  - 权限定义登记（`ohos.permission.kernel.AUTH_AUDIT_EVENT` 的定义在 access_token 部件仓，本仓只做校验方引用）。

## 2. 现状摘要

无架构基线（`.sdd/software_architecture.md` 不存在），探索边界由需求文本与代码结构推断。本仓库现有 3 个 SA（3523 risk_classify / 3524 data_collect / 3525 security_collector），**无任何"阻断"相关实现，本框架为全新增量**。可直接复用的基础设施：IDL 代码生成 IPC（3524 现行方案）、**审计客户端会话管理范式（`EventSubscribeClient` + `AcquireDataSubscribeManager` 的 CreatClient/DestoryClient/Subscribe/Unsubscribe + clientId 会话表 + 配额检查 `IsExceedLimited`，本设计直接对齐该范式）**、双端回调 broker 模式、AccessTokenKit 权限校验、ffrt 并发、`SGLOGx` 日志。配额规格与现有审计会话限额同构：`MAX_SESSION_SIZE_ONE_PROCESS=2`、`MAX_SESSION_SIZE=16`（`acquire_data_subscribe_manager.cpp:46-47`），错误码 `CLIENT_EXCEED_PROCESS_LIMIT=1007`/`CLIENT_EXCEED_GLOBAL_LIMIT=1008` 已存在（`security_guard_define.h:45-46`），直接复用。关键改造点：3524 的 IDL 与服务类追加 4 个方法、新增服务端会话管理器与客户端 SDK 类、bundle.json inner_kits 头文件清单追加。

## 3. 方案

- 方案：在 SA 3524（data_collect）上扩展"AuthEvent 客户端会话 + 订阅通知 + 结果回填"能力，**会话关联采用方案 D「会话即远端对象」**（用户裁决，v9）。服务使用者经 `AuthEventSubscribeClient::CreatClient(callback, client)` 创建会话：服务端执行双轨校验与配额检查后创建会话对象 `AuthEventSessionService`（IDL 生成的 `AuthEventSessionStub` 实例，自带 pid/uid/callback/eventIds 状态），经 `[out]` 参数把该会话对象的远端引用下发给 SDK；SDK 的 client 对象持有 session 代理，`Subscribe/Unsubscribe/SetAuthResult/DeleteClient` 全部直调 session 代理——**binder handle 即会话路由，零身份参数、服务端零会话查表**。服务端 `AuthEventSubscribeManager` 收拢会话集合（配额计数、NotifyAuthEvent 分发遍历）、结果状态表（eventId → allowFlag，内存）与 uid 白名单；会话对象方法转调 manager 完成状态操作（单锁纪律）。订阅者作为决策方经 `session->SetAuthResult(event, allowFlag)` 向框架回填阻断/放行结果；销毁时 `session->Destroy()`（幂等）；订阅者进程死亡时由挂在回调对象上的 per-session DeathRecipient 触发会话自治清理。
- 备选考虑：
  - 新建独立 SA / 挂 3523 / 挂 3525 —— 未采纳：用户已定挂 3524（常驻进程、会话/订阅基础设施最全、免新增 SA 号与 init cfg）；
  - 查询式（pull）或组合模式 —— 未采纳：用户已定全局订阅通知模式；
  - IDL 代码生成 vs 手写 IPC —— 选 IDL（3524 现行方案；`[out] IRemoteObject` 已实测支持：proxy `reply.ReadRemoteObject()`、stub `SUCCEEDED(errCode)` 时 `reply.WriteRemoteObject(session)`）；
  - **clientId 字符串会话键（event_subscribe_client 范式）vs cb binder 指针作键 vs 会话对象下发（方案 D）** —— 选方案 D：clientId 为客户端自报身份（可猜可伪造、需查重/空判/重连重绑定）；cb 作键每个方法都要传 cb、服务端仍需查表；方案 D 会话对象即状态容器，方法直落对象、零查表、零身份参数，"一个 client 对象 = 一个会话"由 binder 对象身份天然保证（先例：媒体 AVSession 等 GetSession 范式）；
  - 复用审计会话表（共享配额）vs 独立会话表 —— 选独立会话集合：AuthEvent 客户端配额独立计数，不挤占现有审计客户端 16/2 配额，对既有行为零影响；
  - 服务端事件超时判断 —— 移出本需求（用户明确：属另一需求，本需求只做会话管理）。

### 3.1 关键流程/状态变化

- 创建会话：使用者调 `AuthEventSubscribeClient::CreatClient(callback, client)` → SDK 构造本地回调 service（`AuthEventCallbackService` 包 `std::function`）→ 现取 SA 3524 proxy 调 `CreatAuthEventClient(cb, session)` → 服务端依次执行：双轨校验 → 回调判空（`NULL_OBJECT`）→ 同 cb 重复创建检查（`BAD_PARAM`）→ 配额检查（该 callerPid 名下会话数 <2 且会话总数 <16）→ 创建 `AuthEventSessionService` 并登记会话集合（含 per-session DeathRecipient，失败回滚）→ session 远端引用经 `[out]` 回传。SDK 保存 session 代理。
- 订阅：`client->Subscribe(eventId)` → session 代理调 `Subscribe(eventId)`（服务端 session stub 方法）→ 双轨校验 → **事件配置校验**（`ConfigDataManager::GetEventConfig` 未命中 → `BAD_PARAM`，对齐 CollectorStart 范式）→ **serviceId 必填校验**（PR #534：命中后校验 `config.serviceId` 非空，空则 `BAD_PARAM`）→ 会话已销毁检查（`BAD_PARAM`）→ pid 归属校验（`BAD_PARAM`）→ `SubscribeAuthEvent(session, eventId, config.serviceId)`（PR #534：管理器锁内同时 insert `eventIds_` 和 `RegisterEventService(eventId, serviceId)`，同步维护 `eventServiceMap_`）→ 异步 `NotifyClientStatusChanged`。
- 分发（预留源触发）：内部生产者调 `AuthEventSubscribeManager::NotifyAuthEvent(event)` → 入口长度守卫（>4096 丢弃）→ 锁内快照命中会话（eventId 已订阅的 callback 列表）→ 锁外逐客户端推送 `OnAuthEvent(event)`（TF_ASYNC，事件本体，不携带 allowFlag）。
- 结果回填：订阅者完成决策后调 `client->SetAuthResult(event, allowFlag)` → session 代理调 `SetAuthResult(event, allowFlag)` → 服务端双轨校验 → 会话已销毁检查（`BAD_PARAM`）→ pid 归属校验（`BAD_PARAM`）→ content/metadata 长度校验（>4096 → `BAD_PARAM`）→ 记录结果状态表（eventId → allowFlag，覆盖更新，新键受 1024 上限）→ allowFlag=false 时锁外 HA 打点 AUTH_BLOCK_RESULT → `SUCCESS`。
- 退订：`client->Unsubscribe(eventId)` → session 代理调 `Unsubscribe(eventId)` → 服务端双轨校验 → 会话已销毁检查 → pid 归属校验 → 从会话 `eventIds_` 集合移除并 `UnregisterEventService(eventId)`（PR #534：同步清理 `eventServiceMap_`，未订阅的 eventId 幂等返回 SUCCESS；不做配置校验：配置运行中可被移除）→ 异步 `NotifyClientStatusChanged`。
- **provider 状态通知（按 serviceId 过滤，PR #534）**：`NotifyClientStatusChanged` → 锁内收集所有有效 provider 的 `(callback, serviceId)` 对 → 锁外对每个 provider 调 `CollectClientInfos(providerServiceId)` 过滤（只收集订阅了属于该 serviceId 的 eventId 的 client，`subscribedEvents` 只含匹配的 eventId；同一 client 订阅不同 serviceId 的 eventId 时，在不同 provider 列表里各出现一次，`subscribedEvents` 不同）→ `proxy->OnClientStatusChanged(filteredClientInfos)`（每个 provider 收到各自过滤后的列表，不再全量广播）。
- 销毁：`client->DeleteClient()`（或最后一个 shared_ptr 释放触发 Deleter）→ SDK 排空在途 OnAuthEvent → session 代理调 `Destroy()` → 服务端双轨校验 → pid 归属校验 → manager 会话集合移除 + 会话置无效（重复 Destroy 幂等返回 SUCCESS；销毁后再调其他方法 → `BAD_PARAM`）→ 锁外 RemoveDeathRecipient。
- 异常：订阅者进程死亡 → per-session DeathRecipient（持该会话对象引用）→ manager 移除会话并置无效；服务端死亡 → SDK DeathRecipient 触发 HandleDeath 退避自动重连重建（重新走 CreatAuthEventClient 拿新 session 代理 + 按快照重订阅，对齐 EventSubscribeClient 范式）；调用方 DeleteClient 后重连被 deleted_ 标志终止。
- 配额超限：`CreatAuthEventClient` 时进程内已有 2 个会话 → `CLIENT_EXCEED_PROCESS_LIMIT`；会话集合已有 16 个 → `CLIENT_EXCEED_GLOBAL_LIMIT`；同一 cb 重复创建 → `BAD_PARAM`。
- 功能裁剪：gni 开关 `security_guard_auth_event_enable=false`（默认）时，主接口 `CreatAuthEventClient` 退化为占位实现（`FAILED`，session 不下发），功能源不编入，对既有 3524 零影响；`auth_event.cpp` 与其单测无条件编入（IDL 生成 stub/proxy 引用其序列化符号）；**5 个对外头位于 `interfaces/inner_api/collect/include/`（声明常驻、不做功能宏包裹），未开启设备上调用方链接期失败（so 无符号）——头内注释声明仅特定设备开放**。
- **serviceId 过滤增强（PR #534）**：`EventCfg` 配置新增 `serviceId` 字段（阻断服务提供者标识），建立 eventId → serviceId 静态映射。client 订阅 eventId 时，SA 通过配置查到该 eventId 所属 serviceId 并存入会话（`eventServiceMap_`）；provider 的 `OnClientStatusChanged` 回调只上报订阅了与该 provider serviceId 相匹配的 eventId 的订阅者（按 serviceId 拆分，`subscribedEvents` 只含属于该 serviceId 的 eventId）。设计决策：1 eventId : 1 serviceId；按 serviceId 拆分；serviceId 必填校验在 Subscribe 时做（`EventCfg` 是通用配置，含非 auth_event 的普通 eventId，启动期无法区分，auth_event 订阅的 eventId 在 Subscribe 时校验 `config.serviceId` 非空）。

## 4. 契约变更

命名空间统一 `OHOS::Security::SecurityGuard`。

### 4.1 数据结构（新增）

- `AuthEvent : Parcelable` — 头文件 `interfaces/inner_api/collect/include/auth_event.h`
  - 字段（三字段）：`int64_t eventId`（阻断/鉴权事件标识）；`std::string content`（事件内容，JSON 扩展）；`std::string metadata`（元数据，JSON 扩展，由订阅者与事件源约定，框架不解析）；
  - 实现手写 `Marshalling/Unmarshalling`（对齐 `security_event.h:24-47` 范式），实现文件 `frameworks/common/collect/src/auth_event.cpp`。
- ~~`AuthEventSubscribeInfo`~~ — v2 取消（会话模式按 eventId 逐个订阅，无需批量结构）。
- `EventCfg` 新增字段 `std::string serviceId`（PR #534，阻断服务提供者标识，`interfaces/inner_api/common/include/security_event_info.h`），JSON key `"serviceId"`（`EVENT_CFG_SERVICE_ID_KEY`，`services/config_manager/include/model_analysis_define.h`），序列化在 `services/config_manager/src/model_cfg_marshalling.cpp` 的 `to_json`/`from_json`。auth_event 订阅的 eventId 必须配 serviceId（Subscribe 时校验非空）。

### 4.2 IPC 接口（3524 扩展，方案 D：主接口 1 方法 + 独立会话接口）

**主接口 IDL**（`services/data_collect/idl/DataCollectManagerIdl.idl`，替换 v8 的 5 方法追加，只追加 1 方法；sequenceable 区保留 `AuthEvent` 声明供 AuthEventSession.idl 引用语义，主接口自身不使用）：

```
void CreatAuthEventClient([in] IRemoteObject cb, [out] IRemoteObject session);
```

- `cb`：客户端回调（`IAuthEventCallback` 的远端对象）；`session`：服务端创建的会话对象（`AuthEventSessionService` stub 实例）远端引用，`[out]` 下发（实测 IDL 支持：proxy `reply.ReadRemoteObject()` / stub `SUCCEEDED(errCode)` 时 `reply.WriteRemoteObject(session)`）。
- 命名对齐现有 `CreatClient/DestoryClient` 的既有拼写（Creat）。
- 接口码：`interfaces/inner_api/collect/include/data_collect_manager_service_ipc_interface_code.h` 的 `DataCollectManagerInterfaceCode` 仅登记 `CMD_CREAT_AUTH_EVENT_CLIENT = 13`（登记值，非 wire code——3524 实际 IPC code 由 IDL 生成枚举 `DataCollectManagerIdlIpcCode` 按声明顺序分配，该方法位于末尾，实际 code 20；既有 19+4 个方法的 code 值不变【注：v8 曾追加 5 方法占 code 20-24，v9 收缩为 1 方法，功能默认关闭且未上机，无兼容性负担】）。

**会话接口 IDL**（新增 `services/data_collect/idl/AuthEventSession.idl`，文件名与接口名一致；IDL 工具生成 `auth_session.h`、`auth_session_stub.h/.cpp`、`auth_session_proxy.h/.cpp` 与枚举 `AuthEventSessionIpcCode`）：

```
void Subscribe([in] long eventId);
void Unsubscribe([in] long eventId);
void SetAuthResult([in] AuthEvent event, [in] boolean allowFlag);
void Destroy();
```

- 四方法均为会话内方法：binder handle 即会话路由，无需任何身份参数。
- 服务端实现（生成 stub 的虚函数覆写，`ErrCode` 返回）：`AuthEventSessionService : public AuthEventSessionStub`，位于 `services/data_collect/sa/`。
- 客户端经 `iface_cast<AuthEventSession>(sessionRemote)` 获得 proxy 直调。

**主接口服务端实现**：`DataCollectManagerService::CreatAuthEventClient(cb, session)`，位于 `services/data_collect/sa/`，转调 `AuthEventSubscribeManager`。

### 4.3 回调 broker（新增）

- `IAuthEventCallback : IRemoteBroker` — `interfaces/inner_api/collect/include/i_auth_event_callback.h`
  - `DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager.AuthEventCallback")`
  - 接口码枚举 `AuthEventCallbackInterfaceCode { CMD_ON_AUTH_EVENT = 1 }`（同文件追加）+ broker 内 `CMD_ON_AUTH_EVENT`；
  - 方法：`virtual int32_t OnAuthEvent(const AuthEvent &event) = 0;`
- 客户端适配（`std::function<void(const AuthEvent&)>` → 远端对象，对齐 `acquire_data_manager_callback_service/stub.h` 范式）：`auth_event_callback_service.h`（继承 `AuthEventCallbackStub`）放 `interfaces/inner_api/collect/include/`，实现 `frameworks/common/collect/src/auth_event_callback_service.cpp`，编入 libsg_collect_sdk。
- 服务端推送代理：`services/data_collect/sa/include/auth_event_callback_proxy.h`（手写 `IRemoteProxy<IAuthEventCallback>` + `BrokerDelegator`，对齐 `risk_analysis_manager_callback_proxy.h:28-36` 范式）。

### 4.4 客户端 SDK（新增，libsg_collect_sdk 内）

- `AuthEventSubscribeClient` — 头文件 `interfaces/inner_api/collect/include/auth_event_subscribe_client.h`（声明常驻，符号按 gni 裁剪，见"功能裁剪"），实现 `frameworks/common/collect/src/auth_event_subscribe_client.cpp`：
  ```cpp
  using AuthEventCallback = std::function<void(const AuthEvent &event)>;
  class AuthEventSubscribeClient {
  public:
      static int32_t CreatClient(AuthEventCallback callback,
          std::shared_ptr<AuthEventSubscribeClient> &client);
      int32_t Subscribe(int64_t eventId);
      int32_t Unsubscribe(int64_t eventId);
      int32_t SetAuthResult(const AuthEvent &event, bool allowFlag);  // 订阅者回填阻断/放行结果
      void DeleteClient();   // 断开已注册回调并排空在途 OnAuthEvent；最后一个 shared_ptr 释放时 Deleter 自动执行
  private:
      static void Deleter(AuthEventSubscribeClient *);
      void HandleDeath();
      sptr<AuthEventCallbackService> callback_{};
      sptr<IRemoteObject> sessionRemote_{};   // 服务端下发的会话对象远端引用，CreatClient 时填充
      sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
      std::set<int64_t> subscribedEventIds_{};
      bool deleted_ {false};     // 已销毁标记：阻止 HandleDeath 复活已删除会话；也阻止销毁后调用
  };
  ```
  - 禁用拷贝；SDK 每次调用现取 SA 3524（`GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID)` + `iface_cast`，对齐 `event_subscribe_client.cpp` 的 ReconnectService 范式）——仅 `CreatClient` 与服务端死亡重连需要主接口 proxy；会话方法直接 `iface_cast<AuthEventSession>(sessionRemote_)` 调用（不再现取 SA）。
  - **clientId 已删除**：会话身份由 session 代理的 binder handle 承载，SDK 无 `ConstructClientId`、无 clientId 存储/校验。
  - `SetAuthResult` 为会话方法：event 传回调收到的事件（或自行构造），服务端按 session 定位，仅校验长度与权限。
  - 服务端死亡：DeathRecipient → `HandleDeath()` 退避自动重连重建（对齐 `event_subscribe_client.cpp:162-207` 范式：{1,5,15,30,60×5} 秒重试 → ReconnectService → 重新走 `CreatAuthEventClient` 拿新 session 代理 → 按快照重订阅）；`deleted_` 标志（DeleteClient/Deleter 置位）在每轮重试前与写回前检查，已删除则销毁新建会话并退出，防会话复活。

### 4.5 接入校验（新增，主接口 CreatAuthEventClient 与 session 四方法前置共用）

- 权限名常量：`ohos.permission.kernel.AUTH_AUDIT_EVENT`（本仓仅校验引用，定义登记在 access_token 部件仓，不在本仓范围）。
- uid 白名单：管理器成员 `allowedUids_` + `IsUidAllowed(uid)`（`auth_event_subscribe_manager.h`；**具体值待用户提供，空清单占位=暂拒所有 native token，补值即生效**）。
- 校验函数 `AuthEventSubscribeManager::IsCallerAllowed()`（静态方法，置于 `services/data_collect/sa/auth_event_subscribe_manager.cpp`，独立于现有 `g_apiPermissionsMap`，对齐 `IsCallerHasApiPermission` 的写法），**主接口 CreatAuthEventClient 与 session 四方法（Subscribe/Unsubscribe/SetAuthResult/Destroy）前置共用**：
  1. `IPCSkeleton::GetCallingTokenID()` → `AccessTokenKit::GetAccessTokenType(callerToken)` 取 token 类型；
  2. native token（SA 应用）：校验 `IPCSkeleton::GetCallingUid()` 在 uid 白名单（管理器成员 `allowedUids_`，空清单=暂拒，补值即生效）内，不在则返回 `NO_PERMISSION`；
  3. HAP token：`AccessTokenKit::VerifyAccessToken(callerToken, "ohos.permission.kernel.AUTH_AUDIT_EVENT")` 为 GRANTED 放行，否则 `NO_PERMISSION`；
  4. 其他 token 类型：`NO_PERMISSION`。
- **会话进程绑定**：session 方法中比对会话记录的 `pid` 与 `IPCSkeleton::GetCallingPid()`，不一致返回 `BAD_PARAM`（binder handle 理论上不可被第三方获取，此为纵深防御）。
- **订阅配置校验（含 serviceId 必填，PR #534）**：`Subscribe` 在权限/会话校验后执行 `ConfigDataManager::GetEventConfig(eventId, config)`，未命中返回 `BAD_PARAM`（事件须在事件配置中，对齐 `CollectorStart` 范式）；**命中后校验 `config.serviceId` 非空**（空则 `BAD_PARAM`，该 eventId 未配置为 auth_event 事件，对齐"启动期无法区分 auth_event 与普通 eventId"的现状）；`Unsubscribe` 不做配置校验（配置运行中可被移除）。

### 4.6 服务端会话对象与管理器（新增）

**会话对象 `AuthEventSessionService`**（`services/data_collect/sa/include/auth_event_session_service.h` + `services/data_collect/sa/auth_event_session_service.cpp`，继承 IDL 生成的 `AuthEventSessionStub`，NoCopyable）——**一个实例 = 一个客户端会话**：

- 构造入参：`pid_t callerPid, int32_t callerUid, const sptr<IRemoteObject> &callback`（状态即成员，非查表所得）；
- 四个 IDL 方法覆写（Subscribe/Unsubscribe/SetAuthResult/Destroy）：前置 `IsCallerAllowed()` 双轨校验 → 会话有效性检查（已销毁 → `BAD_PARAM`，Destroy 幂等 `SUCCESS`）→ pid 归属校验 → 转调 `AuthEventSubscribeManager` 对应状态操作（manager 单锁内操作本会话 eventIds）；
- 状态成员：`pid_/uid_/callback_/eventIds_/eventServiceMap_/valid_`（`eventServiceMap_` 为 eventId→serviceId 映射，PR #534）；状态操作全部经 manager 持锁进行（session 自身无锁，锁纪律见 manager）；
- **serviceId 映射方法（PR #534，管理器锁内调用）**：`RegisterEventService(eventId, serviceId)` / `UnregisterEventService(eventId)` / `GetServiceIdForEvent(eventId)`，与 `eventIds_` 同步维护（SubscribeAuthEvent 锁内同时 insert，UnsubscribeAuthEvent 锁内同时 erase）。
- per-session 死亡清理：构造时由 manager 在 cb 上挂 `AuthEventSessionDeathRecipient`（持本会话 weak 引用），客户端死亡 → `manager->RemoveSession(session)`。

**管理器 `AuthEventSubscribeManager`**（`services/data_collect/sa/include/auth_event_subscribe_manager.h` + `services/data_collect/sa/auth_event_subscribe_manager.cpp`，单例，NoCopyable）：

- `int32_t CreatAuthEventClient(pid_t callerPid, int32_t callerUid, const sptr<IRemoteObject> &callback, sptr<IRemoteObject> &sessionRemote);` — cb 判空（`NULL_OBJECT`）+ 同 cb 重复创建检查（`BAD_PARAM`）+ 配额检查 + 创建 session 对象登记集合（AddDeathRecipient 失败回滚）
- `int32_t SubscribeAuthEvent(AuthEventSessionService *session, int64_t eventId, const std::string &serviceId);`（PR #534：加 `serviceId` 参数，锁内同时 insert `eventIds_` 和 `RegisterEventService(eventId, serviceId)`；会话无效/已销毁 → `BAD_PARAM`；重复 eventId 幂等；单会话上限 1024）
- `int32_t UnsubscribeAuthEvent(AuthEventSessionService *session, int64_t eventId);`（未订阅幂等 `SUCCESS`；PR #534：锁内同时 erase `eventIds_` 和 `UnregisterEventService(eventId)`）
- `int32_t SetAuthResult(AuthEventSessionService *session, pid_t callerPid, int32_t callerUid, const AuthEvent &event, bool allowFlag);` — 记录结果状态表（覆盖更新，新键受 1024 上限）→ 阻断结果锁外 HA 打点
- `int32_t DestroyAuthEventClient(AuthEventSessionService *session);` — 幂等销毁（重复 `SUCCESS`），置会话无效
- `int32_t GetAuthResult(int64_t eventId, bool &allowFlag);` — 预留读取口（`NOT_FOUND`）
- `void NotifyAuthEvent(const AuthEvent &event);` — 内部事件源注入入口（预留，本期无调用方）：长度守卫 → 锁内快照命中会话 callback → 锁外分发推送
- `static int32_t IsCallerAllowed();` — 双轨校验（见 4.5）
- `bool IsUidAllowed(int32_t uid) const;` — uid 白名单查询
- 会话集合：`std::set<sptr<AuthEventSessionService>> sessions_`；结果状态表：`map<int64_t, bool> authResults_`；ffrt::mutex 保护（会话数上限 16，临界区均为短内存操作，有意不分段锁）；临界区内禁止任何外部调用（binder 死亡通知注册/注销、IPC 推送、HA 打点），一律"锁内快照、锁外执行"（对齐 `acquire_data_subscribe_manager.cpp:1122-1128` 锁纪律）；
- 配额常量（置于管理器头文件）：`MAX_AUTH_EVENT_CLIENT_SIZE = 16`（设备全局）、`MAX_AUTH_EVENT_CLIENT_SIZE_ONE_PROCESS = 2`（单进程）；检查逻辑对齐 `IsExceedLimited`（`acquire_data_subscribe_manager.cpp:1132-1166`）：按 callerPid 统计该 pid 名下会话数 ≥2 → `CLIENT_EXCEED_PROCESS_LIMIT`；会话集合总数 ≥16 → `CLIENT_EXCEED_GLOBAL_LIMIT`；
- 常量：字符串 `MAX_AUTH_EVENT_STR_LEN=4096`、集合 `MAX_AUTH_EVENT_SUBSCRIBE_SIZE / MAX_AUTH_EVENT_RESULT_SIZE=1024`。
- ~~超时跟踪表 / CheckAuthResultTimeout / AUTH_RESULT_TIMEOUT_MS~~ — v9 删除（超时属另一需求）。

**协调者 `AuthCoordinator`**（`services/data_collect/sa/include/auth_event/auth_coordinator.h` + `services/data_collect/sa/auth_event/auth_coordinator.cpp`，单例，NoCopyable）——provider 侧会话管理与状态通知（PR #534 serviceId 过滤增强）：

- `std::set<sptr<AuthProviderSessionService>> providerSessions_` — provider 会话集合（按 sptr 排序，无 serviceId 索引；`CreateAuthProvider`/`DestroyAuthProvider`/`RemoveProvider` 增删，`FindProviderLocked` 按裸指针查）。
- `std::vector<AuthClientInfo> CollectClientInfos(const std::string &serviceId)`（PR #534：签名加 `serviceId` 参数）——遍历所有 session，每个 session 按 `serviceId` 过滤 `eventIds`（`GetServiceIdForEvent(eventId) == serviceId`），只收集订阅了属于该 serviceId 的 eventId 的 client；同一 client 订阅不同 serviceId 的 eventId 时，在不同 provider 列表里各出现一次，`subscribedEvents` 只含属于该 serviceId 的 eventId。
- `void NotifyClientStatusChanged()`（PR #534：按 provider 过滤）——锁内收集所有有效 provider 的 `(callback, serviceId)` 对，锁外对每个 provider 调 `CollectClientInfos(providerServiceId)` 过滤后单独发送 `OnClientStatusChanged(filteredClientInfos)`（不再全量广播同一份 clientInfos 给所有 provider）。

### 4.7 错误码 / 兼容

- 错误码复用 `ErrorCode` 枚举（`security_guard_define.h:22-49`）：`SUCCESS / FAILED / NO_PERMISSION / BAD_PARAM / NULL_OBJECT / NOT_FOUND`、配额专用 `CLIENT_EXCEED_PROCESS_LIMIT=1007 / CLIENT_EXCEED_GLOBAL_LIMIT=1008`、集合上限 `FILTER_EXCEED_LIMIT=1006`（均已存在，不新增错误码）。全量错误码场景见 4.9。
- 兼容：主接口纯增量（追加 1 方法，wire code 20）；独立会话集合不挤占审计客户端既有 16/2 配额；旧 SDK 不受影响；**gni 开关默认关闭时主接口 `CreatAuthEventClient` 退化为占位实现（`FAILED`，session 不下发），功能源不编入，对既有功能零影响**；AuthEventSession IDL 生成代码与 `auth_event.cpp` 无条件编入（纯虚方法必须覆写以保持可编译、stub/proxy 引用 AuthEvent 序列化符号）。

### 4.8 HA 打点（新增）

打点通道为 HA lite 客户端（`ha_client_lite_api.h`，**依赖尚未进入本仓构建环境**）：封装为 `AuthEventReporter` 适配层（`services/data_collect/sa/auth_event_reporter.h/.cpp`），真实上报集中在 `ReportToHa()` 单点（当前 SGLOGI 日志兜底，头文件进仓后仅改该函数）；随整个需求宏隔离；`Write` 类耗时接口仅锁外调用。

| 事件 | 触发 | 字段 |
|---|---|---|
| AUTH_BLOCK_RESULT | SetAuthResult 成功且 allowFlag=false | CALLER_PID、CALLER_UID、EVENT_ID、CONTENT、METADATA |

~~AUTH_RESULT_TIMEOUT~~ — v9 删除（超时判断属另一需求）。

### 4.9 错误码场景全量矩阵（v9 用户要求梳理）

**服务层前置（主接口与 session 四方法共用，按序）**：

| # | 场景 | 错误码 | 说明 |
|---|---|---|---|
| P1 | native token（SA 应用）uid 不在白名单 | `NO_PERMISSION` | 空清单=暂拒所有 native token，补值即生效 |
| P2 | HAP token 权限 `ohos.permission.kernel.AUTH_AUDIT_EVENT` DENIED | `NO_PERMISSION` | |
| P3 | token 类型非法（非 native/HAP） | `NO_PERMISSION` | |
| P4 | gni 开关关闭形态下的主接口调用 | `FAILED` | 占位实现一律拒绝，session 不下发 |

**CreatAuthEventClient(cb, [out] session)**：

| # | 场景 | 错误码 | 说明 |
|---|---|---|---|
| C1 | cb == nullptr | `NULL_OBJECT` | 服务层判空 |
| C2 | 同一 cb 重复创建 | `BAD_PARAM` | 用户裁决：对齐撞表语义 |
| C3 | 该 pid 名下会话数 ≥2 | `CLIENT_EXCEED_PROCESS_LIMIT=1007` | 进程配额 |
| C4 | 会话集合总数 ≥16 | `CLIENT_EXCEED_GLOBAL_LIMIT=1008` | 设备配额 |
| C5 | AddDeathRecipient 失败 | `FAILED` | 回滚已登记会话 |

**session->Subscribe(eventId)**：

| # | 场景 | 错误码 | 说明 |
|---|---|---|---|
| S1 | eventId 不在事件配置 | `BAD_PARAM` | GetEventConfig 未命中（对齐 CollectorStart） |
| S2 | 会话已销毁（Destroy 后/死亡清理后） | `BAD_PARAM` | |
| S3 | 调用 pid ≠ 会话 pid | `BAD_PARAM` | 纵深防御 |
| S4 | 会话订阅数 >1024 | `FILTER_EXCEED_LIMIT=1006` | 新增 eventId 时检查 |
| S5 | 重复订阅同 eventId | `SUCCESS`（幂等） | |

**session->Unsubscribe(eventId)**：

| # | 场景 | 错误码 | 说明 |
|---|---|---|---|
| U1 | 会话已销毁 | `BAD_PARAM` | |
| U2 | 调用 pid ≠ 会话 pid | `BAD_PARAM` | |
| U3 | 退订未订阅的 eventId | `SUCCESS`（幂等） | 用户裁决 |
| — | 不做配置校验 | — | 配置运行中可被移除 |

**session->SetAuthResult(event, allowFlag)**：

| # | 场景 | 错误码 | 说明 |
|---|---|---|---|
| R1 | content 或 metadata 长度 >4096 | `BAD_PARAM` | 不可信输入处理 |
| R2 | 会话已销毁 | `BAD_PARAM` | |
| R3 | 调用 pid ≠ 会话 pid | `BAD_PARAM` | |
| R4 | 结果表新键且容量 >1024 | `FILTER_EXCEED_LIMIT=1006` | 覆盖更新已有键不检查 |
| R5 | allowFlag=false | `SUCCESS` + HA 打点 | AUTH_BLOCK_RESULT，锁外上报 |

**session->Destroy()**：

| # | 场景 | 错误码 | 说明 |
|---|---|---|---|
| D1 | 调用 pid ≠ 会话 pid | `BAD_PARAM` | |
| D2 | 重复 Destroy | `SUCCESS`（幂等） | 用户裁决："确保销毁"语义 |
| D3 | 正常销毁 | `SUCCESS` | 移除会话集合 + 置无效 + 锁外 RemoveDeathRecipient |

**其他路径**：

| # | 场景 | 错误码 | 说明 |
|---|---|---|---|
| N1 | GetAuthResult(eventId) 无记录 | `NOT_FOUND` | 预留读取口 |
| N2 | NotifyAuthEvent 事件 content/metadata 超长 | 静默丢弃（日志） | 内部注入口，void 返回 |
| K1 | SDK CreatClient：callback 为空 / SAMGR 获取失败 / proxy 为空 | `NULL_OBJECT` | 对齐 event_subscribe_client 范式 |
| K2 | SDK CreatClient：主接口返回非 SUCCESS | 透传 | client 不落值 |
| K3 | SDK 会话方法（DeleteClient 后调用） | `BAD_PARAM` | deleted_ 检查 |
| K4 | SDK 会话方法：sessionRemote 失效且服务端存活 | `NULL_OBJECT` | 代理获取失败 |
| K5 | SDK 各方法：服务端返回码 | 透传 | |
| A1 | 服务端死亡后 SDK 重连 | 自动重建（无错误码暴露） | 退避 {1,5,15,30,60×5}s |

## 5. 影响面

新增：

- `interfaces/inner_api/collect/include/auth_event.h` —— 新增：AuthEvent 结构
- `interfaces/inner_api/collect/include/i_auth_event_callback.h` —— 新增：回调 broker（含回调接口码枚举）
- `interfaces/inner_api/collect/include/auth_event_callback_service.h` —— 新增：客户端回调适配（service 继承手写 stub）
- `interfaces/inner_api/collect/include/auth_event_subscribe_client.h` —— 新增：SDK 会话客户端类
- `frameworks/common/collect/src/auth_event.cpp` —— 新增：AuthEvent 序列化实现
- `frameworks/common/collect/src/auth_event_callback_service.cpp` —— 新增：回调适配实现（含 stub OnRemoteRequest）
- `frameworks/common/collect/src/auth_event_subscribe_client.cpp` —— 新增：SDK 实现
- `services/data_collect/idl/AuthEventSession.idl` —— 新增：会话接口 IDL（v9，生成 auth_session.h/stub/proxy）
- `services/data_collect/sa/include/auth_event_session_service.h` —— 新增：会话服务对象（v9，一个实例 = 一个客户端会话）
- `services/data_collect/sa/auth_event_session_service.cpp` —— 新增：会话服务实现
- `services/data_collect/sa/include/auth_event_subscribe_manager.h` —— 新增：会话管理器（含配额常量与 uid 白名单）
- `services/data_collect/sa/include/auth_event_reporter.h` —— 新增：HA 打点适配层
- `services/data_collect/sa/auth_event_subscribe_manager.cpp` —— 新增：会话管理器实现（sa/ 下，对齐仓库惯例，无 src/ 子目录）
- `services/data_collect/sa/include/auth_event_callback_proxy.h` —— 新增：服务端推送代理头
- `services/data_collect/sa/auth_event_callback_proxy.cpp` —— 新增：服务端推送代理实现
- `test/unittest/data_collect/sa/auth_event_subscribe_manager_test.cpp` —— 新增：管理器与会话对象单测

修改：

- `security_guard.gni` —— 修改：新增 gni 开关 `security_guard_auth_event_enable`（默认 false），控制整需求编译隔离
- `services/data_collect/idl/DataCollectManagerIdl.idl` —— 修改：v8 追加的 5 方法收缩为 1 方法 `CreatAuthEventClient([in] IRemoteObject cb, [out] IRemoteObject session)`（v9）
- `services/data_collect/idl/BUILD.gn` —— 修改：新增 AuthEventSession IDL 生成 target（v9）
- `interfaces/inner_api/collect/include/data_collect_manager_service_ipc_interface_code.h` —— 修改：登记接口码收缩为仅 CMD_CREAT_AUTH_EVENT_CLIENT=13（v9）
- `services/data_collect/sa/include/data_collect_manager_service.h` —— 修改：声明收缩为 1 方法（v9）；删除 4 方法与超时参数
- `services/data_collect/sa/data_collect_manager_service.cpp` —— 修改：CreatAuthEventClient 单方法实现（双轨校验挪至 manager 静态方法）
- `test/unittest/data_collect/sa/data_collect_manager_service.h` —— 修改：mock 影子头同步 1 方法签名
- `services/data_collect/BUILD.gn` —— 修改：新增 auth_event.cpp、auth_event_session_service.cpp 与服务端源文件
- `frameworks/common/collect/BUILD.gn` —— 修改：新增 SDK 源文件（auth_event/callback_service/subscribe_client）与 auth_session_proxy 依赖（对外头在 interfaces 目录，经 bundle.json header_base 暴露，无需 public_configs 条件通道）
- `frameworks/common/collect/sg_collect_sdk.map` —— 修改：导出 AuthEventSubscribeClient 方法与 AuthEvent 序列化/vtable/VTT 符号
- `frameworks/common/collect/test/BUILD.gn` —— 修改：测试 target 补 SDK 新源文件与新测试
- `bundle.json` —— 无需修改（inner_kits 为 header_files 空数组 + header_base 目录登记，新头自动暴露，对齐仓库现状）
- `test/unittest/data_collect/BUILD.gn` —— 修改：新增单测源文件

删除（v9 收缩）：

- ~~IDL 5 方法中的 DestoryAuthEventClient/SubscribeAuthEvent/UnsubscribeAuthEvent/SetAuthResult~~ —— 改由 AuthEventSession.idl 承载
- ~~超时跟踪相关全部实现~~ —— pendingResults_/PendingAuthResult/PendingKey/CheckAuthResultTimeout/AUTH_RESULT_TIMEOUT_MS/timeoutAllowFlag/seqNum 填充与解析/ReportAuthResultTimeout

不改动：sa_profile/（复用 3524）、根 BUILD.gn、hisysevent.yaml。

## 6. 验收标准

- [x] 编译通过（双形态）：`security_guard_auth_event_enable=false`（默认）与 `=true` 两种 gni 配置下 `hb build security_guard -t` 均无错误；开启形态产物含功能符号，关闭形态 IPC 入口为占位（一律 FAILED）。
- [x] Parcelable 往返：`AuthEvent` 三字段（eventId/content/metadata）往返一致（全字段/缺省值/空 parcel，auth_event_parcelable_test.cpp 3 例）。
- [x] 双轨校验（主接口 + session 四方法前置）：native + uid 在清单（注入）→ SUCCESS；native 不在清单 / HAP+DENIED / 非法 token → NO_PERMISSION；HAP+GRANTED → SUCCESS。
- [x] 订阅配置校验：eventId 不在事件配置 → BAD_PARAM；配置中 eventId 进入会话校验；退订不校验（SubscribeEventIdNotInConfig001）。
- [x] 配额限制：同 pid 第 3 个 → CLIENT_EXCEED_PROCESS_LIMIT；满 16 → CLIENT_EXCEED_GLOBAL_LIMIT；销毁后可重建（QuotaLimit001/002）。
- [x] 会话对象下发：CreatAuthEventClient 返回非空 session 代理；同一 cb 重复创建 → BAD_PARAM；cb 空 → NULL_OBJECT（CreatAuthEventClient001，v9）。
- [x] 销毁语义：Destroy 幂等 SUCCESS；销毁后再调 Subscribe/Unsubscribe/SetAuthResult → BAD_PARAM（DestroySemantics001，v9）。
- [ ] 会话与订阅管理：单测覆盖——Creat 后 Subscribe(eventId) 并 Notify 命中推送；Notify 未订阅 eventId 不推送；Unsubscribe 后不再推送；重复订阅 eventId 幂等；退订未订阅 eventId 幂等 SUCCESS。
- [ ] 结果回填：单测覆盖——SetAuthResult(event, allowFlag) 记录状态表（查询内部表验证 true/false 覆盖更新）；超长 content/metadata → BAD_PARAM；权限校验复用双轨用例（NO_PERMISSION 路径）。
- [ ] 死亡清理：单测模拟订阅者远端对象死亡（触发 DeathRecipient）后 Notify 不再向其推送、且无崩溃。
- [ ] SDK 客户端：单测覆盖 CreatClient/Subscribe/Unsubscribe/SetAuthResult/DeleteClient 经 session 代理到达服务端路径，回调 function 被触发。
- [ ] 回归：现有 3524 单测（test/unittest/data_collect/）全部仍通过。
- [ ] serviceId 必填校验（PR #534）：单测覆盖——Subscribe 时 `config.serviceId` 为空 → `BAD_PARAM`；`config.serviceId` 非空 → SUCCESS（`eventServiceMap_` 正常登记）。
- [ ] serviceId 过滤（PR #534）：单测覆盖——client 订阅 eventId A（serviceId="P1"）和 eventId B（serviceId="P2"）；provider P1 收到的 `OnClientStatusChanged` 只含该 client 且 `subscribedEvents` 只含 A；provider P2 只含该 client 且 `subscribedEvents` 只含 B；无 provider 时 client 仍可订阅（`eventServiceMap_` 正常登记）；client 订阅了某 serviceId 的 eventId 但无对应 serviceId 的 provider 时，该订阅不发给任何 provider。
- ~~[ ] 回填超时跟踪 / 超时处置策略~~ —— v9 删除（超时属另一需求）。

## 7. 存疑

- uid 白名单（管理器成员 `allowedUids_`）的具体值待用户提供：空清单=暂拒所有 native token 接入，补值后即生效（单测已覆盖"补值生效"语义）。
- `ha_client_lite_api.h` 依赖需进入本仓构建环境后，将 `AuthEventReporter::ReportToHa()` 的日志兜底替换为真实 HA 上报（单点改动）。
- `ohos.permission.kernel.AUTH_AUDIT_EVENT` 需在 access_token 部件仓完成权限定义与开放范围登记（本仓外动作，需用户在对应仓推进；不推进则 HAP 侧校验永远 DENIED，但不影响框架代码交付）。
- 实现注意事项（Review 登记，v9 沿用）：① 每次修改 `services/data_collect/sa/include/data_collect_manager_service.h` 必须同步 `test/unittest/data_collect/sa/data_collect_manager_service.h`（mock 影子头）；② `SetAuthResult`/`NotifyAuthEvent` 消费 `content`/`metadata` 时按不可信输入处理（长度上限校验，超限 `BAD_PARAM`，使用点再解析 JSON）。
- v9 移交项：事件超时判断/超时跟踪/超时处置/超时打点由另一需求承接（本仓预留 NotifyAuthEvent 注入口与结果表，不涉及超时）。

## 8. 现状附录（取证全量）

来源：SubAgent 只读取证报告（2026-09-03）+ v2 修订补充取证，关键结论附 file:line。

### 8.1 整体架构与 SA 注册

- 三层划分：SG 接口层 / SG 基础服务层 / SG 安全模型（`README_zh.md:10-15`）；frameworks=基础功能、interfaces=inner_api、services=服务框架（`README_zh.md:27-37`）。
- 组件：component name `security_guard`，subsystem `security`，syscap `SystemCapability.Security.SecurityGuard`（`bundle.json:12-17`）。
- SA 注册现状：

| SA | 模块 | libpath | process | run-on-create |
|---|---|---|---|---|
| 3523 | risk_classify | libsg_classify_service.z.so | security_guard | true |
| 3524 | data_collect | libsg_collect_service.z.so | security_guard | true |
| 3525 | security_collector | libsecurity_collector_service.z.so | security_collector | false |

  证据：`sa_profile/3523.json:2-12`、`sa_profile/3524.json:2-12`、`sa_profile/3525.json:2-12`；SA ID 常量 `i_risk_analysis_manager.h:28`、`i_data_collect_manager.h:31`、`i_security_collector_manager.h:31`；`sa_profile/BUILD.gn:18-36`。
- 进程属性：uid/gid `security_guard`、apl `system_basic`、secon `u:r:security_guard:s0`、权限 COLLECT/QUERY_SECURITY_EVENT（`sa_profile/security_guard.cfg:14-39`）；数据目录 `/data/service/el1/public/security_guard{,/tmp}` 与数据库目录（同文件 line 6-10）。
- 各服务模块职责：
  - risk_classify：模型管理 + 检测插件（`services/risk_classify/include/risk_analysis_manager_service.h:34-39`、`model_manager.cpp:56-107`、`risk_analysis_manager_service.cpp:87-91`）；
  - data_collect：采集/订阅/查询/配置更新 + 审计客户端会话管理（`services/data_collect/sa/include/data_collect_manager_service.h:34-73`）；
  - config_manager：配置加载/缓存/更新，`InitConfig<T>` 模板（`services/config_manager/include/config_manager.h:24-44`），导出 C 符号 `InitAllConfig/UpdateConfig` 供 dlopen（`services/config_manager/src/interface.cpp:21-39`）；
  - collector_manager：进程内采集器 so 加载（`services/collector_manager/include/data_collection.h:35-47`）；
  - security_collector：对"采集器使用者"开放的 SA，手写 IPC，空闲自动卸载（`services/security_collector/src/security_collector_manager_service.cpp:60-86`）。

### 8.2 IPC 模式（新增服务应模仿的范式）

- inner_api SDK 客户端：静态单例 + 每次调用现取 RemoteObject + `iface_cast`（`frameworks/common/collect/src/data_collect_manager.cpp:40-44,86-93`）；classify 为函数式 API（`frameworks/common/classify/src/sg_classify_client.cpp:42-66`）。
- **会话式客户端范式（v2 对齐目标）**：`EventSubscribeClient`（`interfaces/inner_api/collect/include/event_subscribe_client.h:29-67`）：静态 `CreatClient(eventGroup, callback, shared_ptr&)` / `Subscribe(eventId)` / `Unsubscribe(eventId)` / `ClearCallBack()`；`ConstructClientId` 由回调 service 指针构造（`event_subscribe_client.cpp:107`）；shared_ptr Deleter 销毁时自动断连（`event_subscribe_client.cpp:54`）；DeathRecipient + `HandleDeath` + `ReconnectService` 重连重注册（`event_subscribe_client.cpp:147,173-184`）。
- 会话服务端范式：`DataCollectManagerService::CreatClient(eventGroup, clientId, cb)`（`data_collect_manager_service.cpp:1202-1245`）：权限检查 → XCollie → 判空 NULL_OBJECT → 管理器登记 → SetDeathCallBack → clientId 去重（重复 `BAD_PARAM`，line 1232-1237）。
- **配额检查范式**：`AcquireDataSubscribeManager::IsExceedLimited(clientId, eventGroup, callerPid)`（`acquire_data_subscribe_manager.cpp:1132-1166`）：会话计数 ≥ `MAX_SESSION_SIZE=16` → `CLIENT_EXCEED_GLOBAL_LIMIT`；同 pid clientId 数 ≥ `MAX_SESSION_SIZE_ONE_PROCESS=2` → `CLIENT_EXCEED_PROCESS_LIMIT`（常量 line 46-47）；错误码定义 `security_guard_define.h:45-46`。
- 同步等待：`std::promise/future` + 超时（classify 15000ms `sg_classify_client.cpp:34,96-100`；data_collect 10000ms）。
- 回调：客户端把 `std::function` 包成本地 stub 传给服务端（`data_collect_manager.cpp:99-104`、`sg_classify_client.cpp:58-62`）；死亡通知退避重订阅 {1,5,15,30,60...}s（`data_collect_manager.cpp:168-224`）。
- IDL 代码生成（现行主流）：`services/data_collect/idl/DataCollectManagerIdl.idl:21-41` + `idl_gen_interface`（`services/data_collect/idl/BUILD.gn:18-24`）+ stub/proxy source_set（同文件 35-46,70-81）；服务类继承生成 stub（`data_collect_manager_service.h:29,34`）。手写 IPC 仅 3525 保留（`security_collector_manager_stub.cpp:22-56`）。IDL 语法要点（本地 idl 工具实测）：void 方法生成 `ErrCode` 返回的 proxy/stub；`IRemoteObject` 参数名不可用 `callback`（需 `cb`）；文件名须与接口名一致；未使用的 sequenceable 声明安全。
- IPC 接口码：`enum class XxxInterfaceCode`（`data_collect_manager_service_ipc_interface_code.h:23-47`）；broker 描述符 `DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager")`（`i_data_collect_manager.h:36`）。
- 服务注册：`REGISTER_SYSTEM_ABILITY_BY_ID` + `OnStart` 序列（dlopen config → Init → `Publish`）（`data_collect_manager_service.cpp:109,120-155`）。
- 权限校验：API→权限映射表 `g_apiPermissionsMap`（`data_collect_manager_service.cpp:78-90`）→ `IsCallerHasApiPermission`（753-796）：VerifyAccessToken + 系统应用判定，非系统应用 `NO_SYSTEMCALL`。

### 8.3 新增服务模块接线点

1. 根 `BUILD.gn` group（`BUILD.gn:24-32`）；2. `security_guard.gni` gn args（`security_guard.gni:16-36`）；3. `bundle.json` sub_component + inner_kits（`bundle.json:80-131`）；4. `sa_profile/<SAID>.json` + BUILD.gn sources；5. 模块 BUILD.gn 范式（`services/risk_classify/BUILD.gn:25-99`）：`subsystem_name="security"`、`part_name="security_guard"`、version_script .map、统一 sanitize 块（integer_overflow/ubsan/boundary_sanitize/cfi + pac_ret + _FORTIFY_SOURCE=2，`services/data_collect/BUILD.gn:84-100`）；6. external_deps 常用：`ipc:ipc_core`/`ipc_single`、`samgr:samgr_proxy`、`safwk:system_ability_fwk`、`hilog:libhilog`、`c_utils:utils`、`access_token:libaccesstoken_sdk`、`ffrt:libffrt`、`json:nlohmann_json_static`、`sqlite:sqlite`、`hisysevent`；7. IDL 目录模板 `services/data_collect/idl/BUILD.gn:18-103`；8. SDK `innerapi_tags = ["platformsdk","sasdk"]`（`frameworks/common/collect/BUILD.gn:26-30`）；9. 测试接线（根 `BUILD.gn:34-103`、`bundle.json:132-136`）；10. fuzz 构建引用 `data_collect_manager_service.cpp` 的 9 个 BUILD.gn 需同步新增源文件（若编译报缺符号）。

### 8.4 公共能力（可复用）

- 日志 `SGLOGx`（`frameworks/common/log/include/security_guard_log.h:18-35`，domain 0xD002F07）；工具 `SecurityGuardUtils`（`security_guard_utils.h:22-30`）、`FileUtil::ReadFileToStr`（`file_util.h:24-28`）、cJSON 封装（`json_util.h:22-33`）、nlohmann 封装 `JsonCfg::Unmarshal`（`json_cfg.h:32-66`）、`FdsanFd` RAII（`fdsan_fd.h:24-99`）、看门狗 `XCollie_Utils`（`xcollie_utils.h:22-34`）。
- 错误码：`ErrorCode` 枚举（`security_guard_define.h:22-49`：SUCCESS/FAILED/NO_PERMISSION/NO_SYSTEMCALL/BAD_PARAM/NULL_OBJECT/CLIENT_EXCEED_PROCESS_LIMIT=1007/CLIENT_EXCEED_GLOBAL_LIMIT=1008 等）；`ErrCode = int`（c_utils errors.h，经 iremote_broker.h 引入，预处理实测确认）。
- 注意：`frameworks/common/task_handler` 与 `frameworks/common/database` 目录已被删除（多个 BUILD.gn 残留引用）；当前异步/并发一律用 ffrt（`ffrt::submit/queue/thread/sleep_for/mutex`）。
- HiSysEvent：域 SECURITY_GUARD，9 个事件（`hisysevent.yaml:14-78`），统一 `BigData::ReportXxx`（`services/bigdata/src/bigdata.cpp:39-80`）。

### 8.5 risk_classify（阻断决策潜在输入源）

- IPC 接口：`RequestSecurityModelResult(devId, modelId, param, callback)` / `SetModelState` / `StartSecurityModel`（`i_risk_analysis_manager.h:30-44`）；回调 `ResponseSecurityModelResult(devId, modelId, result)`（line 46-55）。
- 结果语义：`RISK_STATUS="risk" / SAFE_STATUS="safe" / UNKNOWN_STATUS="unknown"`（`risk_analysis_define.h:24-26`）；非白名单 modelId 一律 unknown（`risk_analysis_manager_service.cpp:164-167`）。
- 进程内订阅：`IModelResultListener::OnChange(result)`（`i_model_result_listener.h:23-27`，非 IPC）；跨进程走 3523 IPC 客户端（`sg_classify_client.h:33-38`）。
- 模型插件协议：`IModel` + `GetModelApi` 工厂，dlopen 加载（`model_manager.cpp:74-95`）。

### 8.6 配置链路（后续扩展可复用）

- 路径：预置 `/system/etc/security_guard_*.json|cfg`，已生效 `/data/service/el1/public/security_guard/...`，待生效 tmp（`services/config_manager/include/config_define.h:41-57`）；优先 /data 回退 /system/etc（`event_config.cpp:34-59`）。
- 解析：nlohmann + `JsonCfg::Unmarshal`（`event_config.cpp:67,127`）→ `ConfigDataManager` 单例缓存（`config_data_manager.h:27-60`）。
- 初始化：SA OnStart dlopen libsg_config_manager.z.so 调 `InitAllConfig()`（`interface.cpp:21-34`；调用方 `risk_analysis_manager_service.cpp:70-82`）——服务间无依赖初始化的既定模式。
- 在线更新：`ConfigUpdate(fd, name)` IPC + 信任名单 `/system/etc/config_update_trust_list.json`（`data_collect_manager_service.cpp:827-907,941-957`）。

### 8.7 数据库能力（本期不使用，备查）

- 自研 sqlite 封装（非 RDB）：`SqliteHelper`（`store/include/sqlite_helper.h:32-73`）→ `Database`（`database.h:24-52`）→ `DatabaseHelper`（`database_helper.h:23-57`）→ `DatabaseManager` 门面 + `SubscribeDb` 监听（`database_manager.h:27-57`）；表 `risk_event/audit_event/app_info`（`store_define.h:36-38`）；库目录 `/data/service/el1/public/database/security_guard_service/`。
- 独立 so：`sg_collect_service_database`（`services/data_collect/BUILD.gn:143-197`）。

### 8.8 测试组织

- 目录：`test/unittest/<module>/`、fuzz `test/fuzztest/`；unittest target 统一 `part_name="security_guard"`、`subsystem_name="securitycloudgovernance"`（注意：与产品 subsystem `security` 不一致，历史遗留，`test/unittest/data_collect/BUILD.gn:17-21`）。
- mock 模式：mock 头目录 `test/unittest/mock/*`（12 组），静态单例 + MOCK_METHOD，测试 cpp 手动定义 mock 静态成员 + `#define private public`（`security_guard_data_collect_sa_test.cpp:35-65`）；被测 .cpp 直接编进 unittest target（`test/unittest/risk_classify/BUILD.gn:49-62`）。
- 配额相关既有单测：`security_guard_data_collect_sa_test.cpp:1372`、`security_guard_data_collect_sa_new_test.cpp:260`（CLIENT_EXCEED_PROCESS_LIMIT 断言范式）。
- cfi_blocklist 仅 config_manager 测试使用（`test/unittest/config_manager/BUILD.gn:144-151`）。
- 陈旧引用：`services/risk_collect`、`frameworks/common/task_handler`、`frameworks/common/database` 的 BUILD.gn include 为死引用，新模块勿模仿。

### 8.9 隐含约定

- 命名空间 `OHOS::Security::SecurityGuard`；接口 `I` 前缀；文件 `i_xxx.h`/`xxx_client`/`xxx_service`/`xxx_stub`/`xxx_proxy`/`xxx_callback_{service,stub,proxy}`；SA id 常量 `XXX_SA_ID`；错误码 `ErrCode`/`int32_t` + `ErrorCode` 枚举。
- 服务类形状：`class XxxService : public SystemAbility, public XxxStub, public NoCopyable` + `DECLARE_SYSTEM_ABILITY`（`risk_analysis_manager_service.h:26-27`）。
- 日志格式 `SGLOGx("[%{public}s]" fmt, __func__, ...)`，隐私参数 `%{private}`；hidumper 覆写 `Dump(fd,args)`；系统参数未使用（配置全走文件）；so 用 version_script 只导出必要符号；并发统一 ffrt，"锁内快照、锁外执行"纪律。
- 编译环境：本机为部件独立编译 `hb build security_guard -t`（ARM 交叉编译，工作目录 /home/wangyi/code），非 README 的 rk3568 build.sh；单测产物为 ARM 可执行，运行需上机。
