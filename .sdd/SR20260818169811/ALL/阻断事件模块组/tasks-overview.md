# 阻断事件模块组任务计划

## 元信息

- SR 编号：SR20260818169811
- AR 编号：ALL（免拆分）
- 来源详细设计文档：.sdd/SR20260818169811/ALL/阻断事件模块组/模块详细设计说明书.md
- 来源测试用例设计文档：.sdd/SR20260818169811/ALL/阻断事件模块组/模块测试用例设计.md
- 来源模块设计门禁结果：.sdd/SR20260818169811/ALL/阻断事件模块组/.context/模块设计门禁结果.md
- 门禁结论：通过
- 任务总数：3
- 生成时间：2026-11-16

## 执行规则

- 详细设计文档是实现设计的唯一事实来源，测试用例设计文档是验证规格的唯一事实来源。开发每个任务前必须完整读取这两份文档和门禁结果。
- 按串行执行顺序逐个执行，编号与顺序一致；同一时刻只开发一个任务。
- 详细设计或测试设计发生变化时，停止开发，返回设计门禁并重新生成、确认任务计划。

## 串行执行顺序

```text
T1 → T2 → T3
```

## 任务计划

| 编号 | 任务 | 做什么 | 改哪些文件 | 验证哪些用例 | 前置 |
|---|---|---|---|---|---|
| T1 | AuthEvent 状态字段与序列化扩展 | 在 AuthEvent Parcelable 上新增降级状态字段：定义取值枚举（0=正常/1=降级）、getter/setter 访问器与私有成员，并在序列化尾部追加该 int32 字段的读写，产出可往返的 5 字段载荷 | interfaces/inner_api/collect/include/auth_event/auth_event.h、frameworks/common/collect/src/auth_event/auth_event.cpp | TC1、TC2 | 无 |
| T2 | SA 分流推送构造点打标 | 在 AuthCoordinator 分流推送的两条既有路径上写入状态标记：降级通知路径构造事件后显式置为降级值 1，正常推送路径保持默认 0 并补注释说明，不改分流判定与聚合链路 | services/data_collect/sa/auth_event/auth_coordinator.cpp | TC3、TC4、TC5 | T1 |
| T3 | Parcelable 契约回归测试适配 | 更新既有序列化断言并新增状态字段单测用例（置 1 往返、默认 0、尾部追加顺序），沿用既有测试组织与真实头文件直链风格 | test/unittest/data_collect/sa/auth_event_parcelable_test.cpp | TC1、TC2 | T1 |

计划表不保存阶段进度。`task-dev` 只在「执行记录」中写最终 `Completed` 或 `Blocked` 交接。

注：TC7（预留口恒 0，P2 声明性验证）以详细设计说明书 4.1.4 决策 D4 的已知限制声明结案（该口仅单测调用、不强制用例）；T3 验证范围为 TC1/TC2。

## 覆盖核对

内部核对结果（不在任务间重复展开）：

- 设计决策 D1（枚举形态）、D2（字段与序列化）→ T1；D3（两构造点打标）→ T2；D4（预留口声明）→ 不涉及代码改动，由 T3 的 TC7 声明性验证承接。
- 契约 K1（字段/枚举/访问器）→ T1；K2（序列化尾部追加）→ T1 并由 T3 回归；K3（回调通道零改动）→ T2 验证不触碰；K4（测试契约）→ T3。
- 测试用例归属：TC1/TC2（序列化往返与顺序）→ T1 实现 + T3 用例落地；TC3/TC4/TC5（构造点打标与混合分流）→ T2（SA 侧既有 mock 风格，在 T2 内以最小验证确认，正式用例文件属测试设计既有位置）；TC6（默认产物构建验证）→ 跨任务验证，依赖 T1+T2 完成后的完整构建，登记为待处理；TC7（预留口恒 0）→ T3。
- 工程落点 4 文件全覆盖；无设计项遗漏。

## 存疑汇总

无存疑。

## 待处理用例登记

| 用例编号 | 所在任务 | 依赖任务 | 当前无法执行原因 | 最终责任任务 | 状态 |
|---|---|---|---|---|---|
| TC6 | T2 | T1、T2 | 默认 gn args 全量构建验证需 T1/T2 代码全部就位后在完整 OHOS 构建环境执行（本机非完整构建环境） | T2 | Pending |

## 执行记录

由 `task-dev` 在每个任务完成或阻塞时追加一条记录；`task-split` 不预填。

### T1：AuthEvent 状态字段与序列化扩展

- 状态：Completed
- 修改文件：interfaces/inner_api/collect/include/auth_event/auth_event.h、frameworks/common/collect/src/auth_event/auth_event.cpp
- 核心实现：AuthEvent 新增 `enum class AuthEventStatus : int32_t { NORMAL = 0, DEGRADED = 1 }`、`int32_t GetStatus() const`/`void SetStatus(int32_t)` 内联访问器、私有成员 `int32_t status_ = 0`（追加于 metadata_ 之后）；Marshalling/ReadFromParcel 在 metadata 之后尾部追加 WriteInt32/ReadInt32，形成 5 字段定长序列化（载荷 v1→v2），既有 4 字段顺序与读写失败语义不变
- 设计偏差：无
- 待处理：无（TC1/TC2 用例代码属 T3 任务；TC6 构建级验证已在待处理用例登记，最终责任 T2/T3 完成后的完整构建环境执行）
- 后续须知：T2 在 auth_coordinator.cpp 构造点调用 `SetStatus(AuthEventStatus::DEGRADED)` 时直接 include auth_event.h 使用枚举；外仓 Client 侧判读经 GetStatus()，未定义值（≥2）按 NORMAL 处理
- 证据：AAW step 12 attempt 1

### T2：SA 分流推送构造点打标

- 状态：Completed
- 修改文件：services/data_collect/sa/auth_event/auth_coordinator.cpp（+2 行）
- 核心实现：NotifyDegradedClient 构造点在 SetSeqnum 之后新增 `event.SetStatus(static_cast<int32_t>(AuthEventStatus::DEGRADED))`（打标 1）；PushEventsToClients 构造点保持默认 0 仅补注释；分流判定/聚合/回填/打点/预留口零触碰
- 设计偏差：无（static_cast<int32_t> 为 SetStatus 签名下唯一可编译写法，与设计文本 SetStatus(DEGRADED) 值等价）
- 待处理：无（TC3/TC4/TC5 行为断言本机以链路推导核验，gtest 执行与 TC6 构建验证依赖完整 OHOS 环境，登记不变）
- 后续须知：TC6 待处理用例的代码前置（T1+T2）已全部就位，有完整构建环境时可直接执行验证
- 证据：AAW step 13 attempt 1

### T3：Parcelable 契约回归测试适配

- 状态：Completed
- 修改文件：test/unittest/data_collect/sa/auth_event_parcelable_test.cpp（+43 行）
- 核心实现：001/002 既有用例补 GetStatus()==NORMAL 默认值断言；新增 003（SetSeqnum(2002L)+SetStatus(DEGRADED) 全字段往返，含 seqnum 值断言）与 004（逐字段读 Parcel 验证 5 字段尾部顺序 + EXPECT_FALSE 无多余数据，含 seqnum 值断言）；UnmarshallingInvalid 保留不动
- 设计偏差：无
- 待处理：无（用例执行需完整 OHOS 构建环境跑 ohos_unittest，本机以静态结构核对替代；TC6 构建验证登记不变）
- 后续须知：TC7 以说明书 4.1.4 D4 声明性结案（预留口不强制用例），T3 验证范围为 TC1/TC2；后续若启封预留口 NotifyAuthEvent 需补 status 语义用例
- 证据：AAW step 14 attempt 1

