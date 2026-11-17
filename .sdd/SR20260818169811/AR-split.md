# AR 拆分决策

## 拆分结论

免拆分：本 SR 以整体范围进入 module-boundary-design。

## 拆分理由

- 改动面小且高度集中：单一数据结构 `AuthEvent` 扩展（isDegraded 布尔字段 + 序列化尾部追加）+ SA 侧两个构造点打标（NotifyDegradedClient 置 true / PushEventsToClients 保持 false）+ 一个测试文件同步更新，无并行开发诉求。
- 模块链路单一：data_collect（SA 3524）与 libsg_collect_sdk 两处小改属同一 IPC 载荷契约的自然两端，拆开会导致序列化两侧契约需跨 AR 对齐，反而增加协调成本。
- SR-design.md 门禁已通过（结论：通过，无 P0/P1），SR 级契约完整，整体范围可支撑模块边界设计与后续详测。

## 确认来源

用户于 2026-11-16 在 ar-split 工作单中选择「免拆分，整体进入」，模式 `no_split`。
