# 索引文件

> **使用指南**
> - 记录当前代码仓关键文件路径
> - 当新增文档时，需要刷新该目录

---
## 关键文件目录

| 文档名称 | 文档描述 | 文档路径 | 何时使用 |
|--------|---------|-------|------|
|software_architecture.md|组件软件实现设计|./.sdd/software_architecture.md|编码、review、US设计 |
|spec.md |编码规范|./.sdd/spec.md|编码、review|
|AICodingGuidelines.md（可选）|团队 AI 编码约定；其中可包含 task-dev 语义 Review 扩展章节|./.sdd/AICodingGuidelines.md|task-dev 只读取 `## task-dev 语义 Review 扩展规则`；其他章节按各自用途使用|

## 项目概览

- **组件**：`@ohos/security_guard`（security 子系统，SystemCapability.Security.SecurityGuard），设备风险管理平台（SG）
- **语言与框架**：C++（对外 C 接口 extern "C"、JS/NAPI）；OHOS IPC（IDL 生成 proxy/stub）、ffrt 并发、HiSysEvent 打点、sqlite/preferences 存储
- **构建**：GN + Ninja（`ohos_shared_library`/`ohos_unittest`/`ohos_fuzztest`），无独立可执行 bin，SA 由 sa_main 拉起
- **结构**：多模块单仓（非 workspace monorepo）：`services/`（6 个子服务，含 3 个 SA）、`frameworks/`（3 个 inner_kits SDK + JS/NAPI）、`interfaces/inner_api/`（对外头文件）、`oem_property/`（预置配置）、`test/`（unittest + fuzztest）
- **编译开关**：集中在根目录 `security_guard.gni`（如 `security_guard_auth_event_enable` 默认 false）；开启设备构建用 `--gn-args` 传 feature

## 构建 & 测试命令

### 构建

构建需在完整 OpenHarmony 构建环境（源码根目录）内执行：

```bash
# 全量构建组件（在源码根目录）
./build.sh --product-name <product> --build-target security_guard

# 常用 gn args（通过 --gn-args 传入）
# security_guard_enable=true security_guard_auth_event_enable=true
```

### 测试

TDD 单测与 fuzz 在源码根目录触发（本仓无独立可跑的测试脚本）：

```bash
# 单测（gtest，test/unittest/*）
./build.sh --product-name <product> --build-target SecurityCollectorTest --gn args...
# fuzz（test/fuzztest/*，ohos_fuzztest 目标，如 SecurityCollectorManagerServiceFuzzer）
./build.sh --product-name <product> --build-target SecurityCollectorManagerServiceFuzzer
```

注意：`test/unittest/security_collector` 使用 stub 头文件目录（include/ 下为桩实现），不代表现网行为；现网逻辑以 `services/` 为准。

## Code Style

- 4 空格缩进，行宽 120；文件名与类名一致（详见 `./.sdd/spec.md`）
- 命名空间：`OHOS::Security::SecurityGuard` / `OHOS::Security::SecurityCollector`
- 日志宏：`SGLOGD/E/F/I/W`（frameworks/common/log），不要直接调 hilog
- 打点一律走 `services/bigdata`（HiSysEvent）；阻断 HA 打点走 IEventWrapper
- 新 IPC 接口一律用 IDL 工具生成，禁止新增手写 Stub/Proxy
- 单函数 ≤50 行、入参 ≤5 为内部约定；成员禁止未初始化
- 统一 sanitize（integer_overflow/ubsan/boundary/cfi）+ version_script 控制符号导出，导出新符号需改对应 `.map` 文件
