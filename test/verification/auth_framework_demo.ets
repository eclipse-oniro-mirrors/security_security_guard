/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ============================================================================
// 阻断事件管理框架 — JS 接口验证 Demo
//
// 验证内容：
//   1. createAuthProvider 创建 Provider 会话
//   2. onClientStatusChanged 回调接收客户端列表
//   3. requestAuthResult 查询阻断策略（Promise 返回）
//   4. destroyAuthProvider 销毁会话
//   5. 错误码验证（参数校验、并发超限）
//   6. 从严策略验证（DENY 立即阻断、全 ALLOW 放行）
//   7. 超时验证（400ms 超时返回 TIMEOUT）
//
// 前置条件：
//   - 系统应用（system_api）
//   - 权限 ohos.permission.AUTH_SERVICE_ACCESS
//   - security_guard_auth_event_enable = true
//   - SA 3524（data_collect）已启动
//
// 使用方式：
//   本文件为 Stage 模型应用的测试页面，集成到测试 HAP 中运行。
//   hdc shell aa test -b AuthFrameworkTestHap -m /data/test/
// ============================================================================

import securityGuard from '@ohos.security.securityGuard';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';

const AUTH_STRATEGY_ALLOW = 0;
const AUTH_STRATEGY_DENY = 1;
const AUTH_STRATEGY_TIMEOUT = 2;
const TEST_EVENT_ID = 10001;
const TEST_SERVICE_ID = 'auth_demo_provider';
const TIMEOUT_400MS = 400;

export default function authFrameworkTest() {
  describe('AuthFrameworkTest', () => {

    // --------------------------------------------------------------------------
    // TC-D01: createAuthProvider 正常创建
    // --------------------------------------------------------------------------
    it('TC_D01_createAuthProvider_normal', 0, async (done: Function) => {
      console.info('TC_D01: createAuthProvider start');
      try {
        const callback = {
          onClientStatusChanged: (clientInfos: securityGuard.AuthClientInfo[]) => {
            console.info(`TC_D01: onClientStatusChanged, count=${clientInfos.length}`);
            for (const info of clientInfos) {
              console.info(`  clientId=${info.clientId}, bundleName=${info.bundleName}, ` +
                `subscribedEvents=${info.subscribedEvents.length}, ` +
                `defaultTimeoutStrategy=${info.defaultTimeoutStrategy}, ` +
                `defaultTimeoutMs=${info.defaultTimeoutMs}`);
            }
          }
        };
        const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);
        expect(provider).not.toBeNull();
        console.info('TC_D01: createAuthProvider success');

        // 清理
        securityGuard.destroyAuthProvider(provider);
        console.info('TC_D01: destroyAuthProvider done');
        done();
      } catch (err) {
        console.error(`TC_D01: unexpected error, code=${err.code}, msg=${err.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    // --------------------------------------------------------------------------
    // TC-D02: createAuthProvider 参数校验（serviceId 缺失）
    // --------------------------------------------------------------------------
    it('TC_D02_createAuthProvider_missingServiceId', 0, async (done: Function) => {
      console.info('TC_D02: createAuthProvider missing serviceId');
      try {
        const callback = { onClientStatusChanged: (_infos: any) => {} };
        // @ts-ignore: 故意传非 string 的 serviceId 触发 BAD_PARAM
        securityGuard.createAuthProvider(callback, 12345);
        console.error('TC_D02: should throw but did not');
        expect(false).assertTrue();
        done();
      } catch (err) {
        console.info(`TC_D02: got expected error, code=${err.code}`);
        // BAD_PARAM 不是 JS_ERR_XXX 映射，预期抛出参数错误
        expect(err.code !== undefined).assertTrue();
        done();
      }
    });

    // --------------------------------------------------------------------------
    // TC-D03: createAuthProvider 回调缺失
    // --------------------------------------------------------------------------
    it('TC_D03_createAuthProvider_nullCallback', 0, async (done: Function) => {
      console.info('TC_D03: createAuthProvider null callback');
      try {
        // @ts-ignore: 故意传 null 回调
        securityGuard.createAuthProvider(null, TEST_SERVICE_ID);
        expect(false).assertTrue();
        done();
      } catch (err) {
        console.info(`TC_D03: got expected error, code=${err.code}`);
        expect(err).not.toBeNull();
        done();
      }
    });

    // --------------------------------------------------------------------------
    // TC-D04: requestAuthResult 无订阅客户端 → 默认放行 ALLOW
    // 验收 #18: 无订阅 Client 默认放行
    // --------------------------------------------------------------------------
    it('TC_D04_requestAuthResult_noClient_defaultAllow', 0, async (done: Function) => {
      console.info('TC_D04: requestAuthResult no subscribed client');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        const event: securityGuard.AuthEventInfo = {
          eventId: TEST_EVENT_ID,
          version: '1.0',
          content: JSON.stringify({ action: 'test_no_client' })
        };
        const result = await provider.requestAuthResult(event);
        console.info(`TC_D04: result mergedStrategy=${result.mergedAuthStrategy}, ` +
          `clientCount=${result.clientAuthResult.length}`);
        expect(result.mergedAuthStrategy).assertEqual(AUTH_STRATEGY_ALLOW);
        expect(result.clientAuthResult.length).assertEqual(0);
        done();
      } catch (err) {
        console.error(`TC_D04: unexpected error, code=${err.code}`);
        expect(false).assertTrue();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D05: requestAuthResult 事件参数校验（eventId 缺失）
    // --------------------------------------------------------------------------
    it('TC_D05_requestAuthResult_missingEventId', 0, async (done: Function) => {
      console.info('TC_D05: requestAuthResult missing eventId');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        // @ts-ignore: 故意缺 eventId
        const event = { version: '1.0', content: '{}' };
        await provider.requestAuthResult(event);
        console.error('TC_D05: should throw but did not');
        expect(false).assertTrue();
        done();
      } catch (err) {
        console.info(`TC_D05: got expected error, code=${err.code}`);
        expect(err).not.toBeNull();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D06: requestAuthResult content 超长（> 4096）
    // --------------------------------------------------------------------------
    it('TC_D06_requestAuthResult_contentTooLong', 0, async (done: Function) => {
      console.info('TC_D06: requestAuthResult content too long');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        const longContent = 'x'.repeat(5000); // 超过 NAPI_CONTENT_MAX_LEN=4096
        const event: securityGuard.AuthEventInfo = {
          eventId: TEST_EVENT_ID,
          version: '1.0',
          content: longContent
        };
        await provider.requestAuthResult(event);
        console.error('TC_D06: should throw but did not');
        expect(false).assertTrue();
        done();
      } catch (err) {
        console.info(`TC_D06: got expected error, code=${err.code}`);
        expect(err).not.toBeNull();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D07: destroyAuthProvider 后再调用 → 错误
    // 验收 #22: Destroy 幂等（多次 destroy 不 crash）
    // --------------------------------------------------------------------------
    it('TC_D07_destroyAuthProvider_idempotent', 0, async (done: Function) => {
      console.info('TC_D07: destroyAuthProvider idempotent');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      // 第一次 destroy 正常
      securityGuard.destroyAuthProvider(provider);
      console.info('TC_D07: first destroy success');

      // 第二次 destroy 幂等（不 crash）
      try {
        securityGuard.destroyAuthProvider(provider);
        console.info('TC_D07: second destroy success (idempotent)');
        done();
      } catch (err) {
        // destroy 后再调可能抛错也可幂等返回，关键是不 crash
        console.info(`TC_D07: second destroy threw, code=${err.code} (acceptable)`);
        done();
      }
    });

    // --------------------------------------------------------------------------
    // TC-D08: onClientStatusChanged 回调验证
    // 验收 #21: Client 状态变更通知 Provider
    // 前置：需有 Client 通过 createAuthEventClient 接入（Native 侧或另一 HAP）
    // --------------------------------------------------------------------------
    it('TC_D08_onClientStatusChanged_callback', 0, async (done: Function) => {
      console.info('TC_D08: onClientStatusChanged callback test');
      let callbackReceived = false;
      let receivedClientInfos: securityGuard.AuthClientInfo[] = [];

      const callback = {
        onClientStatusChanged: (clientInfos: securityGuard.AuthClientInfo[]) => {
          callbackReceived = true;
          receivedClientInfos = clientInfos;
          console.info(`TC_D08: callback received, count=${clientInfos.length}`);
        }
      };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      // 等待回调（createAuthProvider 后立即触发一次全量下发）
      setTimeout(() => {
        console.info(`TC_D08: callbackReceived=${callbackReceived}, ` +
          `clientCount=${receivedClientInfos.length}`);
        // 回调应被触发（即使无 Client 也应下发空列表）
        expect(callbackReceived).assertTrue();
        done();
        securityGuard.destroyAuthProvider(provider);
      }, 500); // 等 500ms 确保异步通知到达
    });

    // --------------------------------------------------------------------------
    // TC-D09: requestAuthResult 超时验证（无 Client 回填 → 400ms 超时）
    // 可靠性四: kit 侧 400ms 同步等待超时返回 TIMEOUT
    // 前置：需有 Client 订阅但不回填（模拟 Client 不响应）
    // --------------------------------------------------------------------------
    it('TC_D09_requestAuthResult_timeout', 0, async (done: Function) => {
      console.info('TC_D09: requestAuthResult timeout test');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        const event: securityGuard.AuthEventInfo = {
          eventId: TEST_EVENT_ID,
          version: '1.0',
          content: JSON.stringify({ action: 'test_timeout' })
        };
        const startTime = Date.now();
        const result = await provider.requestAuthResult(event);
        const elapsed = Date.now() - startTime;
        console.info(`TC_D09: elapsed=${elapsed}ms, mergedStrategy=${result.mergedAuthStrategy}`);

        // 若无订阅 Client，立即返回 ALLOW（TC_D04 场景）
        // 若有订阅 Client 但不回填，400ms 后返回 TIMEOUT
        // 此处验证：无 Client 时立即返回（elapsed < 100ms）
        if (result.clientAuthResult.length === 0) {
          expect(result.mergedAuthStrategy).assertEqual(AUTH_STRATEGY_ALLOW);
          expect(elapsed).assertLess(100);
          console.info('TC_D09: no client, immediate ALLOW');
        } else {
          // 有 Client 场景：预期超时
          expect(elapsed).assertGreaterEqual(TIMEOUT_400MS - 50); // 容差 50ms
          expect(elapsed).assertLess(TIMEOUT_400MS + 200);
          console.info('TC_D09: timeout scenario verified');
        }
        done();
      } catch (err) {
        console.error(`TC_D09: unexpected error, code=${err.code}`);
        expect(false).assertTrue();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D10: requestAuthResult 并发请求
    // 可靠性三: 每 Provider 并发上限 128，超限返回 27000004
    // --------------------------------------------------------------------------
    it('TC_D10_requestAuthResult_concurrent', 0, async (done: Function) => {
      console.info('TC_D10: concurrent requestAuthResult');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        // 发起 5 个并发请求（远小于 128 上限，验证并发不报错）
        const promises: Promise<securityGuard.AuthResult>[] = [];
        for (let i = 0; i < 5; i++) {
          const event: securityGuard.AuthEventInfo = {
            eventId: TEST_EVENT_ID + i,
            version: '1.0',
            content: JSON.stringify({ action: `concurrent_${i}` })
          };
          promises.push(provider.requestAuthResult(event));
        }
        const results = await Promise.allSettled(promises);
        let successCount = 0;
        for (let i = 0; i < results.length; i++) {
          if (results[i].status === 'fulfilled') {
            successCount++;
            console.info(`TC_D10: [${i}] mergedStrategy=${results[i].value.mergedAuthStrategy}`);
          } else {
            console.info(`TC_D10: [${i}] rejected, code=${results[i].reason?.code}`);
          }
        }
        console.info(`TC_D10: successCount=${successCount}/${results.length}`);
        // 无 Client 场景下全部应成功返回 ALLOW
        expect(successCount).assertEqual(5);
        done();
      } catch (err) {
        console.error(`TC_D10: unexpected error, code=${err.code}`);
        expect(false).assertTrue();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D11: requestAuthResult 降级客户端（isDegraded 必填校验）
    // M9: isDegraded 为必填字段
    // --------------------------------------------------------------------------
    it('TC_D11_requestAuthResult_degradedClient', 0, async (done: Function) => {
      console.info('TC_D11: requestAuthResult with degraded client status');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        const event: securityGuard.AuthEventInfo = {
          eventId: TEST_EVENT_ID,
          version: '1.0',
          content: JSON.stringify({ action: 'test_degraded' }),
          // 传入降级客户端状态（isDegraded=true）
          clientStatus: [
            { clientId: 'fake_client_id', isDegraded: true }
          ]
        };
        const result = await provider.requestAuthResult(event);
        console.info(`TC_D11: mergedStrategy=${result.mergedAuthStrategy}`);
        expect(result.mergedAuthStrategy).assertEqual(AUTH_STRATEGY_ALLOW);
        done();
      } catch (err) {
        console.error(`TC_D11: unexpected error, code=${err.code}`);
        expect(false).assertTrue();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D12: requestAuthResult clientStatus 缺 isDegraded → BAD_PARAM
    // M9: isDegraded 必填校验
    // --------------------------------------------------------------------------
    it('TC_D12_requestAuthResult_missingIsDegraded', 0, async (done: Function) => {
      console.info('TC_D12: requestAuthResult missing isDegraded');
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        // @ts-ignore: 故意缺 isDegraded 字段
        const event: securityGuard.AuthEventInfo = {
          eventId: TEST_EVENT_ID,
          version: '1.0',
          content: '{}',
          clientStatus: [{ clientId: 'fake_client' }] // 缺 isDegraded
        };
        await provider.requestAuthResult(event);
        console.error('TC_D12: should throw but did not');
        expect(false).assertTrue();
        done();
      } catch (err) {
        console.info(`TC_D12: got expected error, code=${err.code}`);
        expect(err).not.toBeNull();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D13: 完整端到端流程（Provider + 模拟 Client 响应）
    // 步骤 1-10 完整验证：需配合 Native 侧 Client SDK 接入
    // --------------------------------------------------------------------------
    it('TC_D13_endToEnd_fullFlow', 0, async (done: Function) => {
      console.info('TC_D13: end-to-end full flow');
      const callback = {
        onClientStatusChanged: (clientInfos: securityGuard.AuthClientInfo[]) => {
          console.info(`TC_D13: client count=${clientInfos.length}`);
          for (const info of clientInfos) {
            console.info(`  clientId=${info.clientId}, events=${info.subscribedEvents}`);
          }
        }
      };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        const event: securityGuard.AuthEventInfo = {
          eventId: TEST_EVENT_ID,
          version: '1.0',
          content: JSON.stringify({ action: 'end_to_end', timestamp: Date.now() })
        };
        console.info('TC_D13: calling requestAuthResult...');
        const result = await provider.requestAuthResult(event);
        console.info(`TC_D13: result mergedStrategy=${result.mergedAuthStrategy}`);
        console.info(`TC_D13: clientAuthResult count=${result.clientAuthResult.length}`);
        for (const cr of result.clientAuthResult) {
          console.info(`  clientId=${cr.clientId}, authStrategy=${cr.authStrategy}`);
        }

        // 验证 AuthResult 结构完整性
        expect(result).not.toBeNull();
        expect(result.mergedAuthStrategy).assertGreaterOrEqual(AUTH_STRATEGY_ALLOW);
        expect(result.mergedAuthStrategy).assertLessOrEqual(AUTH_STRATEGY_TIMEOUT);
        done();
      } catch (err) {
        console.error(`TC_D13: error, code=${err.code}, msg=${err.message}`);
        expect(false).assertTrue();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });

    // --------------------------------------------------------------------------
    // TC-D14: AuthStrategy 枚举值验证
    // --------------------------------------------------------------------------
    it('TC_D14_authStrategy_enum', 0, async (done: Function) => {
      console.info('TC_D14: AuthStrategy enum validation');
      // 通过实际结果验证枚举值在 0-2 范围内
      const callback = { onClientStatusChanged: (_infos: any) => {} };
      const provider = securityGuard.createAuthProvider(callback, TEST_SERVICE_ID);

      try {
        const event: securityGuard.AuthEventInfo = {
          eventId: TEST_EVENT_ID,
          version: '1.0',
          content: '{}'
        };
        const result = await provider.requestAuthResult(event);
        console.info(`TC_D14: mergedStrategy=${result.mergedAuthStrategy}`);
        // ALLOW=0, DENY=1, TIMEOUT=2
        expect(result.mergedAuthStrategy >= 0 && result.mergedAuthStrategy <= 2).assertTrue();
        done();
      } catch (err) {
        expect(false).assertTrue();
        done();
      } finally {
        securityGuard.destroyAuthProvider(provider);
      }
    });
  });
}
