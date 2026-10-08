# 登录接口应用层混合加密改造设计

## 1. 目标与范围

本改造为 SSO Server 的登录页面与 `/login/submit` 增加应用层混合加密。前端通过 ECDH 与服务端协商一次性会话密钥，再使用 AES-256-GCM 加密账号、密码及登录参数。HTTPS/TLS 仍然保留，用于保护页面、密钥协商请求和服务端公钥来源。

本期只覆盖登录请求，不改变 OAuth/OIDC、Token、Refresh Token 及已登录业务接口协议。

## 2. 密码方案

- 密钥协商：ECDH P-256（浏览器 Web Crypto API 与 Java/JCA 均支持）。
- 密钥派生：HKDF-SHA-256，输出 32 字节 AES 密钥。
- 数据加密：AES-256-GCM。
- GCM nonce：每个请求随机生成 12 字节，同一 AES 密钥下绝不复用。
- 认证标签：16 字节。
- 编码：所有二进制字段使用 Base64URL（无填充）。
- 传输：必须使用 HTTPS；应用层加密不能替代 TLS。

不自行实现密码算法，前端使用 Web Crypto API，后端使用 JCA/Bouncy Castle 等成熟实现。

## 3. 协议流程

```text
浏览器                         SSO Server
   |                                |
   | GET /login/crypto/session      |
   |------------------------------->|
   | sessionId, keyId, serverPubKey |
   |<-------------------------------|
   |                                |
   | 生成 client ECDH 临时密钥对      |
   | ECDH(serverPubKey, clientPriv)  |
   | HKDF 派生 AES-256-GCM 密钥       |
   |                                |
   | POST /login/submit              |
   | clientPubKey + nonce + ciphertext + tag
   |------------------------------->|
   |                                |
   | 服务端取出一次性 serverPrivKey   |
   | ECDH(clientPubKey, serverPriv)  |
   | HKDF 派生同一 AES 密钥           |
   | AES-GCM 校验并解密               |
   | 校验时间戳、requestId、会话状态   |
   | 校验账号密码并建立登录会话        |
   |<-------------------------------|
```

服务端为每个 `sessionId` 生成临时 ECDH 密钥对，私钥只保存短时间（建议 2 分钟），成功使用后立即删除。服务端返回的临时公钥必须通过 HTTPS 获取；客户端不得信任来源不明的公钥。

## 4. 密钥派生

双方计算 ECDH 共享秘密后，使用 HKDF-SHA-256：

```text
salt = SHA-256("sso-login-v1|" + sessionId)
info = "sso-login-aes-256-gcm|" + keyId
aesKey = HKDF(sharedSecret, salt, info, 32)
```

`sessionId`、`keyId`、客户端公钥和服务端公钥必须绑定到本次派生上下文，防止跨会话或跨版本复用密钥。

## 5. 接口定义

### 5.1 获取加密会话

`GET /login/crypto/session`

响应：

```json
{
  "version": "v1",
  "sessionId": "base64url",
  "keyId": "login-ecdh-2026-01",
  "curve": "P-256",
  "serverPublicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "expiresAt": "2026-10-08T12:00:00Z"
}
```

接口不得返回服务端私钥。服务端应限制单 IP 和单设备的会话创建频率。

### 5.2 提交登录

`POST /login/submit`

```json
{
  "version": "v1",
  "sessionId": "base64url",
  "keyId": "login-ecdh-2026-01",
  "clientPublicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "requestId": "base64url-16-bytes",
  "timestamp": 1791460800,
  "nonce": "base64url-12-bytes",
  "ciphertext": "base64url",
  "tag": "base64url-16-bytes"
}
```

明文载荷只在内存中存在，不写入日志：

```json
{
  "username": "user@example.com",
  "password": "...",
  "rememberMe": false
}
```

AES-GCM 的 AAD 使用固定顺序的字符串，避免 JSON 字段顺序差异：

```text
v1|sessionId|keyId|requestId|timestamp|clientPublicKeyCanonical
```

服务端解密前必须校验字段格式、长度、版本、`keyId` 和时间戳；解密失败统一返回通用登录失败，不泄露具体原因。

## 6. 防重放与状态管理

- `sessionId` 只能成功使用一次，服务端使用 Redis 原子消费。
- `requestId` 为 16 字节随机值，在短 TTL 内唯一；重复请求直接拒绝。
- `timestamp` 与服务端时间偏差建议不超过 300 秒。
- 加密会话 TTL 建议 2 分钟，解密成功、失败或超时后删除。
- 集群部署时，临时私钥和已消费标记必须存储在共享 Redis，而不能只存本机内存。
- 登录接口继续保留限流、失败计数、账号锁定和 MFA 流程。

## 7. 服务端处理顺序

1. 校验 HTTPS、请求大小和 Content-Type。
2. 校验 `version`、`keyId`、字段长度及 Base64URL 格式。
3. 原子读取并消费 `sessionId`，拒绝不存在、过期或已消费会话。
4. 校验时间戳和 `requestId`。
5. 使用服务端临时私钥与客户端公钥执行 ECDH。
6. 使用相同上下文执行 HKDF，得到 AES-256-GCM 密钥。
7. 使用 nonce、AAD、ciphertext 和 tag 解密并认证。
8. 执行现有账号密码校验、MFA 和会话创建流程。
9. 成功后通过安全 Cookie 建立登录态，不将密码或明文载荷写入日志。

## 8. 错误与兼容

错误响应统一使用通用错误码，例如 `LOGIN_REQUEST_INVALID`、`LOGIN_EXPIRED`、`LOGIN_FAILED`，不得区分“用户不存在”“密码错误”“Tag 错误”等可用于探测的信息。

建议增加配置开关 `sso.login.app-encryption.enabled`。灰度期间可以同时保留旧登录协议，但服务端应记录协议版本和失败原因分类；稳定后关闭明文登录分支。无论开关状态，生产环境都必须强制 HTTPS。

## 9. 安全边界

应用层加密主要保护请求在业务网关、代理或中间服务之间的机密性和完整性。它不能防止被篡改的登录页面或 XSS 在加密前读取密码，因此仍需启用 CSP、XSS 防护、依赖锁定、HTTPS、Secure/HttpOnly/SameSite Cookie、CSRF 防护和登录限流。

## 10. 实施步骤

1. 增加加密会话存储模型及 Redis 原子消费能力。
2. 实现服务端 ECDH 临时密钥生成、HKDF 派生和 AES-GCM 解密组件。
3. 增加 `/login/crypto/session` 和加密版 `/login/submit`。
4. 在登录前端使用 Web Crypto API 实现密钥协商、加密和请求封装。
5. 增加协议版本、密钥轮换、超时、重放和错误场景测试。
6. 灰度发布并观察成功率、解密失败率、过期率和重放拒绝数。
7. 完成迁移后移除明文请求分支。
