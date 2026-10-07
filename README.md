# SSO 认证中心

基于 Java 17、Spring Boot 3.5 和 Spring Authorization Server 的 OAuth 2.0 / OpenID Connect 单点登录认证中心。仓库包含认证服务、RP 接入 SDK、示例应用、资源服务示例和运维 CLI。

## 模块

| 模块 | 用途 |
| --- | --- |
| `sso-server` | SSO HTTP/OIDC 服务及 Dubbo 身份、会话和令牌校验服务；MySQL 保存权威数据，Redis 保存分布式限流状态。 |
| `sso-contracts` | Dubbo 服务接口和版本化数据契约。 |
| `sso-admin` | 运维 CLI；通过 JDBC 管理用户和 OAuth 客户端，不启动 HTTP、Dubbo 或 Nacos 服务。 |
| `sso-client-core` | 与 Spring 无关的客户端协议、PKCE、会话逻辑。 |
| `sso-client-spring-boot-starter` | RP 应用接入 Starter，包含回调、Cookie、Redis 存储和本地单实例存储。 |
| `sso-example-rp` | 标准 Spring Security OAuth2 Login 示例；`sso-sdk` Profile 展示自有 SDK 接入。 |
| `sso-resource-example` | 通过 Dubbo 校验不透明 Access Token 的资源服务示例。 |

## 快速启动（本机开发）

要求 Java 17+、Maven 3.9+ 和 Docker Compose。以下配置仅用于本地开发：Compose 中 Nacos 未启用认证或 TLS，密钥也不是生产密钥。

```powershell
docker compose up -d
$env:SSO_COOKIE_SECURE = 'false' # 仅本机 HTTP 开发
$env:SSO_SESSION_HMAC_KEY = 'local-development-only-change-this-key-before-use'
mvn -pl sso-server -am spring-boot:run
```

认证中心默认监听 `8080`，管理端点监听 `127.0.0.1:8081`。数据库首次启动时由 Flyway 执行迁移；迁移只建表，不创建业务用户或 OAuth 客户端。使用 `sso-admin` 创建账号和客户端，具体命令见[部署指南](docs/部署指南.md)。

## 文档

- [RP / SDK 接入指南](docs/接入指南.md)：注册客户端、依赖、配置、安全过滤链和 SDK 示例。
- [部署指南](docs/部署指南.md)：本地依赖、生产部署前置条件、密钥、数据库迁移、用户与客户端管理、健康检查。
- [SDK 原始配置与迁移说明](docs/specs/012-sso-client-sdk/usage.md)
- [认证中心设计文档](docs/sso-development-design.md)
- [功能规格与运维说明](docs/specs)

## 主要端点

| 端点 | 说明 |
| --- | --- |
| `/login`、`POST /login/submit` | SSO 登录页面和凭据提交。 |
| `/oauth2/authorize`、`/oauth2/token` | OAuth 2.0 授权码与令牌端点。 |
| `/.well-known/openid-configuration`、`/oauth2/jwks` | OIDC Discovery 和签名公钥。 |
| `/userinfo`、`/oauth2/revoke` | OIDC UserInfo 和令牌撤销。 |
| `/session`、`POST /logout` | TGC 会话查询和退出；退出请求要求 CSRF。 |
| `http://127.0.0.1:8081/actuator/health` | 管理端口健康检查。管理端口默认只绑定回环地址。 |

授权码流程要求已登记的精确 Redirect URI、`state`、`nonce` 和 PKCE S256。Access Token 为不透明令牌；RP 不应自行解析或记录令牌。资源服务通过 `TokenIntrospectionService` Dubbo 契约向认证中心校验令牌，并在 RPC 不可用时拒绝访问。

## 测试状态

SDK 单元测试此前已运行：Core 36 项、Starter 22 项通过。`sso-server` Maven package 已成功；服务启动冒烟测试因本机 MySQL 拒绝默认 `sso` 凭据而未能完成。服务器模块没有自动化测试源码；需要可用的 MySQL、Redis、Nacos 和证书配置后才能验证真实部署及端到端登录。详见[部署指南](docs/部署指南.md)中的验证范围。

## 安全提示

生产部署必须使用 TLS、外部密钥管理、MySQL `sslMode=VERIFY_IDENTITY`、Redis TLS、Dubbo Triple 双向 TLS 和启用 TLS/证书校验的 Nacos。不要复用 Compose 凭据或本地默认密钥，不要把客户端密钥、令牌、密码或回调查询参数写入日志。生产参数与轮换步骤见[部署指南](docs/部署指南.md)。
