# 公司统一身份认证中心（SSO）服务端开发设计文档

> 版本：1.0
> 状态：开发基线
> 适用范围：公司内部 Web 应用、后端服务、统一认证服务
> 目标：开发公司自己的统一认证中心服务端，基于 OAuth 2.0 Authorization Code + PKCE 与 OpenID Connect，为旗下应用提供统一认证、TGC 单点登录、授权码和令牌签发、刷新、撤销及全局退出。本文以认证中心本身的实现为主体；应用后端的 Cookie、Redis 用户映射和 SDK 行为只作为协议边界/接入契约描述，不代表它们都属于认证中心代码库。


# 提示词

```


我现在需要你帮我写一个SSO登录系统，我来给你描述一下架构和流程吧，当用户访问我们这个公司的某个应用或者软件的时候，肯定不能频繁的登录认证吧，那么，我来给你描述一下我的SSO架构，首先用户通过浏览器输入公司旗下的某个网站，后端服务器中的服务中写的拦截器或者SDK发现这次请求没有有效的accesstoken，会生成随机state，nounce，code_verifier,code_challenge并且返回,也会返回client_id,redirect_uri这些东西，浏览器前端收到之后会重定向发请求到SSO认证服务上，这个SSO认证服务会先校验client_id,redirect_uri,保存state，challenge，并且校验这个TGC cookie是否存在并且有效，有效的话直接生成code返回给前端，前端通过code加callback接口调用后端服务，后端通过code_verifier和code去换取accesstoken和这个refreshtoken以及ID token，保存下来之后会把client_id_accesstoken作为cookie键，accesstoken作为值返回回去，写入到cookie当中。如果说不存在的话会重定向到登陆界面，登陆界面进行登录认证，确认是否有这么一个人，还会进行MFA二次认证，但是这个可以放到后期再进行开发，认证成功之后创建TGC，签发code，刷写TGC的cookie到浏览器并且返回code，然后就是熟悉的前端调后端，后端调认证系统的过程了，记得PCKE防范code被滥用，返回给后端的同样是accesstoken，refreshtoken以及ID token，这个ID token可以用来帮助获取用户的id等关键信息，后端通过一系列校验认为这个ID token是正确的，没有过期的，提取出里面的信息，可以放入到redis当中作为accesstoken和用户信息的映射，这样子调用其他什么接口都可以拥有这个用户id之类的关键信息了。。。。。accesstoken如果过期了的话，需要调用refreshtoken来重新刷新，如果refreshtoken也过期的话，就只能重新触发SSO认证了，由于accesstoken和这个用户信息是对应的，如果accesstoken过期的话，那么用户信息也会随之从redis消失，同样需要SSO认证，所以存在redis当中就可以了，退出登陆的话就让前端删除cookie，后端删除accesstoken，refreshtoken，并且写入到redis当中充当黑名单。登录认证系统也应该删除TGC相关的信息才行。。。你懂我的这个架构吗现在这个系统是我说的架构吗



```




# 二期提示词

```

我现在想做一个SSO单点登陆系统，我给你说一下我的架构啊，前端访问后端的时候，后端拦截提取accesstoken，不存在或者无效的话，就进行SSO，生成code_verifier,nounce之类的，返回认证中心的地址+/oauth/oauthrize+client_id,redorect_url+nounce等等，然后前端get调用，认证中心验证，如果存在TGT的cookie，直接颁发at，rt ，ID token，不存在的话，跳转到登录页面，输入认证完之后返回code，state，并且给浏览器写入TGT cookie，自己存对应的TGC票据，然后前端调用后端的callback接口，后端调用oauth/token用code兑换token，当然要用PCKE保证这个code被黑客重复使用，返回之后后端自行处理并且保存rt和id token，然后把at写入到浏览器的cookie当中，之后每次请求都要带着个at cookie才能通过校验，访问后端接口资源。然后关于这几个token双方的处理，我先说一下吧，认证中心那里是只负责rt的，sso登陆的时候创建rt，插入到新的家族当中，后续需轮换的时候，校验这个旧的rt是否被使用，是否存在，家族是否被撤销，是否过期，全部通过才能轮换新的并且标记旧的，不通过返回400让客户端处理，家族过期时间是绝对的，轮换是每次都换成新的。然后后端那里就负责处理，at，rt，id token，我想的是以at为键值的一部分，然后rt，id token提取出来的信息，at逻辑过期时间组成的对象为值，设置比rt过期时间稍微长一点的物理过期时间，键值和at不存在，无效就去sso登录，过期的话就去更换，rt过期的话也去sso登录，过期了被物理删除的话那也去sso登录，在的话去调用接口刷新，那边刷新成功的话删除旧映射，建立新映射，返回新cookie，返回400的话删除旧映射，页面请求就去sso登录，api的话返回给前端401，前端自动执行sso单点登录，然后回到那个页面重新调接口。这个逻辑是完全闭环的，没有风险的。

```




## 1. 目标与边界

用户访问公司任一已接入应用时，应用检查自己的本地登录状态。未登录时，浏览器被引导至统一认证服务（下称 SSO/认证中心）。如果浏览器已经持有有效的认证中心登录会话（TGC），认证中心无需再次询问密码，直接为该应用签发短时授权码；否则用户登录，认证中心建立 TGC 后签发授权码。应用后端使用授权码和 PKCE `code_verifier` 换取令牌，验证身份令牌（ID Token），提取用户标识和必要声明，并建立应用本地会话。

认证中心负责：客户端注册校验、认证页面与账号验证、TGC 生命周期、授权请求校验、授权码签发与兑换、PKCE 校验、Access Token/Refresh Token/ID Token 签发、Refresh Token 轮换与撤销、OIDC Discovery/JWKS、认证中心全局退出、审计和运维。应用后端负责：保存 `state`/`nonce`/`code_verifier` 登录事务、处理 callback、在后端兑换令牌、校验 ID Token 并提取用户信息、维护 `{client_id}_access_token` Cookie 及应用侧 Redis 映射、使用 Refresh Token 续期，以及单应用退出。认证中心提供接口和协议约束，应用侧功能可由各应用自行实现或另做独立 SDK。

本期不实现 MFA、社交登录、账号注册/找回、复杂组织权限管理、移动端原生授权、SAML 联邦或多租户隔离；接口预留扩展点。MFA 可在密码校验成功后、创建 TGC 和签发授权码前增加。

## 2. 名词与职责

| 名词 | 含义与职责 |
|---|---|
| SSO / 认证中心 | 验证用户身份，维护中心登录会话，签发授权码和令牌，提供退出、撤销及密钥发现能力。 |
| Client / 应用 | 已注册的公司应用。推荐由后端作为 OAuth confidential client 发起授权并兑换令牌。 |
| `client_id` | 客户端公开标识，不是密码。每个环境/应用应有独立登记项。 |
| `redirect_uri` | 授权完成后浏览器返回的预登记精确回调地址。 |
| TGC | 认证中心浏览器会话 Cookie。Cookie 中仅放不可预测的随机会话句柄；认证状态、用户及过期信息保存在服务端。 |
| `state` | 应用生成的一次性请求关联值，抵御登录 CSRF，并关联应用侧待完成登录事务。 |
| `nonce` | 应用生成的一次性值，绑定 ID Token 与原始认证请求，验证 ID Token 时必须匹配。 |
| `code_verifier` | 应用后端生成并保密保存的 PKCE 随机秘密。只能发给令牌端点，绝不能经浏览器或日志暴露。 |
| `code_challenge` | 从 verifier 通过 SHA-256 与 Base64URL 无填充计算出的公开值，随授权请求发送。仅接受 `S256`。 |
| Authorization Code | 一次性、短有效期、绑定客户端、回调地址和 PKCE challenge 的随机授权凭证。不是令牌。 |
| Access Token | 访问受保护 API 的短时凭证。可采用 JWT 或不透明令牌；本设计建议不透明令牌以便中心撤销。 |
| Refresh Token | 仅供客户端后端向令牌端点续期的长期凭证，应轮换并可撤销。不得给浏览器脚本使用。 |
| ID Token | OIDC 身份断言。仅在令牌兑换响应中供应用后端校验、提取声明；验证后提取必要用户信息存入 Redis，并丢弃 ID Token。 |
| 应用会话 | 某一应用自己的登录态。本架构以按 `client_id` 区分的 Access Token Cookie 和 Redis 中的令牌到用户信息映射支撑应用请求。 |

## 3. 总体组件

1. **公司应用（OAuth/OIDC Client）**：检查本应用状态，发起授权跳转，保存登录事务，处理回调，在后端兑换令牌并校验 ID Token，维护本应用 Cookie 和用户映射。这是认证中心的调用方，不属于认证中心核心服务。
2. **浏览器**：在应用与认证中心之间跟随顶层重定向；不持有 verifier、Refresh Token 或客户端密钥。按当前接入约定，浏览器分别持有应用设置的 Access Token Cookie 和认证中心设置的 TGC Cookie。
3. **认证中心 Web 层**：处理 `/authorize`、登录页面、认证挑战、TGC Cookie 和认证中心全局退出。
4. **认证服务**：认证中心校验账号凭证；本期可接公司用户目录/账号库，MFA 作为后续认证步骤。
5. **授权服务（认证中心核心）**：校验客户端、精确回调地址、state/challenge 参数；签发和消费授权码；签发及轮换令牌。
6. **认证中心令牌与会话存储**：持久化认证中心的用户/客户端/授权码/TGC/令牌和撤销状态。Access Token 到用户信息的 Redis 映射属于接入应用自己的存储责任，不由认证中心代管。必须依据数据恢复和一致性要求选择 Redis 持久化及主存储。
7. **密钥服务**：生成、保护和轮换令牌签名密钥；通过 JWKS 发布公钥。密钥不得写入源码或普通日志。

逻辑关系：`Browser → Client backend → SSO authorization endpoint → Client callback → SSO token endpoint`。浏览器只接触授权端点和回调 URL，不直接调用 token endpoint。

## 4. 登录主流程

### 4.1 应用发现未登录

1. 用户请求业务应用资源。
2. 接入中间件检查应用会话 Cookie，并在服务端验证会话仍有效。
3. 若会话缺失/失效，后端生成高熵随机 `state`、`nonce` 和 `code_verifier`，使用 PKCE S256 计算 `code_challenge`。
4. 后端把登录事务保存到服务端存储，至少包含：`state` 的安全摘要或不可预测索引、`nonce`、verifier、创建时间、目标应用相对路径、预期 `client_id`、精确 `redirect_uri`、事务状态。设置短 TTL（建议 5–10 分钟），并标记未消费。
5. 后端返回 302 到认证中心 `/authorize`，参数包含 `response_type=code`、`client_id`、`redirect_uri`、`scope=openid`（及所需 scope）、`state`、`nonce`、`code_challenge`、`code_challenge_method=S256`。浏览器只拿到 challenge，拿不到 verifier。

应用后端自己生成 OAuth 请求参数，通常直接返回重定向响应即可；不要把 verifier 作为“前端收到后再传回”的字段。若架构确需前端触发跳转，前端只接收完整授权 URL 或由后端提供跳转端点，仍不得接收 verifier。

### 4.2 认证中心处理授权请求

认证中心依次执行：

1. 校验必填参数、长度和编码；拒绝重复或不支持的参数。
2. 根据 `client_id` 查客户端注册记录，要求客户端已启用且允许 `authorization_code`。
3. 将 `redirect_uri` 与该客户端登记地址做**逐字精确匹配**（不得用前缀、通配符、开放重定向或不安全的 URL 规范化）。
4. 要求 `response_type=code`、PKCE 方法为 `S256`，challenge 格式合法；按需校验 scope。未知或未授权 scope 必须拒绝或按明确定义缩减。
5. 生成短时一次性服务端授权事务，将 `state`、challenge、nonce、client、回调地址、scope、创建时间保存，供后续登录完成和 code 签发使用。浏览器返回时原样带回 state。
6. 检查 TGC Cookie：从 Cookie 解析随机会话句柄，到服务端查找会话，校验未过期、未撤销、用户仍允许登录。不能仅凭 Cookie 字符串或客户端可自声明字段认定登录有效。
7. TGC 有效时，直接进入授权码签发步骤；否则展示认证中心登录页。登录页必须防 CSRF，密码仅经 TLS 提交，密码不得写日志。

认证通过后（未来 MFA 通过后），建立 TGC 服务端会话，向浏览器写入 TGC Cookie，再为原始授权事务签发 code。TGC 不应把用户信息、权限或 bearer token 直接编码进 Cookie。

### 4.3 授权码签发与浏览器回调

认证中心生成至少 128 位不可预测熵的随机 code（推荐使用密码学安全随机数），服务端保存其摘要及元数据：客户端 ID、精确 redirect URI、PKCE challenge/method、用户 ID、nonce、获准 scope、认证时间、签发时间、过期时间、消费状态。建议有效期 1–2 分钟，单次使用。

认证中心以 302 将浏览器重定向至已登记 `redirect_uri`，附带 `code` 和原始 `state`。错误时返回标准化 `error` / `error_description`（不得泄露内部细节）及原始 state，且仅可重定向到已验证回调地址。回调页面不得加载第三方脚本、图片或分析组件；应设置 `Referrer-Policy: no-referrer`，并尽快由后端兑换 code 后重定向到去除 query 的干净 URL，避免授权码留在浏览器历史、Referer 和应用日志中。

### 4.4 应用回调与 code 兑换

1. 应用回调后端读取 `code` 和 `state`，在服务端查找对应的未完成登录事务。
2. 以恒定时间比较/安全匹配 state；检查事务未过期、未消费、client 与 redirect URI 仍匹配。失败时终止登录，不创建会话。
3. 后端通过 TLS 直接调用认证中心 token endpoint，提交 `grant_type=authorization_code`、code、client 身份认证、同一 redirect URI 和原始 `code_verifier`。若采用 PKCE-only 公共客户端，不发送 client secret；服务端 confidential client 可用 mTLS 或 `private_key_jwt` 等机制认证。禁止在浏览器发起兑换。
4. 认证中心原子性地确认 code 存在、未过期、未消费、属于此 client、redirect URI 完全一致，并验证 `BASE64URL(SHA256(code_verifier)) == code_challenge`。验证成功后将 code 标记为已消费并签发令牌。并发兑换只能有一个成功。
5. 应用验证令牌响应和 ID Token（见第 7 节）。只有所有校验通过才建立应用会话。验证完成后删除/消费登录事务及 verifier；失败也应清理，或允许一次受限重试的策略需明确定义。

## 5. 令牌签发与应用侧处理契约

本节区分认证中心签发职责和客户端处理职责。认证中心生成令牌并定义声明、受众、有效期、轮换和撤销语义；应用后端负责接收响应、校验 ID Token，并按接入约定维护自己的 Access Token Cookie 与 Redis 映射。认证中心不读取或维护应用本地 Cookie/Redis 用户映射。

### 5.1 令牌选择与保存

- **ID Token**：只用于首次令牌兑换时校验和提取身份声明；验证签名、`iss`、`aud`、`exp`、授权请求中的 `nonce` 等后，提取 `sub` 等必要信息写入 Redis，随后立即丢弃 ID Token。ID Token 本身不写 Redis、数据库或日志，也不下发浏览器。
- **Access Token**：应用后端用于访问资源服务。建议不透明随机 token，认证中心保存 token 摘要及关联身份、客户端、scope、过期时间、撤销状态；若使用 JWT，则资源服务必须验证签名、`iss`、`aud`、`exp`、`nbf`、scope，并接受撤销传播延迟这一权衡。
- **Refresh Token**：只保存在服务端，与当前 Access Token 对应的用户资料一起放在该 Access Token 的单条 Redis 映射记录中；Refresh Token 应加密保存。认证中心保存 token 摘要、family、客户端、用户、过期时间、轮换/撤销状态。成功续期时返回新的 Refresh Token 并使旧 token 失效；检测到已轮换旧 token 重用时，撤销整个 token family 并要求重新认证。Refresh Token 不得放入浏览器 Cookie/LocalStorage。
- **应用 Access Token Cookie**：按本项目架构，应用后端完成 code 兑换和令牌校验后，将 Access Token 写入按客户端区分的 Cookie，名称为 `{client_id}_access_token`，值为 Access Token。Cookie 设置 `Secure; HttpOnly; SameSite=Lax`、限定最小所需 Path，不设置宽泛 Domain。由于 Access Token 到期后浏览器仍需把旧值发给应用，以便后端找到 Redis 映射并触发续期，Cookie 的物理过期时间应覆盖续期窗口；Redis 中 Access Token 的逻辑过期时间仍决定它是否可用于业务访问。Refresh Token 和 ID Token 不得写入浏览器 Cookie。由于浏览器会自动携带 Cookie，所有有副作用的请求必须实施 CSRF 防护，可组合使用 SameSite、CSRF token、Origin/Fetch Metadata 校验。日志和代理访问日志不得记录 Cookie 原文。

应用后端从 Access Token Cookie 取得 token，以其摘要查询应用自身 Redis 中唯一的当前 token 映射记录。记录包含用户必要信息、Access Token 逻辑过期时间，以及加密保存的 Refresh Token 和其过期时间。Access Token 未过期时才可处理业务请求；已过期时只能用该记录中的 Refresh Token 调用认证中心 token endpoint 尝试续期，不能用旧 Access Token 访问业务接口。续期成功后，应用侧先写入新 Access Token 对应的新记录并更新浏览器 Cookie，再删除旧记录。Refresh Token 过期、撤销或续期失败时，应用侧清除 Cookie 和映射并重新走 SSO。退出时应用侧清除此 Cookie、删除映射并调用认证中心撤销令牌。

### 5.2 ID Token 校验规则

ID Token 仅在应用后端收到 token endpoint 响应时使用，不长期保存。必须使用可信 OIDC 元数据/JWKS 验签；拒绝 `alg=none` 和未配置算法。至少校验：

- 签名有效且 `kid` 对应当前或仍在轮换窗口内的可信公钥；密钥来自固定 issuer 的可信 JWKS 地址，不允许 token 自带任意 `jku`/`x5u` 触发 SSRF。
- `iss` 与配置的认证中心 issuer 完全一致。
- `aud` 包含本应用 `client_id`；多 audience 时按 OIDC 规则检查 `azp`。
- `exp` 未过期、`iat` 合理、如有 `nbf` 则已经生效；允许的时钟偏差有明确上限。
- `nonce` 与服务端登录事务保存值完全匹配，并在校验后消费。
- `sub` 存在、非空，作为 issuer 范围内稳定的用户主键。用户数据库的内部 ID 若不同，应通过受控映射得到。
- 按需校验 `auth_time`、`acr`、`amr` 等认证强度声明，不得无依据假定 MFA 已完成。

校验通过后，只提取业务必需的最少声明（推荐 `iss`、`sub`，可选 display name/email 等），映射成内部用户 ID/用户资料并写入 Redis，供 Access Token 到用户信息的映射使用。随后丢弃 ID Token 本身及不需要的原始 claim。邮箱不是稳定主键，也不能未经验证就用作唯一身份。

## 6. Redis 数据模型与生命周期

Redis key 必须按环境和用途命名空间隔离；敏感值尽量存摘要或密文。Redis 过期时间应与对应授权/令牌生命周期一致，刷新时原子更新，退出时删除或标记撤销。

以下将认证中心服务端状态与接入应用本地映射分开列出。`app:{client_id}:token_map:*` 是应用侧接入契约示例，不代表认证中心共享 Redis 中的一类记录。建议逻辑键（字段仅作实现参考）：

| 键 | 内容 | TTL / 处理 |
|---|---|---|
| `sso:auth_tx:{tx_id}` | client、redirect URI、challenge、nonce、state 摘要、scope、创建时间 | 5–10 分钟；兑换/失败后删除 |
| `sso:code:{code_digest}` | client、redirect URI、challenge、用户、nonce、scope、过期、consumed | 1–2 分钟；原子消费 |
| `sso:tgc:{tgc_id_digest}` | user、认证时间、创建/过期、撤销状态、会话版本 | 按 SSO 会话策略；滑动续期需上限 |
| **应用侧** `app:{client_id}:token_map:{access_digest}` | 用户必要信息（含 issuer 范围内的 `sub`/内部用户 ID）、Access Token 逻辑过期时间、加密的当前 Refresh Token、固定的 Refresh Token 过期时间、scope/认证时间 | 固定兜底 TTL 为初始 Refresh Token 绝对过期时间加有限清理宽限期；每次 Refresh Token 轮换沿用原绝对过期时间，不滑动延长。成功刷新后删除旧记录。此键由应用维护，不属于认证中心核心数据 |
| `sso:access:{access_digest}` | （认证中心侧，如采用不透明 Access Token）client、scope、用户、exp、撤销状态/会话版本 | 至 Access Token 到期 |
| `sso:refresh:{refresh_digest}` | （认证中心侧）family、client、user、过期、使用状态、轮换链 | 至 Refresh Token 到期；轮换原子操作 |
| `sso:revoked:{jti_or_digest}` | 撤销标记及原因/时间 | 不超过原 token 剩余有效期 |

以下是应用侧映射契约，不是认证中心自身必须实现的 Redis 表：应用侧只保留一条当前映射，以当前 Access Token 摘要为 key，值包含必要用户信息和加密的 Refresh Token。记录中的 Access Token `exp` 是逻辑过期时间，过期后应用必须拒绝业务访问；Redis 物理 TTL 用于保留续期上下文，也作为兜底回收期限。即使浏览器清除了 Cookie，映射也会在固定 TTL 到期后自动删除。Refresh Token 使用固定绝对过期时间，从最初签发时确定；每次使用时可以轮换 token 值，但新 Refresh Token 沿用同一个绝对到期时间，不能滑动延长。应用 Redis TTL 固定为该绝对到期时间加有限清理宽限期。刷新成功后，应用侧写入新 Access Token 映射并删除旧映射；若应用发现 Refresh Token 已过期、退出或撤销，则立即删除当前 key，不等待宽限期。不得建立 Refresh Token → ID Token 映射。使用原始 bearer token 作为 Redis key/value 会增加日志、监控、备份泄露风险；Redis 访问控制、网络隔离和备份保护由各应用负责。

Access Token 逻辑过期时，映射不立即物理删除，以便找到 Refresh Token 并保留用户信息；该过期 token 只允许触发刷新，不允许访问业务接口。用户主档属于用户目录/业务数据库，不应依赖令牌映射保存。映射有固定物理 TTL：初始 Refresh Token 的绝对过期时间加有限清理宽限期，作为浏览器已清除 Cookie、没有后续请求时的兜底回收；若后端实际发现 Refresh Token 已过期，则立即删除映射并清 Cookie。刷新成功后，以事务/Lua 或等价原子操作完成新映射写入和旧映射删除，并更新 Cookie；新 Refresh Token 沿用初次签发时确定的绝对到期时间，映射 TTL 不因轮换而延长。刷新失败并需重新 SSO 时删除映射。旧记录删除后，Redis 不会随着每次刷新持续积累历史映射。

## 7. Token endpoint、续期与撤销

### 7.1 Access Token 到期

应用后端发现 Access Token 即将过期或资源服务器返回标准 `invalid_token` 后，锁定该应用会话的刷新操作，调用认证中心 token endpoint 的 `grant_type=refresh_token`。认证中心验证 Refresh Token 摘要、client 绑定、固定绝对有效期、未撤销、未重用，执行轮换，返回新 Access Token 和新 Refresh Token（建议总是轮换）；认证中心不负责应用侧 Redis 映射。应用更新自己的 Redis 映射并原子使旧凭证失效。

并发刷新必须防止同一 Refresh Token 被多个请求同时使用：应用侧按当前 Access Token 映射加锁或 single-flight；认证中心 token endpoint 以原子消费保证只有一次成功。认证中心负责拒绝过期/撤销/重用的 Refresh Token 并执行轮换；应用负责成功后写入新映射、更新 Cookie 并删除旧映射。Refresh Token 轮换不改变最初签发时确定的绝对过期时间。失败后应用清理本地登录状态并重新走授权流程，不能继续接受过期 Access Token。

### 7.2 Token 生命周期建议

初始建议值需结合风险及运维能力评审：Authorization Code 60–120 秒；Access Token 5–15 分钟；应用会话按业务设定且可撤销；TGC 可有空闲超时和绝对超时（例如空闲 8 小时、绝对 7 天）；Refresh Token 可按风险设置绝对期限（例如 30 天）并轮换。所有期限、时钟偏差和续期策略都应配置化，不写死在业务代码。高风险应用使用更短期限和强制重新认证策略。

### 7.3 撤销接口

提供受客户端认证保护的撤销端点，可撤销 Refresh Token、Access Token 或整个 refresh family。令牌值通过 TLS 发送，服务器仅存摘要。撤销响应应避免泄漏 token 是否曾有效（按协议返回幂等成功）。如 JWT Access Token 无法即时查询撤销状态，可使用短 TTL、jti denylist、会话版本检查或接受最长 TTL 的撤销窗口，并在文档中说明。

## 8. 退出流程

### 8.1 当前应用退出

1. 浏览器向应用后端发起带 CSRF 防护的 POST logout。
2. 应用后端先从当前 Access Token 的 Redis 映射中读取服务端保存的 Refresh Token，并调用认证中心撤销端点，撤销当前 Refresh Token family 和当前 Access Token（如果实现支持）。
3. 撤销完成或按幂等策略处理失败后，使本地应用登录状态失效，清除应用 Cookie（相同 Path/Domain 属性）并删除当前 Redis 映射；不得先删除映射而丢失撤销所需的 Refresh Token。
4. 浏览器收到完成响应。仅删除 Cookie 不够：被盗用的 bearer token 仍然可能有效。

单应用退出默认不清除认证中心 TGC，因此用户访问另一应用仍可免密登录；界面应清楚说明这一行为。

### 8.2 全局 SSO 退出

1. 用户从认证中心全局退出入口发起 POST，校验 CSRF。
2. 认证中心撤销当前 TGC 服务端会话，删除/失效 TGC Cookie；撤销或标记由此会话创建的 Refresh Token family，并按能力撤销相关 Access Token。可通过令牌 `sid`/会话版本建立关联。
3. 认证中心返回退出完成页面，并可支持已登记的 RP-initiated logout / front-channel 或 back-channel logout 通知。回调目标必须登记和验证，不能接受任意 URL。
4. 各应用接收可信退出通知后删除本地会话和 Redis 映射。通知应签名/认证、幂等并防重放。

如果暂不实现跨应用通知，必须说明全局退出的撤销传播延迟；短 TTL 可限制风险。仅在浏览器端删除 TGC Cookie 不足以使 TGC 服务端会话失效。

## 9. HTTP API 草案

所有端点仅允许 HTTPS。路径可按项目 API 规范调整；协议语义应保持一致。

### 9.1 `GET /oauth2/authorize`

请求参数：`response_type=code`、`client_id`、`redirect_uri`、`scope`、`state`、`nonce`、`code_challenge`、`code_challenge_method=S256`。成功后 302 回调 `?code=...&state=...`。禁止静默接受缺失 state/nonce（OIDC 请求要求 nonce）；错误遵循 OAuth 错误响应规范。

### 9.2 `POST /oauth2/token`

Content-Type 为 `application/x-www-form-urlencoded`，要求客户端认证（具体方式按 client 类型配置）。授权码兑换字段：`grant_type=authorization_code`、`code`、`redirect_uri`、`code_verifier`。响应示例：

```json
{
  "access_token": "opaque-random-value",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "opaque-rotating-value",
  "id_token": "signed-oidc-jwt",
  "scope": "openid profile"
}
```

刷新字段：`grant_type=refresh_token`、`refresh_token`。错误使用标准 `invalid_request`、`invalid_client`、`invalid_grant`、`unsupported_grant_type` 等，不返回堆栈或内部存储信息。响应设置 `Cache-Control: no-store`、`Pragma: no-cache`。

### 9.3 `GET /.well-known/openid-configuration` 与 `GET /jwks.json`

发布固定 issuer、authorize/token/userinfo（如实现）/logout/revocation endpoints、支持的 response type、grant、scope、PKCE 方法和签名算法。JWKS 发布当前与轮换期公钥；不得包含私钥。

### 9.4 `POST /oauth2/revoke`

撤销 token；要求 client authentication，TLS 传输，幂等响应。

### 9.5 `GET/POST /logout`（建议 POST）

提供认证中心会话退出。POST 需要 CSRF 防护；清除浏览器 TGC Cookie 并撤销服务端 TGC 会话。GET 可只用于展示确认页面，不应直接执行有副作用的全局退出。

### 9.6 应用回调 `GET /auth/callback`

接收 `code`、`state` 或 OAuth error。处理成功后立即清理 URL query，并转回应用内原始安全路径。禁止从 query 参数直接决定任意 redirect target；使用事务中保存的站内相对路径。

## 10. 客户端注册与配置

每个 client 注册：`client_id`、显示名称、状态、client 类型、精确回调 URI 列表、logout URI 列表、允许的 scope、令牌认证方式、Access/Refresh Token 策略、允许的来源/部署环境、联系人和变更审计记录。生产、预发、开发环境使用不同 client ID 和密钥。

redirect URI 不得使用通配符，不允许 HTTP（本机回环开发例外需单独约束），不接受开放重定向。客户端凭证推荐 secret manager 中的非对称私钥认证；若用 client secret，存哈希/密文、可轮换、不得发给浏览器。Client Secret 与 PKCE 作用不同，confidential client 仍应使用 PKCE。

## 11. 安全要求与威胁应对

| 威胁 | 控制措施 |
|---|---|
| 授权码被截获/重放 | PKCE S256；短时一次性 code；绑定 client、redirect URI；兑换时原子消费；全链路 TLS。 |
| 登录 CSRF / 会话串用 | state 与服务端事务绑定、一次性校验；nonce 验证；TGC SameSite；登录/退出表单 CSRF token。 |
| 开放重定向/授权码泄露 | 回调 URI 精确白名单；禁止通配和任意 next；回调快速兑换并清理 URL；Referrer-Policy no-referrer。 |
| ID Token 伪造/跨客户端使用 | JWKS 验签；严格 issuer/audience/azp/nonce/exp 等校验；固定算法及可信 issuer。 |
| Token XSS/窃取 | Access Token Cookie 使用 HttpOnly/Secure；Refresh Token 与 ID Token 仅保存在服务端；CSP、输出编码、依赖治理、敏感值脱敏。 |
| Cookie CSRF | SameSite、CSRF token/Origin 校验；变更操作使用 POST；必要时重新认证。 |
| Refresh Token 重放 | 轮换、family 追踪、重用检测、原子消费、客户端认证、服务端保存。 |
| 暴力破解/账号枚举 | 限速、渐进延迟、统一错误文案、异常检测、账号锁定策略及审计。 |
| Redis/日志泄露 | 网络隔离、ACL/TLS、令牌摘要/加密、脱敏日志、备份加密、最小权限。 |
| 密钥泄漏/轮换 | KMS/Secret Manager；定期轮换；kid/JWKS 双钥窗口；密钥访问审计。 |
| 重放/时钟偏差 | 一次性事务、短 TTL、原子状态迁移、NTP、明确定义少量 clock skew。 |
| 浏览器历史/代理日志暴露 | TLS、禁止 query 记录 code/token、短期 code、清理回调 URL、no-store。 |

敏感值（密码、完整 Cookie、授权码、Access/Refresh/ID Token、client secret、verifier）禁止记录。审计日志只保留 request/correlation ID、client、内部 subject 标识（必要时散列）、结果、错误类别、时间和来源风险字段，不写凭证原文。

## 12. 错误处理与状态管理

- 用户取消登录：应用清理对应登录事务，显示可重试页面；不创建空会话。
- state 缺失或不匹配：拒绝 callback，记录安全事件；不得仅靠 state 为空时继续。
- code 无效、过期、已消费、client 不匹配或 PKCE 失败：统一返回 `invalid_grant`，不泄漏 code 存储状态。
- 认证中心不可用：应用显示可重试错误，使用 request ID；不得自动绕过身份认证。
- Redis/主数据库不可用：认证及兑换应 fail closed；不可在无法确认 code 是否消费时重复签发。
- 令牌验证失败：不建立应用会话，清理临时事务；保留不含凭证的审计事件。
- 所有状态转换应可幂等处理或有明确的单次消费保证。

## 13. 数据库与迁移建议

除 Redis 短时状态外，至少需要客户端注册、用户身份映射、授权码（若不完全置于 Redis）、刷新令牌 family/撤销审计、密钥元数据和审计事件等持久化能力。若授权码/refresh state 只在 Redis，部署时必须评估故障切换、持久化和数据丢失对安全与可用性的影响。数据库字段中不保存明文密码；使用成熟密码哈希（如 Argon2id）和账号防护策略。令牌可只存 SHA-256/HMAC 摘要（需高熵随机令牌），客户端秘密应按可验证或可轮换的安全方式处理。

核心实体关系：Client 1—N Redirect URI；User 1—N TGC Session；User 1—N Refresh Token Family；Client/User 1—N Token；Authorization Code 绑定单个 Client、User、Redirect URI 和 PKCE Challenge。

## 14. 可观测性与运维

- 指标：授权请求量/成功率、登录成功/失败率、code 兑换成功率、PKCE/state/nonce 失败数、刷新成功/重用数、撤销延迟、TGC 命中率、Redis 延迟与错误、各端点 P95/P99。
- Trace：跨应用和 SSO 通过随机 correlation ID 关联；不要把 state、code、token 放进 trace 标签。
- 告警：短时间认证失败激增、刷新 token 重用、异常 client/redirect URI、签名失败、密钥过期、Redis 不可用、JWKS 分发异常。
- 时钟：所有节点同步 NTP；签发和校验统一使用 UTC。
- 容量：预估峰值授权/刷新并发、Redis 内存与 TTL 回收、数据库连接、JWKS 缓存刷新；设置限流和背压。
- 恢复：密钥灾备需保护私钥；数据恢复演练应避免恢复已撤销 token 后重新变有效。恢复策略应保存撤销版本/时间水位，或在灾后强制令牌失效。

## 15. 建议项目目录与模块边界

```text
src/
  auth/                 # 账号校验、认证步骤、MFA 扩展
  clients/              # 客户端注册与 redirect URI 策略
  oauth/authorize/      # 授权请求解析、TGC 检查、code 签发
  oauth/token/          # code 兑换、PKCE、令牌签发、refresh rotation
  oauth/revoke/         # 撤销端点
  oidc/                 # issuer、ID Token、JWKS、discovery
  sessions/             # TGC 与应用会话辅助服务
  logout/               # RP logout 和全局退出
  storage/              # 数据库/Redis 仓储、原子操作
  security/              # 随机数、哈希、CSRF、限流、密钥接口
  client-integration/    # 可选独立接入 SDK/示例客户端，不属于认证中心核心服务
  audit/                 # 脱敏审计
```

模块之间通过接口依赖存储和密钥服务，避免业务逻辑直接拼 Redis key 或自己实现密码学原语。生产代码使用成熟 OIDC/OAuth 库；不要自行发明 JWT 验签或密码哈希实现。

## 16. 开发阶段与交付顺序

### 阶段 0：项目基线

确定语言/框架、数据库、Redis、部署域名、issuer、用户来源、客户端类型、令牌形式与客户端认证方式；登记首个测试 client 和开发回调地址。

### 阶段 1：认证中心基础

实现配置、客户端注册查询、登录 UI/账号认证、TGC 建立和校验、CSRF、限速、审计、密钥托管和健康检查。MFA 接口以认证步骤抽象预留。

### 阶段 2：授权码 + PKCE

实现 authorize 参数校验、精确 redirect URI、服务端授权事务、state/nonce、S256 challenge、一次性 code、原子兑换及 OAuth 错误响应。

### 阶段 3：OIDC 与令牌

实现 ID Token 签发、JWKS/Discovery、Access Token、Refresh Token 轮换、撤销端点及客户端认证；固定并记录 issuer。

### 阶段 4：接入验证（认证中心之外的客户端工作）

用最小示例客户端或独立 SDK 验证认证中心协议：服务端登录事务、重定向、callback state 校验、后端 token exchange、ID Token 验证及声明映射、应用 Access Token Cookie、应用侧 Redis 映射和受控刷新。该 SDK 可独立发布，不是认证中心核心服务的必需模块。

### 阶段 5：退出、加固与接入

实现单应用退出和全局退出、跨应用撤销传播、运维指标、密钥轮换、速率限制、备份恢复流程，接入首个应用并完成安全评审。

每一阶段完成后由项目团队运行相应单元、集成、端到端和安全验证；本设计文档本身不代表实现已经通过测试或安全审计。

## 17. 验收标准

1. 未登录访问应用会发起 Authorization Code + PKCE S256 流程，浏览器看不到 verifier、Refresh Token 和 client secret。
2. 任意未登记/不精确 redirect URI 被拒绝；禁止通配回调和开放重定向。
3. 无 TGC 时登录后建立 TGC；有效 TGC 访问第二个应用时无需再次输入密码，但每个应用仍独立完成授权和 token exchange。
4. code 过期、重放、跨 client 使用或 PKCE verifier 错误均兑换失败；并发兑换至多一个成功。
5. 缺失/篡改 state、nonce、错误签名、错误 issuer/audience、过期 ID Token 均不能建立应用会话。
6. ID Token 校验后不持久化；Redis/日志中不出现 ID Token 明文。
7. Access Token 到期可通过有效 Refresh Token 轮换续期；旧 Refresh Token 重用触发 family 撤销/重新认证策略。
8. 应用以 `{client_id}_access_token` Cookie 保存 Access Token，配置 Secure、HttpOnly、合适的 SameSite 和 Path；Cookie 保留到续期窗口结束，以便过期 Access Token 可定位续期记录。Redis 逻辑过期后拒绝业务访问，刷新成功后新映射生效且旧映射被删除；Refresh Token 与 ID Token 不进入浏览器，依赖 Cookie 的有副作用请求具备 CSRF 防护。
9. 单应用退出清理本地 session 和令牌；全局退出使 TGC 服务端会话失效并按定义传播撤销。
10. 日志、错误响应、监控标签和 trace 均不包含密码、Cookie、code、token、verifier 或 client secret。
11. Redis/密钥/认证服务关键依赖故障时认证路径 fail closed，并可观测、可告警。

## 18. 落地前需要确定的配置

以下不是协议阻塞项，可以先按本文建议值实现，再通过环境配置调整：

- 后端语言/框架以及应用接入方式（SDK、中间件或反向代理）。
- 用户身份来源（自建用户表、LDAP、企业身份平台）及内部用户 ID 映射。
- Access Token 选不透明令牌还是 JWT；建议初版不透明令牌，撤销更直接。
- 应用 Cookie 域名、各应用是否不同站点、是否存在跨站 iframe（影响 SameSite 与静默续期）。
- Redis 与关系型数据库的具体产品、HA、持久化和灾备策略。
- client 认证方式、密钥管理服务、生产 issuer/域名及证书。
- 默认 token/session TTL、单应用退出与全局退出的产品语义。
- 用户属性 scope、资源服务器 audience 和权限模型。

## 19. 与原始构想的实现对齐

本文保留了“无有效 Access Token 时发起 SSO、TGC 有效时免密签 code、无 TGC 时登录并创建 TGC、后端以 code + verifier 换取三类令牌、校验 ID Token 后只保存用户映射、Access Token 过期时刷新、Refresh Token 失效后重新 SSO、退出时清理应用和认证中心会话”的主线。

按本架构，`code_verifier` 和应用登录事务由应用后端保存；浏览器只参与授权跳转并在回调中携带 state/code。应用后端将 Access Token 写入 `{client_id}_access_token` Cookie，并把 Access Token 与已验证用户信息关联存入 Redis；Refresh Token 保存在服务端。ID Token 在服务端完成签名、`iss`、`aud`、有效期和 nonce 校验后，提取 `sub` 等必要信息写入 Redis，随后丢弃。



## server端刷新逻辑


## 一次刷新请求的完整过程

假设客户端向授权服务器的 `/oauth2/token`（实际路径由 Spring Authorization Server 的 endpoint 配置决定）发送：

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=<旧的刷新令牌>
```

在这份代码里，已注册客户端允许 `authorization_code` 和 `refresh_token` 两种授权类型，且配置了 `reuseRefreshTokens(false)`，也就是刷新时采用令牌轮换：成功后会签发新的刷新令牌，旧令牌不能再次使用。/E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/storage/SsoRegisteredClientRepository.java:57

### 1\. 授权服务器先找到旧令牌对应的授权记录

Spring 的 token endpoint 校验客户端和刷新请求后，会用旧刷新令牌查找对应的 `OAuth2Authorization`。自定义的 `DigestingJdbcOAuth2AuthorizationService` 覆写了查找逻辑：

1. 对请求里的明文令牌用当前 HMAC 密钥及历史密钥计算摘要。
2. 用摘要去数据库查授权记录，因为数据库保存的是摘要而不是明文。
3. 查到后，再把请求中提供的明文令牌放回内存中的授权对象，供授权服务器后续处理。

查找入口在 `findByToken()`；摘要匹配和恢复令牌的逻辑分别在 /E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/storage/DigestingJdbcOAuth2AuthorizationService.java:52 和 同文件的 restorePresentedToken() (/E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/storage/DigestingJdbcOAuth2AuthorizationService.java:137)。

这个查找阶段还会检查令牌是否已经使用、所属家族是否撤销或过期。发现已使用的旧令牌时，会撤销整个 family 并记录重放事件。/E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/storage/DigestingJdbcOAuth2AuthorizationService.java:91

### 2\. Spring 准备签发新令牌

旧令牌通过查找和授权校验后，Spring 的刷新授权流程会生成新的访问令牌；由于客户端配置了不复用刷新令牌，还会请求 token generator 生成新的刷新令牌。

生成器在授权服务器配置中以委托链的形式注册：JWT、访问令牌由前面的生成器处理，刷新令牌交给 `FamilyAwareRefreshTokenGenerator` 包装的默认刷新令牌生成器处理。/E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/config/AuthorizationServerConfiguration.java:90

## `generate()` 刷新分支逐行说明

### 3\. 非刷新令牌直接委托

```
if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType()))
    return delegate.generate(context);
```

这个生成器虽然注册在总的 token generator 链里，但只额外处理刷新令牌。生成访问令牌时，它会直接调用包装的默认生成器，不做 family 数据库操作。

### 4\. 先生成一个候选的新刷新令牌

```
OAuth2Token generated = delegate.generate(context);
if (!(generated instanceof OAuth2RefreshToken refreshToken)) return generated;
```

Spring 的默认 `OAuth2RefreshTokenGenerator` 先创建新令牌。此时它只是候选值，还要经过下面的 family 轮换检查，成功后才会由授权服务器保存并返回给客户端。

### 5\. 确认这是刷新授权，并准备家族信息

```
AuthorizationGrantType grantType = context.getAuthorizationGrantType();
OAuth2Authorization authorization = context.getAuthorization();
if (authorization == null) throw ...
String familyId = authorization.getId();
```

对于 `grant_type=refresh_token`，授权对象应当包含正在使用的旧刷新令牌。`authorization.getId()` 被用作 family ID，所以同一授权记录下的刷新令牌轮换都归在同一个家族中。

接着计算新令牌的摘要：

```
String newDigest = tokenDigest(refreshToken.getTokenValue());
```

摘要使用 HMAC-SHA256，而不是直接把令牌明文写进 family 表。

### 6\. 取出旧刷新令牌并准备兼容密钥轮换

```
OAuth2Authorization.Token<OAuth2RefreshToken> previous =
    authorization.getRefreshToken();
if (previous == null) throw INVALID_GRANT;

List<String> previousDigests =
    tokenDigests(previous.getToken().getTokenValue());
```

如果授权对象里没有旧刷新令牌，就拒绝请求，返回 `invalid_grant`。

这里对旧令牌尝试当前及历史 HMAC 密钥，是为了支持 HMAC 密钥轮换：旧记录可能是用之前的密钥生成摘要的。相关摘要实现见 /E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/security/FamilyAwareRefreshTokenGenerator.java:126。

### 7\. 在事务中锁定并验证 family

刷新分支调用：

```
Instant absoluteExpiry =
    rotate(context, familyId, previousDigests, newDigest,
           refreshToken.getIssuedAt());
```

`rotate()` 在事务中用 `SELECT ... FOR UPDATE` 锁住 family 行：

```
select current_token_digest, expires_at, revoked
from oauth_refresh_token_family
where family_id = ?
for update
```

这一步防止两个并发请求同时拿同一个旧令牌刷新并都成功。之后有几种结果：

- **找不到 family 行**：轮换失败，最终拒绝刷新。
- **family 已撤销或已超过绝对过期时间**：标记为撤销并拒绝。
- **旧令牌摘要不是 family 当前摘要**：认为旧令牌不是当前有效令牌，也按重放处理，撤销 family 并拒绝。
- **验证通过**：把 family 的 `current_token_digest` 从旧令牌摘要更新成新令牌摘要。

验证和并发锁定在 rotate() (/E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/security/FamilyAwareRefreshTokenGenerator.java:83)。

### 8\. 消耗旧令牌、登记新令牌

验证通过后，事务中还会做两件事：

```
update oauth_refresh_token_history
set token_status = 'USED', consumed_at = ?
where token_digest = ?
  and family_id = ?
  and token_status = 'ACTIVE'
```

这条更新必须恰好改到一行；否则也视作异常或重放，撤销 family 并拒绝。

接着把新令牌写入 history，状态为 `ACTIVE`：

```
insert into oauth_refresh_token_history
    (token_digest, family_id, token_status, issued_at)
values (?, ?, 'ACTIVE', ?)
```

因此正常轮换前后的记录类似：

| 时点 | family 当前摘要 | 旧令牌状态 | 新令牌状态 |
|---|---|---|---|
| 刷新前 | 旧令牌摘要 | `ACTIVE` | 不存在 |
| 刷新后 | 新令牌摘要 | `USED` | `ACTIVE` |

这些数据库操作都在 `TransactionTemplate` 的事务中执行，整体见 rotate() (/E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/security/FamilyAwareRefreshTokenGenerator.java:85)。

### 9\. 失败时撤销或记账，并返回 `invalid_grant`

事务返回失败结果后，代码在事务外：

- 对重放情形增加 `REPLAY_REJECTED` 指标，并写入 `REFRESH_TOKEN_REPLAY` 审计事件。
- 对其他无效情况增加 `INVALID_REJECTED` 指标。
- 抛出 `OAuth2AuthenticationException(INVALID_GRANT)`。

所以客户端收到的是刷新失败，通常表现为 OAuth 错误 `invalid_grant`，不会收到新令牌。

注意：`rotate()` 把撤销操作和失败结果一起在事务里完成，然后才在事务外抛异常。这使得撤销更新可以先提交，不会因为随后抛异常而随整个事务回滚。

### 10\. 将新令牌有效期限制在 family 的绝对过期时间内

轮换成功后，`rotate()` 返回 family 的绝对过期时间。代码把新刷新令牌的过期时间设置为以下两者中更早的一个：

```
Instant tokenExpiry =
    refreshToken.getExpiresAt().isBefore(absoluteExpiry)
        ? refreshToken.getExpiresAt()
        : absoluteExpiry;
```

也就是说每次刷新虽然拿到新令牌，但不会让整个登录会话一直通过连续刷新无限延长。新令牌最晚只能用到 family 的绝对过期时间。

最后返回令牌对象：

```
return new OAuth2RefreshToken(
    refreshToken.getTokenValue(),
    refreshToken.getIssuedAt(),
    tokenExpiry);
```

授权服务器接下来会保存更新后的授权记录，并把新的访问令牌和刷新令牌返回给客户端。由于授权记录服务也会把 token 值摘要化存储，所以数据库不需要保留刷新令牌明文。

## 用一句话概括刷新机制

客户端拿旧刷新令牌请求 `/oauth/token`；授权服务器确认旧令牌有效后生成新令牌，再用数据库行锁确保旧令牌只成功消费一次，把旧令牌标成 `USED`、新令牌设为 family 当前令牌，并让刷新令牌不超过 family 的绝对过期时间。

代码里要特别区分两类校验：`DigestingJdbcOAuth2AuthorizationService` 在授权服务器正式进入刷新生成阶段前就会查令牌并拦截已使用或已撤销的令牌；`FamilyAwareRefreshTokenGenerator.rotate()` 又会在加锁的事务里做一次当前令牌校验，后者负责防并发双花。
```
  Worked for 29s • 12:24
```
旧令牌有效的条件是什么

旧刷新令牌需要同时满足这些条件，授权服务器才会接受它：

1. **能在授权记录中查到**：服务用当前或历史 HMAC 密钥计算令牌摘要，并据此找到对应授权记录。
2. **未过期、未失效**：令牌本身仍有效，所属 family 也没有撤销，且 family 的绝对过期时间还没到。
3. **此前没有被消费**：history 中不能标为 `USED`。
4. **它是 family 当前的令牌**：摘要必须匹配 family 表里的 `current_token_digest`。
5. **客户端和授权校验通过**：请求中的客户端身份、`grant_type=refresh_token` 等还要通过 Spring Authorization Server 的常规校验。

对应代码在 /E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/storage/DigestingJdbcOAuth2AuthorizationService.java:52 和 /E:/AuthSystemSimple/sso-server/src/main/java/com/authsystem/sso/security/FamilyAwareRefreshTokenGenerator.java:83。

若客户端再次提交已用过的旧令牌，代码会将整个令牌 family 撤销，拒绝刷新





## 对于上面响应的处理，客户端sdk是这么做的

- **刷新令牌过期或无效**：认证中心的 `/oauth2/token` 通常返回 **HTTP 400**，响应体包含 OAuth 错误 `invalid_grant`，不是 401。OAuth token endpoint 对无效授权凭证使用 `invalid_grant`；客户端 SDK 把这个拒绝当作刷新失败处理。
- **客户端处理失败**：`SsoSessionService.resolve()` 捕获刷新失败后会删除本地 token 映射并返回空会话。/E:/AuthSystemSimple/sso-client-core/src/main/java/com/authsystem/sso/client/session/SsoSessionService.java:133 /E:/AuthSystemSimple/sso-client-core/src/main/java/com/authsystem/sso/client/protocol/OAuthTokenClient.java:152
- **用户当前的业务请求**：SDK 认证过滤器随后清除浏览器的 access token Cookie。若请求是 API/AJAX，返回 **401**；若是页面请求，则跳转到本地登录入口，再发起 SSO 登录。/E:/AuthSystemSimple/sso-client-spring-boot-starter/src/main/java/com/authsystem/sso/client/starter/SsoAuthenticationFilter.java:43

所以用户看到的通常是：API 请求收到 401，或者页面被引导重新登录；而 **401 是业务应用给用户请求的响应，认证中心给 SDK 的刷新失败响应通常是 400 `invalid_grant`**&#12290;
