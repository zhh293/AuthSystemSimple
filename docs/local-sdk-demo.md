# 本地 SSO SDK 体验

示例 RP 主页位于 `http://localhost:8082`，前端通过项目自带的 Spring Boot Starter 完成 OIDC 登录、读取当前用户和本地退出。页面不会把 Refresh Token 或 ID Token 暴露给浏览器。

## 准备

- Java 17 和 Maven 3.9+
- 通过 SSH 隧道访问远端 SSO issuer `http://127.0.0.1:18080`
- 远端已登记的 confidential client，回调地址必须精确为 `http://localhost:8082/sso/callback`

保持 SSH 隧道终端运行：

```powershell
ssh -i .\zhh2.pem -N -L 18080:127.0.0.1:18080 root@212.64.14.155
```

本仓库 SDK 的开发校验允许 `127.0.0.1` HTTP issuer 仅用于本地存储模式。隧道将本机端口转发到认证服务自身的回环端口，认证服务不需要开放新的公网端口。

## 启动

先在一个 PowerShell 窗口运行上面的 SSH 隧道命令并保持窗口打开。在另一个仓库根目录窗口加载本地忽略的凭据文件并启动 RP：

```powershell
$env:SPRING_PROFILES_ACTIVE = 'sso-sdk'
$demo = Get-Content .env.local-demo | ConvertFrom-StringData
$env:SSO_ISSUER = $demo.SSO_ISSUER
$env:SSO_CLIENT_ID = $demo.SSO_CLIENT_ID
$env:SSO_CLIENT_SECRET = $demo.SSO_CLIENT_SECRET
$env:SSO_REDIRECT_URI = $demo.SSO_REDIRECT_URI
$env:SSO_COOKIE_SECURE = $demo.SSO_COOKIE_SECURE
mvn -pl sso-example-rp -am spring-boot:run
```

打开 `http://localhost:8082`，点击“使用 SSO 登录”。认证完成返回后，身份卡片会显示经 SDK 验证的 subject、姓名和邮箱。退出按钮只退出此 RP 的本地会话；如认证中心 TGC 仍有效，再次登录可能不需要重新输入凭据。

此示例使用进程内单实例存储，重启后会话清空，仅用于本机 HTTP 体验。它不启动资源服务、Dubbo 或 Nacos。

演示登录名和随机生成的密码也保存在 `.env.local-demo` 中；该文件已加入 `.gitignore`，不要复制到代码仓库。
