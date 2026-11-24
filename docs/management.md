# EasyConnect 管理 API 与 WebUI

管理模式在前台运行。进程启动后立即提供 HTTP API 和深色 WebUI，初始状态为 `disconnected`。登录由操作员发起。Supervisor 的 RUNNING 表示管理进程存活，VPN 资源可达性由 `GET /api/health` 判断。

管理模式支持 EasyConnect 的用户态代理，包括原生 Shadowsocks、SOCKS5 和 HTTP，以及网关已支持的用户态 TCP-only 模式。它固定使用配置指定的网关，每次完整登录使用账号密码和服务端要求的验证码。浏览器处理短信挑战。配置了原生 `totp_secret` 的网关仍可通过已有 TOTP 路径认证。需要图形验证码或未配置 TOTP 密钥的挑战会返回 `unsupported_challenge`。TUN、独立 DNS 监听器和端口转发仍可在原有 CLI 模式使用。

## Linux AMD64 安装与 1Panel

从 [GitHub Releases](https://github.com/shiftz300/xmut-connect/releases) 下载同一版本的 `xmut-connect-linux-amd64` 和 `SHA256SUMS`，然后校验文件。以下以 Debian/Ubuntu 为例，使用专用非 root 账号与高位端口。也可以用系统对应的 `useradd` 命令创建服务账号。

```sh
awk '$2 == "xmut-connect-linux-amd64"' SHA256SUMS | sha256sum -c -
sudo adduser --system --group --no-create-home xmut-connect
sudo install -m 0755 xmut-connect-linux-amd64 /usr/local/bin/xmut-connect
sudo install -d -m 0750 -o root -g xmut-connect /etc/xmut-connect
sudo install -d -m 0750 /var/log/supervisor
sudo install -m 0600 -o xmut-connect -g xmut-connect /dev/null /etc/xmut-connect/config.toml
sudoedit /etc/xmut-connect/config.toml
```

新安装时执行创建空配置文件的命令。已有配置时直接编辑。令牌和 Shadowsocks 密码各生成一次独立随机值，例如分别运行 `openssl rand -hex 32`。配置文件使用 TOML，实际凭据只填入 VPS 上权限为 `0600` 的文件。

```toml
protocol = "easyconnect"
server_address = "sslvpn.xmut.edu.cn"
server_port = 443
username = "REPLACE_WITH_VPN_ACCOUNT"
password = "REPLACE_WITH_VPN_PASSWORD"
disable_zju_config = true
remote_dns_server = "auto"
socks_bind = ""
http_bind = ""
shadowsocks_url = "ss://chacha20-ietf-poly1305:REPLACE_WITH_INDEPENDENT_RANDOM_PASSWORD@:1082"

management_enabled = true
management_bind = "127.0.0.1:11083"
management_token = "REPLACE_WITH_RANDOM_64_HEX_CHARACTERS"
management_webui = true
# management_origin = "https://vpn-admin.example.com"
sms_wait_timeout = 180
health_check_url = "https://REPLACE_WITH_AUTHORIZED_CAMPUS_HOST/health"
health_check_interval = 60
# webhook_url = "https://notify.example.com/vpn-events"
```

把健康检查地址换成该账号能通过 VPN 访问、无需额外登录并返回 2xx 或 3xx 的校园资源。探针按现有 DNS 配置解析目标，通过资源匹配后强制走 VPN，验证 TLS 证书并禁止跳转。域名解析失败和目标未匹配策略有独立状态。在部署只允许 IP 资源的网关上，可使用获授权且证书匹配目标的地址，或者为该域配置已有的 `custom_dns`。普通网络错误最多尝试三次隧道重建，退避从 2 秒开始。重建复用当前合法会话，服务端明确判定会话失效时才发起一次完整认证。短信认证失败或超时后需要用户再次发起。

1. 在 1Panel 打开 **工具箱 → 进程守护**，初始化 Supervisor，选用系统实际的 Supervisor 服务名称和配置路径。系统通常通过软件包提供 Supervisor。
2. 创建一个名为 `xmut-connect` 的守护进程，使用绝对命令 `/usr/local/bin/xmut-connect -config /etc/xmut-connect/config.toml`，工作目录填 `/etc/xmut-connect`，运行账号为 `xmut-connect`。
3. 通过进程的「修改源文件」入口核对 [Supervisor 示例](../deploy/xmut-connect.supervisor.ini) 的配置。若选择在系统的 `[include]` 目录手工安装示例，请只保留一个同名 program 段，然后运行 `sudo supervisorctl reread` 和 `sudo supervisorctl update`。账号切换依赖 supervisord 自身运行权限。
4. 启动进程并检查 `sudo supervisorctl status xmut-connect`。VPN 尚未登录时保持 RUNNING。两个相同服务账号启动的管理进程会竞争同一个 Linux 实例锁，管理地址的独占监听也会阻止重复绑定。
5. 通过 HTTPS 访问管理页，输入令牌，点击登录并提交手机收到的验证码。SSH 转发也可以用于管理员首次验收，例如 `ssh -N -L 11083:127.0.0.1:11083 admin@vps.example.com` 后访问 `http://127.0.0.1:11083/`。

[1Panel 进程守护官方文档](https://1panel.cn/docs/v2/user_manual/toolbox/supervisor/) · [Supervisor 配置参考](https://supervisord.org/configuration.html)

升级时先校验新文件，备份当前程序和私有配置，通过 1Panel 或 `supervisorctl stop xmut-connect` 停止进程，使用 `install -m 0755` 替换可执行文件，再启动。停止操作发送 SIGTERM，程序将停止接受管理请求、取消认证、释放监听器及隧道，并在已认证时向网关发出注销请求。升级后从管理页重新登录。回滚时按相同步骤安装备份程序。另有 [systemd 示例](../deploy/xmut-connect.service) 适用于独立部署，同一个配置只交给一个守护进程管理。

## HTTPS 与代理入口

- 管理端口始终绑定回环 IP。在 1Panel 的 HTTPS 站点中反向代理到 `http://127.0.0.1:11083`，保留 Host 和 Authorization，并将站点 HTTPS 源写入 `management_origin`。可参考 [Nginx 示例](../deploy/nginx-management.conf)。如果反向代理运行在独立的网络命名空间中，需要让它经宿主机侧的安全通道到达回环监听器。
- 反向代理使用有效的 TLS 证书。对面向公网的管理站点可用 IP 白名单或私有网络进一步限制来源。日志格式不要记录 Authorization、请求体或完整查询串。
- Shadowsocks 端口与管理端口分开。对外开放的 TCP/UDP 1082 建议在 VPS 防火墙限制到授权客户端来源。每位使用者必须获得校园网接入和资源访问授权。启用 SOCKS5 或 HTTP 时管理模式只接受回环绑定。
- WebUI 只在页面内存保存管理令牌。页面刷新会清除令牌。反向代理不需要注入令牌。API 通过 Authorization 请求头鉴权，浏览器跨源请求会被拒绝。

## 下游客户端

sing-box 的 `outbounds` 项如下。路由规则按校园目标和你的客户端拓扑配置。省略 `network` 时允许原生 TCP 与 UDP。

```json
{
  "type": "shadowsocks",
  "tag": "xmut-vpn",
  "server": "vps.example.com",
  "server_port": 1082,
  "method": "chacha20-ietf-poly1305",
  "password": "REPLACE_WITH_INDEPENDENT_RANDOM_PASSWORD"
}
```

Mihomo 配置如下。

```yaml
proxies:
  - name: XMUT VPN
    type: ss
    server: vps.example.com
    port: 1082
    cipher: chacha20-ietf-poly1305
    password: REPLACE_WITH_INDEPENDENT_RANDOM_PASSWORD
    udp: true
```

[sing-box Shadowsocks 文档](https://sing-box.sagernet.org/configuration/outbound/shadowsocks/) · [Mihomo Shadowsocks 文档](https://wiki.metacubex.one/en/config/proxies/ss/)

## 配置与环境变量

优先级沿用项目默认值、TOML、环境变量、命令行的顺序。TOML 键和 CLI 参数分别使用下划线与连字符。例如 `management_enabled` 对应 `-management-enabled`。配置路径可用 `ZJU_CONNECT_CONFIG` 指定。建议从受保护的 TOML 提供密码与令牌，以免出现在进程命令行或 Supervisor 的 program 配置中。

| TOML | 环境变量 | 默认值 |
| --- | --- | --- |
| `management_enabled` | `ZJU_CONNECT_MANAGEMENT_ENABLED` | `false` |
| `management_bind` | `ZJU_CONNECT_MANAGEMENT_BIND` | `127.0.0.1:11083` |
| `management_origin` | `ZJU_CONNECT_MANAGEMENT_ORIGIN` | 空，仅接受回环 Host |
| `management_token` | `ZJU_CONNECT_MANAGEMENT_TOKEN` | 空，启用时必须设置 |
| `management_webui` | `ZJU_CONNECT_MANAGEMENT_WEBUI` | `true` |
| `sms_wait_timeout` | `ZJU_CONNECT_SMS_WAIT_TIMEOUT` | 180 秒 |
| `health_check_url` | `ZJU_CONNECT_HEALTH_CHECK_URL` | 空，启用时必须设置 |
| `health_check_interval` | `ZJU_CONNECT_HEALTH_CHECK_INTERVAL` | 60 秒 |
| `webhook_url` | `ZJU_CONNECT_WEBHOOK_URL` | 空，禁用 |

原有 `ZJU_CONNECT_USERNAME`、`ZJU_CONNECT_PASSWORD`、`ZJU_CONNECT_SERVER_ADDRESS`、`ZJU_CONNECT_SHADOWSOCKS_URL` 等变量同样可用。管理模式只输出预定义事件到 stdout/stderr。Webhook 向配置的 HTTPS 地址 POST JSON，字段为 `time`、`level` 和 `message`。可能的事件有 `connected`、`session_expired`、`sms_required`、`tunnel_unavailable`、`severe_error`。投递有超时和有界队列，失败时不会阻塞 VPN。

## REST API

所有 API 要求 `Authorization: Bearer <TOKEN>`。提交 JSON 时使用 `Content-Type: application/json`。状态变更接口返回 `202`，操作结果通过 `/api/status` 读取。状态冲突、重复提交、过期挑战返回 `409`，请求限额返回 `429`。完整登录之间默认至少间隔 15 秒。短信提交在当前挑战上只接受一次。

| 方法与路径 | 行为 |
| --- | --- |
| `GET /api/status` | 当前状态、VPN 地址、版本、认证/连接时间、虚拟 IP、代理监听状态和健康摘要 |
| `POST /api/login` | 开始登录 |
| `POST /api/sms` | 提交 `{"challenge_id":"…","code":"123456"}`，保留验证码前导零 |
| `POST /api/cancel` | 提交 `{"attempt_id":"…"}`，取消对应认证 |
| `POST /api/reconnect` | 结束现有会话后发起新登录，必要时等待短信 |
| `POST /api/logout` | 关闭当前会话或取消正在进行的登录 |
| `GET /api/health` | 实际校园资源探针结果。健康时返回 `200`，其他状态返回 `503` |
| `GET /api/logs` | 最近 128 条脱敏事件，按时间从旧到新 |
| `GET /api/info` | 版本、启动时间、协议和运行平台 |

状态依次可见 `disconnected`、`authenticating`、`waiting_sms`、`connecting`、`connected`、`reconnecting`、`expired` 或 `error`。实际状态转移取决于网关回复和健康检查。日志会保留过期事件，即使状态已经转入下一次认证。如果网关注销结果无法确认，状态仍清除本地连接并显示 `gateway_logout_unconfirmed`。

以下例子假设 `VPN_ADMIN` 是管理根 URL，`VPN_ADMIN_TOKEN` 由调用方从安全来源读取。

```sh
curl -fsS -H "Authorization: Bearer $VPN_ADMIN_TOKEN" "$VPN_ADMIN/api/status"
curl -fsS -X POST -H "Authorization: Bearer $VPN_ADMIN_TOKEN" "$VPN_ADMIN/api/login"
curl -fsS -H "Authorization: Bearer $VPN_ADMIN_TOKEN" "$VPN_ADMIN/api/status"
# 从 waiting_sms 状态读出 challenge_id。在终端输入 JSON 请求体，然后按 Ctrl+D。
curl -fsS -H "Authorization: Bearer $VPN_ADMIN_TOKEN" -H "Content-Type: application/json" \
  --data-binary @- "$VPN_ADMIN/api/sms"
```

## 构建与源码

项目沿用上游 [AGPL-3.0](../LICENSE)。分发二进制或允许其他用户通过网络使用修改后的程序时，请按许可证提供对应源码，并保留许可证文件。

```sh
go test ./...
go test -race ./...
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags '-s -w -X main.zjuConnectVersion=main-management' \
  -o dist/xmut-connect-linux-amd64 .
```

## 发布版本

发布时将改动提交并推送到 `main`，在同一个提交上创建并推送新的版本标签。版本标签采用 `vMAJOR.MINOR.PATCH`，预发布可用 `vMAJOR.MINOR.PATCH-rc.1`。标签备注会成为 Release 说明。

```sh
git push origin main
git tag -a vX.Y.Z -m "Describe the release"
git push origin refs/tags/vX.Y.Z
```

每次发布都检查标签对应的 [Release 工作流](https://github.com/shiftz300/xmut-connect/actions/workflows/release.yml) 和 [GitHub Release](https://github.com/shiftz300/xmut-connect/releases)。版本标签推送触发独立 Release 工作流。测试和平台构建全部通过后，Actions 会发布平台 ZIP、Linux AMD64 裸二进制和 `SHA256SUMS`。运行失败时重试对应任务。如果 GitHub 未生成运行记录，可在 Release 工作流的 “Run workflow” 中选中同一个标签再运行。Android AAR 仍可通过独立工作流构建。
