# rstar-codesign-svc 计划（v0.1）

## 目标

在一台专用 Mac（Mac Studio 或 Mac mini，不用 Docker）上跑一个 HTTP 服务。Developer ID 证书和公证凭据只放在这台 Mac 的钥匙串里。GitHub Actions 和 GitLab CI 上传未签名的 `.app`，拿回已签名、已公证、已 staple 的 zip 或 DMG。CI 里不存任何 Apple 密钥。

## 为什么不用现成工具

- `eclipse-cbi/macos-notarization-service`：只做公证，不签名；用 Apple ID 密码。
- `rcodesign` remote signing：每次要人手动加入会话，alpha，不能无人值守。
- 各种 GitHub Action（`lando/notarize-action` 等）：证书要放进 CI secrets。
- self-hosted runner 装在签名 Mac 上：runner 执行任意 workflow 代码，能读钥匙串。

## 语言

Go。标准库 `net/http`；`coreos/go-oidc/v3` 验 token；`yaml.v3` 读配置。签名和公证都调用 Apple 的命令行工具（`codesign`、`notarytool`、`stapler`、`hdiutil`、`ditto`）。

## 架构

```
CI job ──OIDC token + 未签名 zip──▶ Cloudflare Tunnel ──▶ codesign-svc（LaunchAgent，127.0.0.1:8787）
                                                          ├─ 验 token（iss、aud、exp、仓库、ref 白名单）
                                                          ├─ 安全解压，检查 bundle id
                                                          ├─ 从里往外 codesign（不用 --deep）
                                                          ├─ notarytool submit --wait → stapler
                                                          ├─ 可选：做 DMG，签名、公证、staple
                                                          └─ 审计日志（JSON lines）
CI job ◀──轮询状态，下载结果──
```

## API

- `POST /v1/jobs`：`Authorization: Bearer <OIDC token>`；multipart：`file`（含一个 `.app` 的 zip）、`profile`。返回 `202 {id}`；队列满返回 429。
- `GET /v1/jobs/{id}`：`queued|signing|notarizing|done|failed`、错误、公证 id、输出 sha256。只有创建它的仓库能读。
- `GET /v1/jobs/{id}/artifact?kind=zip|dmg`：下载结果。
- `GET /healthz`。

## 安全决定

1. 默认拒绝。白名单：`{issuer, repo, refs(glob), profiles}`。只允许受保护分支和 `v*` tag。
2. 签名身份、钥匙串、团队、entitlements、允许的 bundle id 都在服务端 profile 里。客户端不能传 entitlements。
3. 解压防路径穿越；拒绝指向 bundle 外的符号链接；上传大小上限（默认 2 GiB）。
4. 一次只跑一个任务；队列有上限；每个外部命令都有超时（codesign 5 分钟，公证 70 分钟，hdiutil 10 分钟）。
5. 服务只监听 127.0.0.1，通过 Cloudflare Tunnel 对外。
6. 审计日志记录 issuer、仓库、ref、commit、run URL、profile、bundle id、输入和输出 sha256、结果。
7. 开发模式的静态 token 默认关闭，开启时大声告警。

## 运行环境

- 专用 macOS 用户 `signer`，自动登录；服务作为 LaunchAgent 运行。LaunchDaemon 调用 codesign 会报 `errSecInternalComponent`。
- 专用钥匙串（不用 login 钥匙串）。可选：每个任务前从文件读密码解锁，不写日志。
- 公证凭据：`xcrun notarytool store-credentials`，用 ASC API key。
- 风险：开 FileVault 就不能自动登录，重启后要人工登录一次。

## 客户端

- `clients/sign.sh`：共用脚本（打包、上传、轮询、下载）。
- `clients/github/action.yml`：composite action，要 `permissions: id-token: write`。
- `clients/gitlab/sign.gitlab-ci.yml`：`id_tokens` 模板。

## 测试

`go vet`、`go test`、`gofmt`。单元测试覆盖白名单匹配、本地 OIDC issuer 验签、签名顺序、解压安全、队列满、任务归属、用假 runner 的端到端 API。不调用真的 codesign 和 notarytool。

## 之后

1. 在 Mac Studio 上部署：`signer` 用户、钥匙串、Developer ID 证书、notary 凭据、LaunchAgent、Cloudflare Tunnel。
2. 冷启动验收：重启后不手动操作，发一次签名请求；用不在白名单里的仓库或分支调用，确认被拒绝。
3. 第一个使用方改为调用本服务，保留本地签名作为备用。

## 计划评审（2026-10-19）

| 来源 | 发现 | 处理 |
|---|---|---|
| gpt-6.1-sol P1 | 只按 ref 名字匹配，没开保护的 tag 也能拿到签名 | 接受：规则加 `require_protected_ref`（默认开），检查 `ref_protected` 声明，缺了就拒绝 |
| gpt-6.1-sol P1 | `pull_request_target` 的 token 写的是主仓库和主分支，却可能在构建 fork 的代码 | 接受：规则加 `events` 白名单（GitHub `event_name`，GitLab `pipeline_source`），默认拒绝 PR 类事件；可选 `workflow_refs` 白名单 |
| gpt-6.1-sol P2 | OIDC token 几分钟就过期，客户端要轮询 90 分钟 | 接受：OIDC 只用于 `POST`；返回一次性 `job_token`（服务端只存 SHA-256），`GET` 用它 |
| gpt-6.1-sol P2 | zip 解压后可能很大、文件很多；保留的结果会占满磁盘 | 接受：限制解压后大小和文件数，每个任务有总时限，磁盘剩余不足时返回 503，最多保留 20 个结果 |
| gpt-6.1-sol P2 | 公证凭据在专用钥匙串里，`--keychain-profile` 默认找不到 | 接受：profile 加 `notary_keychain`，每次调用 `notarytool` 都传 `--keychain` |
| Gemini 4 P1 | 和 gpt 的 token 过期、受保护 ref、PR 事件相同 | 已接受；另外默认拒绝 `workflow_run` |
| Gemini 4 P1 | 给 dylib、framework 加 entitlements 会被拒 | 接受：entitlements 只给 .app/.xpc/.appex 的主程序 |
| Gemini 4 P1 | DMG 没签名、没公证 | 拒绝：brief 已写 DMG 要签名、公证、staple；代码评审时核对 |
| Gemini 4 P1 | `ditto -x` 先解压后检查，可经符号链接写到包外 | 接受：用 Go `archive/zip` 解压，逐条检查路径、符号链接、大小，不经符号链接写文件 |
| Gemini 4 P1 | 钥匙串会自动上锁；缺 partition list；`-p` 密码出现在 `ps` 里 | 接受：README 写 `set-keychain-settings`、`set-key-partition-list`；密码经 `security -i` 的 stdin 传 |
| Gemini 4 P2 | 按目录深度排序会签错 framework，会经 `Versions/Current` 重签 | 接受：遍历跳过符号链接，按包含关系从里往外，bundle 按根路径签 |
| Gemini 4 P2 | 跨 issuer 同名仓库能读别人的任务 | 已由 `job_token` 解决；任务另存 (issuer, repo) 供审计 |
| Gemini 4 P2 | zip 里多放一个 App 也会被签 | 接受：zip 根目录只能有一个 .app；嵌套 bundle id 必须以主 bundle id 开头 |
| Gemini 4 P2 | 先收 2 GiB 再验身份；工作目录保留 24 小时 | 接受：先验 token 和名额再读 body；任务结束立即删工作目录，只留结果 |
| Gemini 4 P2 | 客户端 `dmg` 参数和 API 对不上 | 接受：DMG 只由 profile 决定；状态返回 `artifacts` 表 |
| Gemini 4 P3 | OIDC token 可以重放 | 接受：缓存 (iss, jti) 到过期 |
| Gemini 4 P3 | `hdiutil` 因 Spotlight 报 Resource busy | 接受：放 `.metadata_never_index`；只在 Resource busy 时最多重试 2 次 |
| grok-4.7 | 没跑成：402，额度用完 | 无 |

## 代码评审与修复（2026-10-19）

| 来源 | 发现 | 处理 |
|---|---|---|
| gpt-6.1-sol P1 | GitLab 分支名写成 `refs/tags/v1` 可冒充 tag | 已修：优先用 `ref_path`；没有时拒绝以 `refs/` 开头的 ref |
| gpt-6.1-sol P1 | 先占名额、后验白名单，上传无时限 | 已修：白名单和重放检查在占名额前；`upload_timeout` 默认 30 分钟 |
| gpt-6.1-sol P1 | 续跑公证时不解锁钥匙串 | 已修：每个任务开头先解锁 |
| gpt-6.1-sol P2 | zip 中央目录先整个读进内存 | 已修：自己逐条走中央目录计数，超限立即停 |
| gpt-6.1-sol P2 | 磁盘预留不够、重启后预留可变负 | 已修：预留 = 上传 + 3 × 解压上限；解压时查剩余空间；预留加减成对 |
| gpt-6.1-sol P2 | 独立可执行文件拿不到 entitlements | 已修：`inherit_entitlements` 给嵌套 App 和 MH_EXECUTE；真实测试证实了这个问题 |
| gpt-6.1-sol P2 | 示例 `workflow_refs` 匹配不到 | 已修：示例改正，并有测试 |
| gpt-6.1-sol P2 | 客户端 curl 和 smoke 命令无超时 | 已修 |
| gpt-6.1-sol P2 | 429/503 也会用掉 OIDC token | 已修：先查重放，占到名额后再记录 |
| Gemini 4 | 20 分钟超时，无输出 | 用户决定跳过 |

## 真实端到端测试（2026-10-19）

在本机跑服务，用一个 Electron 应用（universal，约 800 MB，带独立 Node 二进制）测试：

- 第一次：签名、公证、staple、`spctl`、`syspolicy_check` 全部通过，但包里的 Node 启动即崩溃（hardened runtime 下没有 `allow-jit`）。公证查不出这种问题。
- 修复后：App 和 DMG 都是 `Notarized Developer ID`；客户端自检通过；smoke 命令运行 Node 的 JIT 循环通过；从 DMG 拷出 App 后台启动，Node 子进程正常运行、应用接口有响应；正常退出。
- 一次任务约 6 分钟（两次公证）。

## 参考 asc CLI（rorkai/App-Store-Connect-CLI）的做法

- 公证不用 `--wait`：先 `submit --no-wait` 拿到 submission id 并立刻存盘，再自己用 `notarytool info` 轮询。服务重启后接着轮询，不用重传。
- 公证凭据两种都支持：钥匙串 profile（带 `--keychain`），或 ASC API `.p8` 文件（`--key --key-id --issuer`，文件必须 0600）。
- 有界检查：文件数、总大小、路径长度都有上限；id 和 sha256 进命令行或 URL 前先校验格式。
- 工作目录 0700。
- 不照搬：asc 自己实现了 Notary REST API 和 S3 上传。我们调用 `notarytool`，代码更少。

## 不在 v0.1

`.pkg` 签名、多 worker、Web 界面、metrics。
