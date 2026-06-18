# 轻量备忘录 · 部署说明 
 
基于 Cloudflare Workers + D1 的网页版富文本备忘录。密码登录、左列表右编辑、多端共享，全程跑在 Cloudflare 免费额度内。 
 
--- 
 
## 一、所需文件 
 
部署只需三个文件，放在同一个文件夹里： 
 
| 文件 | 作用 | 
|---|---| 
| `worker.js` | 应用核心（后端 API + 前端页面，单文件） | 
| `wrangler.toml` | 部署配置（Worker 名称、D1 绑定） | 
| `schema.sql` | 数据库建表脚本 | 
 
--- 
 
## 二、前置条件 
 
- 安装 **Node.js LTS（18 及以上）**。 
- 拥有一个 **Cloudflare 账号**。 
- 所有命令用 `npx wrangler`，无需全局安装。 
 
> **国内网络提示**：若 `npx wrangler` 命令卡顿或超时，先在终端注入本地代理再执行： 
> - PowerShell：`$env:HTTPS_PROXY="http://127.0.0.1:你的端口"` 
> - Mac / Linux：`export https_proxy=http://127.0.0.1:你的端口` 
 
--- 
 
## 三、部署步骤 
 
### 1. 准备目录 
 
进入src目录，目录中有`worker.js`、`Wrangler.toml`（注意大小写，根据你的实际文件名）、`schema.sql`。 
 
### 2. 登录 Cloudflare 
 
```bash 
npx wrangler login 
``` 
 
浏览器弹出授权页，点 **Allow**。 
 
### 3. 创建 D1 数据库 
 
```bash 
npx wrangler d1 create notes-db 
``` 
 
输出中会有一行： 
 
``` 
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" 
``` 
 
复制这个 id，粘进 `Wrangler.toml` 的 `database_id` 一行，替换掉占位文字。 
 
### 4. 建表 
 
> ⚠️ 必须带 `--remote`，否则只会建在本地模拟库，线上仍是空表，登录后列表会报错。 
 
```bash 
npx wrangler d1 execute notes-db --remote --file=schema.sql 
``` 
 
提示确认时输入 `y` 回车。建好 `notes` 和 `login_attempts` 两张表。 
 
### 5. 首次部署 
 
> 必须先部署一次，Worker 存在之后才能设置 Secret。 
 
```bash 
npx wrangler deploy 
``` 
 
成功后会返回一个网址，形如 `https://notes.你的子域.workers.dev`。 
 
### 6. 设置机密（Secret） 
 
```bash 
npx wrangler secret put AUTH_PASSWORD 
# 回车后输入登录密码 
 
npx wrangler secret put SESSION_SECRET 
# 回车后粘贴一段随机长串 
``` 
 
`SESSION_SECRET` 生成方法（Mac / Linux）： 
 
```bash 
openssl rand -base64 48 
``` 
 
Windows 无 openssl 时，手敲一长串无规律字符即可（够长够乱）。 
 
> Secret 设置后**立即生效，无需重新部署**。此时打开网址即可使用。 
 
### 7.（强烈建议）绑定自定义域名 
 
`*.workers.dev` 在国内常因 DNS 污染无法访问。若你有域名托管在 Cloudflare： 
 
进入 **Workers & Pages → `notes` Worker → Settings → Domains & Routes → Add → Custom Domain**，填入子域名（如 `note.yourdomain.com`），几十秒后用该域名访问。 
 
--- 
 
## 四、验证 
 
1. 打开网址，输入第 6 步设置的 `AUTH_PASSWORD`。 
2. 点右上角 `+` 新建一条，写点内容，按 `Cmd/Ctrl + S` 保存。 
3. 刷新页面，确认内容还在。 
4. 换一台设备用同一密码登录，即可共享同一份数据。 
 
--- 
 
## 五、日常维护 
 
- **改了 `worker.js` 重新发布**： 
  ```bash 
  npx wrangler deploy 
  ``` 
- **改数据库结构**（如以后加字段）：再跑一次 `wrangler d1 execute ... --remote`。 
- **改配置或 Secret**：也可直接在 Cloudflare 网页端 Dashboard 操作，不一定用命令行。 
 
--- 
 
## 六、配置项说明 
 
### worker.js 顶部常量（按需调整） 
 
| 常量 | 默认值 | 含义 | 
|---|---|---| 
| `SESSION_TTL` | `7 天` | 登录会话有效期 | 
| `LOGIN_WINDOW_MIN` | `10` | 防爆破统计窗口（分钟） | 
| `LOGIN_MAX_FAILS` | `5` | 窗口内允许的登录失败次数 | 
| `LOGIN_BAN_SEC` | `900` | 触发后封禁时长（秒） | 
| `ENC_ENABLED` | `false` | 加密总开关，置 `true` 时启用静态加密 | 
 
### Secret（机密） 
 
| 名称 | 必需 | 含义 | 
|---|---|---| 
| `AUTH_PASSWORD` | 是 | 登录密码 | 
| `SESSION_SECRET` | 是 | 会话签名密钥（随机长串） | 
| `ENC_KEY` | 否 | 仅当 `ENC_ENABLED=true` 时需要 | 
 
--- 
 
## 七、易错点 
 
- `d1 execute` 漏了 `--remote` → 线上表没建，登录后列表报错。 
- `Wrangler.toml` 的 `binding` 必须是 `NOTE_DB`（对应 `worker.js` 里的 `env.NOTE_DB`）；改名就要两处同步改。 
- 没设 `AUTH_PASSWORD` / `SESSION_SECRET` 就访问 → 登录会一直失败。先设 Secret 再用。 
 
--- 
 
## 八、安全边界（请知悉） 
 
- **防爆破按 IP 限流**：用 Cloudflare 写入的 `CF-Connecting-IP` 作为键，客户端无法伪造。挡得住单机脚本爆破；换 IP 池 / 僵尸网络的分布式爆破挡不住，那需要再上 Turnstile 验证码或 Cloudflare WAF 限流规则。 
- **加密（启用后）是静态加密**：密钥存在服务端 Secret，用户无需输入。它能防 **D1 数据被单独导出 / 泄露**；**防不住** Worker 或 Cloudflare 账号本身被攻破（持有 `ENC_KEY` 者可解密）。它**不是端到端、不是零知识加密**。 
- **HTML 消毒**：编辑器对粘贴 / 加载 / 保存的富文本做了白名单消毒，防存储型 XSS。属于自用级别防护，**非 DOMPurify 级别**；若改造成多用户共享，必须替换为成熟的消毒库。 
 
--- 
 
## 免费额度参考 
 
| 资源 | 免费额度 | 
|---|---| 
| Workers 请求 | 10 万次 / 天 | 
| D1 存储 | 5 GB（单库上限 10 GB） | 
| D1 读 | 500 万行 / 天 | 
| D1 写 | 10 万行 / 天 | 
 
轻量文本备忘录的用量远低于上述上限。