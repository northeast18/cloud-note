-- 备忘录数据表
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL DEFAULT '',      -- 列表标题（从正文首行派生）
  content TEXT NOT NULL DEFAULT '',    -- 富文本 HTML
  format INTEGER NOT NULL DEFAULT 0,   -- 0=明文，1=以后启用加密时的密文
  updated_at INTEGER NOT NULL          -- 毫秒时间戳
);

-- 登录防爆破：按 IP 记录失败次数与封禁截止时间
CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  first_fail_at INTEGER NOT NULL DEFAULT 0,
  banned_until INTEGER NOT NULL DEFAULT 0
);

-- 共享只读快照表
CREATE TABLE IF NOT EXISTS shared_notes (
  id TEXT PRIMARY KEY,               -- 8位随机安全唯一 ID
  title TEXT NOT NULL,               -- 明文标题快照
  content TEXT NOT NULL,             -- 明文 HTML 正文快照
  created_at INTEGER NOT NULL,       -- 创建时间戳
  expires_at INTEGER                 -- 过期时间戳（可空）
);