function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json;charset=UTF-8",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store"
        }
    });
}

// ============================================================
// 权限模型（仅资讯 + 管理 + 设置）
// ============================================================
const ALL_PERMISSIONS = [
    "news.view", "news.fetch", "news.manage",
    "market.view", "market.refresh", "market.config",
    "settings.view", "settings.edit",
    "users.view", "users.create", "users.edit", "users.delete", "users.permissions"
];
const ROLE_PERMISSIONS = {
    admin: ALL_PERMISSIONS,
    user: ["news.view", "news.fetch", "news.manage", "market.view", "market.refresh", "settings.view", "users.view"],
    visitor: ["news.view", "market.view"]
};

function normalizePermissions(role, raw) {
    if (role === "admin") return [...ALL_PERMISSIONS];
    try {
        const parsed = Array.isArray(raw) ? raw : JSON.parse(raw || "[]");
        return parsed.filter(p => ALL_PERMISSIONS.includes(p));
    } catch { return [...(ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS.visitor)]; }
}
function publicUser(user) {
    return {
        id: user.id, username: user.username, display_name: user.display_name || "",
        role: user.role || "visitor", enabled: user.enabled !== 0,
        permissions: normalizePermissions(user.role, user.permissions), created_at: user.created_at
    };
}

// ============================================================
// 密码与 Token
//   密码：PBKDF2-HMAC-SHA256（10 万次迭代 + 16 字节随机盐）
//   Token：HS256 结构的 HMAC 签名（WebCrypto），密钥不进入令牌本体
// ============================================================
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEY_LEN = 32;      // 字节
const TOKEN_TTL_SEC = 24 * 60 * 60;

async function sha256(text) {
    const data = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function base64UrlEncode(str) { return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, ""); }
function base64UrlDecode(str) { str = str.replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "="; return atob(str); }
// 二进制安全的 base64（用于 salt / 摘要）
function bytesToB64(bytes) {
    let s = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
}
function b64ToBytes(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
// 随机盐：16 字节密码学安全随机数
function randomSaltB64() {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    return bytesToB64(b);
}
// 常量时间比较，避免时序侧信道
function timingSafeEqual(a, b) {
    const sa = String(a || ""), sb = String(b || "");
    if (sa.length !== sb.length) return false;
    let diff = 0;
    for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
    return diff === 0;
}

// PBKDF2 派生：口令 → 32 字节派生密钥
async function deriveKey(password, saltB64, iterations = PBKDF2_ITERATIONS) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(String(password)), "PBKDF2", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: b64ToBytes(saltB64), iterations, hash: "SHA-256" },
        keyMaterial,
        PBKDF2_KEY_LEN * 8
    );
    return bytesToB64(new Uint8Array(bits));
}
// 校验口令：兼容历史上「SHA256(口令:盐)」的旧哈希，校验通过后自动升级为 PBKDF2
async function verifyPassword(password, stored, salt) {
    if (!stored) return false;
    if (stored.startsWith("pbkdf2$")) {
        const [, iterStr, saltB64, hashB64] = stored.split("$");
        const iters = parseInt(iterStr, 10) || PBKDF2_ITERATIONS;
        const derived = await deriveKey(password, saltB64, iters);
        return timingSafeEqual(derived, hashB64);
    }
    // 旧格式回退：sha256(password + ":" + salt)
    return (await sha256(String(password) + ":" + salt)) === stored;
}
// 生成新的口令哈希（PBKDF2）
async function hashPassword(password) {
    const salt = randomSaltB64();
    const hash = await deriveKey(password, salt);
    return { salt, hash: `pbkdf2$${PBKDF2_ITERATIONS}$${salt}$${hash}` };
}

// HMAC-SHA256 签名（密钥不出现在令牌中）
async function hmacSign(secret, message) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw", enc.encode(String(secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
    return bytesToB64(new Uint8Array(sig));
}

function jwtSecret(env) {
    const secret = String(env && env.JWT_SECRET || "");
    return secret.length >= 32 ? secret : "";
}

async function generateToken(env, user) {
    const secret = jwtSecret(env);
    if (!secret) throw new Error("JWT_SECRET 未配置或长度不足 32 位");
    const now = Math.floor(Date.now() / 1000);
    // tv = 令牌版本号：改密 / 停用账号时递增，旧令牌随即失效（JWT 本身的主动吊销手段）
    const payload = { exp: now + TOKEN_TTL_SEC, iat: now, username: user.username, uid: user.id, tv: Number(user.token_version || 0) };
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signature = base64UrlEncode(await hmacSign(secret, encodedPayload));
    return `${encodedPayload}.${signature}`;
}

async function verifyToken(request, env) {
    const secret = jwtSecret(env);
    if (!secret) return false;
    const header = request.headers.get("Authorization");
    if (!header || !header.startsWith("Bearer ")) return false;
    const token = header.split(" ")[1];
    try {
        const [encodedPayload, signature] = token.split(".");
        if (!encodedPayload || !signature) return false;
        // 常量时间比较签名，防止时序攻击
        const expected = base64UrlEncode(await hmacSign(secret, encodedPayload));
        if (!timingSafeEqual(signature, expected)) return false;
        const payload = JSON.parse(base64UrlDecode(encodedPayload));
        if (!payload || payload.exp < Math.floor(Date.now() / 1000)) return false;
        return payload;
    } catch { return false; }
}
// 校验签名与过期，并回查用户：令牌有效性 = 签名/有效期通过 且 token_version 与库内一致
// 这样「改密码」「管理员停用账号」能立刻让已签发的旧令牌作废，而不是等 7 天自然过期
async function authUser(request, env) {
    const auth = await verifyToken(request, env);
    if (!auth) return null;
    let row = null;
    if (auth.uid) row = await env.DB.prepare("SELECT * FROM users WHERE id=? AND enabled=1").bind(auth.uid).first();
    if (!row) row = await env.DB.prepare("SELECT * FROM users WHERE username=? AND enabled=1").bind(auth.username).first();
    if (!row) return null;
    if (Number(auth.tv || 0) !== Number(row.token_version || 0)) return null;
    return { auth, row, user: publicUser(row) };
}
async function currentUser(request, env) {
    const r = await authUser(request, env);
    return r ? r.user : null;
}
function can(user, permission) { return !!user && (user.role === "admin" || user.permissions.includes(permission)); }
function forbidden() { return json({ error: "Forbidden", message: "当前账号没有此操作权限" }, 403); }

// ============================================================
// 登录限流：同一 IP+账号 在时间窗内失败过多即拒绝
//   状态存 D1（login_attempts），多 isolate / 多实例共享。
//   旧实现是 isolate 内的 Map，请求分散到不同实例就完全失效。
//   只按「失败次数」计数，密码正确时立即放行并清零，
//   避免管理员误输密码后被永久锁死。
//   限流表故障时放行（fail-open），不能让限流把所有人挡在门外。
// ============================================================
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_MAX_FAILS = 8;

function loginKey(ip, username) { return `${ip}|${String(username || "").toLowerCase()}`; }
async function loginBlocked(env, ip, username) {
    try {
        const row = await env.DB.prepare("SELECT fails, first_at FROM login_attempts WHERE key=?").bind(loginKey(ip, username)).first();
        if (!row) return false;
        if (Date.now() - Number(row.first_at || 0) > LOGIN_WINDOW_MS) return false;
        return Number(row.fails || 0) >= LOGIN_MAX_FAILS;
    } catch (e) { logWarn("login.blocked", e); return false; }
}
async function loginFail(env, ip, username) {
    const now = Date.now();
    const since = now - LOGIN_WINDOW_MS;
    try {
        // 单条 UPSERT 完成「窗口过期则重新计数」，顺带清理过期行，避免表无限增长
        await env.DB.batch([
            env.DB.prepare("INSERT INTO login_attempts(key,fails,first_at,updated_at) VALUES(?,1,?,?) ON CONFLICT(key) DO UPDATE SET fails=CASE WHEN first_at<? THEN 1 ELSE fails+1 END, first_at=CASE WHEN first_at<? THEN ? ELSE first_at END, updated_at=?")
                .bind(loginKey(ip, username), now, now, since, since, now, now),
            env.DB.prepare("DELETE FROM login_attempts WHERE first_at < ?").bind(since)
        ]);
    } catch (e) { logWarn("login.fail", e); }
}
async function loginReset(env, ip, username) {
    try { await env.DB.prepare("DELETE FROM login_attempts WHERE key=?").bind(loginKey(ip, username)).run(); }
    catch (e) { logWarn("login.reset", e); }
}

const DUMMY_SALT_B64 = btoa("0123456789abcdef");

function clientIp(request) {
    return request.headers.get("CF-Connecting-IP") || "local";
}

// ============================================================
// 认证处理
// ============================================================
async function handleLogin(request, env) {
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
    const { username, password } = await request.json().catch(() => ({}));
    if (!username || !password) return json({ success: false, message: "请输入账号和密码" });
    const ip = clientIp(request);
    // 先检查限流：防止锁定期间仍消耗 10 万次 PBKDF2 算力或被继续暴力撞库
    if (await loginBlocked(env, ip, username)) {
        return json({ success: false, message: "登录尝试过于频繁，请 10 分钟后再试" }, 429);
    }
    const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();

    if (!user) {
        // 账号不存在时同样执行一次完整 PBKDF2 派生，消除用户名枚举时序侧信道
        await deriveKey(String(password), DUMMY_SALT_B64, PBKDF2_ITERATIONS);
        await loginFail(env, ip, username);
        return json({ success: false, message: "账号或密码错误" });
    }
    const passOk = await verifyPassword(password, user.password, user.salt);
    if (!passOk) {
        await loginFail(env, ip, username);
        return json({ success: false, message: "账号或密码错误" });
    }
    if (user.enabled === 0) return json({ success: false, message: "账号已被停用" });
    await loginReset(env, ip, username);
    // 旧哈希首次登录成功后自动升级为 PBKDF2（同时递增 token_version，旧令牌失效）
    if (!String(user.password || "").startsWith("pbkdf2$")) {
        const up = await hashPassword(password);
        await env.DB.prepare("UPDATE users SET password=?, salt=?, token_version=token_version+1 WHERE id=?").bind(up.hash, up.salt, user.id).run();
        user.token_version = Number(user.token_version || 0) + 1;
    }
    return json({ success: true, token: await generateToken(env, user), user: publicUser(user), username: user.username });
}
// 公开注册已下线：账号由管理员在「用户管理」里创建，首个管理员由部署时的种子数据/脚本提供
async function handleChangePassword(request, env) {
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
    const cur = await authUser(request, env);
    if (!cur) return json({ error: "Unauthorized" }, 401);
    const { oldPassword, newPassword } = await request.json().catch(() => ({}));
    const user = cur.row;
    if (!(await verifyPassword(oldPassword, user.password, user.salt))) return json({ success: false, message: "原密码错误" });
    if (!newPassword || newPassword.length < 6) return json({ success: false, message: "新密码不能少于6位" });
    if (newPassword === oldPassword) return json({ success: false, message: "新密码不能与原密码相同" });
    const cred = await hashPassword(newPassword);
    // 递增 token_version：本次会话与其他设备上的旧令牌全部立即失效
    await env.DB.prepare("UPDATE users SET password = ?, salt = ?, token_version = token_version + 1 WHERE id=?")
        .bind(cred.hash, cred.salt, user.id).run();
    return json({ success: true, message: "密码修改成功，请重新登录" });
}
async function handleAuth(request, env) {
    const user = await currentUser(request, env);
    return json({ success: !!user, username: user ? user.username : null, user });
}

// ============================================================
// 采集参数定义（按数据域）
//   news  — 消息数据：关键词、频道过滤、抓取量、保留天数等
//   metal — 贵金属数据：采集品种、异动阈值、保留条数等
// ============================================================
const ACQUIRE_DOMAINS = [
    { key: "news", name: "消息数据", icon: "fa-newspaper", desc: "多平台财经资讯的抓取范围、频道过滤与去重留存策略" },
    { key: "metal", name: "贵金属数据", icon: "fa-coins", desc: "贵金属实时报价、K 线与金价快照的采集品种、异动阈值与留存策略" }
];

// ============================================================
// 银行金价（官网一手数据）—— Phase 1
//   交通银行官网公开上海黄金交易所贵金属行情。
//   与 metal_quotes 完全隔离：独立表 + 独立 API + 行情页独立区块。
//   数值列允许 NULL，原生表达「官网无此数据」；严禁伪造涨跌、混算单位、
//   把商品上架时间 / HTTP 头当作官方报价时间，或采集失败写 0 / 空价。
// ============================================================
// 当前仅启用交通银行官网源；历史数据源残留由 migrate() 幂等清理。
const BANK_GOLD_SOURCES = [
    {
        key: "bocom_metal", name: "交通银行 · 贵金属行情", endpoint: "https://www.bankcomm.com/SITE/getNobleMetalNew.do",
        group_name: "银行金价", domain: "metal", sort_order: 80,
        description: "交行官网展示的上海黄金交易所 Au99.99 基础价与 Au 系合约行情（元/克（推断））；非交行零售报价、非投资金条售价；含官方涨跌额，官网涨跌幅字段不可用，未展示；无投资金条零售价。"
    }
];
const BANK_GOLD_SOURCE_KEYS = BANK_GOLD_SOURCES.map(s => s.key);
// 已下线的银行源：仅用于 migrate() 清理残留数据源行与行情行，不参与采集
const BANK_GOLD_RETIRED_KEYS = ["ccb_bar", "ccb_account", "pingan_gold"];
const BANK_GOLD_DISCLAIMER = "以上为交通银行官网展示的上海黄金交易所行情（Au99.99 基础价 + Au 系合约），非交行零售报价、非投资金条售价，不能代表银行金条售价；官网未提供的涨跌幅按原样留空（—），不作推算；仅供参考，不构成投资建议。";

// 建库 DDL：worker.js migrate() 与 schema.sql 必须使用同一份文本（逐字一致）
const BANK_GOLD_TABLE_SQL = `CREATE TABLE IF NOT EXISTS bank_gold_quotes (
    symbol TEXT PRIMARY KEY,
    bank TEXT NOT NULL DEFAULT '',
    source_key TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    caliber TEXT NOT NULL DEFAULT '',
    price REAL,
    bid REAL,
    ask REAL,
    unit TEXT NOT NULL DEFAULT '',
    currency TEXT NOT NULL DEFAULT 'CNY',
    quote_stamp TEXT NOT NULL DEFAULT '',
    stamp_kind TEXT NOT NULL DEFAULT '',
    collected_at TEXT NOT NULL DEFAULT '',
    change REAL,
    change_pct REAL,
    prev_close REAL,
    open REAL,
    high REAL,
    low REAL,
    weight_g REAL,
    note TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ok',
    endpoint TEXT NOT NULL DEFAULT '',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`;

// ============================================================
// 迁移（向前兼容：仅创建资讯表与默认菜单/设置）
//   用实例级标志位缓存「已迁移」状态：同一 isolate 只执行一次；
//   实例回收后标志重置，此时靠下面的「版本闸门」再挡一次，不做任何写入。
//   失败时不置位，保证下次请求能重试。
// ============================================================
let migrateDone = false;
let migratePending = null;

// 迁移版本号 —— 改动 migrate() 里的建表 / 种子 / 兼容 UPDATE 时**必须**把它 +1。
//
// 为什么需要它：migrate() 里有 200+ 条 DDL / INSERT OR IGNORE / UPDATE。
//   D1 的计费口径是「写入行数」：
//     · INSERT OR IGNORE 即使因唯一键冲突被忽略，也照算一行写入；
//     · UPDATE 即使把字段写成原值，也照算一行写入；
//     · 只会被索引命中的表，每个索引还会再加一行。
//   每个新 isolate 都跑一遍完整迁移（cron 每分钟一个新实例 ≈ 每天 500~700 次），
//   单这一块每天就烧掉 5 万+ 写入行，直接把免费额度（10 万/天）打爆。
//   有了版本闸门，同一个库在版本号不变时只读一个 settings 键就返回，
//   真正的迁移只在「首次部署 / 版本号变更」时跑一次。
const MIGRATE_VERSION = "2026-11-19.3";

// 结构化日志：便于在 Cloudflare 日志面板中定位问题（替代被静默吞掉的异常）
function logWarn(scope, err, extra) {
    try {
        console.warn(`[${scope}] ${err && err.message ? err.message : String(err)}`, extra || "");
    } catch {}
}

// 检查并补齐缺失的列（兼容旧库）
// 表名与列名会被拼进 DDL，因此做严格白名单校验（仅允许内部定义的标识符）
const SAFE_IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
async function ensureColumns(env, table, cols) {
    if (!SAFE_IDENT.test(String(table || ""))) return false;
    for (const c of cols || []) {
        if (!SAFE_IDENT.test(String(c.name || ""))) return false;
    }
    try {
        const info = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
        const exist = new Set((info.results || []).map(r => r.name));
        for (const c of cols) {
            if (exist.has(c.name)) continue;
            await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${c.name} ${c.ddl}`).run();
        }
        return true;
    } catch (e) { logWarn("ensureColumns", e); return false; }
}

async function migrate(env) {
    if (migrateDone) return true;
    if (migratePending) return migratePending;
    migratePending = (async () => {
    // —— 版本闸门 ——
    //   settings 表已存在且版本号与代码一致 → 这个库已经迁移过了，直接返回（只读 1 行）。
    //   空库 / 旧库（没有 settings 表、或没有 migrate_ver）会落到下面的完整迁移。
    let gateHit = false;
    try {
        const stamp = await env.DB.prepare("SELECT value FROM settings WHERE key='migrate_ver'").first();
        gateHit = !!(stamp && String(stamp.value || "") === MIGRATE_VERSION);
    } catch (e) { /* settings 不存在：全新库，继续完整迁移 */ }
    if (gateHit) {
        migrateDone = true;
        // 跳过建表 / 种子，但「规则回填」必须照常自检：它们各自带 settings 版本戳，
        //   版本一致时只读 1 行；词表 / 屏蔽词变了才会重算。放在闸门里会永远跑不到。
        await runRuleBackfills(env);
        return true;
    }
    try {
        // 迁移分两阶段批量提交：
        //   D1 的 batch() 会先解析整批语句，同一批里「先建表、后引用该表」会直接报错，
        //   所以 ① 只提交 CREATE TABLE（互不依赖），并先补齐存量库缺失列，② 再提交索引 + 默认数据 + 兼容性 UPDATE。
        const db = [];
        const P = sql => env.DB.prepare(sql);
        const run = async (list) => {
            for (let i = 0; i < list.length; i += 50) await env.DB.batch(list.slice(i, i + 50));
        };

        // —— 阶段一：建表（含全部新列与 eco_events，空库直接具备完整列结构）——
        db.push(P("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, salt TEXT NOT NULL, display_name TEXT DEFAULT '', role TEXT NOT NULL DEFAULT 'visitor', permissions TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, token_version INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        db.push(P("CREATE TABLE IF NOT EXISTS menus (id INTEGER PRIMARY KEY AUTOINCREMENT, menu_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, url TEXT NOT NULL, icon TEXT DEFAULT 'fa-newspaper', parent_key TEXT DEFAULT '', sort_order INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, is_system INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        db.push(P("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')"));
        db.push(P("CREATE TABLE IF NOT EXISTS news (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, summary TEXT DEFAULT '', url TEXT DEFAULT '', source TEXT DEFAULT '', platform TEXT DEFAULT '', channel TEXT NOT NULL DEFAULT 'other', keywords TEXT DEFAULT '', published_at TEXT, fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, hash TEXT UNIQUE, starred INTEGER NOT NULL DEFAULT 0, note TEXT DEFAULT '', symbols TEXT DEFAULT '', sentiment TEXT DEFAULT '', sentiment_map TEXT DEFAULT '', relevant INTEGER NOT NULL DEFAULT 1, impact TEXT DEFAULT '', key_score INTEGER NOT NULL DEFAULT 0, is_key INTEGER NOT NULL DEFAULT 0, key_reasons TEXT DEFAULT '', key_brief TEXT DEFAULT '')"));
        db.push(P("CREATE TABLE IF NOT EXISTS metal_quotes (symbol TEXT PRIMARY KEY, name TEXT NOT NULL, short_name TEXT DEFAULT '', market TEXT DEFAULT '', kind TEXT DEFAULT '', price REAL NOT NULL DEFAULT 0, prev_close REAL NOT NULL DEFAULT 0, open REAL NOT NULL DEFAULT 0, high REAL NOT NULL DEFAULT 0, low REAL NOT NULL DEFAULT 0, bid REAL NOT NULL DEFAULT 0, ask REAL NOT NULL DEFAULT 0, volume REAL NOT NULL DEFAULT 0, open_interest REAL NOT NULL DEFAULT 0, change REAL NOT NULL DEFAULT 0, change_pct REAL NOT NULL DEFAULT 0, amplitude REAL NOT NULL DEFAULT 0, unit TEXT DEFAULT '', currency TEXT DEFAULT 'USD', source TEXT DEFAULT 'sina', quote_date TEXT DEFAULT '', quote_time TEXT DEFAULT '', updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        db.push(P("CREATE TABLE IF NOT EXISTS metal_history (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, price REAL NOT NULL DEFAULT 0, quote_time TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        // 品种注册表：贵金属 / 稀有金属的可配置品种池（内置品种建库时写入，之后以库为准）
        db.push(P("CREATE TABLE IF NOT EXISTS metal_instruments (symbol TEXT PRIMARY KEY, sina TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', short_name TEXT NOT NULL DEFAULT '', market TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', unit TEXT NOT NULL DEFAULT '', currency TEXT NOT NULL DEFAULT 'CNY', em TEXT NOT NULL DEFAULT '', chain TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL DEFAULT 'rare', enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT '', updated_at TEXT DEFAULT '')"));
        db.push(P("CREATE TABLE IF NOT EXISTS metal_snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, batch_at TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 0, xau_price REAL NOT NULL DEFAULT 0, xau_change_pct REAL NOT NULL DEFAULT 0, au0_price REAL NOT NULL DEFAULT 0, au0_change_pct REAL NOT NULL DEFAULT 0, autd_price REAL NOT NULL DEFAULT 0, autd_change_pct REAL NOT NULL DEFAULT 0, xag_price REAL NOT NULL DEFAULT 0, silver_price REAL NOT NULL DEFAULT 0, usdcny REAL NOT NULL DEFAULT 0, gold_silver_ratio REAL NOT NULL DEFAULT 0, shanghai_premium REAL NOT NULL DEFAULT 0, day_high REAL NOT NULL DEFAULT 0, day_low REAL NOT NULL DEFAULT 0, prev_xau_price REAL NOT NULL DEFAULT 0, prev_base_price REAL NOT NULL DEFAULT 0, base_symbol TEXT DEFAULT '', base_name TEXT DEFAULT '', base_price REAL NOT NULL DEFAULT 0, base_change_pct REAL NOT NULL DEFAULT 0, base_unit TEXT DEFAULT '', interval_change REAL NOT NULL DEFAULT 0, interval_change_pct REAL NOT NULL DEFAULT 0, level TEXT DEFAULT 'normal', summary TEXT DEFAULT '', detail TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        db.push(P("CREATE TABLE IF NOT EXISTS data_sources (id INTEGER PRIMARY KEY AUTOINCREMENT, source_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, group_name TEXT DEFAULT '其它', domain TEXT NOT NULL DEFAULT 'news', endpoint TEXT DEFAULT '', description TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, last_status TEXT DEFAULT '', last_checked_at TEXT DEFAULT '', last_latency_ms INTEGER NOT NULL DEFAULT 0, last_message TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        db.push(P("CREATE TABLE IF NOT EXISTS fetch_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, task_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT DEFAULT '', domain TEXT NOT NULL DEFAULT 'news', interval_min INTEGER NOT NULL DEFAULT 30, interval_sec INTEGER, enabled INTEGER NOT NULL DEFAULT 1, run_at_hour INTEGER NOT NULL DEFAULT -1, last_run_at TEXT DEFAULT '', last_status TEXT DEFAULT '', last_message TEXT DEFAULT '', next_run_at TEXT DEFAULT '', run_count INTEGER NOT NULL DEFAULT 0, fail_count INTEGER NOT NULL DEFAULT 0, fail_streak INTEGER NOT NULL DEFAULT 0, lease_until INTEGER NOT NULL DEFAULT 0, sort_order INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        db.push(P("CREATE TABLE IF NOT EXISTS fetch_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_key TEXT NOT NULL, trigger_type TEXT NOT NULL DEFAULT 'cron', started_at TEXT NOT NULL, finished_at TEXT DEFAULT '', duration_ms INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'success', fetched INTEGER NOT NULL DEFAULT 0, inserted INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0, message TEXT DEFAULT '')"));
        db.push(P("CREATE TABLE IF NOT EXISTS acquire_options (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, option_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, value TEXT DEFAULT '', value_type TEXT DEFAULT 'text', options TEXT DEFAULT '', meta TEXT DEFAULT '', description TEXT DEFAULT '', sort_order INTEGER NOT NULL DEFAULT 0, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        // 银行金价独立表：数值列可空，与 metal_quotes 的 NOT NULL DEFAULT 0 彻底隔离
        db.push(P(BANK_GOLD_TABLE_SQL));
        // 登录失败限流状态（原来放 isolate 内存，多实例下等于没限流）
        db.push(P("CREATE TABLE IF NOT EXISTS login_attempts (key TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)"));
        // 聚合结果缓存（跨 isolate / 跨机房共享：一次轮询只读 1 行，而不是重扫 news 表）
        db.push(P("CREATE TABLE IF NOT EXISTS agg_cache (key TEXT PRIMARY KEY, val TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL DEFAULT 0)"));
        // 价格预警（目标价 / 涨跌幅阈值）
        db.push(P("CREATE TABLE IF NOT EXISTS price_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, name TEXT DEFAULT '', direction TEXT NOT NULL DEFAULT 'above', target REAL NOT NULL DEFAULT 0, cooldown_min INTEGER NOT NULL DEFAULT 30, enabled INTEGER NOT NULL DEFAULT 1, note TEXT DEFAULT '', trigger_count INTEGER NOT NULL DEFAULT 0, last_trigger_epoch INTEGER NOT NULL DEFAULT 0, last_trigger_at TEXT DEFAULT '', last_trigger_price REAL NOT NULL DEFAULT 0, created_by TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        // 站内通知（dedup_key 唯一，冷却窗口内同一事件只落一条）
        db.push(P("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL DEFAULT 'system', level TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL, body TEXT DEFAULT '', ref_type TEXT DEFAULT '', ref_id INTEGER NOT NULL DEFAULT 0, dedup_key TEXT DEFAULT '', read INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        // 推送通道（企业微信 / 钉钉 / 飞书 / 通用 Webhook）
        db.push(P("CREATE TABLE IF NOT EXISTS notify_channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, channel_type TEXT NOT NULL DEFAULT 'wecom', webhook_url TEXT NOT NULL DEFAULT '', secret TEXT DEFAULT '', events TEXT DEFAULT 'alert', enabled INTEGER NOT NULL DEFAULT 1, last_status TEXT DEFAULT '', last_sent_at TEXT DEFAULT '', last_message TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        // 持仓（按 created_by 隔离，管理员可见全部）
        db.push(P("CREATE TABLE IF NOT EXISTS positions (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, name TEXT DEFAULT '', qty REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0, fee REAL NOT NULL DEFAULT 0, opened_at TEXT DEFAULT '', note TEXT DEFAULT '', created_by TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        // 自选观察池：投资决策的入口（先看 → 再决定建仓），按用户隔离
        db.push(P("CREATE TABLE IF NOT EXISTS watchlist (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, note TEXT DEFAULT '', created_by TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(created_by, symbol))"));
        // 建仓计划：自选 / 持仓的「准备怎么买」——目标价、止损价、分批价位
        db.push(P("CREATE TABLE IF NOT EXISTS trade_plans (id INTEGER PRIMARY KEY AUTOINCREMENT, symbol TEXT NOT NULL, name TEXT DEFAULT '', target_price REAL NOT NULL DEFAULT 0, stop_loss REAL NOT NULL DEFAULT 0, entry_price REAL NOT NULL DEFAULT 0, tranches TEXT DEFAULT '', status TEXT DEFAULT 'planning', note TEXT DEFAULT '', created_by TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        // 财经日历（经济事件日程；记录到点提醒状态）
        db.push(P("CREATE TABLE IF NOT EXISTS eco_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_at TEXT NOT NULL, country TEXT NOT NULL DEFAULT '美国', name TEXT NOT NULL, importance INTEGER NOT NULL DEFAULT 2, previous TEXT DEFAULT '', forecast TEXT DEFAULT '', actual TEXT DEFAULT '', unit TEXT DEFAULT '', note TEXT DEFAULT '', notified INTEGER NOT NULL DEFAULT 0, created_by TEXT DEFAULT '', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"));
        await run(db);
        db.length = 0;

        // —— 阶段一补列（必须在创建索引前执行，否则旧库缺少 is_key / relevant 列会导致阶段二建索引失败）——
        await ensureColumns(env, "metal_snapshots", [
            { name: "prev_base_price", ddl: "REAL NOT NULL DEFAULT 0" },
            { name: "base_symbol", ddl: "TEXT DEFAULT ''" },
            { name: "base_name", ddl: "TEXT DEFAULT ''" },
            { name: "base_price", ddl: "REAL NOT NULL DEFAULT 0" },
            { name: "base_change_pct", ddl: "REAL NOT NULL DEFAULT 0" },
            { name: "base_unit", ddl: "TEXT DEFAULT ''" }
        ]);
        await ensureColumns(env, "news", [
            { name: "symbols", ddl: "TEXT DEFAULT ''" },
            { name: "sentiment", ddl: "TEXT DEFAULT ''" },
            { name: "sentiment_map", ddl: "TEXT DEFAULT ''" },
            { name: "relevant", ddl: "INTEGER NOT NULL DEFAULT 1" },
            { name: "impact", ddl: "TEXT DEFAULT ''" },
            { name: "key_score", ddl: "INTEGER NOT NULL DEFAULT 0" },
            { name: "is_key", ddl: "INTEGER NOT NULL DEFAULT 0" },
            { name: "key_reasons", ddl: "TEXT DEFAULT ''" },
            { name: "key_brief", ddl: "TEXT DEFAULT ''" }
        ]);
        await ensureColumns(env, "data_sources", [{ name: "domain", ddl: "TEXT NOT NULL DEFAULT 'news'" }]);
        await ensureColumns(env, "fetch_tasks", [
            { name: "domain", ddl: "TEXT NOT NULL DEFAULT 'news'" },
            { name: "fail_streak", ddl: "INTEGER NOT NULL DEFAULT 0" },
            { name: "interval_sec", ddl: "INTEGER" },
            { name: "lease_until", ddl: "INTEGER NOT NULL DEFAULT 0" }
        ]);
        await ensureColumns(env, "users", [{ name: "token_version", ddl: "INTEGER NOT NULL DEFAULT 0" }]);

        // —— 阶段二：索引 + 默认数据（此时所有表和列都已存在，可安全同批）——
        db.push(P("CREATE INDEX IF NOT EXISTS idx_news_pub ON news(published_at DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_news_channel ON news(channel, published_at DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_news_source ON news(source)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_news_starred ON news(starred, published_at DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_news_day ON news(substr(published_at,1,10))"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_news_key ON news(is_key, key_score DESC, published_at DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_news_rel ON news(relevant, published_at DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_metal_history_sym ON metal_history(symbol, id DESC)"));
        db.push(P("CREATE UNIQUE INDEX IF NOT EXISTS idx_metal_snap_batch ON metal_snapshots(batch_at)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_metal_snap_epoch ON metal_snapshots(epoch DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_fetch_logs_task ON fetch_logs(task_key, id DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_fetch_logs_started ON fetch_logs(started_at DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_alerts_enabled ON price_alerts(enabled, symbol)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(id DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(read, id DESC)"));
        db.push(P("CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedup ON notifications(dedup_key) WHERE dedup_key <> ''"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_eco_events_at ON eco_events(event_at)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_positions_owner ON positions(created_by, id DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_watchlist_owner ON watchlist(created_by, symbol)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_trade_plans_owner ON trade_plans(created_by, id DESC)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_trade_plans_symbol ON trade_plans(symbol)"));
        db.push(P("CREATE INDEX IF NOT EXISTS idx_acquire_options_domain ON acquire_options(domain, sort_order)"));
        // 菜单：财经日历 / 数据采集（两个二级）/ 消息中心 / 用户管理 / 系统设置
        //   注：「数据大屏 / 实时行情 / 稀有金属」已合并进投资工作台的标签页，不再作为独立菜单
        const menuDefaults = [
            ["calendar", "财经日历", "#calendar", "fa-calendar-days", "", 8],
            ["acquire", "数据采集", "#acquire", "fa-download", "", 9],
            ["acquire-news", "消息数据", "#acquire-news", "fa-newspaper", "acquire", 10],
            ["acquire-metal", "贵金属数据", "#acquire-metal", "fa-coins", "acquire", 11],
            ["news", "消息中心", "#news", "fa-newspaper", "", 20],
            ["users", "用户管理", "#users", "fa-users", "", 50],
            ["settings", "系统设置", "#settings", "fa-sliders", "", 60]
        ];
        for (const m of menuDefaults) {
            db.push(env.DB.prepare("INSERT OR IGNORE INTO menus(menu_key,name,url,icon,parent_key,sort_order,enabled,is_system) VALUES(?,?,?,?,?,?,1,1)")
                .bind(m[0], m[1], m[2], m[3], m[4], m[5]));
            // 规范化菜单名称 / 图标 / 父子关系 / 排序（历史库中旧记录可能残留旧值）
            db.push(env.DB.prepare("UPDATE menus SET name=?,url=?,icon=?,parent_key=?,sort_order=?,enabled=1 WHERE menu_key=?")
                .bind(m[1], m[2], m[3], m[4], m[5], m[0]));
        }
        // 统一清理不再使用的历史菜单记录，导航以当前菜单定义为准。
        db.push(P("DELETE FROM menus WHERE menu_key='metals'"));
        db.push(P("DELETE FROM menus WHERE menu_key IN ('dashboard','quote','rare','feed')"));
        const settingDefaults = [
            ["system_name", "稀有金属投资咨询平台"],
            ["news_keywords", DEFAULT_NEWS_KEYWORDS.join(",")],
            ["news_sources", "eastmoney,sina,wscn"],
            ["last_news_refresh", ""],
            ["last_metal_refresh", ""],
            ["last_metal_snapshot", ""],
            ["metal_snapshot_interval", "30"]
        ];
        for (const s of settingDefaults) {
            db.push(env.DB.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").bind(s[0], s[1]));
        }
        const srcDefaults = [
            ["sina_quote", "新浪财经 · 实时行情", "贵金属行情", "metal", "https://hq.sinajs.cn/list=nf_AU0,nf_AG0", "沪金 / 沪银实时报价 + 美元兑人民币汇率", 10],
            ["em_kline", "东方财富 · 历史K线", "历史K线", "metal", "https://push2his.eastmoney.com/api/qt/stock/kline/get", "日K / 周K / 月K / 5分钟K线，支撑详细数据页的蜡烛图与分时图", 20],
            ["eastmoney", "东方财富 · 财经搜索", "财经资讯", "news", "https://search-api-web.eastmoney.com/search/jsonp", "按关注关键词 + 泛化 AI 主题词全网搜索财经资讯，覆盖媒体最广", 30],
            ["sina_news", "新浪财经 · 7×24快讯", "财经资讯", "news", "https://zhibo.sina.com.cn/api/zhibo/feed", "宏观政策与盘中异动快讯", 40],
            ["wscn", "华尔街见闻 · 7×24", "财经资讯", "news", "https://api-one-wscn.awtmt.com/apiv1/content/lives", "全球宏观与商品频道快讯", 50],
            ["bocom_metal", "交通银行 · 贵金属行情", "银行金价", "metal", "https://www.bankcomm.com/SITE/getNobleMetalNew.do", "交行官网展示的上海黄金交易所 Au99.99 基础价与 Au 系合约行情（元/克（推断））；非交行零售报价、非投资金条售价；含官方涨跌额，官网涨跌幅字段不可用，未展示；无投资金条零售价。", 80]
        ];
        for (const s of srcDefaults) {
            db.push(env.DB.prepare("INSERT OR IGNORE INTO data_sources(source_key,name,group_name,domain,endpoint,description,enabled,sort_order) VALUES(?,?,?,?,?,?,1,?)")
                .bind(s[0], s[1], s[2], s[3], s[4], s[5], s[6]));
        }
        // 兼容旧库：为已有数据源/任务补齐 domain 字段
        db.push(P("UPDATE data_sources SET domain='metal' WHERE source_key IN ('sina_quote','em_kline') AND (domain IS NULL OR domain='' OR domain='news')"));
        db.push(P("UPDATE fetch_tasks SET domain='metal' WHERE task_key IN ('metal_snapshot','metal_quote') AND (domain IS NULL OR domain='' OR domain='news')"));
        const taskDefaults = [
            ["metal_snapshot", "金价快照采集", "拉取贵金属实时行情，生成一条金价快照并计算环比涨跌、异动等级与处理结论，写入 metal_snapshots", "metal", 30, 10],
            ["metal_quote", "贵金属行情刷新", "拉取贵金属实时报价并更新行情看板的现价、涨跌幅、振幅、持仓量等字段", "metal", 10, 20],
            ["news_crawl", "财经资讯抓取", "按关注关键词从启用的资讯数据源抓取财经快讯，按标题指纹去重后入库", "news", 10, 30],
            ["bank_gold_quote", "银行金价采集", "抓取交通银行官网贵金属行情并写入 bank_gold_quotes", "metal", 10, 40]
        ];
        for (const t of taskDefaults) {
            db.push(env.DB.prepare("INSERT OR IGNORE INTO fetch_tasks(task_key,name,description,domain,interval_min,interval_sec,enabled,run_at_hour,sort_order) VALUES(?,?,?,?,?,?,1,-1,?)")
                .bind(t[0], t[1], t[2], t[3], t[4], t[4] * 60, t[5]));
        }
        // 默认采集参数
        for (const o of ACQUIRE_OPTION_DEFAULTS) {
            db.push(env.DB.prepare("INSERT OR IGNORE INTO acquire_options(domain,option_key,name,value,value_type,options,meta,description,sort_order) VALUES(?,?,?,?,?,?,?,?,?)")
                .bind(o.domain, o.key, o.name, o.value, o.type, o.options || "", o.meta || "", o.description || "", o.sort));
        }
        // 品种注册表种子：内置贵金属 / 稀有金属品种各写一行，之后由用户在页面上增删改
        //   兼容历史数据库中的停用品种状态，迁移阶段会继续清理其行情数据。
        for (const i of METAL_INSTRUMENTS) {
            db.push(env.DB.prepare("INSERT OR IGNORE INTO metal_instruments(symbol,sina,name,short_name,market,kind,unit,currency,em,chain,scope,enabled,sort_order,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'','metal',?,?,1,?,?)")
                .bind(i.symbol, i.sina, i.name, i.short_name, i.market, i.kind, i.unit, i.currency, i.em || "",
                    i.symbol === "XPD" ? 0 : 1,
                    (METAL_ORDER.indexOf(i.symbol) + 1) * 10, nowBeijing(), nowBeijing()));
        }
        for (let k = 0; k < RARE_INSTRUMENTS.length; k++) {
            const i = RARE_INSTRUMENTS[k];
            db.push(env.DB.prepare("INSERT OR IGNORE INTO metal_instruments(symbol,sina,name,short_name,market,kind,unit,currency,em,chain,scope,enabled,sort_order,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'rare',1,?,1,?,?)")
                .bind(i.symbol, i.sina, i.name, i.short_name, i.market, i.kind, i.unit, i.currency, i.em || "", i.chain || "",
                    (k + 1) * 10, nowBeijing(), nowBeijing()));
        }
        await run(db);

        // 快照新增基准品种字段；PRAGMA 需逐表判断，不能进 batch
        await ensureColumns(env, "metal_snapshots", [
            { name: "prev_base_price", ddl: "REAL NOT NULL DEFAULT 0" },
            { name: "base_symbol", ddl: "TEXT DEFAULT ''" },
            { name: "base_name", ddl: "TEXT DEFAULT ''" },
            { name: "base_price", ddl: "REAL NOT NULL DEFAULT 0" },
            { name: "base_change_pct", ddl: "REAL NOT NULL DEFAULT 0" },
            { name: "base_unit", ddl: "TEXT DEFAULT ''" }
        ]);
        // 兼容旧库：消息关联标的（逗号分隔的品种代码，如 "AU0"）
        await ensureColumns(env, "news", [
            { name: "symbols", ddl: "TEXT DEFAULT ''" },
            // 消息情绪：整体倾向（bullish/bearish/neutral）+ 按标的的细分倾向
            { name: "sentiment", ddl: "TEXT DEFAULT ''" },
            { name: "sentiment_map", ddl: "TEXT DEFAULT ''" },
            // 相关性标记：标题是否命中「品种 / 中国政策 / 金价驱动 / AI 相关（直接+间接）」四类白名单（1 相关 / 0 无关）
            //   入库时算好存成标记位，查询只判这一个字段（D1 单条 SQL 最多 100 个绑定参数，拼 100+ 个 LIKE 会超限）
            { name: "relevant", ddl: "INTEGER NOT NULL DEFAULT 1" },
            // 消息影响研判 JSON：方向 / 强度 / 影响标的 / 传导链 / 依据（与 sentiment 并存，互不污染）
            { name: "impact", ddl: "TEXT DEFAULT ''" },
            // 重点消息标记：key_score 综合分（0-100）/ is_key 是否点亮 / key_reasons 挑选理由 JSON
            { name: "key_score", ddl: "INTEGER NOT NULL DEFAULT 0" },
            { name: "is_key", ddl: "INTEGER NOT NULL DEFAULT 0" },
            { name: "key_reasons", ddl: "TEXT DEFAULT ''" },
            { name: "key_brief", ddl: "TEXT DEFAULT ''" }
        ]);
        // 兼容旧库：补齐 domain 列
        await ensureColumns(env, "data_sources", [{ name: "domain", ddl: "TEXT NOT NULL DEFAULT 'news'" }]);
        await ensureColumns(env, "fetch_tasks", [
            { name: "domain", ddl: "TEXT NOT NULL DEFAULT 'news'" },
            { name: "fail_streak", ddl: "INTEGER NOT NULL DEFAULT 0" },
            // 采集间隔改按秒（interval_sec 为唯一口径；interval_min 继续同步写，兼容旧代码与回滚）
            { name: "interval_sec", ddl: "INTEGER" },
            // 执行租约：任务被某个 isolate 领取后写入到期时间（epoch 毫秒），
            //   0 表示空闲；防止 cron / 页面补采 / 手动采集在多个 isolate 并发重复执行。
            { name: "lease_until", ddl: "INTEGER NOT NULL DEFAULT 0" }
        ]);
        // 存量库：用旧的分钟值回填秒（幂等，只在为空/非法时写）
        try {
            await env.DB.prepare("UPDATE fetch_tasks SET interval_sec = CAST(interval_min AS INTEGER) * 60 WHERE interval_sec IS NULL OR interval_sec <= 0").run();
        } catch (e) { logWarn("migrate.taskIntervalSec", e); }

        // 频道表同步：options 由 NEWS_CHANNELS 动态生成，存量库需要显式重写；
        //   勾选串补齐当前默认频道，历史未知频道归入 other。
        try {
            const chOpts = JSON.stringify(Object.keys(NEWS_CHANNELS).map(k => ({ value: k, label: NEWS_CHANNELS[k].label })));
            await env.DB.batch([
                env.DB.prepare("UPDATE acquire_options SET options=? WHERE option_key='news_channels'").bind(chOpts),
                env.DB.prepare("UPDATE news SET channel='other' WHERE channel='crypto'")
            ]);
            const chRow = await env.DB.prepare("SELECT value FROM acquire_options WHERE option_key='news_channels'").first();
            const chOld = chRow ? String(chRow.value || "") : "";
            const chParts = chOld.split(",").map(x => x.trim()).filter(x => x && x !== "crypto" && NEWS_CHANNELS[x]);
            // 留空是「不过滤」，不能凭空塞 ai；非空勾选串才补上新频道
            if (chOld.trim() && !chParts.includes("ai")) chParts.push("ai");
            const chNew = chParts.join(",");
            if (chNew !== chOld) await env.DB.prepare("UPDATE acquire_options SET value=? WHERE option_key='news_channels'").bind(chNew).run();
            // 历史 AI / 算力消息原来多落在 equity / other，改标 ai，
            //   否则默认只勾选 metal / macro / forex / policy / ai 时它们仍会被频道过滤挡掉。
            //   SQL LIKE 用中文 / 长词，不放裸 AI（'%ai%' 会误伤 said / air），也不放具体人名。
            const AI_HISTORY_TERMS = ["人工智能", "算力", "GPU", "显卡", "AI芯片", "半导体", "数据中心", "液冷", "光模块", "大模型", "AIGC", "具身智能", "HBM", "CUDA", "英伟达", "NVIDIA"];
            const aiCond = AI_HISTORY_TERMS.map(w => "title LIKE '%" + w.replace(/'/g, "''") + "%'").join(" OR ");
            await env.DB.prepare("UPDATE news SET channel='ai' WHERE channel IN ('equity','fund','bond','property','other') AND (" + aiCond + ")").run();
        } catch (e) { logWarn("migrate.newsChannels", e); }

        // AI 相关采集口径（2026-11-12 用户指令，同日二次调整改为泛化主题词）：存量库显式幂等迁移。
        //   只改 DEFAULT_NEWS_KEYWORDS / optionDefs 对已有库无效（INSERT OR IGNORE），
        //   所以关键词、检索上限、描述、屏蔽词都要在这里收口；自定义配置尽量不覆盖。
        //   两代旧默认值都要迁：15 词（无 AI）与 21 词（含人名 / 公司名）→ 23 词泛化主题词。
        try {
            const newKeywords = DEFAULT_NEWS_KEYWORDS.join(",");
            await env.DB.batch([
                env.DB.prepare("UPDATE settings SET value=? WHERE key='news_keywords' AND value=?").bind(newKeywords, LEGACY_NEWS_KEYWORDS),
                env.DB.prepare("UPDATE acquire_options SET value=? WHERE option_key='news_keywords' AND value=?").bind(newKeywords, LEGACY_NEWS_KEYWORDS),
                env.DB.prepare("UPDATE settings SET value=? WHERE key='news_keywords' AND value=?").bind(newKeywords, LEGACY_NEWS_KEYWORDS_V2),
                env.DB.prepare("UPDATE acquire_options SET value=? WHERE option_key='news_keywords' AND value=?").bind(newKeywords, LEGACY_NEWS_KEYWORDS_V2),
                // 「美元指数」从关注关键词彻底移除（2026-11-13 用户指令）。种子是 INSERT OR IGNORE，
                //   且上面的 legacy 迁移只认 15/21 词旧值，认不出「23 词含美元指数」的存量值，
                //   所以这里按词边界显式剔除；用 ','||value||',' 精确匹配独立词条，不误伤自定义词，
                //   替换后不再含该词即不再命中，幂等、重启重跑无副作用。
                env.DB.prepare("UPDATE settings SET value=trim(replace(replace(','||value||',', ',美元指数,', ','), ',,', ','), ',') WHERE key='news_keywords' AND ','||value||',' LIKE '%,美元指数,%'"),
                env.DB.prepare("UPDATE acquire_options SET value=trim(replace(replace(','||value||',', ',美元指数,', ','), ',,', ','), ',') WHERE option_key='news_keywords' AND ','||value||',' LIKE '%,美元指数,%'"),
                env.DB.prepare("UPDATE acquire_options SET description=? WHERE option_key='news_keywords'").bind(NEWS_KEYWORDS_DESC),
                env.DB.prepare("UPDATE acquire_options SET value=? WHERE option_key='news_max_keywords' AND value=?").bind("24", LEGACY_NEWS_MAX_KEYWORDS),
                env.DB.prepare("UPDATE acquire_options SET meta=? WHERE option_key='news_max_keywords'").bind(JSON.stringify({ min: 1, max: 24, step: 1 })),
                env.DB.prepare("UPDATE acquire_options SET description=? WHERE option_key='news_max_keywords'").bind(NEWS_MAX_KEYWORDS_DESC),
                env.DB.prepare("UPDATE acquire_options SET description=? WHERE option_key='news_relevance_only'").bind(NEWS_RELEVANCE_DESC),
                env.DB.prepare("UPDATE acquire_options SET description=? WHERE option_key='news_blacklist'").bind(NEWS_BLACKLIST_DESC),
                // 单源抓取条数固定 30（2026-11-13 用户指令）：上限 / 默认值都锁死为 30，采集页只读展示。
                //   种子是 INSERT OR IGNORE，存量库里可能还留着 100，这里显式收敛值 / meta / 描述；
                //   每次冷启动重跑结果一致，幂等无副作用。
                env.DB.prepare("UPDATE acquire_options SET value=?, meta=?, description=? WHERE option_key='news_per_source'")
                    .bind(String(NEWS_PER_SOURCE_FIXED), JSON.stringify({ min: NEWS_PER_SOURCE_FIXED, max: NEWS_PER_SOURCE_FIXED, step: 1, readonly: true }), NEWS_PER_SOURCE_DESC),
                // 重点消息通知口径在 2026-11-13 调整：「全部重点消息都进通知中心并点亮」，
                //   原「重点推送上限 5 条」只约束外部通道推送。种子是 INSERT OR IGNORE，
                //   存量库的名称 / 描述还是旧口径，这里显式改写（不改用户已经设过的开关值）。
                env.DB.prepare("UPDATE acquire_options SET name=?, description=? WHERE option_key='news_key_notify_max'")
                    .bind("外部推送上限", "每次采集完成后，最多把多少条「新采集的重点消息」推送到外部通道（企业微信 / 钉钉 / 飞书机器人）；写入通知中心不受此限制 —— 全部重点消息都会进通知中心"),
                env.DB.prepare("UPDATE acquire_options SET name=?, description=? WHERE option_key='news_key_notify_enabled'")
                    .bind("重点推送", "开启后：库内全部重点消息都会写入通知中心并点亮（未读），已读过的不会重复点亮；同时把本次新采集的重点消息推送到已配置的外部通道")
            ]);
            // 屏蔽词：把「董事 / 监事 / 辞职 / 辞去」这类泛词换成窄短语，
            //   既继续挡「XX 辞去副总裁」格式噪音，又不误伤 AI / 显卡重大公司事件（含 CEO 变动）。
            //   用户自定义的其他屏蔽词原样保留。
            const blRow = await env.DB.prepare("SELECT value FROM acquire_options WHERE option_key='news_blacklist'").first();
            const blOld = blRow ? String(blRow.value || "") : "";
            const blLegacy = ["董事", "监事", "辞职", "辞去"];
            let blParts = blOld.split(/[,，;；\s]+/).map(s => s.trim()).filter(Boolean);
            const hasLegacy = !blOld.trim() || blOld === "日本" || blParts.some(w => blLegacy.includes(w));
            if (hasLegacy) {
                blParts = blParts.filter(w => !blLegacy.includes(w));
                for (const w of NEWS_BLACKLIST_DEFAULT.split(",")) if (!blParts.includes(w)) blParts.push(w);
                const blNew = blParts.join(",");
                if (blNew !== blOld) await env.DB.prepare("UPDATE acquire_options SET value=? WHERE option_key='news_blacklist'").bind(blNew).run();
            }
        } catch (e) { logWarn("migrate.aiNewsScope", e); }

        // 采集参数控件名统一收敛成短标签（2026-11-13 用户指令：高级设置要紧凑、标签最多三个字、说明走悬停）
        //   种子是 INSERT OR IGNORE，存量库里 name 还是旧长名（如「大幅异动阈值」），这里按
        //   ACQUIRE_OPTION_DEFAULTS 幂等对齐 name + description（description 是页面 title 悬停的唯一来源）。
        //   只改文案，不动用户已经设过的 value；migrate() 每个实例只跑一次，重启重跑结果一致。
        try {
            const labelWrites = ACQUIRE_OPTION_DEFAULTS.map(o =>
                env.DB.prepare("UPDATE acquire_options SET name=?, description=? WHERE option_key=?")
                    .bind(o.name, o.description || "", o.key));
            if (labelWrites.length) await env.DB.batch(labelWrites);
        } catch (e) { logWarn("migrate.acquireLabels", e); }

        // 兼容旧库：令牌版本号（改密 / 停用后旧 token 立即失效）
        await ensureColumns(env, "users", [{ name: "token_version", ddl: "INTEGER NOT NULL DEFAULT 0" }]);

        // 兼容旧库：采集品种仍是「全部品种」旧默认值时，迁移为「仅上海品种」
        const LEGACY_ALL_SYMBOLS = "XAU,XAG,XPT,XPD,GC,SI,AU0,AG0,AUTD,AGTD";
        try {
            const symRow = await env.DB.prepare("SELECT value FROM acquire_options WHERE option_key='metal_symbols'").first();
            if (symRow && String(symRow.value || "").trim() === LEGACY_ALL_SYMBOLS) {
                await env.DB.prepare("UPDATE acquire_options SET value=? WHERE option_key='metal_symbols'").bind(METAL_DEFAULT_SYMBOLS.join(",")).run();
            }
        } catch (e) { logWarn("migrate.symbols", e); }

        // 兼容历史数据库中的停用品种：清理注册表、报价与轨迹数据；迁移幂等且不会复活停用品种。
        //   历史快照 detail JSON、news.symbols 标签与新闻打标词表保留为只读数据。
        try {
            const bankGoldMigrateAt = nowBeijing();
            await env.DB.batch([
                env.DB.prepare("UPDATE metal_instruments SET enabled=0, updated_at=? WHERE symbol='XPD'").bind(bankGoldMigrateAt),
                env.DB.prepare("DELETE FROM metal_quotes WHERE symbol='XPD'"),
                env.DB.prepare("DELETE FROM metal_history WHERE symbol='XPD'")
            ]);
        } catch (e) { logWarn("migrate.bankGold", e); }

        // 银行金价源收敛为单一官网源：清理历史源的注册行与残留行情行。
        //   种子是 INSERT OR IGNORE，不会删掉存量行，必须显式 DELETE；幂等，重启重跑无副作用。
        try {
            const retiredMark = BANK_GOLD_RETIRED_KEYS.map(() => "?").join(",");
            await env.DB.batch([
                env.DB.prepare(`DELETE FROM data_sources WHERE source_key IN (${retiredMark})`).bind(...BANK_GOLD_RETIRED_KEYS),
                env.DB.prepare(`DELETE FROM bank_gold_quotes WHERE source_key IN (${retiredMark})`).bind(...BANK_GOLD_RETIRED_KEYS),
                // 任务描述改名：fetch_tasks 种子是 INSERT OR IGNORE，存量库不会自动更新文案
                env.DB.prepare("UPDATE fetch_tasks SET description=? WHERE task_key='bank_gold_quote'")
                    .bind("抓取交通银行官网贵金属行情并写入 bank_gold_quotes")
            ]);
        } catch (e) { logWarn("migrate.bankGoldRetired", e); }

        // 财联社数据源彻底移除（2026-11-13 用户指令：本机网络无法访问 cailianpress，拿不到数据）。
        //   种子是 INSERT OR IGNORE，存量库里 migrate 曾写入的 cailian 行需显式 DELETE；幂等，重启重跑无副作用。
        try {
            await env.DB.batch([
                env.DB.prepare("DELETE FROM data_sources WHERE source_key='cailian'"),
                env.DB.prepare("DELETE FROM news WHERE source='cailian'")
            ]);
        } catch (e) { logWarn("migrate.cailianRetired", e); }

        // 清理停采品种：注册表行、残留行情与采集轨迹一并移除。
        //   采集 / 展示配置中的停用品种、类别与市场也一并剔除；值干净时跳过写入。
        //   metal_snapshots 的历史 detail JSON 与旧新闻 symbols 标签为只读数据，不在此清理。
        try {
            const METAL_RETIRED_SYMBOLS = ["AUTD", "AGTD", "XAU", "XAG", "XPT", "XPD", "GC", "SI"];
            const retiredMk = METAL_RETIRED_SYMBOLS.map(() => "?").join(",");
            await env.DB.batch([
                env.DB.prepare(`DELETE FROM metal_instruments WHERE symbol IN (${retiredMk})`).bind(...METAL_RETIRED_SYMBOLS),
                env.DB.prepare(`DELETE FROM metal_quotes WHERE symbol IN (${retiredMk})`).bind(...METAL_RETIRED_SYMBOLS),
                env.DB.prepare(`DELETE FROM metal_history WHERE symbol IN (${retiredMk})`).bind(...METAL_RETIRED_SYMBOLS)
            ]);
            const cleanOpt = async (key, drop) => {
                const row = await env.DB.prepare("SELECT value FROM acquire_options WHERE option_key=?").bind(key).first();
                if (!row) return;
                const v = String(row.value || "");
                const cleaned = v.split(",").map(x => x.trim()).filter(x => x && !drop.includes(x)).join(",");
                if (cleaned !== v) {
                    await env.DB.prepare("UPDATE acquire_options SET value=? WHERE option_key=?").bind(cleaned, key).run();
                }
            };
            await cleanOpt("metal_symbols", METAL_RETIRED_SYMBOLS);
            await cleanOpt("metal_snapshot_base", METAL_RETIRED_SYMBOLS);
            await cleanOpt("metal_kinds", ["铂金", "钯金"]);
            await cleanOpt("metal_markets", ["伦敦", "纽约", "COMEX"]);
            // data_sources 的 sina_quote 行是 INSERT OR IGNORE 种子，存量库的 endpoint / 描述还停留在旧品种口径，显式 UPDATE 收口
            // （注意：batch() 里放语句本身即可，不能再链 .run() —— 上一版多写了 .run() 导致每次迁移抛 ZodError）
            await env.DB.batch([
                env.DB.prepare("UPDATE data_sources SET endpoint='https://hq.sinajs.cn/list=nf_AU0,nf_AG0' WHERE source_key='sina_quote' AND endpoint LIKE '%hf_XAU%'"),
                env.DB.prepare("UPDATE data_sources SET description=? WHERE source_key='sina_quote' AND description LIKE '%伦敦金银%'")
                    .bind("沪金 / 沪银实时报价 + 美元兑人民币汇率"),
                // 采集参数描述同样是 INSERT OR IGNORE 种子，存量库文案还停留在旧口径
                env.DB.prepare("UPDATE acquire_options SET description=? WHERE option_key='metal_markets' AND description LIKE '%COMEX%'")
                    .bind("贵金属页面展示的市场；当前为上海，留空表示全部展示"),
                env.DB.prepare("UPDATE acquire_options SET description=? WHERE option_key='metal_kinds'")
                    .bind("贵金属页面展示的金属类别；留空表示全部展示")
            ]);
        } catch (e) { logWarn("migrate.metalRetired", e); }

        // 屏蔽词默认值已在上面的 migrate.aiNewsScope 统一收口（移除「董事 / 监事 / 辞职 / 辞去」泛词、
        //   换成窄短语并同步描述），此处不再重复写旧默认，避免把新口径又覆盖回去。

        // 清理历史菜单 / 参数记录，并同步快照任务的当前说明；所有操作幂等。
        //   metal_snapshots 采集链路（metal_snapshot 任务 + captureMetalSnapshot）保留不动。
        try {
            await env.DB.batch([
                env.DB.prepare("DELETE FROM menus WHERE menu_key='feed'"),
                env.DB.prepare("DELETE FROM acquire_options WHERE option_key='metal_feed_hours'"),
                env.DB.prepare("UPDATE fetch_tasks SET description=? WHERE task_key='metal_snapshot'")
                    .bind("拉取贵金属实时行情，生成一条金价快照并计算环比涨跌、异动等级与处理结论，写入 metal_snapshots")
                // 注：「大幅异动」阈值的 description 已由上面的 migrate.acquireLabels 统一按
                //   ACQUIRE_OPTION_DEFAULTS 收口（动态流下线时那句旧文案不再单独维护，避免两处漂移）
            ]);
        } catch (e) { logWarn("migrate.feedRetired", e); }

        // 清理历史数据库中的废弃报表表与生成时间设置，保持迁移幂等。
        try {
            await env.DB.prepare("DROP TABLE IF EXISTS daily_reports").run();
        } catch (e) { logWarn("migrate.dailyRetired.drop", e); }
        try {
            await env.DB.batch([
                env.DB.prepare("DELETE FROM settings WHERE key='daily_report_hour'"),
                env.DB.prepare("DELETE FROM notifications WHERE kind='daily' OR ref_type='daily_report'"),
                env.DB.prepare("UPDATE notify_channels SET events=TRIM(REPLACE(REPLACE(REPLACE(',' || events || ',', ',daily,', ','), ',,', ','), ',,', ','), ',') WHERE events LIKE '%daily%'")
            ]);
        } catch (e) { logWarn("migrate.dailyRetired", e); }

        // 数据保留参数（2026-11-16）：新增 3 个留存参数 + 更新 3 个旧参数的 name/description，
        //   幂等写入存量库（INSERT OR IGNORE 对存量库无效）；只同步元数据、不覆盖用户已改的 value。
        try {
            const retentionKeys = ["news_retention_days", "fetch_log_retention_days", "metal_snapshot_keep", "metal_snapshot_days", "metal_history_keep", "metal_history_days"];
            await env.DB.batch(ACQUIRE_OPTION_DEFAULTS.filter(o => retentionKeys.includes(o.key)).map(o =>
                env.DB.prepare("INSERT INTO acquire_options(domain,option_key,name,value,value_type,options,meta,description,sort_order) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(option_key) DO UPDATE SET name=excluded.name, description=excluded.description, meta=excluded.meta, options=excluded.options, sort_order=excluded.sort_order")
                    .bind(o.domain, o.key, o.name, o.value, o.type, o.options || "", o.meta || "", o.description || "", o.sort)
            ));
        } catch (e) { logWarn("migrate.retentionOptions", e); }

        // 存量数据补 relevant 标记 / 研判 / 重点评分（各自的版本戳一致时只读 1 行）。
        //   放在全部种子与兼容 UPDATE 之后：屏蔽词的规范化也在上面完成，
        //   否则会用「规范化前」的屏蔽词算一遍 relevant，白白多跑一轮回填。
        await runRuleBackfills(env);
        // 冷启动把库内全部重点消息同步进通知中心（幂等；未读的即为「点亮」状态）
        try { await syncKeyNotifications(env); } catch (e) { logWarn("migrate.keyNotifySync", e); }

        // 记录迁移版本：后续新 isolate 只读这一个键就返回，不再重复写种子 / 兼容 UPDATE。
        //   写入失败也置位（避免同一实例里每次请求都重跑一遍完整迁移），下个实例会再试。
        try {
            await env.DB.prepare("INSERT INTO settings(key,value) VALUES('migrate_ver',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                .bind(MIGRATE_VERSION).run();
        } catch (e) { logWarn("migrate.version", e); }

        migrateDone = true;
        return true;
    } catch (e) {
        // 迁移失败不置位，下次请求会重试；记录日志便于排查
        logWarn("migrate", e);
        return false;
    }
    })();
    try { return await migratePending; }
    finally { migratePending = null; }
}

// ============================================================
// 字段清洗
// ============================================================
function cleanStr(v, max = 2000) { return String(v == null ? "" : v).trim().slice(0, max); }
function cleanNum(v, def = 0) { const n = Number(v); return Number.isFinite(n) ? n : def; }
// 发布时间归一化：接受 YYYY-MM-DD / YYYY-MM-DD HH:MM[:SS]，非法值返回空串（由调用方兜底为当前时间）
function normalizeStamp(v) {
    const s = cleanStr(v, 32).replace("T", " ");
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + " 00:00:00";
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(s)) return s + ":00";
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) return s;
    return "";
}
// URL 白名单：仅允许 http/https，杜绝 javascript: / data: 等伪协议注入
function safeUrl(v) {
    const s = cleanStr(v, 1000);
    if (!s) return "";
    try {
        const u = new URL(s);
        if (u.protocol !== "http:" && u.protocol !== "https:") return "";
        return u.toString();
    } catch { return ""; }
}
function fetchWithTimeout(url, options = {}, ms = 9000) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    return fetch(url, { ...options, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

// ============================================================
// 消息中心：多平台资讯抓取 / 检索
// 数据源（均免密钥）：
//   eastmoney — 东方财富全网财经搜索（按关键词，覆盖媒体最广）
//   sina      — 新浪财经 7×24 快讯（宏观/市场盘中异动）
//   wscn      — 华尔街见闻 7×24（全球宏观 / 商品频道）
// ============================================================
const NEWS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";
// AI 主题词表（2026-11-12 二次调整）：用户要求「关键词不要包含人名，因为人名不泛化；
//   AI 相关的直接、间接消息都要获取」。
//   ① 检索关键词（NEWS_AI_KEYWORDS / DEFAULT_NEWS_KEYWORDS）只用泛化主题词，不放人名 / 高管名 / 公司名；
//   ② 本词表用于标题判定与频道分类，公司名仅作兜底（不是人名），并补上产业链 / 能源 / 政策等间接关联词；
//   ③ 裸 AI 这类短英文词由 termMatches() 做边界匹配，避免 said / air / email 被误命中。
const AI_COMPUTE_TERMS = [
    // 泛化主题：直接 AI 消息（不含任何具体人名 / 高管名）
    "AI", "人工智能", "AIGC", "生成式AI", "大模型", "AI应用", "AI模型", "AI Agent", "AI智能体",
    "具身智能", "人形机器人", "自动驾驶", "AI PC", "AI手机", "AI眼镜", "AI监管", "AI法案",
    // 算力 / 芯片 / 硬件
    "算力", "AI算力", "智算", "超算", "算力中心", "智算中心", "数据中心", "AI数据中心", "液冷数据中心",
    "GPU", "显卡", "AI芯片", "AI芯片组", "AI服务器", "AI加速卡", "加速卡", "训练芯片", "推理芯片",
    "HBM", "CUDA", "CoWoS", "GB200", "Blackwell", "Hopper", "DGX", "NVL72",
    "芯片", "半导体", "集成电路", "晶圆", "光刻", "光刻机", "EDA", "先进封装", "存储芯片", "半导体设备",
    "服务器", "交换机", "CPO", "光模块", "液冷", "高速铜缆", "铜连接", "云计算", "边缘计算",
    // 产业链 / 能源 / 政策等间接关联：带 AI / 算力 / 数据中心限定，避免裸「电力 / 电网」把全网新闻捞进来
    "芯片出口管制", "GPU出口管制", "半导体出口管制", "AI芯片出口管制", "AI用电", "算力用电", "数据中心用电",
    "AI电力", "算力电力", "数据中心电力", "AI耗电", "算力耗电", "AI供电", "算力供电", "数据中心供电",
    // 公司 / 产品名仅作标题兜底判定，不进入检索关键词（不是人名；避免关键词不泛化）
    "英伟达", "NVIDIA", "AMD", "英特尔", "台积电"
];
// 东方财富固定补充检索词：全部是泛化主题词，不含人名 / 高管名 / 公司名。
//   即使用户清空 / 自定义「关注关键词」，这 10 个词仍会参与检索；
//   「直接 AI 事件」与「产业链 / 能源 / 材料等间接消息」都靠它们兜底。
const NEWS_AI_KEYWORDS = ["人工智能", "AI", "算力", "GPU", "显卡", "AI芯片", "半导体", "数据中心", "液冷", "光模块"];
const NEWS_CHANNELS = {
    equity: { label: "股市·权益", keywords: ["A股", "股市", "股票", "沪指", "创业板", "港股", "美股", "证监会", "IPO", "分红", "回购"] },
    fund: { label: "基金·ETF", keywords: ["基金", "ETF", "指数基金", "公募", "量化", "定投", "净值"] },
    bond: { label: "债券·固收", keywords: ["国债", "债券", "可转债", "利率债", "信用债", "降准", "逆回购", "收益率"] },
    metal: { label: "贵金属", keywords: ["黄金", "金价", "沪金", "AU99", "金条", "央行购金", "白银", "贵金属", "金银比"] },
    macro: { label: "宏观·美联储", keywords: ["美联储", "加息", "降息", "通胀", "CPI", "非农", "鲍威尔", "美债", "缩表", "美元指数", "GDP"] },
    forex: { label: "外汇·汇率", keywords: ["汇率", "人民币", "美元", "欧元", "日元", "外汇储备", "结汇"] },
    property: { label: "房地产", keywords: ["房价", "楼市", "房地产", "二手房", "新房", "房贷", "土地出让", "REITs"] },
    policy: { label: "政策·监管", keywords: ["央行", "LPR", "证监会", "资管", "理财", "保险", "印花税", "政策"] },
    ai: { label: "AI·算力", keywords: AI_COMPUTE_TERMS },
    other: { label: "综合", keywords: [] }
};
const NEWS_CHANNEL_ORDER = ["equity", "fund", "bond", "metal", "macro", "forex", "property", "policy", "ai", "other"];
// 8 个泛化 AI 主题词 + 原有 15 个金属 / 宏观词 = 23 个（≤24 上限）；
//   「液冷 / 光模块」由 NEWS_AI_KEYWORDS 固定补充检索，不占「关注关键词」名额。
const DEFAULT_NEWS_KEYWORDS = [...NEWS_AI_KEYWORDS.slice(0, 8), "碳酸锂", "工业硅", "沪镍", "沪锡", "稀土", "铜", "铝", "黄金", "白银", "美联储", "加息", "降息", "通胀", "汇率"];
// 单源每次抓取条数固定为 30（2026-11-13 用户定稿）：上限与默认值都锁死为 30，
//   采集页只展示、不允许更改。快讯源按「最新 N 条」拉取 + hash 去重，实测 30 条的
//   回溯窗口远大于约 60 秒的采集间隔，不会漏新闻；调大还会让新浪接口退化成只回 10 条。
const NEWS_PER_SOURCE_FIXED = 30;
const NEWS_SOURCES = { eastmoney: "东方财富", sina: "新浪财经 7×24", wscn: "华尔街见闻" };
// 展示 / 筛选用的来源标签（比可抓取源多出「手动录入」）
const NEWS_SOURCE_LABELS = { eastmoney: "东方财富", sina: "新浪财经 7×24", wscn: "华尔街见闻", manual: "手动录入" };
const NEWS_SORT_MODES = ["time", "oldest", "relevance", "key"];

// ============================================================
// 消息 → 标的 关联打标
//   这是「消息 / 行情 / 决策」串成一条线的关键：没有这层映射，
//   消息中心只是一堆和行情无关的文本，用户还得自己判断「这条影响谁」。
//   规则分三层：① 库里的品种全称 / 简称（最精准）② 行业别名 ③ 宏观词的默认影响面。
//   一条消息最多贴 4 个标的，避免「美联储」这类词把半个市场都贴上。
// ============================================================
// 类别 → 代表性合约：每个类别落到当前品种池中的代表合约，防止一条新闻打十几个标
const NEWS_KIND_SYMBOLS = {
    // 当前贵金属类别只包含黄金与白银
    黄金: ["AU0"],
    白银: ["AG0"],
    锂: ["LC0"],
    硅: ["SI0", "PS0"],
    镍: ["NI0"],
    锡: ["SN0"],
    铜: ["CU0"],
    铝: ["AL0"]
};
const NEWS_ALIAS_KIND = {
    黄金: ["黄金", "金价", "现货金", "沪金", "金饰", "金条", "央行购金", "gold", "bullion"],
    白银: ["白银", "银价", "沪银", "白银期货", "silver"],
    锂: ["锂", "碳酸锂", "锂电", "锂矿", "lithium"],
    硅: ["工业硅", "多晶硅", "硅料", "硅片", "polysilicon"],
    镍: ["镍", "硫酸镍", "镍矿", "nickel"],
    锡: ["锡价", "沪锡", "锡矿", "精锡", "tin"],
    铜: ["铜价", "沪铜", "电解铜", "铜矿", "精铜", "copper"],
    铝: ["铝价", "沪铝", "电解铝", "氧化铝", "铝土", "aluminium", "aluminum"]
};
// 贵金属泛称：同时指向黄金/白银（「贵金属板块走强」要能落到具体品种上）
const NEWS_GENERIC_METALS = ["贵金属"];
const NEWS_GENERIC_KINDS = ["黄金", "白银"];
// 干扰主语：这些主语的方向与贵金属无关（"油价暴跌"不该算成黄金利空）
const NEWS_IGNORE_SUBJECTS = ["油价", "原油", "燃料油", "沥青", "液化气", "汽油", "柴油", "煤炭",
    "螺纹钢", "铁矿石", "豆粕", "比特币", "美股", "a股", "港股", "恒生", "创业板", "科创板",
    "纳指", "纳斯达克", "标普", "道琼斯", "道指", "股指", "离岸人民币"];
// 利率 / 美元 / 通胀是金银的核心定价变量：这类消息默认只影响黄金，不扩散到工业金属
const NEWS_MACRO_ALIASES = ["美联储", "降息", "加息", "美元指数", "实际利率", "非农", "cpi", "通胀", "避险", "缩表", "降准"];
// 成语/固定搭配里的金属字眼不能当成品种消息，等长替换以免影响后续位置匹配
const NEWS_NOISE_PHRASES = ["真金白银", "金银价格", "金银财宝", "金玉满堂", "火眼金睛", "点石成金"];

// —— 资讯相关性白名单（2026-11-12 定稿；同日二次调整：AI 口径泛化）——
// 投资平台要的不是「全网新闻」，只要四类：① 贵金属 / 稀有金属品种的行情与供需 ② 中国政策与官方数据 ③ 直接定价金价的海外变量 ④ AI 相关消息（直接事件 + 产业链 / 能源 / 政策等间接消息）。
// 判定只看**标题**：摘要常夹带无关词（一份 ETF 早报里提一句「黄金」就会被误留），标题最能代表这条消息在讲什么。
// 四组之间是「或」；都不命中即判为无关（日本 / 欧洲央行官员讲话、他国股市、个股行情、企业动态都落在这里）。
// 前三组仍不放泛词：`央行` 会命中「韩国央行」、`加息` 会命中「日本央行加息」、`美元` 会命中「3 亿美元收购」。
// 第 ④ 组按用户要求改为**泛化主题词**：不放具体人名 / 高管名，直接、间接 AI 消息都要；
//   裸 AI / AIGC / GPU 这类短英文词由 termMatches() 做边界匹配，避免 said / air / email 被误命中。
const AI_TERM_RE_CACHE = new Map();
function termMatches(lowerText, term) {
    const w = String(term || "").toLowerCase();
    if (!w) return false;
    // 纯 ASCII 词（AI / GPU / AIGC / GB200 / AI PC…）要求前后不是字母数字；
    //   含中文的词（AI芯片 / 美元/盎司…）直接子串匹配即可
    if (/^[\x20-\x7e]+$/.test(w)) {
        let re = AI_TERM_RE_CACHE.get(w);
        if (!re) {
            const esc = w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            re = new RegExp("(^|[^a-z0-9])" + esc + "(?=$|[^a-z0-9])");
            AI_TERM_RE_CACHE.set(w, re);
        }
        return re.test(lowerText);
    }
    return lowerText.includes(w);
}
const NEWS_RELEVANCE_TERMS = {
    // 品种：优先用「行情 / 盘面」说法（金价、沪镍、LME铜），避免裸金属字误伤公司名（国潮铜艺、铝谷、铜粉）
    metal: ["黄金", "金价", "白银", "银价", "贵金属", "铂金", "钯金", "沪金", "沪银", "上海金", "伦敦金", "现货金", "现货银",
        "期金", "期银", "纽约金", "纽约银", "伦敦金", "伦敦铜", "伦敦铝", "伦敦镍", "金条", "金饰", "金店", "购金",
        "稀土", "碳酸锂", "锂价", "沪镍", "镍价", "伦镍", "沪铜", "铜价", "伦铜", "LME铜", "期铜", "沪铝", "铝价", "伦铝", "LME铝", "期铝",
        "沪锌", "锌价", "沪锡", "锡价", "沪铅", "铅价", "钴价", "钨价", "锑价", "钼价", "铟价", "锗价", "镓价", "硅价", "多晶硅", "工业硅"],
    // 中国政策与官方口径：机构名 + 政策工具名。`人民银行` 而不是裸 `央行`，避免把境外央行一起捞进来
    policy: ["国务院", "国常会", "国新办", "发改委", "财政部", "人民银行", "中国人民银行", "证监会", "金融监管总局",
        "商务部", "工信部", "自然资源部", "住建部", "国家统计局", "国资委", "税务总局", "海关总署", "能源局", "储备局",
        "上期所", "大商所", "郑商所", "广期所", "央行降准", "央行降息", "全面降准", "定向降准", "逆回购", "MLF", "LPR",
        "专项债", "特别国债", "收储", "出口管制", "出口配额", "关税", "退税", "补贴", "限产", "环保督察",
        "十五五", "两会", "政治局", "中央经济工作会议", "社融", "M2", "信贷投放", "稳增长", "内需", "反内卷"],
    // 金价驱动：美联储 / 实际利率 / 美元指数 / 通胀就业数据 / 央行购金 / 避险，这些才是「国际上直接影响金价」的那部分
    driver: ["美联储", "FOMC", "实际利率", "美债", "美元指数", "非农", "CPI", "PCE", "央行购金", "避险", "地缘",
        "COMEX", "缩表", "点阵图", "美元/盎司"],
    // AI 相关（2026-11-12 二次调整）：泛化主题词，直接 + 间接消息都收；复用频道词表保证「留得下 / 分得对」同口径
    ai_compute: AI_COMPUTE_TERMS
};
const NEWS_RELEVANCE_ALL = [...NEWS_RELEVANCE_TERMS.metal, ...NEWS_RELEVANCE_TERMS.policy, ...NEWS_RELEVANCE_TERMS.driver, ...NEWS_RELEVANCE_TERMS.ai_compute];

// 标题是否与四类白名单相关；命中即保留。英文短词走边界匹配，中文词直接子串匹配
function newsTitleRelevant(title) {
    const t = String(title || "").toLowerCase();
    if (!t) return false;
    return NEWS_RELEVANCE_ALL.some(w => termMatches(t, w));
}

// 屏蔽词命中判定：与原先 SQL 侧 `title||' '||summary||' '||keywords LIKE '%w%'` 同口径
//   （LIKE 对 ASCII 不区分大小写，这里统一转小写；中文不受影响）
function newsBlacklistHit(blacklist, row) {
    if (!blacklist || !blacklist.length) return false;
    const r = row || {};
    const hay = [r.title, r.summary, r.keywords].map(v => String(v == null ? "" : v)).join(" ").toLowerCase();
    if (!hay.trim()) return false;
    return blacklist.some(w => w && hay.includes(String(w).toLowerCase()));
}

// 结构化「是否保留」标记（1 保留 / 0 过滤）：
//   命中四类白名单 **且** 不命中屏蔽词。
//   把屏蔽词也烘进 relevant 之后，查询端只判 `relevant = 1`（走 idx_news_rel），
//   不必再给每条聚合 SQL 拼 N 个 `NOT LIKE`（SQLite 只能逐行全表扫，实测单次 4~6 千行）。
function newsRelevantFlag(row, blacklist) {
    const r = row || {};
    if (!newsTitleRelevant(r.title)) return 0;
    return newsBlacklistHit(blacklist, r) ? 0 : 1;
}
// 采集端要给出「为什么留下」的原因，便于日志排查
function newsRelevanceHit(title) {
    const t = String(title || "").toLowerCase();
    for (const [group, label] of [["metal", "品种"], ["policy", "政策"], ["driver", "驱动"], ["ai_compute", "AI算力"]]) {
        const hit = NEWS_RELEVANCE_TERMS[group].find(w => termMatches(t, w));
        if (hit) return label + ":" + hit;
    }
    return "";
}

// 词表版本：改了 NEWS_RELEVANCE_TERMS 就把版本号 +1，重启后会自动重算历史数据的 relevant 标记
//   v4（2026-11-19）：屏蔽词也并入 relevant —— 命中屏蔽词的行同样记 0，
//   查询端就能只判 `relevant = 1`，不再拼一堆 NOT LIKE 做全表扫描。
const NEWS_RELEVANCE_VERSION = "v4-20261119-blacklist";
let RELEVANCE_BACKFILLED = "";
// 给存量数据补 relevant 标记（历史行入库时还没有这个字段，默认都是 1）
//   进度记在 settings.news_relevance_ver，版本一致就直接跳过；isolate 内再缓存一次，避免每个请求都查库。
//   令牌里带上屏蔽词的指纹：用户改了屏蔽词 → 自动重算一次（否则旧的 0/1 会一直沿用）。
async function backfillNewsRelevance(env) {
    // 直接单行读取屏蔽词（不要走 acquireOptionMap：那会整表读 29 行，
    //   而这里是「每次冷启动都要自检」的热路径，只需要 1 行 + 1 行版本戳）
    const blRow = await env.DB.prepare("SELECT value FROM acquire_options WHERE option_key='news_blacklist'").first().catch(() => null);
    const blacklist = splitList(blRow ? blRow.value : "");
    const token = NEWS_RELEVANCE_VERSION + "|bl:" + newsHash(blacklist.join(","));
    if (RELEVANCE_BACKFILLED === token) return;
    const cur = await env.DB.prepare("SELECT value FROM settings WHERE key='news_relevance_ver'").first().catch(() => null);
    if (cur && String(cur.value || "") === token) { RELEVANCE_BACKFILLED = token; return; }
    let lastId = 0;
    for (let round = 0; round < 200; round++) {
        const page = (await env.DB.prepare("SELECT id,title,summary,keywords FROM news WHERE id > ? ORDER BY id LIMIT 200").bind(lastId).all()).results || [];
        if (!page.length) break;
        const stmts = page.map(r => env.DB.prepare("UPDATE news SET relevant=? WHERE id=?").bind(newsRelevantFlag(r, blacklist), r.id));
        for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
        lastId = page[page.length - 1].id;
    }
    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('news_relevance_ver',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(token).run();
    RELEVANCE_BACKFILLED = token;
}

// 给存量消息补「影响研判」。版本记在 settings.news_impact_ver，规则词表改动后 bump
//   IMPACT_VERSION 即会在冷启动自动重算；人工改判（manual=1）的行永远跳过，不被覆盖。
let IMPACT_BACKFILLED = "";
async function backfillImpact(env) {
    if (IMPACT_BACKFILLED === IMPACT_VERSION) return;
    const cur = await env.DB.prepare("SELECT value FROM settings WHERE key='news_impact_ver'").first().catch(() => null);
    if (cur && String(cur.value || "") === IMPACT_VERSION) { IMPACT_BACKFILLED = IMPACT_VERSION; return; }
    let lastId = 0;
    for (let round = 0; round < 200; round++) {
        const page = (await env.DB.prepare("SELECT id,title,summary,channel,impact FROM news WHERE id > ? ORDER BY id LIMIT 200").bind(lastId).all()).results || [];
        if (!page.length) break;
        const stmts = [];
        page.forEach(r => {
            const old = parseImpact(r.impact);
            if (old && old.manual) return;                         // 人工改判保留
            if (old && old.v === IMPACT_VERSION) return;           // 已是当前版本
            const j = judgeImpact(r.title, r.summary, r.channel);
            stmts.push(env.DB.prepare("UPDATE news SET impact=? WHERE id=?").bind(JSON.stringify(j), r.id));
        });
        for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
        lastId = page[page.length - 1].id;
    }
    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('news_impact_ver',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(IMPACT_VERSION).run();
    IMPACT_BACKFILLED = IMPACT_VERSION;
}

// 给存量消息补「重点」评分。版本记在 settings.news_pick_ver，挑选算法/阈值改动后 bump
//   KEY_PICK_VERSION 即会在冷启动自动重算。依赖 impact 已回填（先算研判再算重点）。
let KEY_PICK_BACKFILLED = "";
async function backfillKeyPick(env) {
    if (KEY_PICK_BACKFILLED === KEY_PICK_VERSION) return;
    const cur = await env.DB.prepare("SELECT value FROM settings WHERE key='news_pick_ver'").first().catch(() => null);
    if (cur && String(cur.value || "") === KEY_PICK_VERSION) { KEY_PICK_BACKFILLED = KEY_PICK_VERSION; return; }
    const now = Date.now();
    let lastId = 0;
    for (let round = 0; round < 200; round++) {
        const page = (await env.DB.prepare("SELECT id,title,summary,channel,impact,source,published_at,key_reasons FROM news WHERE id > ? ORDER BY id LIMIT 200").bind(lastId).all()).results || [];
        if (!page.length) break;
        const stmts = [];
        page.forEach(r => {
            const old = parseKeyPick(r.key_reasons);
            if (old && old.v === KEY_PICK_VERSION) return;   // 已是当前版本
            const imp = parseImpact(r.impact);
            // 研判规则版本比本行新 → 重点评分是基于旧研判算的，必须跟着重算
            if (old && old.v === KEY_PICK_VERSION && imp && imp.v === IMPACT_VERSION) return;
            const kp = pickKeyNews(r.title, r.summary, r.channel, imp, r.source, r.published_at, now);
            stmts.push(env.DB.prepare("UPDATE news SET key_score=?, is_key=?, key_reasons=?, key_brief=? WHERE id=?")
                .bind(kp.score, kp.isKey ? 1 : 0, JSON.stringify(kp), kp.brief || "", r.id));
        });
        for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
        lastId = page[page.length - 1].id;
    }
    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('news_pick_ver',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(KEY_PICK_VERSION).run();
    KEY_PICK_BACKFILLED = KEY_PICK_VERSION;
    // 清理失效的重点通知：规则调整后，原本被点亮的消息可能已不再属于重点，
    //   但通知还留在通知中心里指向它 —— 这会让通知内容与实际标记不一致。
    try {
        await env.DB.prepare(
            "DELETE FROM notifications WHERE kind='news_key' AND ref_type='news' AND ref_id>0 "
            + "AND ref_id NOT IN (SELECT id FROM news WHERE is_key=1)"
        ).run();
    } catch (e) { logWarn("migrate.keyNotifyCleanup", e); }
}

// 规则回填入口：三个回填各自带 settings 版本戳，版本一致时只读 1 行就返回。
//   ⚠️ 必须同时挂在「迁移版本闸门命中」的分支上（见 migrate()），
//   否则闸门一命中，之后改词表 / 屏蔽词就再也不会对存量库生效了。
async function runRuleBackfills(env) {
    try { await backfillNewsRelevance(env); } catch (e) { logWarn("rules.newsRelevance", e); }
    try { await backfillImpact(env); } catch (e) { logWarn("rules.impact", e); }
    try { await backfillKeyPick(env); } catch (e) { logWarn("rules.keyPick", e); }
}

// 容错解析重点评分 JSON（坏数据一律当空）
function parseKeyPick(raw) {    try { const o = JSON.parse(String(raw || "")); return (o && typeof o === "object") ? o : null; }
    catch (e) { return null; }
}

function stripNoisePhrases(text) {
    let s = String(text || "");
    NEWS_NOISE_PHRASES.forEach(p => { s = s.split(p).join(new Array(p.length + 1).join(" ")); });
    return s;
}

function tagNewsSymbols(text, instruments) {
    const t = stripNoisePhrases(text).toLowerCase();
    if (!t) return [];
    const out = [];
    const add = s => { if (s && !out.includes(s)) out.push(s); };
    const addKind = kind => (NEWS_KIND_SYMBOLS[kind] || []).forEach(add);

    // ① 品种全称 / 简称：按词长倒序匹配，长词命中后从文本里剔除，避免「工业硅」又被「硅」重复命中
    const dict = [];
    (instruments || []).forEach(i => {
        [i.name, i.short_name].filter(Boolean).forEach(w => {
            const word = String(w).toLowerCase().replace(/主连|连续|现货|主力/g, "");
            if (word.length >= 2) dict.push({ word, symbol: i.symbol });
        });
    });
    dict.sort((a, b) => b.word.length - a.word.length);
    let rest = t;
    const hitSymbols = [];
    for (const d of dict) {
        if (rest.includes(d.word)) {
            hitSymbols.push(d.symbol);
            rest = rest.split(d.word).join(" ");
            if (hitSymbols.length >= 3) break;
        }
    }
    hitSymbols.forEach(add);

    // ② 行业别名：命中即落到该类别（工业金属常说「铜价」「锂矿」而不带合约名）
    for (const kind of Object.keys(NEWS_ALIAS_KIND)) {
        if (NEWS_ALIAS_KIND[kind].some(w => t.includes(w))) addKind(kind);
    }
    // ②' 泛称：「贵金属」同时指向黄金与白银
    if (NEWS_GENERIC_METALS.some(w => t.includes(w))) { addKind("黄金"); addKind("白银"); }
    // ③ 宏观词：只补黄金，且已经贴满 3 个标的不再加
    if (NEWS_MACRO_ALIASES.some(w => t.includes(w)) && out.length < 3) addKind("黄金");
    return out.slice(0, 4);
}

// ============================================================
// 消息情绪判定：这条消息对它（每个标的）是「利多」还是「利空」
//   关键点：情绪必须**按标的**判定，而不是给整条消息贴一个标签。
//   同一条「美元指数大涨」对黄金是利空；「铜价下跌」对铜利空，对黄金毫无关系。
//   做法：
//     ① 按句号/问号切句（句内保持主谓完整，否则「直线拉升！现货黄金重返4000」会被拆散）
//     ② 句内找方向词（上涨/下跌/降息/增产…，带权重）与否定前缀（「未上涨」反向）
//     ③ 句内找主语，按**中文语序**配对（主语在谓语左边，取左边最近的那个）：
//        · 品种全称 / 简称（「沪金」等）→ 具体标的，最具体（spec=2）
//        · 行业别名（「铜价」「锂矿」「金价」）→ 该类别下已打标的标的（spec=1）
//        · 宏观主体（「美元指数」「美联储」「实际利率」「通胀」）→ 贵金属（spec=1）
//          美元/实际利率/通胀走强 = 贵金属走弱，所以方向词要**取反**
//     ④ 同一句里若某个品种已被具体品种名点名，就不再被行业别名重复分摊
//        （「沪金」点名过沪金，同句的「黄金」泛指就不该再算到沪金头上）
//     ⑤ 句内无主语也无方向词时，宏观自带动方向的词兜底（避险、央行购金）
//   只有**已打标的标的**才会参与判定：一条讲苹果降级的消息与我们无关，不该算成利空。
//   结果落库：news.sentiment（整体）+ news.sentiment_map（按标的明细，含人工修正）
// ============================================================
// 摘要相对标题降权：标题是新闻主旨，摘要里的次要信息不该盖过标题
const SUMMARY_WEIGHT = 0.6;
// 主语与方向词的最大绑定距离（字符）：超过就认为两者无关，不强行绑定
const MAX_BIND_DIST = 12;
// 方向词：[词, 方向(1=利多/-1=利空), 权重]
const SENTIMENT_WORDS = [
    // —— 价格走势 ——
    ["上涨", 1, 1], ["大涨", 1, 2], ["暴涨", 1, 2], ["飙升", 1, 2], ["走高", 1, 1], ["走强", 1, 1],
    ["反弹", 1, 1], ["突破", 1, 1], ["创新高", 1, 2], ["新高", 1, 1.5], ["涨至", 1, 1],
    ["涨超", 1, 1.5], ["涨幅", 1, 1], ["上涨超", 1, 1.5], ["续涨", 1, 1.5], ["拉升", 1, 1.5],
    ["跳涨", 1, 1.5], ["攀升", 1, 1.5], ["上行", 1, 1], ["重返", 1, 1], ["站上", 1, 1],
    ["收复", 1, 1], ["涨", 0.6, 0.6],
    ["下跌", -1, 1], ["大跌", -1, 2], ["暴跌", -1, 2], ["走低", -1, 1], ["走弱", -1, 1],
    ["回调", -1, 1], ["跌破", -1, 1.5], ["创新低", -1, 2], ["新低", -1, 1.5], ["跌至", -1, 1],
    ["跌超", -1, 1.5], ["跌幅", -1, 1], ["下跌超", -1, 1.5], ["续跌", -1, 1.5], ["下挫", -1, 1.5],
    ["下行", -1, 1], ["回落", -1, 1], ["承压", -1, 1], ["抛压", -1, 1], ["疲软", -1, 1],
    ["萎缩", -1, 1], ["失守", -1, 1], ["跌", -0.6, 0.6],
    // —— 资金与持仓 ——
    ["增持", 1, 1.5], ["增持黄金", 1, 2], ["净买入", 1, 1.5], ["流入", 1, 1],
    ["减持", -1, 1.5], ["抛售", -1, 1.5], ["净卖出", -1, 1.5], ["流出", -1, 1],
    // —— 供需与产业 ——
    ["减产", 1, 1.5], ["限产", 1, 1.5], ["停产", 1, 1], ["供应中断", 1, 2], ["断供", 1, 2],
    ["供应紧张", 1, 2], ["供给收缩", 1, 2], ["供不应求", 1, 2], ["涨价", 1, 1.5], ["提价", 1, 1.5],
    ["需求增长", 1, 1.5], ["需求回暖", 1, 1.5], ["满产", 1, 1], ["扩产", -1, 1], ["增产", -1, 1.5],
    ["供应过剩", -1, 2], ["供给过剩", -1, 2], ["库存增加", -1, 1.5], ["累库", -1, 1.5],
    ["需求疲软", -1, 1.5], ["需求走弱", -1, 1.5], ["降价", -1, 1.5], ["去库", 1, 1],
    // —— 政策与预期 ——
    ["降息", 1, 2], ["降准", 1, 1.5], ["宽松", 1, 1.5], ["超预期", 1, 1.5], ["好于预期", 1, 1.5],
    ["加息", -1, 2], ["缩表", -1, 1.5], ["收紧", -1, 1], ["不及预期", -1, 1.5],
    ["低于预期", -1, 1.5], ["利好", 1, 1.5], ["利空", -1, 1.5],
    // —— 表述类：主语明确时才生效（"为黄金提供支撑"、"黄金更受益"、"避险需求"）——
    ["提供支撑", 1, 1.5], ["受益", 1, 1], ["避险", 1, 1]];
// 政策类方向词自带确定含义，不参与宏观主体的取反（加息就是利空，不能被"通胀"反转成利多）
const POLICY_WORDS = ["加息", "降息", "降准", "缩表", "宽松", "收紧"];
// 否定词：紧贴方向词时把它反向（"未上涨""不达预期"）
const SENTIMENT_NEGATIONS = ["不", "未", "无", "没有", "难", "非", "免于", "尚未"];
// 宏观主体：出现在句中时，方向词要按「主体与贵金属的关系」来解释
//   inv = -1 → 主体走强 = 贵金属走弱（美元指数/实际利率/通胀上行 → 黄金利空），方向词取反
//   inv =  0 → 方向词自带方向（美联储加息 = 利空、降息 = 利多）
const MACRO_SUBJECTS = [
    { key: "usd", words: ["美元指数", "美元兑", "美元汇率", "美元走强", "美元走弱", "美元承压", "美元下跌", "美元上涨", "美元回落", "美元飙升", "美元大跌", "美元反弹", "美元飙升"], inv: -1, w: 2, kinds: ["黄金", "白银"], desc: "美元" },
    { key: "rate", words: ["实际利率", "美债收益率", "美债实际收益率"], inv: -1, w: 2, kinds: ["黄金", "白银"], desc: "实际利率" },
    { key: "fed", words: ["美联储"], inv: 0, w: 2, kinds: ["黄金", "白银"], desc: "美联储" },
    { key: "cpi", words: ["cpi", "通胀", "物价"], inv: -1, w: 1.5, kinds: ["黄金", "白银"], desc: "通胀" }
];
// 自带动方向的宏观词（句内既没有主语也没有方向词时用来兜底）
const MACRO_WORDS = [
    { words: ["避险", "地缘紧张", "局势紧张", "冲突升级"], dir: 1, w: 2, kinds: ["黄金"] },
    { words: ["央行购金", "增持黄金"], dir: 1, w: 2, kinds: ["黄金"] },
    { words: ["通胀压力", "通胀高位", "通胀反弹", "通胀飙升"], dir: -1, w: 2, kinds: ["黄金", "白银"] }
];

// 按句号切句（保留句内主谓的完整性）
function splitSentences(text) {
    return String(text || "").split(/[。！？!?\n\r]+/).map(s => s.trim()).filter(Boolean);
}

// 判断一个方向词前是否有否定词（只看紧邻的前几个字）
function isNegated(text, pos) {
    const head = text.slice(Math.max(0, pos - 6), pos);
    for (const n of SENTIMENT_NEGATIONS) {
        let from = 0, last = -1;
        for (;;) {
            const k = head.indexOf(n, from);
            if (k < 0) break;
            last = k; from = k + n.length;
        }
        // 否定词与方向词之间最多隔 1 个字："美联储不愿降息" → 降息取反
        if (last >= 0 && head.length - (last + n.length) <= 1) return true;
    }
    return false;
}

// 收集一段文本里的方向词命中（带位置）
function collectDirections(text) {
    const hits = [];
    const lower = String(text || "").toLowerCase();
    for (const [word, dir, w] of SENTIMENT_WORDS) {
        const lw = word.toLowerCase();
        let from = 0;
        for (;;) {
            const idx = lower.indexOf(lw, from);
            if (idx < 0) break;
            const neg = isNegated(lower, idx);
            hits.push({ word, dir: neg ? -dir : dir, weight: neg ? w * 0.8 : w, pos: idx, negated: neg });
            from = idx + lw.length;
            if (hits.length > 60) break;
        }
    }
    // 长词优先：同一位置命中「大涨」时不应再单独算一次「涨」
    hits.sort((a, b) => b.word.length - a.word.length);
    const kept = [];
    const used = new Set();
    hits.forEach(h => {
        const key = h.pos;
        if (used.has(key)) return;
        // 若该位置已被更长的词覆盖，跳过
        let covered = false;
        for (let i = h.pos; i < h.pos + h.word.length; i++) {
            if (used.has("c" + i)) { covered = true; break; }
        }
        if (covered) return;
        for (let i = h.pos; i < h.pos + h.word.length; i++) used.add("c" + i);
        used.add(key);
        kept.push(h);
    });
    return kept;
}

// 找出某个词在文本里的所有出现位置
function wordPositions(lower, word) {
    const out = [];
    const lw = String(word).toLowerCase();
    let from = 0;
    for (;;) {
        const i = lower.indexOf(lw, from);
        if (i < 0) break;
        out.push(i);
        from = i + lw.length;
        if (out.length > 40) break;
    }
    return out;
}

/**
 * 判定一条消息对各标的的情绪
 * @param text 标题 + 摘要
 * @param instruments 品种注册表
 * @param taggedSymbols 这条消息已经关联上的标的（只有它们参与判定）
 * @param prevMap 已有的 sentiment_map（保留人工修正）
 */
/**
 * 核心判定：把一段文本按句切开，逐句找方向词并绑定到主语，返回每个标的的净分与依据
 * @param text   待判定的文本（标题或摘要）
 * @param ctx    { kindOf, tagged, taggedSet, nameMap, nameWords }
 * @param scale  该段文本的权重（标题 1，摘要降权）
 */
function judgeCore(text, ctx, scale) {
    const { kindOf, tagged, taggedSet, nameMap, nameWords } = ctx;
    const weight = scale == null ? 1 : scale;
    const acc = {}; // symbol -> { score, hits }
    const sentences = splitSentences(stripNoisePhrases(text));

    sentences.forEach(sentence => {
        const lower = sentence.toLowerCase();
        const hits = collectDirections(sentence);
        const cands = [];
        const nameCovered = new Set(); // 本句里被具体品种名点名的标的

        // —— 主语候选 ① 具体品种名（最具体，spec=2）——
        nameWords.forEach(word => {
            const syms = Array.from(nameMap[word]).filter(s => taggedSet.has(s));
            if (!syms.length) return;
            const positions = wordPositions(lower, word);
            if (!positions.length) return;
            syms.forEach(s => nameCovered.add(s));
            cands.push({ type: "inst", positions, symbols: syms, spec: syms.length === 1 ? 2 : 1 });
        });

        // —— 主语候选 ② 行业别名 → 该类别下已打标的标的（已点名的品种不再重复分摊）——
        Object.keys(NEWS_ALIAS_KIND).forEach(kind => {
            const syms = tagged.filter(s => kindOf[s] === kind && !nameCovered.has(s));
            if (!syms.length) return;
            let positions = [];
            NEWS_ALIAS_KIND[kind].forEach(w => { positions = positions.concat(wordPositions(lower, w)); });
            positions = Array.from(new Set(positions)).sort((a, b) => a - b);
            if (!positions.length) return;
            cands.push({ type: "inst", positions, symbols: syms, spec: 1 });
        });

        // —— 主语候选 ②' 泛称（贵金属）→ 黄金/白银/铂金/钯金 ——
        NEWS_GENERIC_METALS.forEach(gw => {
            const gpos = wordPositions(lower, gw);
            if (!gpos.length) return;
            const gsyms = tagged.filter(s => NEWS_GENERIC_KINDS.indexOf(kindOf[s]) >= 0);
            if (!gsyms.length) return;
            cands.push({ type: "inst", positions: gpos, symbols: gsyms, spec: 1 });
        });

        // —— 主语候选 ④ 干扰主语：方向词归它，不落到任何标的 ——
        let ignorePos = [];
        NEWS_IGNORE_SUBJECTS.forEach(w => { ignorePos = ignorePos.concat(wordPositions(lower, w)); });
        if (ignorePos.length) cands.push({ type: "ignore", positions: ignorePos, symbols: [], spec: 0 });

        // —— 主语候选 ③ 宏观主体 → 贵金属（美元/实际利率/通胀走强 = 贵金属走弱）——
        MACRO_SUBJECTS.forEach(ms => {
            const syms = tagged.filter(s => ms.kinds.indexOf(kindOf[s]) >= 0);
            if (!syms.length) return;
            let positions = [];
            ms.words.forEach(w => { positions = positions.concat(wordPositions(lower, w)); });
            positions = Array.from(new Set(positions)).sort((a, b) => a - b);
            if (!positions.length) return;
            cands.push({ type: "macro", positions, symbols: syms, spec: 1, inv: ms.inv, w: ms.w });
        });

        const perSymbol = {}; // symbol -> [{dir,w,word,spec}]
        const push = (sym, dir, w, word, spec) => {
            let list = perSymbol[sym];
            if (!list) { list = []; perSymbol[sym] = list; }
            list.push({ dir, w, word, spec });
        };

        if (hits.length && cands.length) {
            hits.forEach(h => {
                // 中文语序：主语在谓语左边，取左边最近的那个；左边没有才退化为绝对距离最近
                // 两轮配对：先只看「主语在左边」的（中文语序），左边没有/太远再回退到全局最近
                const pickCand = (onlyLeft) => {
                    let best = null, bestKey = Infinity, bestPos = -1, bestDist = Infinity;
                    cands.forEach(c => {
                        if (c.type === "ignore") return;
                        let bd = Infinity, left = false, bp = -1;
                        c.positions.forEach(p => {
                            if (onlyLeft) {
                                if (p <= h.pos) { const d = h.pos - p; if (d < bd) { bd = d; bp = p; left = true; } }
                            } else {
                                const d = Math.abs(h.pos - p); if (d < bd) { bd = d; bp = p; left = false; }
                            }
                        });
                        if (bd === Infinity) return;
                        if (bd > MAX_BIND_DIST) return; // 距离太远，不算这个主语
                        const key = (left ? 0 : 1000000) + bd * 10 - c.spec * 2;
                        if (key < bestKey) { bestKey = key; best = c; bestPos = bp; bestDist = bd; }
                    });
                    return { best, bestPos, bestDist };
                };
                let picked = pickCand(true);
                if (!picked.best) picked = pickCand(false);
                const best = picked.best, bestPos = picked.bestPos, bestDist = picked.bestDist;                if (!best) return;
                // 干扰主语（油价、A股…）比正常主语明显更近时，这个方向词与贵金属无关，直接丢弃
                let igDist = Infinity;
                cands.forEach(c => {
                    if (c.type !== "ignore") return;
                    c.positions.forEach(p => { const d = Math.abs(h.pos - p); if (d < igDist) igDist = d; });
                });
                if (igDist + 4 < bestDist) return;
                // 并列主语：「金价银价大涨」里金价与银价并列，方向词对两者都成立
                const targets = [best];
                cands.forEach(c => {
                    if (c === best) return;
                    let near = false;
                    c.positions.forEach(p => { if (p >= bestPos - 3 && p < bestPos) near = true; });
                    if (near && targets.indexOf(c) < 0) targets.push(c);
                });
                targets.forEach(t => {
                    if (t.type === "macro") {
                        // 美元/实际利率/通胀走强 → 贵金属走弱，方向词取反
                        const effDir = (t.inv === -1 && POLICY_WORDS.indexOf(h.word) < 0) ? -h.dir : h.dir;
                        const w = Math.max(t.w, h.weight);
                        t.symbols.forEach(s => push(s, effDir, w, h.word, t.spec));
                    } else {
                        t.symbols.forEach(s => push(s, h.dir, h.weight, h.word, t.spec));
                    }
                });
            });
        } else {
            // —— 句内无主语或无方向词：宏观自带动方向的词兜底（只落贵金属）——
            const mw = MACRO_WORDS.find(m => m.words.some(w => lower.includes(w)));
            if (mw) {
                const word = mw.words.find(w => lower.includes(w));
                const syms = [];
                mw.kinds.forEach(k => tagged.forEach(s => { if (kindOf[s] === k) syms.push(s); }));
                if (syms.length) syms.forEach(s => push(s, mw.dir, mw.w, word, 1));
            }
        }

        // 同一标的在本句里被多个主语命中时，以更具体的那次为准（沪金比「黄金」更具体）
        Object.keys(perSymbol).forEach(sym => {
            const list = perSymbol[sym];
            let maxSpec = 0;
            list.forEach(x => { if (x.spec > maxSpec) maxSpec = x.spec; });
            list.filter(x => x.spec === maxSpec).forEach(x => {
                let row = acc[sym];
                if (!row) { row = { score: 0, hits: [] }; acc[sym] = row; }
                row.score += x.dir * x.w * weight;
                if (x.word && row.hits.indexOf(x.word) < 0 && row.hits.length < 4) row.hits.push(x.word);
            });
        });
    });
    return acc;
}


function judgeSentiment(text, instruments, taggedSymbols, prevMap) {

    const insts = (instruments || []).filter(i => Number(i.enabled) === 1);
    const kindOf = {};
    insts.forEach(i => { kindOf[i.symbol] = i.kind || ""; });
    const tagged = (Array.isArray(taggedSymbols) ? taggedSymbols : []).filter(s => kindOf[s] != null);
    if (!tagged.length) {
        // 没有关联标的的消息不参与判定（例如讲美股评级的新闻与我们无关）
        return { sentiment: "neutral", score: 0, hits: [], map: {} };
    }
    const taggedSet = new Set(tagged);

    // 品种全称 / 简称 → 标的集合（同一个词可能对应多个品种）
    const nameMap = {};
    insts.forEach(i => {
        [i.name, i.short_name].filter(Boolean).forEach(w => {
            const word = String(w).toLowerCase().replace(/主连|连续|现货|主力/g, "");
            if (word.length < 2) return;
            let set = nameMap[word];
            if (!set) { set = new Set(); nameMap[word] = set; }
            set.add(i.symbol);
        });
    });
    const nameWords = Object.keys(nameMap).sort((a, b) => b.length - a.length);

    const ctx = { kindOf, tagged, taggedSet, nameMap, nameWords };
    // 标题与摘要分开判定：新闻标题是主旨，摘要只是补充。
    // 「期市收评｜商品期货跌多涨少 贵金属涨幅居前」标题说利多，摘要里一句「加息」不该把它压成利空。
    const full = String(text || "");
    const cut = full.indexOf("。");
    const titlePart = cut > 0 ? full.slice(0, cut) : full;
    const restPart = cut > 0 ? full.slice(cut + 1) : "";
    const acc = {}; // symbol -> { score, hits }
    const merge = (src) => {
        Object.keys(src).forEach(sym => {
            const row = acc[sym] || (acc[sym] = { score: 0, hits: [] });
            row.score += src[sym].score;
            (src[sym].hits || []).forEach(h => { if (row.hits.indexOf(h) < 0 && row.hits.length < 4) row.hits.push(h); });
        });
    };
    merge(judgeCore(titlePart, ctx, 1));
    if (restPart.trim()) merge(judgeCore(restPart, ctx, SUMMARY_WEIGHT));

    // 输出 map（保留人工修正：manual 的条目不被自动判定覆盖）
    const map = {};
    // 已打标但本条消息没有明确方向的标的，也要落一条中性，工作台的「消息面」统计才完整
    tagged.forEach(sym => {
        if (!acc[sym]) map[sym] = { label: "neutral", score: 0, hits: [], manual: 0 };
    });
    Object.keys(acc).forEach(sym => {
        const row = acc[sym];
        const score = row.score;
        map[sym] = {
            label: score > 0.6 ? "bullish" : score < -0.6 ? "bearish" : "neutral",
            score: Math.round(score * 100) / 100,
            hits: row.hits,
            manual: 0
        };
    });
    if (prevMap && typeof prevMap === "object") {
        Object.keys(prevMap).forEach(sym => {
            const p = prevMap[sym];
            if (!p || !p.manual) return;
            map[sym] = Object.assign({}, map[sym] || {}, {
                label: p.label,
                score: p.score != null ? p.score : (map[sym] ? map[sym].score : 0),
                hits: p.hits && p.hits.length ? p.hits : ((map[sym] && map[sym].hits) || []),
                manual: 1
            });
        });
    }

    // 整体标签：按标的投票（利多的标的多就是利多）
    // 不能用分数求和——求和会被标的数量放大（4 个标的各 -0.2 会被算成 -0.8 而判成利空）。
    // 这里与人工修正后的 overallSentimentOf 保持同一口径，重算时整体标签才不会跳变。
    let bull = 0, bear = 0, symCount = 0;
    Object.keys(map).forEach(s => {
        const v = map[s] || {};
        const wgt = v.manual ? 2 : 1;
        symCount++;
        if (v.label === "bullish") bull += wgt;
        else if (v.label === "bearish") bear += wgt;
    });
    const sentiment = bull > bear ? "bullish" : bear > bull ? "bearish" : "neutral";
    const overall = symCount ? (bull - bear) / symCount : 0;
    const allHits = [];
    Object.keys(map).forEach(s => (map[s].hits || []).forEach(h => { if (allHits.indexOf(h) < 0) allHits.push(h); }));
    return { sentiment, score: Math.round(overall * 100) / 100, hits: allHits.slice(0, 6), map };
}

function nowBeijing() {
    return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 19).replace("T", " ");
}

// ==== IMPACT_ENGINE_START ====
// ============================================================
// 消息影响研判（impact）：把「最新消息」推演成「未来方向倾向 + 传导链」
//   与 sentiment 分工（两套并存，互不污染）：
//     · sentiment = 按 AU0/AG0 品种的情绪打标，供工作台 / 决策面板统计（既有能力）
//     · impact    = 面向两类问题的方向研判：
//         ① 宏观变量 → 金价：美联储加息 / 美元走强 / 实际利率上行 → 金价偏跌
//         ② AI 事件 → 板块与公司：出口管制 → 英伟达偏跌；业绩超预期 → AI算力偏涨
//   边界（务必守住）：这是**消息面规则推演**，不是价格预测。项目没有股票行情数据，
//     不输出股价、涨跌幅、目标价；结论只反映这条消息本身的倾向，且可能已被市场提前定价。
//   自包含：本段不引用 worker 其它函数 / 常量，便于单测按起止标记切片独立运行。
// ============================================================
const IMPACT_VERSION = "v1-20261113-impact3";

// 虚拟标的：只用于研判展示，**不进 metal_instruments**，因此不污染行情 / 工作台 / 品种口径
//   （品种域仍只有 AU0 / AG0）。公司名只用于标题匹配，不作为检索关键词（沿用 2026-11-12 定稿）。
const IMPACT_TARGETS = [
    { key: "NVDA", name: "英伟达", words: ["英伟达", "nvidia"], kind: "公司" },
    { key: "AICHIP", name: "AI芯片", words: ["ai芯片", "算力芯片", "gpu", "显卡", "hbm", "先进封装", "cowos"], kind: "板块" },
    { key: "COMPUTE", name: "AI算力", words: ["算力", "智算", "超算", "数据中心", "液冷", "光模块", "ai服务器"], kind: "板块" },
    { key: "SEMI", name: "半导体", words: ["半导体", "芯片", "光刻机", "晶圆", "eda", "制程"], kind: "板块" },
    { key: "AIMODEL", name: "大模型应用", words: ["大模型", "生成式ai", "aigc", "ai应用", "ai agent", "人形机器人", "自动驾驶"], kind: "板块" },
    { key: "AIENERGY", name: "AI能源", words: ["ai用电", "算力用电", "数据中心用电", "ai电力", "核电", "电网"], kind: "板块" }
];

// 宏观 → 金价：requires = 必须出现的主体（防「日本央行加息」误伤）；except = 出现即跳过
const IMPACT_MACRO = [
    { words: ["美联储加息", "加息", "缩表", "收紧货币政策"], dir: -1, w: 2.5, event: "宏观·利率", requires: ["美联储", "美国", "fed", "联储"], except: ["日本", "欧洲央行", "英国央行", "韩国", "中国央行"], chain: "美联储加息/紧缩 → 实际利率上行 → 持有黄金的机会成本上升 → 金价承压偏跌" },
    { words: ["美联储降息", "降息", "货币宽松", "宽松预期"], dir: 1, w: 2.5, event: "宏观·利率", requires: ["美联储", "美国", "fed", "联储"], except: ["日本", "欧洲央行", "英国央行", "韩国", "中国央行"], chain: "美联储降息/宽松 → 实际利率下行 → 持有黄金的机会成本下降 → 金价偏涨" },
    { words: ["美元指数走强", "美元走强", "美元升值", "美元大涨", "美元指数上涨"], dir: -1, w: 2, event: "宏观·汇率", chain: "美元走强 → 以美元计价的黄金变贵 → 金价承压偏跌" },
    { words: ["美元指数走弱", "美元走弱", "美元贬值", "美元回落", "美元下跌"], dir: 1, w: 2, event: "宏观·汇率", chain: "美元走弱 → 以美元计价的黄金变便宜 → 金价偏涨" },
    { words: ["实际利率上行", "美债收益率上行", "美债收益率飙升", "实际利率走高"], dir: -1, w: 2, event: "宏观·利率", chain: "实际利率上行 → 无息资产吸引力下降 → 金价偏跌" },
    { words: ["实际利率下行", "美债收益率下行", "实际利率走低"], dir: 1, w: 2, event: "宏观·利率", chain: "实际利率下行 → 无息资产吸引力上升 → 金价偏涨" },
    { words: ["通胀升温", "通胀飙升", "通胀超预期", "cpi超预期", "通胀压力加大"], dir: 1, w: 1.5, event: "宏观·通胀", chain: "通胀升温 → 保值需求上升 → 金价偏涨（若同时引发加息预期，方向可能反转）" },
    { words: ["避险情绪", "避险需求", "地缘紧张", "冲突升级", "局势紧张"], dir: 1, w: 2, event: "宏观·避险", chain: "避险情绪升温 → 资金流向黄金 → 金价偏涨" },
    { words: ["央行购金", "增持黄金"], dir: 1, w: 1.5, event: "宏观·供需", chain: "央行购金 → 实物需求增加 → 金价偏涨" }
];

// AI / 科技事件 → 板块与公司方向。每条规则最多计一次分，避免同义重复叠加。
const IMPACT_AI_EVENTS = [
    // except：「反对滥用出口管制」是反对管制的表态，不是管制落地，不能判成利空
    { words: ["出口管制", "限制出口", "禁售", "实体清单", "芯片禁令", "管制升级", "制裁"], dir: -1, w: 2.5, event: "政策监管", except: ["反对出口管制", "反对滥用", "滥用出口管制"], chain: "出口管制/禁令 → 高端芯片出货受限 → 相关公司营收承压 → 偏跌" },
    { words: ["反垄断调查", "反垄断", "监管收紧", "立案调查", "罚款"], dir: -1, w: 1.5, event: "政策监管", chain: "监管调查 → 经营不确定性上升 → 估值承压 → 偏跌" },
    { words: ["政策扶持", "专项补贴", "国产替代", "纳入规划", "专项支持", "算力券"], dir: 1, w: 1.5, event: "政策扶持", chain: "政策扶持 → 资金与需求落地 → 产业链订单预期改善 → 偏涨" },
    { words: ["业绩超预期", "营收超预期", "指引上调", "上调全年", "创纪录营收", "利润大增"], dir: 1, w: 2.5, event: "公司业绩", chain: "业绩超预期 → 盈利上修 → 估值支撑 → 偏涨" },
    { words: ["业绩不及预期", "营收不及预期", "盈利不及预期", "指引不及预期", "营收下滑", "指引下调", "下调预期", "亏损扩大", "利润下滑"], dir: -1, w: 2.5, event: "公司业绩", chain: "业绩不及预期 → 盈利下修 → 估值承压 → 偏跌" },
    { words: ["大单", "获得订单", "中标", "签约", "供货", "进入供应链", "订单饱满", "订单激增"], dir: 1, w: 2, event: "订单需求", chain: "订单/客户落地 → 收入确定性提升 → 偏涨" },
    { words: ["砍单", "订单取消", "削减订单", "客户流失", "取消订单"], dir: -1, w: 2, event: "订单需求", chain: "砍单 → 需求预期下修 → 偏跌" },
    { words: ["新品发布", "新一代", "量产", "技术突破", "流片成功", "发布大模型"], dir: 1, w: 1.5, event: "产品技术", chain: "新品/技术突破 → 产品周期启动 → 偏涨" },
    { words: ["延期", "跳票", "召回", "停产", "重大故障", "良率不及"], dir: -1, w: 2, event: "经营风险", chain: "产品延期/事故 → 交付与声誉受损 → 偏跌" },
    { words: ["供不应求", "产能满载", "满产", "涨价", "提价", "供需紧张", "缺货"], dir: 1, w: 1.5, event: "产业供需", chain: "供不应求/涨价 → 议价能力上升 → 偏涨" },
    { words: ["价格战", "降价", "库存积压", "产能过剩", "需求疲软", "需求走弱", "去库存"], dir: -1, w: 1.5, event: "产业供需", chain: "价格战/需求走弱 → 毛利与销量承压 → 偏跌" },
    // except：「收紧数据中心新建审批」是限制而非扩产，摘要里出现「扩建」也不能判成利多
    { words: ["资本开支上调", "加大投资", "扩产", "新建产线", "扩建"], dir: 1, w: 1, event: "产业投资", except: ["收紧", "限制新建", "审批收紧", "暂停"], chain: "资本开支上调 → 上游设备/材料需求增加 → 产业链偏涨（对扩产方本身可能中性）" },
    { words: ["缩减开支", "暂停项目", "裁员", "冻结招聘", "削减资本开支"], dir: -1, w: 1.5, event: "经营收缩", chain: "缩减开支/裁员 → 景气度回落信号 → 偏跌" },
    // —— 真实快讯高频表述（2026-11-13 抽样校准）——
    { words: ["增收不增利", "毛利率下滑", "利润率下降", "毛利承压"], dir: -1, w: 1.5, event: "盈利质量", chain: "营收增长但利润未同步 → 盈利质量走弱 → 偏跌" },
    // 市场表现类：这是**已发生的价格反应**，不是未来预测，传导链里必须写明，避免循环论证
    { words: ["集体下挫", "高开低走", "大幅下挫", "板块走弱", "股价下挫"], dir: -1, w: 1, event: "市场表现", chain: "板块/个股已出现明显回落 → 短期情绪偏弱（已发生的价格反应，非未来预测）" },
    { words: ["获批", "过会", "ipo过会", "发布在即", "再迎催化", "销量增", "订单增长", "业绩预增", "扭亏为盈", "取得积极成果", "毛利率提升", "毛利率持续提升"], dir: 1, w: 1, event: "积极进展", except: ["增速放缓", "销量增速放缓"], chain: "审批/产品/订单取得实质进展 → 基本面预期改善 → 偏涨" }
];

// 词边界匹配：纯 ASCII 词要求前后不是字母数字，避免 eda 命中 edaily、ai 误伤 said/air
function impactFind(lower, w) {
    if (/^[a-z0-9]+$/.test(w)) {
        let from = 0;
        for (;;) {
            const i = lower.indexOf(w, from);
            if (i < 0) return -1;
            const before = i === 0 ? "" : lower[i - 1];
            const after = i + w.length >= lower.length ? "" : lower[i + w.length];
            if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) return i;
            from = i + w.length;
        }
    }
    return lower.indexOf(w);
}
// 方向词前紧贴否定字时反向（「不加息」「未超预期」）
function impactNegated(lower, pos) {
    if (pos <= 0) return false;
    return /(?:不|未|无|没有|尚未|难|非)$/.test(lower.slice(Math.max(0, pos - 4), pos));
}
function impactMatchRules(lower, rules, acc) {
    rules.forEach(rule => {
        if (rule.except && rule.except.some(x => impactFind(lower, x) >= 0)) return;
        if (rule.requires && !rule.requires.some(x => impactFind(lower, x) >= 0)) return;
        let hitWord = "", pos = -1;
        for (const w of rule.words) {
            const p = impactFind(lower, w);
            if (p >= 0) { hitWord = w; pos = p; break; }
        }
        if (!hitWord) return;
        const neg = impactNegated(lower, pos);
        acc.push({ word: hitWord, dir: neg ? -rule.dir : rule.dir, w: rule.w * (neg ? 0.8 : 1), event: rule.event, chain: rule.chain });
    });
}

/**
 * 研判一条消息的未来方向倾向（消息面规则推演，非价格预测）
 * @returns {v,direction(bullish/bearish/neutral),score,strength,event,targets,hits,chains,scope,manual}
 */
function judgeImpact(title, summary, channel) {
    const t = String(title || ""), s = String(summary || "");
    const lower = (t + "。" + s).toLowerCase();
    const titleLower = t.toLowerCase();

    // ① 虚拟标的只在标题里找：摘要里出现的公司名多半是配角
    const targets = [];
    IMPACT_TARGETS.forEach(x => {
        if (x.words.some(w => impactFind(titleLower, w) >= 0)) targets.push({ key: x.key, name: x.name, kind: x.kind });
    });

    // ② 事件 / 宏观规则命中
    const aiHits = [], macroHits = [];
    impactMatchRules(lower, IMPACT_AI_EVENTS, aiHits);
    impactMatchRules(lower, IMPACT_MACRO, macroHits);
    const all = aiHits.concat(macroHits);
    if (!all.length) {
        return { v: IMPACT_VERSION, direction: "neutral", score: 0, strength: "—", event: "", targets: [], hits: [], chains: [], scope: "none", manual: 0 };
    }

    // ③ AI 频道但没点名具体标的时，用「AI板块」兜底；宏观命中则把金价列为影响对象
    //   注意：只有「频道本身就是 ai」才加 AI板块 兜底 —— 不能因为命中了 AI 类事件词就加，
    //   否则「黄金配置价值」这类 metal 消息会因摘要里出现「不及预期」被错挂上「AI板块」。
    if (channel === "ai" && !targets.length) targets.push({ key: "AI", name: "AI板块", kind: "板块" });
    if (macroHits.length && !targets.some(x => x.key === "GOLD")) targets.push({ key: "GOLD", name: "金价/银价", kind: "贵金属" });

    let score = 0;
    all.forEach(h => { score += h.dir * h.w; });
    score = Math.round(score * 100) / 100;
    const ranked = all.slice().sort((a, b) => b.w - a.w);
    const chains = [], hits = [];
    ranked.forEach(h => { if (h.chain && chains.indexOf(h.chain) < 0 && chains.length < 2) chains.push(h.chain); });
    all.forEach(h => { if (h.word && hits.indexOf(h.word) < 0 && hits.length < 5) hits.push(h.word); });
    const abs = Math.abs(score);
    // 多空交织：正负两侧都有实打实的信号，且净值不大 → 这类消息本身就在讲分歧，
    //   强行给单一涨跌方向会误导（如「多重因素支撑…但实际利率上行会压制…」）。
    //   判为 neutral 并标注 mixed，避免拿分歧稿当方向催化。
    const posW = all.filter(h => h.dir > 0).reduce((s, h) => s + h.w, 0);
    const negW = all.filter(h => h.dir < 0).reduce((s, h) => s + h.w, 0);
    const mixed = posW > 0 && negW > 0 && Math.abs(score) < 1.5;
    return {
        v: IMPACT_VERSION,
        direction: mixed ? "neutral" : score > 0.6 ? "bullish" : score < -0.6 ? "bearish" : "neutral",
        score: score,
        strength: mixed ? "分歧" : abs >= 3 ? "强" : abs >= 1.5 ? "中" : "弱",
        event: ranked[0].event,
        targets: targets.slice(0, 4),
        hits: hits,
        chains: chains,
        mixed: mixed ? 1 : 0,
        scope: aiHits.length && macroHits.length ? "both" : aiHits.length ? "ai" : "metal",
        manual: 0
    };
}
// 容错解析：坏 JSON 一律当空，不让一条脏数据打断整页
function parseImpact(raw) {
    try { const o = JSON.parse(String(raw || "")); return (o && typeof o === "object") ? o : null; }
    catch (e) { return null; }
}
// ==== IMPACT_ENGINE_END ====

// ==== KEY_PICK_ENGINE_START ====
// ============================================================
// 重点消息自动挑选算法（key pick）：在已入库的消息里挑出「值得重点看」的
//   定位：impact 引擎判「方向 + 传导链」，本引擎判「重要性排序」——两者串联：
//     impact 判不出方向（scope=none）→ 基本不会是重点；
//     impact 判出方向后，本引擎按六个维度打分，决定是否点亮为「重点」。
//   六个维度（满分 100）：
//     ① 研判方向强度（0-30）：方向明确 + 强度高 = 核心驱动；scope=none 基本为 0
//     ② 影响范围（0-20）：影响标的越多、越贴近核心品种（AU0/AG0）+ AI 板块越重要
//     ③ 事件类型权重（0-25）：政策监管 / 宏观利率 / 公司业绩 这类「能改变预期」的事件更重
//     ④ 标题信号强度（0-15）：突发、创纪录、超预期、暴跌 等强信号词
//     ⑤ 来源权威度（0-10）：华尔街见闻 / 新浪 7×24 属一线快讯源
//     ⑥ 时效性（0-10）：刚发布的消息更重要
//   降权项：研报 / 问答 / 盘点 / 名单类「信息量低」的内容减分，避免通知中心被噪音刷屏。
//   边界：这是**重要性排序**，不是投资建议；分数只反映「这条消息值不值得重点看」。
//   自包含：不引用 worker 其它函数 / 常量，便于单测按起止标记切片独立运行。
// ============================================================
const KEY_PICK_VERSION = "v1-20261113-key3";

// 事件类型 → 权重（0-25）。规则对应 impact 引擎给出的 event 字段。
const KEY_EVENT_WEIGHT = {
    "宏观·利率": 25, "宏观·汇率": 22, "政策监管": 22, "公司业绩": 22,
    "宏观·通胀": 18, "宏观·避险": 18, "订单需求": 18, "经营风险": 18,
    "宏观·供需": 14, "产业供需": 14, "经营收缩": 14, "盈利质量": 14,
    "产品技术": 12, "政策扶持": 12, "产业投资": 12, "积极进展": 10,
    "市场表现": 8
};

    // —— 标题强信号词：命中即加「信号强度」分（同一词只计一次，最多 4 个词）
    //   注意：裸「不及预期」不算强信号 —— 它在分析稿里常是条件句（「若…不及预期则转为利多」），
    //   只有带主语的「业绩/营收不及预期」才算真正的利空信号。
const KEY_STRONG_SIGNALS = [
    "突发", "紧急", "重大", "创纪录", "历史新高", "历史新低", "超预期", "远超预期",
    "业绩不及预期", "营收不及预期", "暴跌", "暴涨", "大跌", "大涨", "飙升", "重挫", "崩盘", "熔断",
    "首次", "全球首", "历史首次", "量产", "突破", "翻倍", "腰斩", "制裁", "禁令",
    "禁运", "断供", "停产", "停摆", "罢工", "爆炸", "事故", "违约", "破产",
    "加息", "降息", "加息25", "缩表", "关税", "出口管制", "实体清单", "新高", "新低"
];

// 低信息量内容（降权）：研报 / 问答 / 盘点 / 名单 / 教程类，不是增量信息
const KEY_NOISE_PATTERNS = [
    "研报", "券商", "评级", "目标价", "问答", "答疑", "一图", "盘点", "合集", "汇总",
    "名单", "榜单", "排行", "解读", "点评", "复盘", "回顾", "盘点", "招聘", "教程",
    "指南", "科普", "什么是", "如何", "怎么", "教你", "别错过", "收藏", "值得关注吗",
    "有什么", "是什么", "能不能", "影响吗", "算不算", "值得"
];

// 来源权威度（0-10）：一线快讯源 > 资讯搜索源
const KEY_SOURCE_WEIGHT = { wscn: 10, sina: 9, eastmoney: 6, manual: 7 };

/**
 * 重点消息「简明摘要」：一句话讲清「发生了什么 → 偏涨还是偏跌 → 影响谁」
 *   规则：
 *   ① 主体取标题核心（去掉句末标点，超长截断），不编造原文没有的事实；
 *   ② 方向来自研判（偏涨/偏跌/多空分歧/方向不明），没有研判就不硬给方向；
 *   ③ 影响标的最多列 2 个；事件类型作为补充；
 *   ④ 整体不超过 70 字 —— 通知中心与资讯卡片都要一眼看完。
 *   自包含：不引用外部函数，便于单测切片运行。
 * @param {string} title 标题
 * @param {string} summary 原始摘要（标题缺失时兜底）
 * @param {object} impact judgeImpact() 的结果（可为空）
 * @returns {string} 简明摘要（可能为空串）
 */
function briefKeyNews(title, summary, impact) {
    const t = String(title == null ? "" : title).replace(/\s+/g, " ").trim();
    const imp = (impact && typeof impact === "object") ? impact : null;

    // ① 主体：标题（去掉句末标点）
    let head = t.replace(/[。．.！!？?；;，,、\s]+$/g, "");
    if (head.length > 36) head = head.slice(0, 36) + "…";

    // ② 方向：只在研判给了方向时才写，避免「方向不明」也硬凑一个结论
    let dir = "";
    if (imp) {
        if (imp.direction === "bullish") dir = "偏涨";
        else if (imp.direction === "bearish") dir = "偏跌";
        else if (imp.direction === "mixed" || imp.strength === "分歧") dir = "多空分歧";
        else if (imp.scope && imp.scope !== "none") dir = "方向不明";
    }

    // ③ 影响标的（最多 2 个）
    const tg = (imp && Array.isArray(imp.targets))
        ? imp.targets.map(x => (x && x.name) ? String(x.name) : "").filter(Boolean).slice(0, 2)
        : [];

    // ④ 事件类型
    const ev = (imp && imp.event) ? String(imp.event) : "";

    let brief = head;
    if (dir) brief += (brief ? " → " : "") + dir;
    if (tg.length) brief += "（影响 " + tg.join("、") + "）";
    if (ev) brief += (brief ? " · " : "") + ev;
    if (brief.length > 70) brief = brief.slice(0, 70) + "…";

    // ⑤ 连标题都没有：用原始摘要首句兜底，仍然「不编造」
    if (!brief) {
        const s = String(summary == null ? "" : summary).replace(/\s+/g, " ").trim();
        brief = s.length > 60 ? s.slice(0, 60) + "…" : s;
    }
    return brief;
}

/**
 * 给一条消息打「重点分」，并判定是否点亮为重点
 * @param {string} title 标题
 * @param {string} summary 摘要
 * @param {string} channel 频道（ai/macro/metal/equity...）
 * @param {object} impact judgeImpact() 的结果（可为空）
 * @param {string} source 来源 key（wscn/sina/eastmoney/manual）
 * @param {string} publishedAt 发布时间（北京时间字符串）
 * @param {number} nowMs 当前时间戳（毫秒），传入便于单测固定时间
 * @returns {{score:number,isKey:boolean,reasons:string[],dims:object,brief:string}}
 */
function pickKeyNews(title, summary, channel, impact, source, publishedAt, nowMs) {
    const t = String(title || ""), s = String(summary || "");
    const text = t + "。" + s;
    const reasons = [];
    const dims = { impact: 0, scope: 0, event: 0, signal: 0, source: 0, fresh: 0, noise: 0 };
    let score = 0;

    const imp = (impact && typeof impact === "object") ? impact : null;
    const direction = imp && (imp.direction === "bullish" || imp.direction === "bearish") ? imp.direction : "";

    // ① 研判方向强度（0-30）：方向明确且强度高 = 核心驱动信号
    //   「分歧」强度意味着多空交织（本身在讲分歧），不计入方向分 —— 否则分歧稿会被当成强方向催化。
    if (direction) {
        const st = imp.strength || "弱";
        const base = st === "强" ? 22 : st === "中" ? 16 : st === "分歧" ? 0 : 10;
        dims.impact = base;
        score += base;
        reasons.push((direction === "bullish" ? "方向偏涨" : "方向偏跌") + "（强度" + st + "）");
    }

    // ② 影响范围（0-20）：影响标的数量 + 是否命中核心品种
    const targets = (imp && Array.isArray(imp.targets)) ? imp.targets : [];
    const names = targets.map(x => x.name).filter(Boolean);
    if (names.length) {
        const per = Math.min(8, 6 + (names.length - 1) * 3);
        let v = per;
        const core = names.some(n => /金价|银价|黄金|白银|沪金|沪银/.test(n));
        if (core) v += 6;                       // 直击核心品种（AU0/AG0）加权
        if (imp.scope === "both") v += 4;       // 同时影响 AI 与贵金属，跨域传导更重要
        dims.scope = Math.min(20, v);
        score += dims.scope;
        reasons.push("影响 " + names.slice(0, 3).join("/") + (core ? "（直击贵金属）" : ""));
    }

    // ③ 事件类型权重（0-25）：能改变市场预期的事件更重
    if (imp && imp.event && KEY_EVENT_WEIGHT[imp.event]) {
        dims.event = KEY_EVENT_WEIGHT[imp.event];
        score += dims.event;
        reasons.push("事件类型：" + imp.event);
    }

    // ④ 标题强信号词（0-15）：最多 4 个词，每个 4 分
    let sigCount = 0;
    const sigs = [];
    KEY_STRONG_SIGNALS.forEach(w => {
        if (sigs.length >= 4) return;
        if (text.indexOf(w) >= 0) { sigs.push(w); }
    });
    if (sigs.length) {
        dims.signal = Math.min(15, sigs.length * 4);
        score += dims.signal;
        reasons.push("强信号：" + sigs.slice(0, 4).join("、"));
    }
    sigCount = sigs.length;

    // ⑤ 来源权威度（0-10）
    dims.source = KEY_SOURCE_WEIGHT[source] != null ? KEY_SOURCE_WEIGHT[source] : 5;
    score += dims.source;

    // ⑥ 时效性（0-10）：1 小时内 10 分，6 小时内 7 分，24 小时内 4 分
    const pub = String(publishedAt || "");
    const pubMs = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(pub) ? Date.parse(pub.replace(" ", "T") + "+08:00") : NaN;
    const now = Number(nowMs) || Date.now();
    if (!isNaN(pubMs)) {
        const hours = (now - pubMs) / 3600000;
        if (hours >= -1 && hours < 1) dims.fresh = 10;
        else if (hours < 6) dims.fresh = 7;
        else if (hours < 24) dims.fresh = 4;
        else dims.fresh = 0;
        score += dims.fresh;
    }

    // 降权：低信息量内容（研报 / 问答 / 盘点 / 名单…）减 12 分
    let noiseHit = "";
    for (const w of KEY_NOISE_PATTERNS) {
        if (text.indexOf(w) >= 0) { noiseHit = w; break; }
    }
    if (noiseHit) {
        dims.noise = -12;
        score += dims.noise;
        reasons.push("信息量偏低（含「" + noiseHit + "」）");
    }

    score = Math.max(0, Math.round(score));
    // 判定阈值 55：必须同时具备方向或强信号，否则不予点亮（避免普通陈述被当成重点）
    const hasSignal = sigCount > 0 || direction !== "";
    // 多空交织稿（研判标了 mixed / 强度为「分歧」）直接排除：
    //   这类消息本身在讲分歧，把「事件类型 + 时效 + 来源」的分数堆起来点亮，
    //   会让分析稿冒充方向催化（实测「多重因素支撑 黄金中长期配置价值仍存」就是这么被误亮的）。
    const isMixed = !!(imp && (imp.mixed === 1 || imp.strength === "分歧"));
    const isKey = score >= 55 && hasSignal && !isMixed;
    if (isMixed) reasons.push("多空交织，非单向催化，不列为重点");
    else if (!isKey && score >= 40) reasons.push("综合分 " + score + "，未达重点阈值 55");
    // 简明摘要：重点消息要一眼看懂「发生了什么→偏涨偏跌→影响谁」，非重点也顺带生成，便于后续规则变化时直接点亮
    const brief = briefKeyNews(t, s, imp);
    return { v: KEY_PICK_VERSION, score: score, isKey: isKey, reasons: reasons, dims: dims, brief: brief };
}

// ==== KEY_PICK_ENGINE_END ====

// 解析 sentiment_map（容忍脏数据：坏 JSON 一律当空表，不让一条脏数据打断整页）
function parseSentimentMap(raw) {
    if (!raw) return {};
    if (typeof raw === "object") return raw;
    try {
        const o = JSON.parse(String(raw));
        return (o && typeof o === "object" && !Array.isArray(o)) ? o : {};
    } catch { return {}; }
}

// 由按标的的明细汇总出整体标签（人工修正的条目权重更高）
function overallSentimentOf(map) {
    const m = map || {};
    const keys = Object.keys(m);
    if (!keys.length) return "neutral";
    let score = 0;
    keys.forEach(k => {
        const v = m[k] || {};
        const w = v.manual ? 2 : 1;
        score += (v.label === "bullish" ? 1 : v.label === "bearish" ? -1 : 0) * w;
    });
    return score > 0 ? "bullish" : score < 0 ? "bearish" : "neutral";
}

function stripHtml(s) {
    return String(s == null ? "" : s)
        .replace(/<script[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/g, " ").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
        .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")
        .replace(/\s+/g, " ").trim();
}
function newsHash(s) {
    // 轻量双哈希指纹，用于标题级去重（同步、无需 await）
    let h1 = 5381, h2 = 52711;
    const str = String(s || "");
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        h1 = ((h1 * 33) ^ c) >>> 0;
        h2 = ((h2 * 31) ^ c) >>> 0;
    }
    return h1.toString(16) + h2.toString(16) + str.length.toString(16);
}
function normNewsText(t) {
    // 剔除中文成语等假阳性（「真金白银」并非白银行情）；统一转小写，
    //   让 NVIDIA / GPU / CUDA / Blackwell 这类英文词不因大小写漏匹配
    return String(t == null ? "" : t).replace(/真金白银/g, "").toLowerCase();
}
function newsFingerprint(title) {
    // 以标题为指纹（去掉标点与小数尾零），可合并不同平台的同题快讯
    const t = String(title || "").toLowerCase()
        .replace(/[\s,，。、！!？?%％:：;；"'"'“”‘’()（）[\]]/g, "")
        .replace(/(\d+)\.0+(?=[^\d]|$)/g, "$1");
    return newsHash(t);
}
function matchNewsKeywords(text) {
    const t = normNewsText(text);
    const hit = [];
    for (const key of Object.keys(NEWS_CHANNELS)) {
        for (const kw of NEWS_CHANNELS[key].keywords) {
            // 统一走 termMatches：英文短词边界匹配（AI 不命中 said / air），中文词子串匹配
            if (termMatches(t, kw) && !hit.includes(kw)) hit.push(kw);
        }
    }
    return hit;
}
function classifyNews(text, hint) {
    if (hint && NEWS_CHANNELS[hint] && hint !== "other") return hint;
    const t = normNewsText(text);
    for (const key of NEWS_CHANNEL_ORDER) {
        if (NEWS_CHANNELS[key].keywords.some(kw => termMatches(t, kw))) return key;
    }
    return "other";
}
function flashTitle(text) {
    const s = stripHtml(text);
    const m = s.match(/^【([^】]{4,80})】/);
    if (m) return m[1].trim();
    const cut = s.split(/[。！？!?\n]/)[0] || s;
    return cut.slice(0, 60).trim();
}
function tsToBeijing(sec) {
    const n = Number(sec) || 0;
    if (!n) return nowBeijing();
    return new Date(n * 1000 + 8 * 3600 * 1000).toISOString().slice(0, 19).replace("T", " ");
}
// 通用列表切分：空值就是空列表。
//   ⚠ 不要用它替代 parseNewsKeywords —— 后者在空值时会回退成默认关键词，
//   用在「屏蔽词」这类字段上会把「清空」变成「屏蔽全部关键词」。
function splitList(raw, max) {
    const list = String(raw || "").split(/[,，;；\s]+/).map(s => s.trim()).filter(Boolean);
    const uniq = [...new Set(list)];
    return max ? uniq.slice(0, max) : uniq;
}
function parseNewsKeywords(raw) {
    // 21 个默认词（6 个 AI / 显卡固定词 + 15 个金属 / 宏观词），上限留到 24 方便用户再加
    const uniq = splitList(raw, 24);
    return uniq.length ? uniq : DEFAULT_NEWS_KEYWORDS;
}
function parseNewsSources(raw) {
    const list = String(raw || "").split(",").map(s => s.trim()).filter(s => NEWS_SOURCES[s]);
    return list.length ? list : ["eastmoney", "sina", "wscn"];
}
async function runPool(jobs, limit = 5) {
    const queue = jobs.slice();
    const runners = Array.from({ length: Math.min(limit, queue.length || 1) }, async () => {
        while (queue.length) {
            const job = queue.shift();
            // 单个任务失败不影响整批，但必须留下日志（否则采集失败完全静默）
            try { await job(); } catch (e) { logWarn("pool.job", e); }
        }
    });
    await Promise.all(runners);
}
async function settingsMap(env) {
    try {
        const rows = await env.DB.prepare("SELECT key,value FROM settings").all();
        const map = {};
        rows.results.forEach(r => { map[r.key] = r.value; });
        return map;
    } catch { return {}; }
}

// —— 东方财富：按关键词搜索全网财经媒体 ——
async function emSearch(keyword, size = 8, sort = "default", timeout = 9000) {
    // sort=default → 按相关性（结果精准）；sort=time → 按时间（返回最新财经稿，需二次按关键词过滤）
    const param = {
        uid: "", keyword, type: ["cmsArticleWebOld"], client: "web", clientType: "web", clientVersion: "curr",
        param: { cmsArticleWebOld: { searchScope: "default", sort, pageIndex: 1, pageSize: size, preTag: "", postTag: "" } }
    };
    const url = "https://search-api-web.eastmoney.com/search/jsonp?cb=cb&param=" + encodeURIComponent(JSON.stringify(param));
    const r = await fetchWithTimeout(url, { headers: { "User-Agent": NEWS_UA, "Referer": "https://so.eastmoney.com/" } }, timeout);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const text = await r.text();
    const body = text.replace(/^[^(]*\(/, "").replace(/\)\s*;?\s*$/, "");
    const data = JSON.parse(body);
    const list = (data && data.result && data.result.cmsArticleWebOld) || [];
    return list.map(a => ({
        title: stripHtml(a.title),
        summary: stripHtml(a.content).slice(0, 500),
        url: a.url || "",
        platform: stripHtml(a.mediaName) || NEWS_SOURCES.eastmoney,
        published_at: (a.date || "").trim(),
        source: "eastmoney",
        hint: "",
        sort
    })).filter(x => x.title);
}
// —— 新浪财经 7×24 快讯 ——
async function sinaLives(size = 30, timeout = 9000) {
    const url = `https://zhibo.sina.com.cn/api/zhibo/feed?page=1&page_size=${size}&zhibo_id=152&tag_id=0&dire=f&dpc=1`;
    const r = await fetchWithTimeout(url, { headers: { "User-Agent": NEWS_UA, "Referer": "https://finance.sina.com.cn/7x24/" } }, timeout);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    const list = (data && data.result && data.result.data && data.result.data.feed && data.result.data.feed.list) || [];
    return list.map(it => {
        const text = stripHtml(it.rich_text || it.content || "");
        return {
            title: flashTitle(text),
            summary: text.slice(0, 500),
            url: it.docurl || "",
            platform: "新浪财经·7×24",
            published_at: it.create_time || nowBeijing(),
            source: "sina",
            hint: ""
        };
    }).filter(x => x.title);
}
// —— 华尔街见闻 7×24 ——
async function wscnLives(channel = "global-channel", limit = 20, timeout = 9000) {
    const url = `https://api-one-wscn.awtmt.com/apiv1/content/lives?channel=${encodeURIComponent(channel)}&limit=${limit}`;
    const r = await fetchWithTimeout(url, { headers: { "User-Agent": NEWS_UA } }, timeout);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    const list = (data && data.data && data.data.items) || [];
    return list.map(it => {
        const text = stripHtml(it.content_text || it.content || "");
        const title = (it.title && String(it.title).trim()) || flashTitle(text);
        return {
            title: stripHtml(title),
            summary: text.slice(0, 500),
            url: it.uri || (it.id ? "https://wallstreetcn.com/livenews/" + it.id : ""),
            platform: channel === "commodity-channel" ? "华尔街见闻·商品" : "华尔街见闻",
            published_at: tsToBeijing(it.display_time),
            source: "wscn",
            hint: channel === "commodity-channel" ? "gold" : ""
        };
    }).filter(x => x.title);
}

async function crawlNews(env, opts = {}) {
    const cfg = await settingsMap(env);
    // 关键词优先取「消息数据」域配置
    const cfgKeywords = await acquireOption(env, "news", "news_keywords", cfg.news_keywords || "");
    const keywords = parseNewsKeywords(opts.keywords || cfgKeywords);
    // 数据源启用状态由「数据采集」页统一管理；opts.sources 优先
    //   注意：这里不能用 parseNewsSources（它空值时会回退成「全部启用」），
    //   否则「全部停用」会被 opts.sources 空串绕过。
    const sources = opts.sources
        ? String(opts.sources).split(",").map(s => s.trim()).filter(s => NEWS_SOURCES[s])
        : await enabledNewsSourceIds(env);
    // —— 消息域采集参数 ——
    const perSourceLimit = await acquireNum(env, "news", "news_per_source", NEWS_PER_SOURCE_FIXED, NEWS_PER_SOURCE_FIXED, NEWS_PER_SOURCE_FIXED);
    const maxKeywords = await acquireNum(env, "news", "news_max_keywords", 12, 1, 24);
    const channelFilter = (await acquireList(env, "news", "news_channels")).filter(c => NEWS_CHANNELS[c]);
    const retentionDays = await acquireNum(env, "news", "news_retention_days", 90, 1, 3650);
    const autoStarMetal = (await acquireOption(env, "news", "news_auto_star_metal", "1")) === "1";
    // 过滤规则：屏蔽词 / 标题最短长度（0 = 不过滤）
    const blacklist = splitList(await acquireOption(env, "news", "news_blacklist", ""));
    const minTitleLen = await acquireNum(env, "news", "news_min_title_len", 6, 0, 40);
    // 运行控制：单请求超时
    const timeoutMs = Math.round(await acquireNum(env, "news", "news_timeout_sec", 9, 3, 30) * 1000);

    if (!sources.length) {
        return {
            success: true, skipped: true, crawled: 0, inserted: 0, cleaned: 0,
            by_source: {}, by_channel: {}, keywords, channels: channelFilter,
            retention_days: retentionDays, errors: [],
            skipped_reason: "资讯数据源全部停用，已跳过本次抓取（可在「数据采集 → 消息数据」启用）",
            refreshed_at: nowBeijing()
        };
    }

    // 消息入库时顺手打上关联标的（品种池按库驱动，新增品种后新消息自动覆盖）
    const instruments = await instrumentRows(env);

    const items = [];
    const errors = [];
    const perSource = {};
    const sourceStats = {};
    const markSource = (source, ok) => {
        const s = sourceStats[source] || { ok: 0, failed: 0 };
        s[ok ? "ok" : "failed"]++;
        sourceStats[source] = s;
    };
    const jobs = [];

    let emKeywords = [];
    if (sources.includes("eastmoney")) {
        const pushEm = (kw, size, sort) => jobs.push(async () => {
            try {
                const rows = await emSearch(kw, size, sort, timeoutMs);
                markSource("eastmoney", true);
                perSource.eastmoney = (perSource.eastmoney || 0) + rows.length;
                items.push(...rows.map(r => ({ ...r, hit: kw })));
            } catch (e) { markSource("eastmoney", false); errors.push(`东方财富「${kw}」(${sort})：${e.message}`); }
        });
        // AI / 显卡固定词始终参与检索，不受用户是否写在「关注关键词」里影响；
        //   其余按「关注关键词」前 N 个，去重后总量最多 maxKeywords + 6，避免一次抓太多把源打限流。
        emKeywords = [...new Set([...NEWS_AI_KEYWORDS, ...keywords])]
            .slice(0, Math.max(maxKeywords, NEWS_AI_KEYWORDS.length) + NEWS_AI_KEYWORDS.length);
        // 每个词按相关性抓 8 条（结果最精准）
        emKeywords.forEach(kw => pushEm(kw, 8, "default"));
        // 再对几个核心词按时间抓 6 条，补足当天最新动态（下面会过滤掉不含关键词的）
        ["黄金", "美联储", "白银", "人工智能", "AI", "算力", "数据中心", "房价", "美元"]
            .filter(k => emKeywords.includes(k)).slice(0, 5).forEach(kw => pushEm(kw, 6, "time"));
    }
    if (sources.includes("sina")) {
        jobs.push(async () => {
            try {
                const rows = await sinaLives(perSourceLimit, timeoutMs);
                markSource("sina", true);
                perSource.sina = (perSource.sina || 0) + rows.length;
                items.push(...rows);
            } catch (e) { markSource("sina", false); errors.push("新浪财经 7×24：" + e.message); }
        });
    }
    if (sources.includes("wscn")) {
        ["global-channel", "commodity-channel"].forEach(ch => jobs.push(async () => {
            try {
                const rows = await wscnLives(ch, perSourceLimit, timeoutMs);
                markSource("wscn", true);
                perSource.wscn = (perSource.wscn || 0) + rows.length;
                items.push(...rows);
            } catch (e) { markSource("wscn", false); errors.push("华尔街见闻 " + ch + "：" + e.message); }
        }));
    }
    await runPool(jobs, 5);
    const sourceStatus = {};
    for (const source of sources) {
        const stat = sourceStats[source] || { ok: 0, failed: 0 };
        sourceStatus[source] = stat.ok && stat.failed ? "partial" : stat.ok ? "success" : "failed";
    }
    const successfulSources = Object.values(sourceStatus).filter(s => s === "success" || s === "partial").length;
    if (sources.length && successfulSources === 0) {
        throw new Error("所有资讯数据源均采集失败：" + (errors[0] || "未返回有效结果"));
    }
    const partial = Object.values(sourceStatus).some(s => s === "partial");

    // 相关性检索/时间序检索都要求标题真正命中关键词；快讯可用标题+摘要命中
    const filtered = items.filter(it => {
        const title = normNewsText(it.title);
        const text = title + " " + normNewsText(it.summary);
        if (it.source === "eastmoney") {
            // 检索词也走边界匹配：关键词「AI」不会把 said / air / email 当成命中
            const hit = String(it.hit || "").toLowerCase();
            return !!(hit && termMatches(title, hit)) || matchNewsKeywords(title).length > 0;
        }
        return matchNewsKeywords(text).length > 0;
    });

    // —— 屏蔽词 / 标题长度过滤（在关键词过滤之后、去重之前）——
    //   统计口径单独记下来，日志里能看出「噪声过滤」拦掉了多少条，
    //   否则用户改了屏蔽词却看不到任何反馈。
    let blockedCount = 0, shortCount = 0;
    const kept = filtered.filter(it => {
        const title = String(it.title || "");
        const text = title + " " + String(it.summary || "");
        if (blacklist.length && blacklist.some(w => w && text.includes(w))) { blockedCount++; return false; }
        if (minTitleLen > 0 && title.length < minTitleLen) { shortCount++; return false; }
        return true;
    });

    // —— 相关性闸门（2026-11-12，同日二次调整：AI 泛化）——
    //   投资平台只要四类：贵金属 / 稀有金属品种、中国政策与官方数据、直接定价金价的海外变量、
    //   AI 相关消息（直接事件 + 产业链 / 能源 / 政策等间接消息；词表不含具体人名）。
    //   判定只看标题：摘要经常夹带无关词（一份 ETF 早报里提一句「黄金」就会被误留）。
    //   关掉该开关即退回「抓到什么就存什么」。
    const relevanceOnly = (await acquireOption(env, "news", "news_relevance_only", "1")) === "1";
    let irrelevantCount = 0;
    const relevant = relevanceOnly ? kept.filter(it => {
        if (newsTitleRelevant(it.title)) return true;
        irrelevantCount++;
        return false;
    }) : kept;

    const seen = new Set();
    const rows = [];
    for (const it of relevant) {
        const text = (it.title || "") + "。" + (it.summary || "");
        const hits = [...new Set([...(it.hit ? [it.hit] : []), ...matchNewsKeywords(text)])].slice(0, 8);
        const channel = classifyNews(text, it.hint);
        // 频道过滤（留空 = 不过滤）
        if (channelFilter.length && !channelFilter.includes(channel)) continue;
        const fingerprint = newsFingerprint(it.title);
        if (seen.has(fingerprint)) continue;
        seen.add(fingerprint);
        const text2 = text;
        const syms = tagNewsSymbols(text2, instruments);
        // 入库时同步判定情绪（按标的），人工修正过的消息不会被覆盖（judge 内部保留 manual）
        const judge = judgeSentiment(text2, instruments, syms);
        // 入库时同步判定「影响研判」与「重点评分」（重点算法复用研判结论，串联打分）
        const publishedAt = /^\d{4}-\d{2}-\d{2}/.test(it.published_at || "") ? it.published_at : nowBeijing();
        const imp = judgeImpact(it.title, it.summary, channel);
        const kp = pickKeyNews(it.title, it.summary, channel, imp, it.source, publishedAt, Date.now());
        rows.push({
            title: cleanStr(it.title, 300),
            summary: cleanStr(it.summary, 1000),
            url: safeUrl(it.url),
            source: it.source,
            platform: cleanStr(it.platform, 60),
            channel,
            keywords: hits.join(","),
            published_at: publishedAt,
            hash: fingerprint,
            symbols: syms.join(","),
            sentiment: judge.sentiment,
            sentiment_map: JSON.stringify(judge.map),
            impact: JSON.stringify(imp),
            key_score: kp.score,
            is_key: kp.isKey ? 1 : 0,
            key_reasons: JSON.stringify(kp),
            key_brief: kp.brief || "",
            starred: (autoStarMetal && channel === "metal") ? 1 : 0
        });
    }

    let inserted = 0;
    const insertedHashes = [];
    // relevant：标题是否与「品种 / 中国政策 / 金价驱动 / AI 相关（直接+间接）」四类白名单相关 **且** 未命中屏蔽词，
    //   入库时算好存成标记位（newsRelevantFlag）。查询侧只判 `relevant = 1`：
    //   既不用把 100 多个关键词拼成 SQL（D1 单条最多 100 个绑定参数），也不用逐行跑 N 个 NOT LIKE。
    const stmt = env.DB.prepare("INSERT OR IGNORE INTO news(title,summary,url,source,platform,channel,keywords,symbols,published_at,fetched_at,hash,starred,sentiment,sentiment_map,relevant,impact,key_score,is_key,key_reasons,key_brief) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    const fetchedAt = nowBeijing();
    for (let i = 0; i < rows.length; i += 40) {
        const chunk = rows.slice(i, i + 40);
        const results = await env.DB.batch(chunk.map(r => stmt.bind(r.title, r.summary, r.url, r.source, r.platform, r.channel, r.keywords, r.symbols || "", r.published_at, fetchedAt, r.hash, r.starred, r.sentiment || "neutral", r.sentiment_map || "{}", newsRelevantFlag(r, blacklist), r.impact || "", r.key_score || 0, r.is_key || 0, r.key_reasons || "", r.key_brief || "")));
        results.forEach((x, idx) => {
            const ch = (x.meta && x.meta.changes) || 0;
            if (ch) { inserted++; insertedHashes.push(chunk[idx].hash); }
        });
    }

    // 清理超过保留天数的旧消息
    let cleaned = 0;
    try {
        const cutoff = new Date(Date.now() + 8 * 3600 * 1000 - retentionDays * 86400000).toISOString().slice(0, 10);
        const del = await env.DB.prepare("DELETE FROM news WHERE substr(published_at,1,10) < ? AND starred=0").bind(cutoff).run();
        cleaned = (del.meta && del.meta.changes) || 0;
    } catch (e) { logWarn("crawl.cleanup", e); }

    const byChannel = {};
    rows.forEach(r => { byChannel[r.channel] = (byChannel[r.channel] || 0) + 1; });
    try {
        await env.DB.prepare("INSERT INTO settings(key,value) VALUES('last_news_refresh',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(fetchedAt).run();
    } catch (e) { logWarn("crawl.setting", e); }

    // —— 重点消息推送到通知中心 ——
    //   ① 全量同步：库内所有重点消息都进通知中心（静默入库，仍是未读的就是「点亮」状态）
    //   ② 通道推送：只推本次真正新入库的重点消息到外部通道，避免每次抓取都重复刷屏
    let keyNotified = 0, keySynced = 0;
    try {
        keySynced = await syncKeyNotifications(env);
    } catch (e) { logWarn("crawl.keySync", e); }
    try {
        keyNotified = await pushKeyNotifications(env, insertedHashes);
    } catch (e) { logWarn("crawl.keyNotify", e); }

    return {
        success: true,
        status: partial ? "partial" : "success",
        crawled: rows.length,
        inserted,
        skipped: rows.length - inserted,
        cleaned,
        key_notified: keyNotified,
        key_synced: keySynced,
        by_source: perSource,
        source_status: sourceStatus,
        by_channel: byChannel,
        keywords,
        // 东方财富实际参与检索的词（含固定补充的 AI / 显卡词），便于日志排查漏采
        search_keywords: emKeywords,
        ai_keywords: NEWS_AI_KEYWORDS,
        channels: channelFilter,
        retention_days: retentionDays,
        // 过滤漏斗：抓到多少 → 关键词命中多少 → 噪声滤掉多少 → 无关滤掉多少 → 入库多少
        raw_count: items.length,
        keyword_hits: filtered.length,
        blocked: blockedCount,
        too_short: shortCount,
        irrelevant: irrelevantCount,
        timeout_ms: timeoutMs,
        errors: errors.slice(0, 8),
        refreshed_at: fetchedAt
    };
}

// —— 重点消息 → 通知中心 ——
//   两条链路，职责不同：
//   ① syncKeyNotifications：把库内**全部**重点消息（保留窗口内）灌进通知中心，静默入库不刷外部通道。
//      dedup_key = "news_key:" + hash + 唯一索引 → 幂等；已读过的不会被重新点亮（INSERT OR IGNORE 不覆盖 read）。
//   ② pushKeyNotifications：只对「本次新入库」的重点消息推外部通道（webhook），按综合分降序，最多 news_key_notify_max 条。
//   保留：清理失效的重点通知（指向的消息已不再被点亮 / 已超出保留窗口），避免通知中心无限堆积。
const KEY_NOTIFY_KEEP_DAYS = 7;
// 通知正文的格式版本：文案结构变了（加简报、改版式）就把已存在的通知正文刷新一遍，只跑一次
const KEY_NOTIFY_BODY_VERSION = "v2-20261119-detail";

// 重点消息的通知文案：第一行给「简明摘要」，后面补分数 / 方向 / 传导链，最后标明是规则推演
function keyNotifyText(r) {
    const kp = parseKeyPick(r.key_reasons);
    const imp = parseImpact(r.impact);
    const dirLabel = imp && imp.direction === "bullish" ? "偏涨"
        : imp && imp.direction === "bearish" ? "偏跌"
        : imp && (imp.direction === "mixed" || imp.strength === "分歧") ? "多空分歧" : "中性";
    const tgt = (imp && Array.isArray(imp.targets) && imp.targets.length)
        ? imp.targets.map(t => t.name).filter(Boolean).slice(0, 2).join("、") : "";
    const chain = (imp && Array.isArray(imp.chains) && imp.chains[0]) ? imp.chains[0] : "";
    const reasons = (kp && Array.isArray(kp.reasons)) ? kp.reasons : [];
    const brief = String(r.key_brief || "").trim()
        || (kp && kp.brief ? String(kp.brief) : "")
        || String(r.title || "").slice(0, 60);
    const title = "【重点】" + String(r.title || "").slice(0, 60);
    const meta = [
        r.source ? "来源：" + r.source : "",
        r.channel ? "频道：" + r.channel : ""
    ].filter(Boolean).join(" · ");
    const body = [
        brief,
        "重点 " + (r.key_score || 0) + " 分 · " + dirLabel + (tgt ? " · 影响 " + tgt : ""),
        meta,
        r.published_at ? "发布：" + r.published_at : "",
        chain ? "传导链：" + chain : "",
        reasons.length ? "挑选依据：" + reasons.slice(0, 2).join("；") : "",
        r.url ? "原文：" + r.url : "",
        "规则推演，非投资建议"
    ].filter(Boolean).join("\n");
    return { title, body };
}

// 全量同步：所有重点消息进通知中心（静默入库，不触发 webhook）
//   ⚠ migrate() 在每个 API 请求前都会跑，所以这里必须有「快速通道」：
//     · 第一道：同步令牌（规则版本 + 最大消息 id）。重点消息集合只会在「有新消息入库」或
//       「重点/研判/正文规则版本变化」时改变 —— 令牌没变就直接返回，只读 1 行。
//       早期版本这里只有 COUNT 扫描，实测每天 604 次 × 约 3,960 行 = 2.39M 行读取，
//       单这一条 SQL 就吃掉免费读额度（5M/天）的近一半。
//     · 第二道：COUNT 只判断「有没有还没进通知中心的重点消息」+「正文格式版本有没有变」，
//       两样都没有就返回，不做任何写操作。
async function syncKeyNotifications(env) {
    const enabled = (await acquireOption(env, "news", "news_key_notify_enabled", "1")) === "1";
    if (!enabled) return 0;
    const cutoff = new Date(Date.now() + 8 * 3600 * 1000 - KEY_NOTIFY_KEEP_DAYS * 86400000).toISOString().slice(0, 10);

    // ⓪ 同步令牌：规则版本 + 当前最大消息 id 都没变 → 不可能有新重点消息，直接返回
    let wantToken = "";
    try {
        const t = await env.DB.prepare(
            "SELECT (SELECT MAX(id) FROM news) AS max_id, "
            + "(SELECT value FROM settings WHERE key='news_key_notify_token') AS token"
        ).first();
        wantToken = [KEY_PICK_VERSION, IMPACT_VERSION, KEY_NOTIFY_BODY_VERSION, Number((t && t.max_id) || 0)].join("|");
        if (t && String(t.token || "") === wantToken) return 0;
    } catch (e) { wantToken = ""; /* 读不到令牌就照常走完整流程 */ }
    const markSynced = async () => {
        if (!wantToken) return 0;
        try {
            await env.DB.prepare("INSERT INTO settings(key,value) VALUES('news_key_notify_token',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                .bind(wantToken).run();
        } catch (e) { logWarn("notify.keySync.token", e); }
        return 0;
    };

    // ① 快速通道：缺多少条 + 正文版本是否需要刷新
    let missCnt = 0;
    try {
        const c = (await env.DB.prepare(
            "SELECT COUNT(*) c FROM news n WHERE n.is_key=1 AND substr(n.published_at,1,10) >= ? AND NOT EXISTS ("
            + "SELECT 1 FROM notifications t WHERE t.dedup_key = 'news_key:' || IFNULL(n.hash,'id_' || n.id))"
        ).bind(cutoff).first());
        missCnt = Number((c && c.c) || 0);
    } catch (e) { logWarn("notify.keySync.count", e); return 0; }
    let needRefresh = false;
    try {
        const ver = await env.DB.prepare("SELECT value FROM settings WHERE key='news_notify_body_ver'").first();
        needRefresh = !ver || String(ver.value || "") !== KEY_NOTIFY_BODY_VERSION;
    } catch (e) { needRefresh = false; }
    if (!missCnt && !needRefresh) return markSynced();

    let rows = [];
    try {
        rows = (await env.DB.prepare(
            "SELECT id,title,url,source,channel,published_at,hash,impact,key_score,key_reasons,key_brief FROM news "
            + "WHERE is_key=1 AND substr(published_at,1,10) >= ? ORDER BY key_score DESC, published_at DESC LIMIT 500"
        ).bind(cutoff).all()).results || [];
    } catch (e) { logWarn("notify.keySync.query", e); return 0; }
    if (!rows.length) return markSynced();
    let added = 0;
    for (const r of rows) {
        const t = keyNotifyText(r);
        const dedup = "news_key:" + (r.hash || ("id_" + r.id));
        const ok = await pushNotification(env, {
            kind: "news_key", level: "warn", title: t.title, body: t.body,
            ref_type: "news", ref_id: r.id, dedup_key: dedup, silent: true
        });
        if (ok) added++;
        // 已存在的通知同步刷新文案（简明摘要可能随规则版本变化），但不碰 read 状态
        if (needRefresh) {
            try {
                await env.DB.prepare("UPDATE notifications SET title=?, body=? WHERE dedup_key=?")
                    .bind(t.title, t.body, dedup).run();
            } catch (e) { logWarn("notify.keySync.refresh", e); }
        }
    }
    // 清理失效的重点通知：① 指向的消息已不再被点亮 ② 指向的消息已超出保留窗口
    try {
        await env.DB.prepare(
            "DELETE FROM notifications WHERE kind='news_key' AND ref_type='news' AND ref_id>0 "
            + "AND (ref_id NOT IN (SELECT id FROM news WHERE is_key=1) "
            + "  OR ref_id IN (SELECT id FROM news WHERE substr(published_at,1,10) < ?))"
        ).bind(cutoff).run();
    } catch (e) { logWarn("notify.keyCleanup", e); }
    if (needRefresh) {
        try {
            await env.DB.prepare("INSERT INTO settings(key,value) VALUES('news_notify_body_ver',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                .bind(KEY_NOTIFY_BODY_VERSION).run();
        } catch (e) { logWarn("notify.keySync.ver", e); }
    }
    await markSynced();
    return added;
}

// 通道推送：只推「本次真正新入库」的重点消息（按插入时记录的 hash 精确定位）
async function pushKeyNotifications(env, insertedHashes) {
    const list = (Array.isArray(insertedHashes) ? insertedHashes : []).filter(Boolean);
    if (!list.length) return 0;
    const enabled = (await acquireOption(env, "news", "news_key_notify_enabled", "1")) === "1";
    if (!enabled) return 0;
    const maxPush = await acquireNum(env, "news", "news_key_notify_max", 5, 1, 20);
    // 按 hash 取本次新插入的重点消息（D1 单条 SQL 最多 100 个绑定参数，分批查）
    const rows = [];
    for (let i = 0; i < list.length; i += 50) {
        const part = list.slice(i, i + 50);
        const ph = part.map(() => "?").join(",");
        const got = (await env.DB.prepare(
            "SELECT id,title,url,source,channel,published_at,hash,impact,key_score,key_reasons,key_brief FROM news "
            + "WHERE is_key=1 AND hash IN (" + ph + ") ORDER BY key_score DESC LIMIT ?"
        ).bind(...part, maxPush).all()).results || [];
        rows.push(...got);
    }
    if (!rows.length) return 0;
    rows.sort((a, b) => (Number(b.key_score) || 0) - (Number(a.key_score) || 0));
    let pushed = 0;
    for (const r of rows.slice(0, maxPush)) {
        const t = keyNotifyText(r);
        // 入库由 syncKeyNotifications 负责（静默全量），这里只推外部通道，避免重复
        try {
            await dispatchWebhooks(env, { kind: "news_key", title: t.title, body: t.body });
            pushed++;
        } catch (e) { logWarn("notify.keyWebhook", e); }
    }
    return pushed;
}

async function refreshNews(request, env, user) {
    if (!can(user, "news.fetch")) return forbidden();
    const body = await request.json().catch(() => ({}));
    const startedAt = beijingStamp(Date.now());
    const t0 = Date.now();
    let r = null, status = "success", message = "";
    try {
        r = await crawlNews(env, { keywords: body.keywords, sources: body.sources });
        status = r.status === "partial" ? "partial" : "success";
        message = newsLogMessage(r);
    } catch (e) {
        status = "failed";
        message = `资讯页手动抓取失败：${e && e.message ? e.message : String(e)}`;
    }
    // 资讯页的「抓取最新」也是一次真实采集，同样落一条日志，采集日志页可追溯
    await writeFetchLog(env, {
        task_key: MANUAL_NEWS_LOG_KEY, trigger_type: "manual", started_at: startedAt,
        duration_ms: Date.now() - t0, status,
        fetched: (r && r.crawled) || 0, inserted: (r && r.inserted) || 0, skipped: (r && r.skipped) || 0,
        message
    });
    if (status === "failed") return json({ success: false, message }, 500);
    return json(r);
}

// 近 N 天的起止日期（含今天），用于「今日 / 近 3 天 / 近 7 天 / 近 30 天」快捷筛选
function newsDateWindow(days) {
    const d = Math.min(3650, Math.max(0, parseInt(days, 10) || 0));
    if (!d) return { from: "", to: "" };
    const base = Date.now() + 8 * 3600 * 1000;
    const from = new Date(base - (d - 1) * 86400000).toISOString().slice(0, 10);
    const to = new Date(base).toISOString().slice(0, 10);
    return { from, to };
}

// 资讯的统一过滤条件（屏蔽词 + 四类相关性白名单）
//   列表 total / stats / 频道分布 / 来源分布 / 趋势 / 热词必须共用同一片段，
//   否则会出现「列表 285、统计 537」这种对不上的情况（历史教训）。
//   例外：① 用户显式搜索某词时不按相关性过滤（主动查询不该空手而归）
//        ② skipFilter=true 看全量（导出 / 排查）
//   2026-11-19：屏蔽词已经烘进 `relevant`（入库 / 回填时写入 0），
//     默认路径只需 `relevant = 1` 一个条件 → 走 idx_news_rel，不再逐行跑 N 个 NOT LIKE。
//     只有「关掉相关性过滤」或「带关键词搜索」时才退回 LIKE 兜底（这两条都不是轮询路径）。
async function newsRelevanceFilter(env, opts) {
    const o = opts || {};
    const keyword = o.keyword || "";
    const skipFilter = !!o.skipFilter;
    const blacklist = splitList(await acquireOption(env, "news", "news_blacklist", ""));
    const keywordAsksBlocked = !!keyword && blacklist.some(w => w && keyword.includes(w));
    const relevanceOnly = (await acquireOption(env, "news", "news_relevance_only", "1")) === "1";
    const parts = [];
    const params = [];
    // 默认轮询路径：relevant 已同时代表「命中白名单 + 未命中屏蔽词」
    const flagOnly = relevanceOnly && !skipFilter && !keyword;
    if (blacklist.length && !skipFilter && !keywordAsksBlocked && !flagOnly) {
        parts.push(blacklist.map(() => "NOT (IFNULL(title,'')||' '||IFNULL(summary,'')||' '||IFNULL(keywords,'') LIKE ?)").join(" AND "));
        params.push(...blacklist.map(w => "%" + w + "%"));
    }
    // 相关性：只判入库时算好的 relevant 标记（不放 100+ 个 LIKE，D1 单条 SQL 最多 100 个绑定参数）
    if (flagOnly) parts.push("relevant = 1");
    return { cond: parts.length ? parts.map(p => "(" + p + ")").join(" AND ") : "", params };
}

// —— 聚合缓存（读配额保护，L1 内存 + L2 D1 表）——
//   页面轮询（资讯 30 秒 / 总览 30 秒）会反复打同一组 COUNT / GROUP BY，
//   而 D1 免费额度按「扫描行数」计费。这里只缓存统计聚合（不含列表和行情）。
//   TTL 2 分钟：统计数字晚 2 分钟不影响决策（列表 / 行情 / 重点消息仍是实时）。
//   写操作会调 invalidateAggCache(env) 主动失效（L1 与 L2 一起清）。
const AGG_CACHE = new Map();
const AGG_CACHE_TTL_MS = 120000;
const AGG_CACHE_MAX = 120;
// 两级缓存：
//   L1 = 本 isolate 的 Map（零成本，但 isolate 被回收就没了，而且同一个用户的不同请求
//        经常落到不同的 isolate / 机房，实测命中率接近 0）
//   L2 = D1 里的 agg_cache 表（跨 isolate / 跨机房共享，读 1 行、写 1 行）
//   实测证明只靠 L1 挡不住轮询：把 TTL 从 45 秒提到 3 分钟，命中率依然接近 0。
async function aggCached(env, key, fn, ttlMs) {
    const ttl = ttlMs || AGG_CACHE_TTL_MS;
    const now = Date.now();
    const hit = AGG_CACHE.get(key);
    if (hit && now - hit.at < ttl) return hit.val;
    if (env && env.DB) {
        try {
            const row = await env.DB.prepare("SELECT val, at FROM agg_cache WHERE key=?").bind(key).first();
            if (row && now - (Number(row.at) || 0) < ttl) {
                const val = JSON.parse(row.val);
                AGG_CACHE.set(key, { at: Number(row.at) || now, val });
                return val;
            }
        } catch (e) { /* 表还没建 / JSON 损坏：退化为直接计算 */ }
    }
    const val = await fn();
    if (AGG_CACHE.size >= AGG_CACHE_MAX) {
        for (const [k, v] of AGG_CACHE) if (now - v.at >= ttl) AGG_CACHE.delete(k);
        if (AGG_CACHE.size >= AGG_CACHE_MAX) AGG_CACHE.clear();
    }
    AGG_CACHE.set(key, { at: now, val });
    if (env && env.DB) {
        try {
            await env.DB.prepare("INSERT INTO agg_cache(key,val,at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET val=excluded.val, at=excluded.at")
                .bind(key, JSON.stringify(val), now).run();
        } catch (e) { /* 缓存写失败不影响返回 */ }
    }
    return val;
}
// 写操作后主动失效（资讯新增 / 删除 / 收藏 / 重算都走 saveNews，统计会立刻变）
async function invalidateAggCache(env) {
    AGG_CACHE.clear();
    if (env && env.DB) {
        try { await env.DB.prepare("DELETE FROM agg_cache").run(); } catch (e) { /* 表未建时忽略 */ }
    }
}

// 统计最近若干天每天的消息条数（补齐空缺日期）
// extra: { cond, params } —— 追加的过滤条件（如屏蔽词），让趋势图与列表同口径
async function newsDailyTrend(env, days, extra) {
    const span = Math.min(90, Math.max(1, parseInt(days, 10) || 14));
    const base = Date.now() + 8 * 3600 * 1000;
    const from = new Date(base - (span - 1) * 86400000).toISOString().slice(0, 10);
    const ex = extra && extra.cond ? " AND " + extra.cond : "";
    const exParams = (extra && extra.params) || [];
    let rows = [];
    try {
        rows = (await env.DB.prepare("SELECT substr(published_at,1,10) d, COUNT(*) c FROM news WHERE published_at >= ?" + ex + " GROUP BY d").bind(from, ...exParams).all()).results || [];
    } catch (e) { logWarn("news.trend", e); }
    const map = {};
    rows.forEach(r => { map[r.d] = r.c || 0; });
    const out = [];
    for (let i = span - 1; i >= 0; i--) {
        const d = new Date(base - i * 86400000).toISOString().slice(0, 10);
        out.push({ date: d, count: map[d] || 0 });
    }
    return out;
}

// 统计热门关键词（在最近若干条消息的 keywords 字段上做频次统计）
async function newsHotKeywords(env, limit, extra) {
    const top = Math.min(30, Math.max(5, parseInt(limit, 10) || 12));
    const ex = extra && extra.cond ? " AND " + extra.cond : "";
    const exParams = (extra && extra.params) || [];
    let rows = [];
    try {
        rows = (await env.DB.prepare("SELECT keywords FROM (SELECT keywords FROM news WHERE keywords <> '' AND keywords IS NOT NULL" + ex + " ORDER BY id DESC LIMIT 1000)").bind(...exParams).all()).results || [];
    } catch (e) { logWarn("news.hotKeywords", e); }
    const map = {};
    rows.forEach(r => {
        String(r.keywords || "").split(",").map(s => s.trim()).filter(Boolean).forEach(k => { map[k] = (map[k] || 0) + 1; });
    });
    return Object.keys(map)
        .map(k => ({ keyword: k, count: map[k] }))
        .sort((a, b) => b.count - a.count)
        .slice(0, top);
}

// 日期字符串 +1 天（bundle 的「今日」区间用 published_at >= 今天 AND < 明天，
//   而不是 substr(published_at,1,10)=?：后者用不上 idx_news_rel，每轮都要扫全表）
function nextDayStr(day) {
    const d = new Date(String(day) + "T00:00:00Z");
    if (isNaN(d.getTime())) return String(day);
    d.setUTCDate(d.getUTCDate() + 1);
    return d.toISOString().slice(0, 10);
}

// —— 资讯统计聚合（/api/news 侧栏 + /api/desk 系统概览共用同一份缓存）——
//   两个页面轮询的其实是同一组 COUNT / GROUP BY（默认都是 `relevant = 1`），
//   用同一个缓存键就只算一次。列表 rows / 行情 / 日历 / 预警都不在这里（保持实时）。
//   成本：以前是 5 个 COUNT + 3 个 GROUP BY 各扫一遍 news（约 9,800 行/次），
//   现在合并成「1 条聚合 + 1 条明细」两遍扫描（约 2,000 行/次），分布 / 趋势 / 热词在 JS 里算。
async function newsStatsBundle(env, cond, params, today) {
    const p = params || [];
    const ex = cond ? " AND " + cond : "";
    const day = today || nowBeijing().slice(0, 10);
    const next = nextDayStr(day);
    const key = "news.stats|" + day + "|" + (cond || "") + "|" + JSON.stringify(p);
    return aggCached(env, key, async () => {
        // 明细上限：分布 / 热词只看最近这么多条（当前全库约 1,000 条，够用且防未来暴涨）
        const DETAIL_CAP = 3000;
        const safeStat = async (label, sql, args) => {
            try { return await env.DB.prepare(sql).bind(...args).first(); }
            catch (e) { logWarn("news.stats." + label, e); return null; }
        };
        const [counts, detail, starred, notif] = await Promise.all([
            // 一条 SQL 出总量 / 今日 / 重点 / 最新时间（单次扫描，不再拆成 4 个子查询）
            safeStat("counts",
                "SELECT COUNT(*) total,"
                + " SUM(CASE WHEN published_at>=? AND published_at<? THEN 1 ELSE 0 END) today,"
                + " SUM(CASE WHEN is_key=1 THEN 1 ELSE 0 END) key_count,"
                + " MAX(published_at) latest FROM news WHERE 1=1" + ex,
                [day, next, ...p]),
            (async () => {
                try {
                    return (await env.DB.prepare(
                        "SELECT published_at, sentiment, channel, source, keywords FROM news WHERE 1=1" + ex
                        + " ORDER BY id DESC LIMIT " + DETAIL_CAP
                    ).bind(...p).all()).results || [];
                } catch (e) { logWarn("news.stats.detail", e); return []; }
            })(),
            // 收藏数刻意不加过滤：收藏是用户自己的行为，与「相关性白名单」无关
            safeStat("starred", "SELECT COUNT(*) c FROM news WHERE starred=1", []),
            // 未读通知按类型分布（总览铃铛用，小表）
            (async () => {
                try {
                    return (await env.DB.prepare("SELECT kind, COUNT(*) c FROM notifications WHERE read=0 GROUP BY kind").all()).results || [];
                } catch (e) { logWarn("news.stats.notifyKind", e); return []; }
            })()
        ]);

        const sentMap = new Map(), chanMap = new Map(), srcMap = new Map(), kwMap = new Map();
        (detail || []).forEach(r => {
            const s = r.sentiment == null ? "" : String(r.sentiment);
            sentMap.set(s, (sentMap.get(s) || 0) + 1);
            const ch = r.channel == null ? "" : String(r.channel);
            chanMap.set(ch, (chanMap.get(ch) || 0) + 1);
            const sc = r.source == null ? "" : String(r.source);
            srcMap.set(sc, (srcMap.get(sc) || 0) + 1);
            String(r.keywords || "").split(",").map(k => k.trim()).filter(Boolean)
                .forEach(k => kwMap.set(k, (kwMap.get(k) || 0) + 1));
        });
        // 明细没被截断时，14 天趋势直接由这批行算出（零额外读）；被截断才回退到 SQL 聚合
        const trend = (detail || []).length >= DETAIL_CAP
            ? await newsDailyTrend(env, 14, cond ? { cond, params: p } : null)
            : buildDailyTrend(detail, day, 14);
        const hotKeywords = [...kwMap.entries()].map(([keyword, count]) => ({ keyword, count }))
            .sort((a, b) => b.count - a.count).slice(0, 12);

        return {
            total: Number(counts && counts.total) || 0,
            today: Number(counts && counts.today) || 0,
            keyCount: Number(counts && counts.key_count) || 0,
            starred: Number(starred && starred.c) || 0,
            latest: (counts && counts.latest) || "",
            sentiment: [...sentMap.entries()].map(([k, c]) => ({ sentiment: k, c })),
            channel: [...chanMap.entries()].map(([k, c]) => ({ channel: k, c })),
            source: [...srcMap.entries()].map(([k, c]) => ({ source: k, c })),
            trend, hotKeywords,
            notifyKinds: notif || []
        };
    });
}

// 从明细行算最近 N 天每天的消息条数（补齐空缺日期），口径与 newsDailyTrend 一致
function buildDailyTrend(rows, day, days) {
    const span = Math.min(90, Math.max(1, parseInt(days, 10) || 14));
    const end = new Date(String(day) + "T00:00:00Z");
    const base = isNaN(end.getTime()) ? new Date() : end;
    const map = {};
    (rows || []).forEach(r => {
        const d = String(r.published_at || "").slice(0, 10);
        if (d) map[d] = (map[d] || 0) + 1;
    });
    const out = [];
    for (let i = span - 1; i >= 0; i--) {
        const d = new Date(base.getTime() - i * 86400000).toISOString().slice(0, 10);
        out.push({ date: d, count: map[d] || 0 });
    }
    return out;
}

async function getNews(url, env) {
    const keyword = (url.searchParams.get("keyword") || "").trim();
    const channel = url.searchParams.get("channel") || "";
    const source = url.searchParams.get("source") || "";
    const starred = url.searchParams.get("starred") === "1";
    // 按关联标的过滤：消息在入库时已打标（symbols 存 "XAU,AU0"），这里是「从标的看消息」的入口
    const symbol = String(url.searchParams.get("symbol") || "").trim().toUpperCase();
    const dateFrom = url.searchParams.get("date_from") || "";
    const dateTo = url.searchParams.get("date_to") || "";
    const days = parseInt(url.searchParams.get("days")) || 0;
    const sort = NEWS_SORT_MODES.includes(url.searchParams.get("sort")) ? url.searchParams.get("sort") : "time";
    const offset = Math.max(0, parseInt(url.searchParams.get("offset")) || 0);
    // 导出场景需要一次拉全量，普通列表仍限制 200 条防超时
    const limitMax = url.searchParams.get("export") === "1" ? 5000 : 200;
    const rawLimit = parseInt(url.searchParams.get("limit"), 10);
    const limit = Number.isFinite(rawLimit) ? Math.min(limitMax, Math.max(1, rawLimit)) : 20;

    // 页面轮询驱动的自动抓取：到「自动抓取间隔」才回源，未到点只读库。
    // 导出场景不触发抓取，避免导出动作被外部抓取拖慢。
    const liveSec = await liveIntervalSec(env, "news", "news_live_sec", 10, 5, 300);
    if (url.searchParams.get("export") !== "1") {
        await refreshNewsIfStale(env, await settingsMap(env));
    }

    const conditions = ["1=1"];
    const params = [];
    if (keyword) {
        conditions.push("(title LIKE ? OR summary LIKE ? OR keywords LIKE ? OR platform LIKE ?)");
        const k = "%" + keyword + "%";
        params.push(k, k, k, k);
    }
    if (channel && NEWS_CHANNELS[channel]) { conditions.push("channel = ?"); params.push(channel); }
    if (source && NEWS_SOURCE_LABELS[source]) { conditions.push("source = ?"); params.push(source); }
    if (starred) conditions.push("starred = 1");
    if (symbol) { conditions.push("(','||IFNULL(symbols,'')||',') LIKE ?"); params.push("%," + symbol + ",%"); }
    // 情绪筛选：只看利多 / 只看利空
    const sentiment = String(url.searchParams.get("sentiment") || "").trim();
    if (sentiment === "bullish" || sentiment === "bearish" || sentiment === "neutral") {
        conditions.push("IFNULL(sentiment,'') = ?");
        params.push(sentiment);
    }
    // 研判方向筛选：impact 是 JSON 字符串，用 LIKE 匹配固定键，避免 json_extract 对空串报错。
    //   researched = 规则识别到研判对象（scope 非 none），偏涨/偏跌 = 明确方向。
    const impactDir = String(url.searchParams.get("impact") || "").trim();
    if (impactDir === "bullish" || impactDir === "bearish") {
        conditions.push("impact LIKE ?");
        params.push('%"direction":"' + impactDir + '"%');
    } else if (impactDir === "researched") {
        conditions.push("IFNULL(impact,'') LIKE '%\"scope\":%' AND IFNULL(impact,'') NOT LIKE '%\"scope\":\"none\"%'");
    }
    // 重点筛选：key=1 只看被算法点亮为「重点」的消息
    if (url.searchParams.get("key") === "1") conditions.push("is_key = 1");
    // 快捷时间范围（days）优先于显式日期
    const win = days ? newsDateWindow(days) : { from: dateFrom, to: dateTo };
    if (/^\d{4}-\d{2}-\d{2}$/.test(win.from)) { conditions.push("substr(published_at,1,10) >= ?"); params.push(win.from); }
    if (/^\d{4}-\d{2}-\d{2}$/.test(win.to)) { conditions.push("substr(published_at,1,10) <= ?"); params.push(win.to); }

    // —— 统一过滤（2026-11-12）：屏蔽词 + 四类相关性白名单 ——
    //   采集端已按同一套规则丢弃，但历史存量还在库里，查询时再挡一道；
    //   列表 total、stats、频道分布、来源分布、趋势、热词必须共用同一片段，否则会出现「列表 285、侧栏 537」。
    const rel = await newsRelevanceFilter(env, { keyword, skipFilter: url.searchParams.get("exclude") === "0" });
    const filterSql = rel.cond;
    const filterParams = rel.params;
    if (filterSql) {
        conditions.push(filterSql);
        params.push(...filterParams);
    }

    const whereSQL = "WHERE " + conditions.join(" AND ");
    // 排序：time=最新优先 / oldest=最早优先 / relevance=命中度优先（有关键词时生效） / key=重点优先
    let orderExpr = "ORDER BY published_at DESC, id DESC";
    let orderParams = [];
    if (sort === "oldest") orderExpr = "ORDER BY published_at ASC, id ASC";
    else if (sort === "key") orderExpr = "ORDER BY is_key DESC, key_score DESC, published_at DESC, id DESC";
    else if (sort === "relevance" && keyword) {
        // 只有明确选择「命中度优先」时，关键词才参与排序；不能覆盖用户选择的最新优先。
        orderExpr = "ORDER BY CASE WHEN title LIKE ? THEN 0 WHEN keywords LIKE ? OR summary LIKE ? THEN 1 ELSE 2 END, published_at DESC, id DESC";
        const k = "%" + keyword + "%";
        orderParams = [k, k, k];
    } else if (sort === "relevance") {
        orderExpr = "ORDER BY relevant DESC, key_score DESC, published_at DESC, id DESC";
    }

    // 统计类查询与列表并行执行；统计聚合与投资总览共用同一份缓存（见 newsStatsBundle）
    const today = nowBeijing().slice(0, 10);
    const [agg, rows, cfg] = await Promise.all([
        newsStatsBundle(env, conditions.join(" AND "), params, today),
        // 显式列代替 SELECT *：减少网络传输与反序列化开销（避免把大字段带出）
        env.DB.prepare(
            "SELECT id,title,summary,url,source,platform,channel,keywords,symbols,sentiment,sentiment_map,impact,key_score,is_key,key_reasons,key_brief,published_at,fetched_at,starred,note FROM news "
            + whereSQL + " " + orderExpr + " LIMIT ? OFFSET ?"
        ).bind(...params, ...orderParams, limit, offset).all(),
        settingsMap(env)
    ]);

    return json({
        total: agg.total || 0,
        rows: rows.results || [],
        query: { keyword, channel, source, starred, symbol, days, sort, date_from: win.from, date_to: win.to, sentiment, impact: impactDir, key: url.searchParams.get("key") === "1" ? 1 : 0 },
        // 前端按该间隔轮询列表（服务端是否回源由「自动抓取间隔」决定）
        live_sec: liveSec,
        stats: {
            total: agg.total || 0, starred: agg.starred || 0, today: agg.today || 0, latest: agg.latest || "",
            key_count: agg.keyCount || 0,
            by_channel: agg.channel, by_source: agg.source,
            trend: agg.trend, hot_keywords: agg.hotKeywords,
            last_refresh: cfg.last_news_refresh || ""
        }
    });
}

async function saveNews(request, env, user) {
    const body = await request.json();
    const action = body.action;
    // 这里的每个 action 都会改动 news（增删 / 收藏 / 备注 / 重算），聚合统计直接失效，
    //   避免用户点完收藏后统计卡还要等缓存过期（L1 + D1 缓存一起清）。
    await invalidateAggCache(env);
    if (action === "star" || action === "unstar") {
        if (!can(user, "news.manage")) return forbidden();
        const id = parseInt(body.id);
        if (!id) return json({ success: false, message: "参数错误" }, 400);
        await env.DB.prepare("UPDATE news SET starred=? WHERE id=?").bind(action === "star" ? 1 : 0, id).run();
        return json({ success: true });
    }
    if (action === "delete") {
        if (!can(user, "news.manage")) return forbidden();
        const delId = parseInt(body.id) || 0;
        await env.DB.batch([
            env.DB.prepare("DELETE FROM news WHERE id=?").bind(delId),
            env.DB.prepare("DELETE FROM notifications WHERE ref_type='news' AND ref_id=?").bind(delId)
        ]);
        return json({ success: true });
    }
    if (action === "note") {
        if (!can(user, "news.manage")) return forbidden();
        const id = parseInt(body.id);
        if (!id) return json({ success: false, message: "参数错误" }, 400);
        await env.DB.prepare("UPDATE news SET note=? WHERE id=?").bind(cleanStr(body.note, 1000), id).run();
        return json({ success: true });
    }
    if (action === "bulk") {
        if (!can(user, "news.manage")) return forbidden();
        const ids = Array.isArray(body.ids) ? body.ids.map(x => parseInt(x) || 0).filter(Boolean).slice(0, 500) : [];
        const op = String(body.op || "");
        if (!ids.length) return json({ success: false, message: "未选择任何消息" }, 400);
        // D1 单语句绑定参数上限为 100，超出需分批执行
        const CHUNK = 90;
        let affected = 0;
        for (let i = 0; i < ids.length; i += CHUNK) {
            const part = ids.slice(i, i + CHUNK);
            const ph = part.map(() => "?").join(",");
            if (op === "star" || op === "unstar") {
                const r = await env.DB.prepare(`UPDATE news SET starred=? WHERE id IN (${ph})`).bind(op === "star" ? 1 : 0, ...part).run();
                affected += (r.meta && r.meta.changes) || 0;
            } else if (op === "delete") {
                const r = await env.DB.prepare(`DELETE FROM news WHERE id IN (${ph})`).bind(...part).run();
                await env.DB.prepare(`DELETE FROM notifications WHERE ref_type='news' AND ref_id IN (${ph})`).bind(...part).run();
                affected += (r.meta && r.meta.changes) || 0;
            } else {
                return json({ success: false, message: "未知批量操作" }, 400);
            }
        }
        return json({ success: true, affected });
    }
    if (action === "retag") {
        // 新增 / 改名品种后，历史消息需要用新词表重新标注一遍（否则老消息永远贴不上新标的）
        // 同时重算情绪：打标变了，消息对标的的含义也可能变（例如「锂价上涨」原来只贴了铜）
        if (!can(user, "news.manage")) return forbidden();
        const rows = (await env.DB.prepare("SELECT id,title,summary,keywords,channel,source,published_at,sentiment_map FROM news").all()).results || [];
        const instruments = await instrumentRows(env);
        const retagBlacklist = splitList(await acquireOption(env, "news", "news_blacklist", ""));
        const stmt = env.DB.prepare("UPDATE news SET symbols=?, sentiment=?, sentiment_map=?, relevant=?, impact=?, key_score=?, is_key=?, key_reasons=?, key_brief=? WHERE id=?");
        let done = 0;
        for (let i = 0; i < rows.length; i += 50) {
            const chunk = rows.slice(i, i + 50);
            await env.DB.batch(chunk.map(r => {
                const text = (r.title || "") + "。" + (r.summary || "");
                const prev = parseSentimentMap(r.sentiment_map);
                const syms = tagNewsSymbols(text, instruments);
                const j = judgeSentiment(text, instruments, syms, prev);
                const imp = judgeImpact(r.title, r.summary, r.channel);
                const kp = pickKeyNews(r.title, r.summary, r.channel, imp, r.source, r.published_at || nowBeijing(), Date.now());
                return stmt.bind(syms.join(","), j.sentiment, JSON.stringify(j.map), newsRelevantFlag(r, retagBlacklist),
                    JSON.stringify(imp), kp.score || 0, kp.isKey ? 1 : 0, JSON.stringify(kp), kp.brief || "", r.id);
            }));
            done += chunk.length;
        }
        return json({ success: true, tagged: done, message: `已重新标注 ${done} 条消息并重算情绪、影响和重点评分` });
    }
    if (action === "resentiment") {
        // 单独重算情绪（不改动标）：规则调整后一键刷新全部历史消息
        if (!can(user, "news.manage")) return forbidden();
        const rows = (await env.DB.prepare("SELECT id,title,summary,symbols,sentiment_map FROM news").all()).results || [];
        const instruments = await instrumentRows(env);
        const stmt = env.DB.prepare("UPDATE news SET sentiment=?, sentiment_map=? WHERE id=?");
        let done = 0;
        for (let i = 0; i < rows.length; i += 50) {
            const chunk = rows.slice(i, i + 50);
            await env.DB.batch(chunk.map(r => {
                const text = (r.title || "") + "。" + (r.summary || "");
                // 沿用库里已有的打标（不改动标，只重算情绪）
                const syms = String(r.symbols || "").split(",").filter(Boolean);
                const j = judgeSentiment(text, instruments, syms, parseSentimentMap(r.sentiment_map));
                return stmt.bind(j.sentiment, JSON.stringify(j.map), r.id);
            }));
            done += chunk.length;
        }
        return json({ success: true, updated: done, message: `已重算 ${done} 条消息的利多利空` });
    }
    if (action === "sentiment") {
        // 人工修正某条消息对某标的的判断（自动判定难免有误，人可以改，改后不会被重算覆盖）
        if (!can(user, "news.manage")) return forbidden();
        const id = parseInt(body.id);
        if (!id) return json({ success: false, message: "参数错误" }, 400);
        const symbol = cleanStr(body.symbol, 20).toUpperCase();
        const label = String(body.label || "");
        if (!symbol) return json({ success: false, message: "请选择标的" }, 400);
        if (!["bullish", "bearish", "neutral"].includes(label)) return json({ success: false, message: "无效的情绪值" }, 400);
        const row = await env.DB.prepare("SELECT symbols, sentiment_map FROM news WHERE id=?").bind(id).first();
        if (!row) return json({ success: false, message: "消息不存在" }, 404);
        const symbols = String(row.symbols || "").split(",").map(s => s.trim().toUpperCase()).filter(Boolean);
        if (!symbols.includes(symbol)) return json({ success: false, message: "该标的未关联到此消息" }, 400);
        const map = parseSentimentMap(row.sentiment_map);
        map[symbol] = Object.assign({}, map[symbol] || {}, { label, manual: 1, score: label === "bullish" ? 1 : label === "bearish" ? -1 : 0 });
        const overall = overallSentimentOf(map);
        await env.DB.prepare("UPDATE news SET sentiment=?, sentiment_map=? WHERE id=?").bind(overall, JSON.stringify(map), id).run();
        return json({ success: true, sentiment: overall, map, message: "已修正该消息的利多利空判定" });
    }
    if (action === "reimpact") {
        // 规则词表调整后一键重算全部历史消息的研判与重点简报；人工改判过的行保留
        if (!can(user, "news.manage")) return forbidden();
        const rows = (await env.DB.prepare("SELECT id,title,summary,channel,source,published_at,impact FROM news").all()).results || [];
        const stmt = env.DB.prepare("UPDATE news SET impact=?, key_score=?, is_key=?, key_reasons=?, key_brief=? WHERE id=?");
        let done = 0, skipped = 0;
        const now = Date.now();
        for (let i = 0; i < rows.length; i += 50) {
            const chunk = rows.slice(i, i + 50);
            const stmts = [];
            chunk.forEach(r => {
                const old = parseImpact(r.impact);
                if (old && old.manual) { skipped++; return; }
                const imp = judgeImpact(r.title, r.summary, r.channel);
                const kp = pickKeyNews(r.title, r.summary, r.channel, imp, r.source, r.published_at || nowBeijing(), now);
                stmts.push(stmt.bind(JSON.stringify(imp), kp.score || 0, kp.isKey ? 1 : 0, JSON.stringify(kp), kp.brief || "", r.id));
            });
            for (let k = 0; k < stmts.length; k += 50) await env.DB.batch(stmts.slice(k, k + 50));
            done += stmts.length;
        }
        return json({ success: true, updated: done, skipped, message: `已重算 ${done} 条消息的影响研判与重点简报${skipped ? `，保留 ${skipped} 条人工改判` : ""}` });
    }
    if (action === "impact") {
        // 人工改判研判方向（规则判定难免有误，人说了算；改后同步重算重点评分与简明摘要，避免卡片简报与研判方向矛盾）
        if (!can(user, "news.manage")) return forbidden();
        const id = parseInt(body.id);
        if (!id) return json({ success: false, message: "参数错误" }, 400);
        const direction = String(body.direction || "");
        if (!["bullish", "bearish", "neutral"].includes(direction)) return json({ success: false, message: "无效的方向值" }, 400);
        const row = await env.DB.prepare("SELECT id,title,summary,channel,source,published_at,hash,impact FROM news WHERE id=?").bind(id).first();
        if (!row) return json({ success: false, message: "消息不存在" }, 404);
        const old = parseImpact(row.impact) || judgeImpact(row.title, row.summary, row.channel);
        old.direction = direction;
        old.manual = 1;
        if (direction !== "neutral") old.mixed = 0;
        const kp = pickKeyNews(row.title, row.summary, row.channel, old, row.source, row.published_at || nowBeijing(), Date.now());
        await env.DB.prepare("UPDATE news SET impact=?, key_score=?, is_key=?, key_reasons=?, key_brief=? WHERE id=?")
            .bind(JSON.stringify(old), kp.score || 0, kp.isKey ? 1 : 0, JSON.stringify(kp), kp.brief || "", id).run();
        // 同步更新或清理通知中心对应条目
        try {
            if (kp.isKey) {
                const nt = keyNotifyText({ ...row, impact: JSON.stringify(old), key_score: kp.score, key_reasons: JSON.stringify(kp), key_brief: kp.brief || "" });
                const dedup = "news_key:" + (row.hash || ("id_" + row.id));
                await env.DB.prepare("UPDATE notifications SET title=?, body=? WHERE dedup_key=?").bind(nt.title, nt.body, dedup).run();
            } else {
                await env.DB.prepare("DELETE FROM notifications WHERE kind='news_key' AND ref_type='news' AND ref_id=?").bind(id).run();
            }
        } catch (e) { logWarn("news.impactNotifySync", e); }
        return json({ success: true, impact: old, key_score: kp.score, is_key: kp.isKey ? 1 : 0, key_brief: kp.brief || "", message: "已人工修正该消息的研判方向并同步简报" });
    }
    if (action === "create") {
        if (!can(user, "news.fetch")) return forbidden();
        const title = cleanStr(body.title, 300);
        if (!title) return json({ success: false, message: "请填写标题" }, 400);
        const summary = cleanStr(body.summary, 1000);
        const hit = matchNewsKeywords(title + " " + summary);
        const channel = NEWS_CHANNELS[body.channel] ? body.channel : classifyNews(title + " " + summary);
        const instruments = await instrumentRows(env);
        const syms = tagNewsSymbols(title + "。" + summary, instruments);
        const symbols = syms.join(",");
        const judge = judgeSentiment(title + "。" + summary, instruments, syms);
        // 手动录入同样走「研判 → 重点评分」，与自动采集口径一致
        const publishedAt = normalizeStamp(body.published_at) || nowBeijing();
        const imp = judgeImpact(title, summary, channel);
        const kp = pickKeyNews(title, summary, channel, imp, "manual", publishedAt, Date.now());
        const createBlacklist = splitList(await acquireOption(env, "news", "news_blacklist", ""));
        const ins = await env.DB.prepare("INSERT OR IGNORE INTO news(title,summary,url,source,platform,channel,keywords,symbols,published_at,fetched_at,hash,sentiment,sentiment_map,relevant,impact,key_score,is_key,key_reasons,key_brief) VALUES(?,?,?,'manual',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(title, summary, safeUrl(body.url), "手动录入", channel, hit.join(","), symbols, publishedAt, nowBeijing(), newsFingerprint(title), judge.sentiment, JSON.stringify(judge.map), newsRelevantFlag({ title, summary, keywords: hit.join(",") }, createBlacklist), JSON.stringify(imp), kp.score, kp.isKey ? 1 : 0, JSON.stringify(kp), kp.brief || "").run();
        return json({ success: true, inserted: (ins.meta && ins.meta.changes) || 0 });
    }
    return json({ success: false, message: "未知操作" }, 400);
}

async function getNewsMeta(env) {
    const cfg = await settingsMap(env);
    const kwRaw = await acquireOption(env, "news", "news_keywords", cfg.news_keywords || "");
    const channelFilter = (await acquireList(env, "news", "news_channels")).filter(c => NEWS_CHANNELS[c]);
    return json({
        channels: Object.keys(NEWS_CHANNELS).map(key => ({ key, label: NEWS_CHANNELS[key].label, keywords: NEWS_CHANNELS[key].keywords })),
        sources: Object.keys(NEWS_SOURCE_LABELS).map(key => ({ key, label: NEWS_SOURCE_LABELS[key] })),
        keywords: parseNewsKeywords(kwRaw),
        // 与抓取实际行为保持一致：以 data_sources 的启停状态为准
        enabled_sources: await enabledNewsSourceIds(env),
        enabled_channels: channelFilter,
        sorts: [{ key: "time", label: "最新优先" }, { key: "oldest", label: "最早优先" }, { key: "relevance", label: "命中度优先" }, { key: "key", label: "重点优先" }],
        // 消息可关联的全部标的（前端用来把代码翻译成中文名）
        symbols: (await instrumentRows(env)).filter(i => Number(i.enabled) === 1)
            .map(i => ({ symbol: i.symbol, name: i.short_name || i.name || i.symbol, scope: i.scope })),
        last_refresh: cfg.last_news_refresh || ""
    });
}

// ============================================================
// 用户管理
// ============================================================
async function handleUsers(request, env, actor) {
    if (!can(actor, "users.view")) return forbidden();
    if (request.method === "GET") {
        const rows = await env.DB.prepare("SELECT id,username,display_name,role,permissions,enabled,created_at FROM users ORDER BY id").all();
        return json(rows.results.map(publicUser));
    }
    const body = await request.json();
    if (body.action === "create") {
        if (!can(actor, "users.create")) return forbidden();
        if (!body.username || !body.password || body.password.length < 6) return json({ success: false, message: "用户名必填，密码至少6位" }, 400);
        const role = ROLE_PERMISSIONS[body.role] ? body.role : "visitor";
        const permissions = normalizePermissions(role, body.permissions || ROLE_PERMISSIONS[role]);
        const cred = await hashPassword(body.password);
        try {
            await env.DB.prepare("INSERT INTO users(username,password,salt,display_name,role,permissions,enabled) VALUES(?,?,?,?,?,?,?)").bind(body.username, cred.hash, cred.salt, body.display_name || "", role, JSON.stringify(permissions), body.enabled === false ? 0 : 1).run();
            return json({ success: true });
        } catch { return json({ success: false, message: "用户名已存在" }, 400); }
    }
    if (body.action === "edit") {
        if (!can(actor, "users.edit")) return forbidden();
        const target = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(body.id).first();
        if (!target) return json({ success: false, message: "用户不存在" }, 404);
        const username = cleanStr(body.username, 60) || target.username;
        // 先校验再落库：旧实现先 UPDATE 资料、后校验密码长度，报错时资料已改动（半生效）
        const pwdChanged = body.password != null && String(body.password) !== "";
        if (pwdChanged && String(body.password).length < 6) return json({ success: false, message: "密码至少6位" }, 400);
        const role = ROLE_PERMISSIONS[body.role] ? body.role : target.role;
        // 不允许把自己降权或停用，避免管理员把自己锁在系统外
        if (Number(target.id) === Number(actor.id) && (role !== "admin" || body.enabled === false)) {
            return json({ success: false, message: "不能修改当前登录账号的角色或停用自己" }, 400);
        }
        // 权限继承：前端编辑时并不提交 permissions，旧实现会按 [] 覆盖，
        // 导致「编辑一次」就把普通用户的 news.fetch / news.manage 全部清空。
        let permissions;
        if (Array.isArray(body.permissions) && can(actor, "users.permissions")) permissions = normalizePermissions(role, body.permissions);
        else if (role !== target.role) permissions = [...(ROLE_PERMISSIONS[role] || [])];
        else permissions = normalizePermissions(role, target.permissions);
        // 停用账号时递增 token_version：重新启用后，停用前签发的令牌也不会复活
        const disabling = body.enabled === false && Number(target.enabled) !== 0;
        try {
            await env.DB.prepare("UPDATE users SET username=?,display_name=?,role=?,permissions=?,enabled=?,token_version=token_version+? WHERE id=?")
                .bind(username, cleanStr(body.display_name, 60), role, JSON.stringify(permissions), body.enabled === false ? 0 : 1, disabling ? 1 : 0, target.id).run();
        } catch (e) {
            logWarn("users.edit", e);
            return json({ success: false, message: "账号已存在，请换一个" }, 400);
        }
        if (pwdChanged) {
            const cred = await hashPassword(String(body.password));
            // 管理员重置密码后，该用户已登录的会话全部失效
            await env.DB.prepare("UPDATE users SET password=?,salt=?,token_version=token_version+1 WHERE id=?").bind(cred.hash, cred.salt, target.id).run();
        }
        return json({ success: true });
    }
    if (body.action === "delete") {
        if (!can(actor, "users.delete")) return forbidden();
        if (Number(body.id) === Number(actor.id)) return json({ success: false, message: "不能删除当前登录账号" }, 400);
        await env.DB.prepare("DELETE FROM users WHERE id=?").bind(body.id).run();
        return json({ success: true });
    }
    return json({ success: false, message: "未知操作" }, 400);
}

// ============================================================
// 价格预警 / 通知中心 / 推送通道 / 持仓管理
//   补齐 GitHub 同类项目的三项核心能力：
//   - 目标价与涨跌幅预警（对应 invest-watcher 的点位报警）
//   - 站内通知中心 + Webhook 推送（对应 GoldMonitor / fund-monitor 的告警）
//   - 持仓成本、盈亏与资产分布（对应 invest-watcher / fund-monitor）
// ============================================================
const ALERT_DIRECTIONS = { above: "价格上破", below: "价格下破", rise: "涨幅达到", fall: "跌幅达到" };
// 推送通道类型目录：
//   webhook 类（企业微信 / 钉钉 / 飞书 / 通用 / ShowDoc）—— 用户填一个 URL，直接 POST 过去
//   token 类（Telegram / 微信推送 PushPlus / Bark）—— 用户填 Token / 设备密钥，由系统拼出官方接口地址
//   urlLabel / urlPlaceholder / secretLabel / secretPlaceholder 供前端按类型动态渲染表单字段
const NOTIFY_CHANNEL_TYPES = {
    wecom:    { label: "企业微信机器人", kind: "webhook", icon: "fa-brands fa-weixin",
        urlLabel: "Webhook 地址", urlPlaceholder: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." },
    dingtalk: { label: "钉钉机器人", kind: "webhook", icon: "fa-brands fa-dingtalk",
        urlLabel: "Webhook 地址", urlPlaceholder: "https://oapi.dingtalk.com/robot/send?access_token=...",
        secretLabel: "加签 Secret（可选）", secretPlaceholder: "SEC..." },
    feishu:   { label: "飞书机器人", kind: "webhook", icon: "fa-solid fa-comment-dots",
        urlLabel: "Webhook 地址", urlPlaceholder: "https://open.feishu.cn/open-apis/bot/v2/hook/..." },
    showdoc:  { label: "ShowDoc 推送", kind: "webhook", icon: "fa-solid fa-book-open",
        urlLabel: "专属推送地址", urlPlaceholder: "https://push.showdoc.com.cn/server/api/push/..." },
    generic:  { label: "通用 JSON Webhook", kind: "webhook", icon: "fa-solid fa-code",
        urlLabel: "Webhook 地址", urlPlaceholder: "https://example.com/webhook" },
    telegram: { label: "Telegram 机器人", kind: "token", icon: "fa-brands fa-telegram",
        urlLabel: "Bot Token", urlPlaceholder: "123456:ABCdefGHIJK...",
        secretLabel: "Chat ID", secretPlaceholder: "-1001234567890 或 用户 ID" },
    pushplus: { label: "微信推送（PushPlus）", kind: "token", icon: "fa-solid fa-bell",
        urlLabel: "Token", urlPlaceholder: "你的 PushPlus Token" },
    bark:     { label: "Bark（iOS 推送）", kind: "token", icon: "fa-brands fa-apple",
        urlLabel: "设备密钥 / 服务器", urlPlaceholder: "设备密钥，或 https://你的.bark.server" }
};

// —— 站内通知：写入 + 去重 + 触发推送 ——
//   silent=true 时只入库、不触发 webhook —— 用于「历史重点消息补录进通知中心」这类
//   一次性灌库场景，避免把几十条旧消息一次性刷到外部通道。
async function pushNotification(env, n) {
    try {
        const res = await env.DB.prepare("INSERT OR IGNORE INTO notifications(kind,level,title,body,ref_type,ref_id,dedup_key,read,created_at) VALUES(?,?,?,?,?,?,?,0,?)")
            .bind(n.kind || "system", n.level || "info", cleanStr(n.title, 200), cleanStr(n.body, 2000),
                n.ref_type || "", Number(n.ref_id) || 0, n.dedup_key || "", nowBeijing()).run();
        // 去重命中（dedup_key 已存在）时不重复推送
        if (!(res.meta && res.meta.changes)) return false;
        if (!n.silent) await dispatchWebhooks(env, n);
        return true;
    } catch (e) { logWarn("notify.push", e); return false; }
}

// 阻断本地回环、私有网段、链路本地元数据地址与内网后缀，防止 SSRF 探测
function isPrivateHost(hostname) {
    const h = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
    if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan")) return true;
    if (h === "::1" || h === "0:0:0:0:0:0:0:1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true;
    const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
    if (ipv4) {
        const a = Number(ipv4[1]), b = Number(ipv4[2]);
        if (a === 0 || a === 10 || a === 127) return true;
        if (a === 169 && b === 254) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
    }
    return false;
}

// Webhook 地址只允许公网 http/https，阻断内网探测与伪协议
function safeWebhook(v) {
    const s = String(v == null ? "" : v).trim();
    if (!s) return "";
    try {
        const u = new URL(s);
        if (u.protocol !== "http:" && u.protocol !== "https:") return "";
        if (isPrivateHost(u.hostname)) return "";
        return u.href;
    } catch { return ""; }
}

function webhookBody(type, title, body) {
    const text = `${title}\n${body}`.trim();
    if (type === "wecom") return { msgtype: "text", text: { content: text } };
    if (type === "dingtalk") return { msgtype: "text", text: { content: text } };
    if (type === "feishu") return { msg_type: "text", content: { text } };
    return { title, body, text, ts: Date.now() };
}

// 按通道类型产出一次外部推送请求：{ url, method, qs?, json? }
//   webhook 类（企业微信 / 钉钉 / 飞书 / 通用）：直接 POST 到用户填的 URL（钉钉支持 SEC 加签）
//   token 类（Telegram / PushPlus / Bark）：用 Token / 设备密钥拼出官方接口地址
async function buildChannelRequest(c, title, body) {
    // 统一加「发送时间」页脚：外部推送（尤其手机通知）经常脱离站内上下文，
    //   没有时间戳就无法判断这条是刚发生的还是延迟补发的。
    const stamp = new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 19).replace("T", " ");
    const footer = `发送时间：${stamp}（北京时间）`;
    const bodyFull = body ? `${body}\n\n——\n${footer}` : `${title}\n\n——\n${footer}`;
    const text = `${title}\n${bodyFull}`.trim();
    const t = c.channel_type;
    if (t === "telegram") {
        const token = String(c.webhook_url || "").trim();
        const chat = String(c.secret || "").trim();
        if (!token || !chat) return null;
        const url = `https://api.telegram.org/bot${token}/sendMessage`;
        return { url, method: "GET", qs: { chat_id: chat, text } };
    }
    if (t === "pushplus") {
        const token = String(c.webhook_url || "").trim();
        if (!token) return null;
        return { url: "https://www.pushplus.plus/send", method: "POST",
            json: { token, title, content: bodyFull, template: "txt" } };
    }
    if (t === "bark") {
        const raw = String(c.webhook_url || "").trim();
        if (!raw) return null;
        const url = /^https?:\/\//i.test(raw) ? safeWebhook(raw) : `https://api.day.app/${encodeURIComponent(raw)}`;
        if (!url) return null;
        return { url, method: "POST", json: { title, body: bodyFull, isArchive: 1 } };
    }
    // webhook 类：地址必须是合法公网 http/https
    let wu = safeWebhook(c.webhook_url);
    if (!wu) return null;
    // ShowDoc 推送服务：POST 表单 title + content（两个都不能为空），GET 传 text/desp 会被判空
    if (t === "showdoc") {
        return { url: wu, method: "POST", form: { title, content: bodyFull } };
    }
    if (t === "dingtalk" && String(c.secret || "").trim()) {
        const secret = String(c.secret).trim();
        const ts = Date.now();
        const sign = await hmacSign(secret, `${ts}\n${secret}`);
        const u = new URL(wu);
        u.searchParams.set("timestamp", String(ts));
        u.searchParams.set("sign", sign);
        wu = u.href;
    }
    return { url: wu, method: "POST", json: webhookBody(t, title, bodyFull) };
}

// 把一次请求真正发出去（GET 拼 qs / POST 发 JSON 或表单），并更新通道状态
async function sendChannelRequest(env, c, req) {
    try {
        const init = { method: req.method, headers: {} };
        if (req.method === "POST" && req.json) {
            init.headers["Content-Type"] = "application/json";
            init.body = JSON.stringify(req.json);
        }
        if (req.method === "POST" && req.form) {
            init.headers["Content-Type"] = "application/x-www-form-urlencoded;charset=utf-8";
            init.body = new URLSearchParams(req.form).toString();
        }
        if (req.method === "GET" && req.qs) {
            const u = new URL(req.url);
            Object.entries(req.qs).forEach(([k, v]) => u.searchParams.set(k, v));
            req.url = u.href;
        }
        const r = await fetchWithTimeout(req.url, init, 8000);
        const t = (await r.text()).slice(0, 200);
        // ShowDoc 这类国产推送服务习惯用 HTTP 200 + error_code 表达失败，不能只看状态码
        const bizFail = /"error_code"\s*:\s*[1-9]/.test(t);
        const ok = r.ok && !bizFail;
        await markChannel(env, c.id, ok ? "success" : "failed", ok ? (t || "ok") : `HTTP ${r.status} ${t}`);
        return ok;
    } catch (e) {
        await markChannel(env, c.id, "failed", String(e && e.message || e).slice(0, 200));
        return false;
    }
}

async function dispatchWebhooks(env, payload) {
    try {
        const channels = (await env.DB.prepare("SELECT * FROM notify_channels WHERE enabled=1").all()).results || [];
        if (!channels.length) return;
        const kind = payload.kind || "system";
        const targets = channels.filter(c => {
            const ev = String(c.events || "alert").split(",").map(s => s.trim()).filter(Boolean);
            return ev.includes("all") || ev.includes(kind);
        });
        if (!targets.length) return;
        await Promise.allSettled(targets.map(async c => {
            let req;
            try { req = await buildChannelRequest(c, payload.title || "", payload.body || ""); }
            catch (e) { await markChannel(env, c.id, "failed", String(e && e.message || e).slice(0, 200)); return; }
            if (!req || !req.url) { await markChannel(env, c.id, "failed", "通道配置不完整（地址 / Token 缺失）"); return; }
            await sendChannelRequest(env, c, req);
        }));
    } catch (e) { logWarn("notify.webhook", e); }
}

async function markChannel(env, id, status, message) {
    try {
        await env.DB.prepare("UPDATE notify_channels SET last_status=?, last_message=?, last_sent_at=? WHERE id=?")
            .bind(status, String(message || "").slice(0, 300), nowBeijing(), id).run();
    } catch (e) { logWarn("notify.mark", e); }
}

// —— 预警评估：每次行情刷新后按当前报价逐条判定 ——
async function evaluateAlerts(env, quotes) {
    try {
        const alerts = (await env.DB.prepare("SELECT * FROM price_alerts WHERE enabled=1").all()).results || [];
        if (!alerts.length) return { checked: 0, triggered: 0 };
        const by = {};
        (quotes || []).forEach(q => { by[q.symbol] = q; });
        const now = Date.now();
        let triggered = 0;
        for (const a of alerts) {
            const q = by[a.symbol];
            if (!q) continue;
            const price = Number(q.price) || 0;
            if (price <= 0) continue;
            const chg = Number(q.change_pct) || 0;
            const target = Number(a.target) || 0;
            if (target <= 0) continue;
            let hit = false;
            if (a.direction === "above") hit = price >= target;
            else if (a.direction === "below") hit = price <= target;
            else if (a.direction === "rise") hit = chg >= target;
            else if (a.direction === "fall") hit = chg <= -Math.abs(target);
            if (!hit) continue;
            // 冷却：同一预警在冷却期内只提醒一次，避免连续采集刷屏
            const coolMs = Math.max(1, Number(a.cooldown_min) || 30) * 60000;
            if (now - Number(a.last_trigger_epoch || 0) < coolMs) continue;
            const win = Math.floor(now / coolMs);
            const unitPct = a.direction === "rise" || a.direction === "fall";
            const qUnit = String(q.unit || "");
            const cond = `${ALERT_DIRECTIONS[a.direction] || a.direction} ${target}${unitPct ? "%" : qUnit}`;
            const num = v => (Number(v) > 0 ? String(round2(Number(v))) : "—");
            const chgAbs = Number(q.change) || 0;
            const title = `价格预警 · ${a.name || q.name || a.symbol}（${a.symbol}）`;
            // 正文给足以判断的上下文：品种 / 现价 / 涨跌 / 日内区间 / 触发条件 / 行情时间 / 上次触发
            const body = [
                `品种：${a.name || q.name || a.symbol}（${a.symbol}）`,
                `现价：${round2(price)}${qUnit}（${chg >= 0 ? "+" : ""}${chg.toFixed(2)}%）`,
                `涨跌：${chgAbs >= 0 ? "+" : ""}${round2(chgAbs)}${qUnit}`,
                `日内：开 ${num(q.open)} / 高 ${num(q.high)} / 低 ${num(q.low)} / 昨结 ${num(q.prev_close)}`,
                `触发条件：${cond}`,
                `行情时间：${q.quote_time || q.updated_at || nowBeijing()}`,
                a.last_trigger_at ? `上次触发：${a.last_trigger_at}` : "上次触发：无（首次触发）",
                "",
                "规则提醒，非投资建议"
            ].join("\n");
            const written = await pushNotification(env, {
                kind: "alert", level: "warn", title, body,
                ref_type: "alert", ref_id: a.id, dedup_key: `alert:${a.id}:${win}`
            });
            await env.DB.prepare("UPDATE price_alerts SET trigger_count=trigger_count+1, last_trigger_epoch=?, last_trigger_at=?, last_trigger_price=? WHERE id=?")
                .bind(now, nowBeijing(), price, a.id).run();
            if (written) triggered++;
        }
        return { checked: alerts.length, triggered };
    } catch (e) { logWarn("alert.eval", e); return { checked: 0, triggered: 0 }; }
}

// —— 预警 CRUD ——
async function handleAlerts(request, env, user, url) {
    if (request.method === "GET") {
        const rows = (await env.DB.prepare("SELECT * FROM price_alerts ORDER BY enabled DESC, id DESC").all()).results || [];
        const symbols = (await env.DB.prepare("SELECT symbol,name,short_name,unit,price,change_pct FROM metal_quotes ORDER BY symbol").all()).results || [];
        const recent = (await env.DB.prepare("SELECT * FROM notifications WHERE kind='alert' ORDER BY id DESC LIMIT 20").all()).results || [];
        return json({
            rows, symbols, recent,
            directions: Object.keys(ALERT_DIRECTIONS).map(key => ({ key, label: ALERT_DIRECTIONS[key] }))
        });
    }
    if (!can(user, "market.config")) return forbidden();
    const body = await request.json().catch(() => ({}));
    const action = body.action;

    if (action === "create" || action === "update") {
        const symbol = cleanStr(body.symbol, 20).toUpperCase();
        if (!symbol) return json({ success: false, message: "请选择品种" }, 400);
        const direction = ALERT_DIRECTIONS[body.direction] ? body.direction : "above";
        const target = Number(body.target);
        if (!Number.isFinite(target) || target <= 0) return json({ success: false, message: "阈值必须大于 0" }, 400);
        if (direction === "rise" || direction === "fall") {
            if (target > 100) return json({ success: false, message: "涨跌幅阈值不能超过 100%" }, 400);
        }
        const cooldown = Math.min(1440, Math.max(1, parseInt(body.cooldown_min, 10) || 30));
        const q = await env.DB.prepare("SELECT name FROM metal_quotes WHERE symbol=?").bind(symbol).first();
        const name = cleanStr(body.name, 40) || (q ? q.name : symbol);
        if (action === "update") {
            if (!body.id) return json({ success: false, message: "缺少预警 ID" }, 400);
            await env.DB.prepare("UPDATE price_alerts SET symbol=?,name=?,direction=?,target=?,cooldown_min=?,enabled=?,note=? WHERE id=?")
                .bind(symbol, name, direction, target, cooldown, body.enabled === false ? 0 : 1, cleanStr(body.note, 200), body.id).run();
            return json({ success: true, message: "预警已更新" });
        }
        await env.DB.prepare("INSERT INTO price_alerts(symbol,name,direction,target,cooldown_min,enabled,note,created_by,created_at) VALUES(?,?,?,?,?,1,?,?,?)")
            .bind(symbol, name, direction, target, cooldown, cleanStr(body.note, 200), user.username, nowBeijing()).run();
        return json({ success: true, message: "预警已创建" });
    }
    if (action === "toggle") {
        if (!body.id) return json({ success: false, message: "缺少预警 ID" }, 400);
        await env.DB.prepare("UPDATE price_alerts SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?").bind(body.id).run();
        return json({ success: true });
    }
    if (action === "delete") {
        if (!body.id) return json({ success: false, message: "缺少预警 ID" }, 400);
        await env.DB.prepare("DELETE FROM price_alerts WHERE id=?").bind(body.id).run();
        return json({ success: true });
    }
    if (action === "test") {
        const ok = await pushNotification(env, {
            kind: "system", level: "info",
            title: "通知通道测试",
            body: `由 ${user.username} 于 ${nowBeijing()} 发起，收到即表示站内通知与 Webhook 推送链路正常。`,
            dedup_key: `test:${Date.now()}`
        });
        return json({ success: ok, message: ok ? "测试通知已发送" : "推送失败，请检查通道配置" });
    }
    return json({ success: false, message: "未知操作" }, 400);
}

// —— 通知中心 ——
async function handleNotifications(request, env, user, url) {
    if (request.method === "GET") {
        const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit"), 10) || 20));
        const unreadOnly = url.searchParams.get("unread") === "1";
        const kind = cleanStr(url.searchParams.get("kind"), 30);
        const conds = [];
        const params = [];
        if (unreadOnly) conds.push("read=0");
        if (kind) { conds.push("kind=?"); params.push(kind); }
        const where = conds.length ? "WHERE " + conds.join(" AND ") : "";
        const rows = (await env.DB.prepare(`SELECT * FROM notifications ${where} ORDER BY id DESC LIMIT ?`).bind(...params, limit).all()).results || [];
        const cnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM notifications WHERE read=0").first();
        const keyCnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM notifications WHERE read=0 AND kind='news_key'").first();
        return json({
            rows,
            unread: Number((cnt && cnt.c) || 0),
            key_unread: Number((keyCnt && keyCnt.c) || 0),
            unread_by_kind: await unreadByKind(env)
        });
    }
    if (!user || user.role === "visitor") return forbidden();
    const body = await request.json().catch(() => ({}));
    if (body.action === "read") {
        await env.DB.prepare("UPDATE notifications SET read=1 WHERE id=?").bind(body.id).run();
        return json({ success: true });
    }
    // 批量已读：资讯中心「看过即消除未读」用 —— 把这些消息对应的通知一次性标记为已读
    if (body.action === "read_refs") {
        const refType = cleanStr(body.ref_type, 30) || "news";
        const ids = (Array.isArray(body.ids) ? body.ids : []).map(x => parseInt(x, 10)).filter(x => x > 0);
        if (!ids.length) return json({ success: true, updated: 0 });
        const ph = ids.map(() => "?").join(",");
        const res = await env.DB.prepare(`UPDATE notifications SET read=1 WHERE read=0 AND ref_type=? AND ref_id IN (${ph})`)
            .bind(refType, ...ids).run();
        return json({ success: true, updated: (res.meta && res.meta.changes) || 0 });
    }
    // 一键已读：可只清某一类（kind），默认全清
    if (body.action === "read_all") {
        const kind = cleanStr(body.kind, 30);
        const res = kind
            ? await env.DB.prepare("UPDATE notifications SET read=1 WHERE read=0 AND kind=?").bind(kind).run()
            : await env.DB.prepare("UPDATE notifications SET read=1 WHERE read=0").run();
        return json({ success: true, updated: (res.meta && res.meta.changes) || 0 });
    }
    // 手动把库内重点消息全量同步进通知中心（幂等；已读状态不变）
    if (body.action === "sync_key") {
        const added = await syncKeyNotifications(env);
        return json({ success: true, added, message: added ? `已同步 ${added} 条重点消息到通知中心` : "没有新的重点消息需要同步" });
    }
    if (body.action === "delete") {
        if (!can(user, "news.manage") && !can(user, "settings.edit")) return forbidden();
        await env.DB.prepare("DELETE FROM notifications WHERE id=?").bind(body.id).run();
        return json({ success: true });
    }
    if (body.action === "clear") {
        if (!can(user, "news.manage") && !can(user, "settings.edit")) return forbidden();
        await env.DB.prepare("DELETE FROM notifications").run();
        return json({ success: true });
    }
    return json({ success: false, message: "未知操作" }, 400);
}

// 未读通知按类型统计（通知中心的分类角标用）
//   铃铛每 60 秒轮询一次，这条 GROUP BY 要扫全表（150+ 行），用 2 分钟缓存挡掉一半请求。
async function unreadByKind(env) {
    try {
        const rows = await aggCached(env, "notify.unreadKind", async () => {
            const r = (await env.DB.prepare("SELECT kind, COUNT(*) c FROM notifications WHERE read=0 GROUP BY kind").all()).results || [];
            return r;
        }, 120000);
        const out = {};
        rows.forEach(r => { out[r.kind] = Number(r.c) || 0; });
        return out;
    } catch (e) { logWarn("notify.unreadByKind", e); return {}; }
}

function maskSecretValue(v) {
    const s = String(v || "").trim();
    if (!s) return "";
    if (s.length <= 8) return "****";
    return s.slice(0, 4) + "****" + s.slice(-4);
}

// —— 推送通道 ——
async function handleNotifyChannels(request, env, user) {
    const canEdit = can(user, "settings.edit");
    if (request.method === "GET") {
        const rawRows = (await env.DB.prepare("SELECT * FROM notify_channels ORDER BY id").all()).results || [];
        const rows = canEdit ? rawRows : rawRows.map(r => ({
            ...r,
            webhook_url: maskSecretValue(r.webhook_url),
            secret: maskSecretValue(r.secret)
        }));
        const types = Object.entries(NOTIFY_CHANNEL_TYPES).map(([key, m]) => ({
            key, label: m.label, kind: m.kind, icon: m.icon,
            urlLabel: m.urlLabel, urlPlaceholder: m.urlPlaceholder,
            secretLabel: m.secretLabel || "", secretPlaceholder: m.secretPlaceholder || ""
        }));
        return json({ rows, types });
    }
    if (!can(user, "settings.edit")) return forbidden();
    const body = await request.json().catch(() => ({}));
    if (body.action === "create" || body.action === "update") {
        const type = NOTIFY_CHANNEL_TYPES[body.channel_type] ? body.channel_type : "wecom";
        const meta = NOTIFY_CHANNEL_TYPES[type];
        const isWebhook = meta.kind === "webhook";
        const url = isWebhook ? safeWebhook(body.webhook_url) : String(body.webhook_url || "").trim();
        if (!url) return json({ success: false, message: isWebhook ? "Webhook 地址非法（仅支持 http/https）" : "请填写 Token / Bot Token" }, 400);
        if (type === "telegram" && !String(body.secret || "").trim()) return json({ success: false, message: "Telegram 需要填写 Chat ID" }, 400);
        const events = (Array.isArray(body.events) ? body.events : String(body.events || "alert").split(","))
            .map(s => String(s).trim()).filter(s => ["alert", "news_key", "calendar", "system", "all"].includes(s));
        const ev = events.length ? [...new Set(events)].join(",") : "alert";
        const secret = cleanStr(body.secret, 200);
        if (body.action === "update") {
            if (!body.id) return json({ success: false, message: "缺少通道 ID" }, 400);
            await env.DB.prepare("UPDATE notify_channels SET name=?,channel_type=?,webhook_url=?,secret=?,events=?,enabled=? WHERE id=?")
                .bind(cleanStr(body.name, 60) || meta.label, type, url, secret, ev, body.enabled === false ? 0 : 1, body.id).run();
            return json({ success: true, message: "通道已更新" });
        }
        await env.DB.prepare("INSERT INTO notify_channels(name,channel_type,webhook_url,secret,events,enabled,created_at) VALUES(?,?,?,?,?,1,?)")
            .bind(cleanStr(body.name, 60) || meta.label, type, url, secret, ev, nowBeijing()).run();
        return json({ success: true, message: "通道已添加" });
    }
    if (body.action === "toggle") {
        if (!body.id) return json({ success: false, message: "缺少通道 ID" }, 400);
        const row = await env.DB.prepare("SELECT enabled FROM notify_channels WHERE id=?").bind(body.id).first();
        if (!row) return json({ success: false, message: "通道不存在" }, 404);
        const enabled = row.enabled ? 0 : 1;
        await env.DB.prepare("UPDATE notify_channels SET enabled=? WHERE id=?").bind(enabled, body.id).run();
        return json({ success: true, enabled, message: enabled ? "已启用" : "已停用" });
    }
    if (body.action === "test") {
        const row = await env.DB.prepare("SELECT * FROM notify_channels WHERE id=?").bind(body.id).first();
        if (!row) return json({ success: false, message: "通道不存在" }, 404);
        const req = await buildChannelRequest(row, "通知通道测试",
            `由 ${user.username} 于 ${nowBeijing()} 发起，收到即表示「${row.name}」推送链路正常。`);
        if (!req || !req.url) return json({ success: false, message: "通道配置不完整（地址 / Token 缺失）" }, 400);
        const ok = await sendChannelRequest(env, row, req);
        return json({ success: ok, message: ok ? "测试已发送，请查收" : "推送失败，请检查通道配置" });
    }
    if (body.action === "delete") {
        await env.DB.prepare("DELETE FROM notify_channels WHERE id=?").bind(body.id).run();
        return json({ success: true });
    }
    return json({ success: false, message: "未知操作" }, 400);
}

// ============================================================
// 建仓计划：自选 / 持仓的「准备怎么买」
//   自选是「准备买」，持仓是「已经买了」，但两者都缺一样东西：
//   打算在什么价位买、跌到多少认输、分几笔建仓。没有这个，就只能凭感觉动手。
//   一个 symbol 一条计划（覆盖式更新），按 created_by 隔离。
//   分批价位 tranches 存 JSON 数组：[{price, qty, pct}]，pct 为该笔占总仓位的百分比。
// ============================================================
async function handleTradePlans(request, env, user, url) {
    if (!can(user, "market.view")) return forbidden();
    const isAdmin = user.role === "admin";
    const symbolFilter = cleanStr(url.searchParams.get("symbol"), 20).toUpperCase();

    if (request.method === "GET") {
        let rows = isAdmin
            ? (await env.DB.prepare("SELECT * FROM trade_plans ORDER BY id DESC").all()).results || []
            : (await env.DB.prepare("SELECT * FROM trade_plans WHERE created_by=? ORDER BY id DESC").bind(user.username).all()).results || [];
        if (symbolFilter) rows = rows.filter(r => String(r.symbol || "").toUpperCase() === symbolFilter);
        const quotes = (await env.DB.prepare("SELECT symbol,name,short_name,kind,unit,price,change_pct FROM metal_quotes").all()).results || [];
        const qby = {};
        quotes.forEach(q => { qby[q.symbol] = q; });
        const detail = rows.map(p => {
            const q = qby[p.symbol] || {};
            const price = Number(q.price) || 0;
            const target = Number(p.target_price) || 0;
            const stop = Number(p.stop_loss) || 0;
            const entry = Number(p.entry_price) || 0;
            return {
                ...p,
                target_price: target, stop_loss: stop, entry_price: entry,
                tranches: parseTranches(p.tranches),
                price,
                unit: q.unit || "",
                short_name: q.short_name || q.name || p.name || p.symbol,
                kind: q.kind || "",
                // 距目标 / 止损的空间（正=还差多少，负=已经越过）
                to_target_pct: (price > 0 && target > 0) ? (target - price) / price * 100 : null,
                to_stop_pct: (price > 0 && stop > 0) ? (stop - price) / price * 100 : null,
                // 风险回报比：(目标-现价) / (现价-止损)
                risk_reward: (price > 0 && target > 0 && stop > 0 && price > stop)
                    ? Math.round((target - price) / (price - stop) * 100) / 100 : null
            };
        });
        return json({ rows: detail });
    }

    if (!user || user.role === "visitor") return forbidden();
    const body = await request.json().catch(() => ({}));
    const action = body.action || "save";

    if (action === "delete") {
        const id = parseInt(body.id) || 0;
        if (!id) return json({ success: false, message: "参数错误" }, 400);
        const row = await env.DB.prepare("SELECT created_by FROM trade_plans WHERE id=?").bind(id).first();
        if (!row) return json({ success: false, message: "计划不存在" }, 404);
        if (!isAdmin && row.created_by !== user.username) return forbidden();
        await env.DB.prepare("DELETE FROM trade_plans WHERE id=?").bind(id).run();
        return json({ success: true, message: "已删除建仓计划" });
    }

    // 保存 / 更新
    const symbol = cleanStr(body.symbol, 20).toUpperCase();
    if (!symbol) return json({ success: false, message: "请选择品种" }, 400);
    const target = Number(body.target_price) || 0;
    const stop = Number(body.stop_loss) || 0;
    const entry = Number(body.entry_price) || 0;
    if (!(target > 0)) return json({ success: false, message: "请填写目标价" }, 400);
    if (!(stop > 0)) return json({ success: false, message: "请填写止损价" }, 400);
    if (stop >= target) return json({ success: false, message: "止损价必须低于目标价" }, 400);
    const tranches = parseTranches(body.tranches);
    const hasTranchePayload = body.tranches !== undefined && body.tranches !== null;
    if (hasTranchePayload && !tranches.length) {
        return json({ success: false, message: "请至少保留一批有效分批（比例合计需为 100%）" }, 400);
    }
    if (hasTranchePayload) {
        const sum = tranches.reduce((s, t) => s + (Number(t.pct) || 0), 0);
        if (Math.abs(sum - 100) > 0.5) return json({ success: false, message: `分批比例合计需为 100%（当前 ${sum.toFixed(1)}%）` }, 400);
    }
    const status = ["planning", "active", "done", "cancelled"].includes(body.status) ? body.status : "planning";
    const note = cleanStr(body.note, 500);
    const name = cleanStr(body.name, 60);
    const id = parseInt(body.id) || 0;

    if (id) {
        const row = await env.DB.prepare("SELECT created_by FROM trade_plans WHERE id=?").bind(id).first();
        if (!row) return json({ success: false, message: "计划不存在" }, 404);
        if (!isAdmin && row.created_by !== user.username) return forbidden();
        await env.DB.prepare(
            "UPDATE trade_plans SET symbol=?,name=?,target_price=?,stop_loss=?,entry_price=?,tranches=?,status=?,note=?,updated_at=? WHERE id=?"
        ).bind(symbol, name, target, stop, entry, JSON.stringify(tranches), status, note, nowBeijing(), id).run();
        return json({ success: true, id, message: "建仓计划已更新" });
    }

    // 同一用户同一品种只保留一条计划（新的覆盖旧的）
    const exist = await env.DB.prepare("SELECT id FROM trade_plans WHERE created_by=? AND symbol=?").bind(user.username, symbol).first();
    if (exist && exist.id) {
        await env.DB.prepare(
            "UPDATE trade_plans SET name=?,target_price=?,stop_loss=?,entry_price=?,tranches=?,status=?,note=?,updated_at=? WHERE id=?"
        ).bind(name, target, stop, entry, JSON.stringify(tranches), status, note, nowBeijing(), exist.id).run();
        return json({ success: true, id: exist.id, message: "该品种已有建仓计划，已覆盖更新" });
    }
    const ins = await env.DB.prepare(
        "INSERT INTO trade_plans(symbol,name,target_price,stop_loss,entry_price,tranches,status,note,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(symbol, name, target, stop, entry, JSON.stringify(tranches), status, note, user.username, nowBeijing(), nowBeijing()).run();
    return json({ success: true, id: (ins.meta && ins.meta.last_row_id) || 0, message: "建仓计划已保存" });
}

// 分批价位：接受 JSON 字符串或数组，统一成 [{price,qty,pct}]
function parseTranches(raw) {
    let arr = raw;
    if (typeof raw === "string") {
        const s = raw.trim();
        if (!s) return [];
        try { arr = JSON.parse(s); } catch { return []; }
    }
    if (!Array.isArray(arr)) return [];
    return arr.map(x => {
        const o = (x && typeof x === "object") ? x : { price: x };
        return {
            price: Math.max(0, Number(o.price) || 0),
            qty: Math.max(0, Number(o.qty) || 0),
            pct: Math.max(0, Math.min(100, Number(o.pct) || 0))
        };
    }).filter(t => t.price > 0 || t.qty > 0 || t.pct > 0).slice(0, 10);
}

// —— 持仓：按用户隔离，管理员可见全部 ——
async function handlePositions(request, env, user) {
    const isAdmin = user.role === "admin";
    if (request.method === "GET") {
        const rows = isAdmin
            ? (await env.DB.prepare("SELECT * FROM positions ORDER BY id DESC").all()).results || []
            : (await env.DB.prepare("SELECT * FROM positions WHERE created_by=? ORDER BY id DESC").bind(user.username).all()).results || [];
        const quotes = (await env.DB.prepare("SELECT symbol,name,short_name,kind,unit,currency,price,change_pct FROM metal_quotes").all()).results || [];
        const by = {};
        quotes.forEach(q => { by[q.symbol] = q; });
        let costValue = 0, marketValue = 0, pnl = 0;
        const detail = rows.map(p => {
            const q = by[p.symbol] || {};
            const price = Number(q.price) || 0;
            const qty = Number(p.qty) || 0;
            const cost = Number(p.cost) || 0;
            const fee = Number(p.fee) || 0;
            const cv = qty * cost;
            const mv = qty * price;
            const pl = mv - cv - fee;
            costValue += cv; marketValue += mv; pnl += pl;
            return {
                ...p,
                price, unit: q.unit || p.unit || "", kind: q.kind || "",
                cost_value: cv, market_value: mv,
                pnl: price > 0 ? pl : 0,
                pnl_pct: (price > 0 && cv > 0) ? (pl / cv * 100) : 0,
                change_pct: Number(q.change_pct) || 0
            };
        });
        // 资产分布（按品种市值占比）
        const alloc = detail.filter(d => d.market_value > 0)
            .map(d => ({ symbol: d.symbol, name: d.name || d.symbol, value: d.market_value, pct: marketValue > 0 ? d.market_value / marketValue * 100 : 0 }))
            .sort((a, b) => b.value - a.value);
        return json({
            rows: detail, symbols: quotes,
            summary: {
                cost_value: costValue, market_value: marketValue, pnl,
                pnl_pct: costValue > 0 ? pnl / costValue * 100 : 0,
                count: detail.length, alloc
            }
        });
    }
    if (!user || user.role === "visitor") return forbidden();
    const body = await request.json().catch(() => ({}));
    if (body.action === "create" || body.action === "update") {
        const symbol = cleanStr(body.symbol, 20).toUpperCase();
        if (!symbol) return json({ success: false, message: "请选择品种" }, 400);
        const qty = Number(body.qty);
        const cost = Number(body.cost);
        if (!Number.isFinite(qty) || qty <= 0) return json({ success: false, message: "数量必须大于 0" }, 400);
        if (!Number.isFinite(cost) || cost <= 0) return json({ success: false, message: "成本价必须大于 0" }, 400);
        const fee = Number.isFinite(Number(body.fee)) ? Math.max(0, Number(body.fee)) : 0;
        const q = await env.DB.prepare("SELECT name FROM metal_quotes WHERE symbol=?").bind(symbol).first();
        const name = cleanStr(body.name, 40) || (q ? q.name : symbol);
        if (body.action === "update") {
            if (!body.id) return json({ success: false, message: "缺少持仓 ID" }, 400);
            const own = await env.DB.prepare("SELECT created_by FROM positions WHERE id=?").bind(body.id).first();
            if (!own) return json({ success: false, message: "持仓不存在" }, 404);
            if (!isAdmin && own.created_by !== user.username) return forbidden();
            await env.DB.prepare("UPDATE positions SET symbol=?,name=?,qty=?,cost=?,fee=?,opened_at=?,note=? WHERE id=?")
                .bind(symbol, name, qty, cost, fee, cleanStr(body.opened_at, 20), cleanStr(body.note, 200), body.id).run();
            return json({ success: true, message: "持仓已更新" });
        }
        await env.DB.prepare("INSERT INTO positions(symbol,name,qty,cost,fee,opened_at,note,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(symbol, name, qty, cost, fee, cleanStr(body.opened_at, 20), cleanStr(body.note, 200), user.username, nowBeijing()).run();
        return json({ success: true, message: "持仓已添加" });
    }
    if (body.action === "delete") {
        const own = await env.DB.prepare("SELECT created_by FROM positions WHERE id=?").bind(body.id).first();
        if (!own) return json({ success: true });
        if (!isAdmin && own.created_by !== user.username) return forbidden();
        await env.DB.prepare("DELETE FROM positions WHERE id=?").bind(body.id).run();
        return json({ success: true });
    }
    return json({ success: false, message: "未知操作" }, 400);
}

// ============================================================
// 自选观察池：投资决策的第一步
//   持仓是「已经买了」，自选是「准备买」。两者分开，才谈得上「准备投资」：
//   先在自选池里观察，再决定是否建仓。按 created_by 隔离，可见性规则与持仓一致。
// ============================================================
async function handleWatchlist(request, env, user) {
    if (!can(user, "market.view")) return forbidden();
    if (request.method === "GET") {
        const rows = (await env.DB.prepare(
            "SELECT w.id,w.symbol,w.note,w.created_at,q.name,q.short_name,q.price,q.change_pct,q.unit "
            + "FROM watchlist w LEFT JOIN metal_quotes q ON q.symbol=w.symbol WHERE w.created_by=? ORDER BY w.id DESC"
        ).bind(user.username).all()).results || [];
        return json({ rows, symbols: rows.map(r => r.symbol) });
    }
    if (!user || user.role === "visitor") return forbidden();
    const body = await request.json().catch(() => ({}));
    const symbol = cleanStr(body.symbol, 20).toUpperCase();
    if (!symbol) return json({ success: false, message: "请选择品种" }, 400);
    const exist = await env.DB.prepare("SELECT id FROM watchlist WHERE created_by=? AND symbol=?").bind(user.username, symbol).first();
    const action = body.action === "remove" ? "remove" : body.action === "toggle" ? (exist ? "remove" : "add") : "add";
    if (action === "remove") {
        await env.DB.prepare("DELETE FROM watchlist WHERE created_by=? AND symbol=?").bind(user.username, symbol).run();
        return json({ success: true, watching: false, message: "已从自选移除" });
    }
    if (!exist) {
        await env.DB.prepare("INSERT OR IGNORE INTO watchlist(symbol,note,created_by,created_at) VALUES(?,?,?,?)")
            .bind(symbol, cleanStr(body.note, 100), user.username, nowBeijing()).run();
    }
    return json({ success: true, watching: true, message: "已加入自选" });
}

// ============================================================
// 品种清单（只读、不触发行情刷新）
//   给「建仓计划」「持仓」这类需要先选品种的场合用：
//   /api/desk 会顺带刷新行情，太重；这里只查库，秒回。
//   注意：/api/rare/instruments 只给稀有金属品种，这里要的是贵金属 + 稀有金属的合集。
// ============================================================
async function getSymbolCatalog(env) {
    const instruments = (await instrumentRows(env)).filter(r => Number(r.enabled) === 1);
    const quotes = (await env.DB.prepare("SELECT symbol,price,change_pct,unit FROM metal_quotes").all()).results || [];
    const qby = {};
    quotes.forEach(q => { qby[q.symbol] = q; });
    return json({
        rows: instruments.map(i => {
            const q = qby[i.symbol] || {};
            return {
                symbol: i.symbol,
                name: i.name || i.symbol,
                short_name: i.short_name || i.name || i.symbol,
                kind: i.kind || "",
                market: i.market || "",
                scope: i.scope === "metal" ? "metal" : "rare",
                unit: i.unit || q.unit || "",
                price: Number(q.price) || 0,
                change_pct: Number(q.change_pct) || 0
            };
        })
    });
}

// ============================================================
// 投资工作台：把「消息 → 标的 → 决策」合成一次请求
//   过去贵金属、稀有金属、消息中心、持仓是四个互不相干的页面，用户得自己在脑子里拼；
//   这里统一以「标的」为主键，把行情、相关消息、我的自选/持仓、预警、事件挂到同一行上。
// ============================================================
async function getDesk(env, user, url) {
    const hours = Math.min(72, Math.max(3, parseInt(url.searchParams.get("hours"), 10) || 24));
    // 总览页与行情页共用同一套节流：到点才回源，避免两个页面各拉一次
    const liveCfg = await settingsMap(env);
    const liveSec = await liveIntervalSec(env, "metal", "metal_live_sec", 10, 5, 120);
    await Promise.all([
        refreshMetalQuotesIfStale(env, liveCfg, liveSec),
        readRareQuotes(env, false).catch(() => [])
    ]);
    const instruments = (await instrumentRows(env)).filter(r => Number(r.enabled) === 1);
    // 贵金属域「在采集」品种集合：不在集合里的品种行情停在上次启用时的旧价（与实时行情页过滤同源）。
    //   稀有金属域走 readRareQuotes 按需刷新，所有启用品种始终活跃，不参与该判断。
    const activeMetal = new Set(await acquireList(env, "metal", "metal_symbols"));
    const quotes = (await env.DB.prepare(
        "SELECT symbol,name,short_name,kind,market,unit,price,change,change_pct,amplitude,quote_time,updated_at FROM metal_quotes"
    ).all()).results || [];
    const qby = {};
    quotes.forEach(q => { qby[q.symbol] = q; });

    // —— 自选 ——
    let watchRows = [];
    try {
        watchRows = (await env.DB.prepare("SELECT symbol FROM watchlist WHERE created_by=?").bind(user.username).all()).results || [];
    } catch (e) { logWarn("desk.watch", e); }
    const watchSet = new Set(watchRows.map(r => r.symbol));

    // —— 持仓（口径与持仓页一致：管理员看全部）——
    const posSum = { count: 0, cost_value: 0, market_value: 0, pnl: 0, pnl_pct: 0, by_symbol: {} };
    try {
        const rows = (user.role === "admin"
            ? await env.DB.prepare("SELECT * FROM positions").all()
            : await env.DB.prepare("SELECT * FROM positions WHERE created_by=?").bind(user.username).all()).results || [];
        rows.forEach(p => {
            const q = qby[p.symbol] || {};
            const price = Number(q.price) || 0;
            const qty = Number(p.qty) || 0;
            const cv = qty * (Number(p.cost) || 0);
            const mv = qty * price;
            const pl = price > 0 ? mv - cv - (Number(p.fee) || 0) : 0;
            posSum.cost_value += cv;
            posSum.market_value += mv;
            posSum.pnl += pl;
            posSum.count++;
            const b = posSum.by_symbol[p.symbol] || { qty: 0, cost_value: 0, market_value: 0, pnl: 0 };
            b.qty += qty; b.cost_value += cv; b.market_value += mv; b.pnl += pl;
            posSum.by_symbol[p.symbol] = b;
        });
        posSum.pnl_pct = posSum.cost_value > 0 ? posSum.pnl / posSum.cost_value * 100 : 0;
    } catch (e) { logWarn("desk.positions", e); }

    // —— 预警 ——
    const alerts = { active: 0, triggered_today: 0, by_symbol: {} };
    try {
        const rows = (await env.DB.prepare("SELECT symbol, COUNT(*) c FROM price_alerts WHERE enabled=1 GROUP BY symbol").all()).results || [];
        rows.forEach(r => { alerts.by_symbol[r.symbol] = Number(r.c) || 0; alerts.active += Number(r.c) || 0; });
        // pushNotification 写入的 notifications.created_at 为北京时间（nowBeijing），按北京时间今日 00:00:00 统计
        const todayBjStart = nowBeijing().slice(0, 10) + " 00:00:00";
        const hit = await env.DB.prepare("SELECT COUNT(*) n FROM notifications WHERE kind='alert' AND created_at >= ?").bind(todayBjStart).first();
        alerts.triggered_today = Number(hit && hit.n) || 0;
    } catch (e) { logWarn("desk.alerts", e); }

    // —— 消息：近 N 天按标的聚合（消息量不大，一次取回在内存里分组比多次 LIKE 查询更省）——
    //   与资讯中心同口径：屏蔽词 + 四类相关性白名单，避免工作台消息流出现资讯中心已隐藏的噪声。
    const relFilter = await newsRelevanceFilter(env, {});
    const relCond = relFilter.cond ? " AND " + relFilter.cond : "";
    const relParams = relFilter.params || [];
    const since = beijingStamp(Date.now() - hours * 3600000);
    let newsRows = [];
    try {
        newsRows = (await env.DB.prepare(
            "SELECT id,title,summary,url,source,platform,channel,symbols,sentiment,sentiment_map,published_at FROM news WHERE published_at >= ?" + relCond + " ORDER BY published_at DESC, id DESC LIMIT 200"
        ).bind(since, ...relParams).all()).results || [];
    } catch (e) { logWarn("desk.news", e); }
    const nameOf = {};
    instruments.forEach(i => { nameOf[i.symbol] = i.short_name || i.name || i.symbol; });
    const newsCount = {}, newsLatest = {};
    // 情绪按标的统计：bull / bear / neutral 三个计数，供工作台一眼看出消息面
    const sentCount = {};
    newsRows.forEach(n => {
        String(n.symbols || "").split(",").filter(Boolean).forEach(s => {
            newsCount[s] = (newsCount[s] || 0) + 1;
            if (!newsLatest[s]) newsLatest[s] = n.title;
        });
        const sm = parseSentimentMap(n.sentiment_map);
        String(n.symbols || "").split(",").filter(Boolean).forEach(s => {
            const c = sentCount[s] || (sentCount[s] = { bullish: 0, bearish: 0, neutral: 0, score: 0 });
            const lbl = (sm[s] && sm[s].label) || n.sentiment || "neutral";
            if (c[lbl] != null) c[lbl]++;
            c.score += (sm[s] && Number(sm[s].score)) || 0;
        });
    });

    // —— 建仓计划：自选 / 持仓的准备买入价、止损、分批 ——
    let planRows = [];
    try {
        planRows = (await env.DB.prepare(
            "SELECT * FROM trade_plans WHERE created_by=? ORDER BY id DESC"
        ).bind(user.username).all()).results || [];
    } catch (e) { logWarn("desk.plans", e); }
    const planBy = {};
    planRows.forEach(p => {
        const price = Number(qby[p.symbol] && qby[p.symbol].price) || 0;
        const target = Number(p.target_price) || 0;
        const stop = Number(p.stop_loss) || 0;
        planBy[p.symbol] = {
            id: p.id, symbol: p.symbol, name: p.name || "",
            target_price: target, stop_loss: stop, entry_price: Number(p.entry_price) || 0,
            tranches: parseTranches(p.tranches), status: p.status || "planning", note: p.note || "",
            to_target_pct: (price > 0 && target > 0) ? round2((target - price) / price * 100) : null,
            to_stop_pct: (price > 0 && stop > 0) ? round2((stop - price) / price * 100) : null,
            risk_reward: (price > 0 && target > 0 && stop > 0 && price > stop)
                ? Math.round((target - price) / (price - stop) * 100) / 100 : null
        };
    });

    //   贵金属域只保留「在采集」的品种（与实时行情页同口径）：未采集品种不展示，避免旧价被误读。
    //   列表为空（什么都不采）时不过滤；稀有金属走按需刷新，全部保留。
    //   自选 / 持仓 / 计划 / 预警若挂在未采集品种上会一并隐藏 —— 当前库里全部挂在 AU0/AG0，无影响。
    const poolInstruments = activeMetal.size
        ? instruments.filter(i => i.scope !== "metal" || activeMetal.has(i.symbol))
        : instruments;
    const rows = poolInstruments.map(i => {
        const q = qby[i.symbol] || {};
        const b = posSum.by_symbol[i.symbol] || null;
        return {
            symbol: i.symbol,
            name: i.name || q.name || i.symbol,
            short_name: i.short_name || q.short_name || i.name || i.symbol,
            scope: i.scope === "metal" ? "metal" : "rare",
            kind: i.kind || q.kind || "",
            market: i.market || q.market || "",
            chain: i.chain || "",
            unit: i.unit || q.unit || "",
            price: Number(q.price) || 0,
            change: Number(q.change) || 0,
            change_pct: Number(q.change_pct) || 0,
            amplitude: Number(q.amplitude) || 0,
            quote_time: q.quote_time || "",
            updated_at: q.updated_at || "",
            news_count: newsCount[i.symbol] || 0,
            news_latest: newsLatest[i.symbol] || "",
            news_sentiment: sentCount[i.symbol]
                ? { bullish: sentCount[i.symbol].bullish, bearish: sentCount[i.symbol].bearish, neutral: sentCount[i.symbol].neutral, score: round2(sentCount[i.symbol].score) }
                : null,
            watching: watchSet.has(i.symbol),
            alert_count: alerts.by_symbol[i.symbol] || 0,
            plan: planBy[i.symbol] || null,
            // 陈旧标记：贵金属域不在采集列表里、但库里还留着旧价的品种（price=0 的未采过品种走「未采集」展示，不算陈旧）
            stale: i.scope === "metal" && activeMetal.size > 0 && !activeMetal.has(i.symbol) && Number(q.price) > 0,
            position: b ? { qty: b.qty, cost_value: b.cost_value, market_value: b.market_value, pnl: b.pnl, pnl_pct: b.cost_value > 0 ? b.pnl / b.cost_value * 100 : 0 } : null
        };
    });

    const scopeStats = list => {
        // 涨跌统计只算「当前在采集」的品种：陈旧行的旧涨跌混进来会把统计带偏
        const live = list.filter(r => r.price > 0 && !r.stale);
        return {
            count: list.length, quoted: live.length,
            up: live.filter(r => r.change_pct > 0).length,
            down: live.filter(r => r.change_pct < 0).length,
            avg_pct: live.length ? round2(live.reduce((s, r) => s + r.change_pct, 0) / live.length) : 0
        };
    };

    // —— 消息流：解析出可点选的标的，前端直接按名称展示 ——
    const news = newsRows.slice(0, 30).map(n => {
        const sm = parseSentimentMap(n.sentiment_map);
        return {
            id: n.id, title: n.title, url: n.url, source: n.source, platform: n.platform,
            channel: n.channel, published_at: n.published_at,
            sentiment: n.sentiment || "neutral",
            sentiment_map: sm,
            symbols: String(n.symbols || "").split(",").filter(Boolean).map(s => ({
                symbol: s, name: nameOf[s] || s,
                sentiment: (sm[s] && sm[s].label) || "neutral",
                sentiment_score: (sm[s] && Number(sm[s].score)) || 0,
                sentiment_hits: (sm[s] && sm[s].hits) || []
            }))
        };
    });

    const todayNews = newsRows.filter(n => String(n.published_at || "").slice(0, 10) === nowBeijing().slice(0, 10)).length;
    // 情绪总览：窗口内所有消息按「整体倾向」计数（按标的的明细在 instruments.news_sentiment 里）
    const sentTotal = { bullish: 0, bearish: 0, neutral: 0 };
    newsRows.forEach(n => {
        const lbl = n.sentiment || "neutral";
        if (sentTotal[lbl] != null) sentTotal[lbl]++;
    });

    // —— 近 14 天消息量趋势（口径与资讯中心一致：屏蔽词 + 四类相关性白名单）——
    //   趋势图已从资讯中心搬到投资总览，这里直接随 /api/desk 一起返回，前端不必再发一次请求。
    //   与「系统概览」聚合一并走进 newsStatsBundle 的 3 分钟缓存（与资讯中心共用同一份）。

    // —— 系统总体统计（投资总览顶部的「系统概览」卡片区）——
    //   全部走与资讯中心一致的过滤口径（屏蔽词 + 四类相关性白名单），避免出现「卡片 936 条、列表 285 条」的矛盾。
    const todayStr = nowBeijing().slice(0, 10);
    const safeStat = async (label, sql, params) => {
        try { return await env.DB.prepare(sql).bind(...params).first(); }
        catch (e) { logWarn("desk.overview." + label, e); return null; }
    };
    const safeAll = async (label, sql, params) => {
        try { return (await env.DB.prepare(sql).bind(...params).all()).results || []; }
        catch (e) { logWarn("desk.overview." + label, e); return []; }
    };
    const [newsAgg, calStat, alertStat] = await Promise.all([
        // 统计聚合与资讯中心共用同一份缓存（键 = 过滤条件 + 参数 + 日期，TTL 3 分钟）：
        //   两个页面轮询的是同一组 COUNT / GROUP BY，没必要各算一遍。
        //   行情 / 消息流 / 重点 Top / 日历 / 预警都不缓存，保持实时。
        newsStatsBundle(env, relFilter.cond || "", relParams, todayStr),
        // 财经日历：未来 14 天事件（小表，不必缓存）
        safeStat("calendar",
            "SELECT COUNT(*) total, SUM(CASE WHEN importance=3 THEN 1 ELSE 0 END) high,"
            + " SUM(CASE WHEN event_at>=? AND event_at<=? THEN 1 ELSE 0 END) upcoming_24h FROM eco_events WHERE event_at>=?",
            [nowBeijing(), beijingStamp(Date.now() + 86400000), nowBeijing()]),
        // 价格预警：启用中 / 今日触发（小表，不必缓存）
        safeStat("alerts",
            "SELECT (SELECT COUNT(*) FROM price_alerts WHERE enabled=1) active,"
            + " (SELECT COUNT(*) FROM price_alerts WHERE last_trigger_at>=?) triggered_today",
            [todayStr])
    ]);
    const newsTrend = newsAgg.trend;
    const libStat = {
        total: newsAgg.total, today: newsAgg.today, key_count: newsAgg.keyCount,
        starred: newsAgg.starred, latest: newsAgg.latest
    };
    const sentStat = newsAgg.sentiment;
    // 频道分布 Top 6（bundle 里是全量分布，与资讯中心共用）
    const chanStat = (newsAgg.channel || []).slice()
        .sort((a, b) => (Number(b.c) || 0) - (Number(a.c) || 0)).slice(0, 6);

    const sentimentDist = { bullish: 0, bearish: 0, neutral: 0 };
    (sentStat || []).forEach(r => {
        const k = ["bullish", "bearish", "neutral"].includes(r.sentiment) ? r.sentiment : "neutral";
        sentimentDist[k] += Number(r.c) || 0;
    });

    // —— 重点消息 Top（系统「重点信息」栏：按综合分排序，带方向与影响标的）——
    let keyNews = [];
    try {
        keyNews = (await env.DB.prepare(
            "SELECT id,title,url,source,platform,channel,published_at,key_score,key_brief,impact,symbols,sentiment FROM news"
            + " WHERE is_key=1" + relCond + " ORDER BY key_score DESC, published_at DESC LIMIT 8"
        ).bind(...relParams).all()).results || [];
        // symbols 是逗号分隔字符串，转成 [{symbol,name}] 供前端渲染可点的标的标签
        keyNews = keyNews.map(n => ({
            ...n,
            symbols: String(n.symbols || "").split(",").filter(Boolean).map(s => ({
                symbol: s, name: nameOf[s] || s
            }))
        }));
    } catch (e) { logWarn("desk.keynews", e); }

    // —— 即将到来的重要财经事件（未来 7 天，重要度高的排前面）——
    let upcomingEvents = [];
    try {
        const from = nowBeijing();
        const to = beijingStamp(Date.now() + 7 * 86400000);
        upcomingEvents = (await env.DB.prepare(
            "SELECT id,event_at,country,name,importance,previous,forecast,actual,unit FROM eco_events"
            + " WHERE event_at>=? AND event_at<=? ORDER BY importance DESC, event_at ASC LIMIT 6"
        ).bind(from, to).all()).results || [];
    } catch (e) { logWarn("desk.events", e); }

    const overview = {
        news_total: Number(libStat && libStat.total) || 0,
        news_today: Number(libStat && libStat.today) || 0,
        key_count: Number(libStat && libStat.key_count) || 0,
        starred: Number(libStat && libStat.starred) || 0,
        latest: (libStat && libStat.latest) || "",
        sentiment: sentimentDist,
        channels: (chanStat || []).map(r => ({ key: r.channel, c: Number(r.c) || 0 })),
        calendar_total: Number(calStat && calStat.total) || 0,
        calendar_high: Number(calStat && calStat.high) || 0,
        calendar_24h: Number(calStat && calStat.upcoming_24h) || 0,
        alerts_active: Number(alertStat && alertStat.active) || 0,
        alerts_triggered: Number(alertStat && alertStat.triggered_today) || 0,
        last_news_refresh: (liveCfg && liveCfg.last_news_refresh) || "",
        last_metal_refresh: (liveCfg && liveCfg.last_metal_refresh) || ""
    };

    return json({
        generated_at: nowBeijing(),
        hours,
        live_sec: liveSec,
        instruments: rows,
        news_trend: newsTrend,
        overview,
        key_news: keyNews,
        upcoming_events: upcomingEvents,
        stats: {
            metal: scopeStats(rows.filter(r => r.scope === "metal")),
            rare: scopeStats(rows.filter(r => r.scope === "rare")),
            news_today: todayNews,
            news_window: newsRows.length,
            // 窗口内能落到具体标的上的消息数（消息与行情的耦合度，便于判断打标是否生效）
            news_tagged: newsRows.filter(n => String(n.symbols || "").trim()).length,
            news_sentiment: sentTotal,
            watch: [...watchSet].length,
            plans: planRows.length,
            positions: posSum,
            alerts
        },
        news
    });
}

// ============================================================
// 财经日历（经济事件日程）
//   说明：金十 / 东财的日历接口目前均无稳定公开通道（实测 404 / 报表未开放），
//   因此这里采用「自建事件库」：管理员录入或批量导入，系统负责到点提醒。
//   数据结构与提醒链路与外部源解耦，后续若接上数据源只需写库，前端无需改动。
// ============================================================
const CAL_COUNTRIES = ["中国", "美国", "欧元区", "日本", "英国", "其他"];
const CAL_IMPORTANCE = { 1: "低", 2: "中", 3: "高" };

// 常用事件模板：只预填名称/国家/重要度，时间由用户选择（不硬编码具体日期，避免给出错误日程）
const CAL_TEMPLATES = [
    { name: "美国非农就业人数", country: "美国", importance: 3, unit: "万人" },
    { name: "美国 CPI 年率", country: "美国", importance: 3, unit: "%" },
    { name: "美国核心 CPI 年率", country: "美国", importance: 3, unit: "%" },
    { name: "美联储利率决议", country: "美国", importance: 3, unit: "%" },
    { name: "美联储主席讲话", country: "美国", importance: 2, unit: "" },
    { name: "美国初请失业金人数", country: "美国", importance: 2, unit: "万人" },
    { name: "美国 ISM 制造业 PMI", country: "美国", importance: 2, unit: "" },
    { name: "中国 CPI 年率", country: "中国", importance: 3, unit: "%" },
    { name: "中国制造业 PMI", country: "中国", importance: 2, unit: "" },
    { name: "中国社会融资规模", country: "中国", importance: 2, unit: "亿元" },
    { name: "欧元区利率决议", country: "欧元区", importance: 2, unit: "%" },
    { name: "欧元区 CPI 年率", country: "欧元区", importance: 2, unit: "%" }
];

// 北京时间字符串 → epoch（"YYYY-MM-DD HH:mm"，可省略时分）
function beijingEpoch(str) {
    const s = String(str || "").trim().replace(" ", "T");
    if (!/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2})?/.test(s)) return 0;
    const full = s.length === 10 ? s + "T00:00" : s.slice(0, 16);
    const t = Date.parse(full + ":00+08:00");
    return Number.isFinite(t) ? t : 0;
}

// 归一化成统一格式，非法返回空串。
// 严格校验真实年月日，避免 Date.parse 将 2 月 31 日等非法日期静默滚动到下个月。
function normalizeEventAt(v) {
    const s = String(v == null ? "" : v).trim().replace("T", " ").replace(/\//g, "-");
    const m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:\s+(\d{1,2}):(\d{2}))?$/);
    if (!m) return "";
    const year = Number(m[1]);
    const month = Number(m[2]);
    const day = Number(m[3]);
    const hour = m[4] == null ? 0 : Number(m[4]);
    const minute = m[5] == null ? 0 : Number(m[5]);
    if (!Number.isInteger(year) || year < 1 || year > 9999) return "";
    if (!Number.isInteger(month) || month < 1 || month > 12) return "";
    if (!Number.isInteger(day) || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()) return "";
    if (!Number.isInteger(hour) || hour < 0 || hour > 23) return "";
    if (!Number.isInteger(minute) || minute < 0 || minute > 59) return "";
    return `${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")} ${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
}

async function listEcoEvents(env, opts = {}) {
    const from = opts.from || "";
    const to = opts.to || "";
    const where = [];
    const binds = [];
    if (from) { where.push("event_at >= ?"); binds.push(from); }
    if (to) { where.push("event_at <= ?"); binds.push(to + " 23:59"); }
    if (opts.country) { where.push("country = ?"); binds.push(opts.country); }
    if (opts.importance) { where.push("importance >= ?"); binds.push(Number(opts.importance)); }
    const sql = `SELECT * FROM eco_events ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY event_at ASC, importance DESC LIMIT 500`;
    const rows = (await env.DB.prepare(sql).bind(...binds).all()).results || [];
    return rows;
}

async function getCalendar(env, url) {
    const days = Math.min(180, Math.max(1, parseInt(url.searchParams.get("days")) || 14));
    // 默认看「今天起 N 天」，也支持显式 from/to
    const today = nowBeijing().slice(0, 10);
    const from = normalizeEventAt(url.searchParams.get("from") || today).slice(0, 10) || today;
    const toDate = new Date(beijingEpoch(from) + 86400000 * (days - 1));
    const to = url.searchParams.get("to")
        ? (normalizeEventAt(url.searchParams.get("to")).slice(0, 10) || "")
        : beijingStamp(toDate.getTime()).slice(0, 10);
    const events = await listEcoEvents(env, {
        from, to,
        country: String(url.searchParams.get("country") || "").trim(),
        importance: Number(url.searchParams.get("importance")) || 0
    });
    const now = Date.now();
    const rows = events.map(e => ({
        ...e,
        importance_label: CAL_IMPORTANCE[e.importance] || "中",
        epoch: beijingEpoch(e.event_at),
        is_past: beijingEpoch(e.event_at) + 3600000 < now,
        countdown_min: Math.round((beijingEpoch(e.event_at) - now) / 60000)
    }));
    // 按日分组，前端直接渲染
    const groups = [];
    const byDate = new Map();
    rows.forEach(r => {
        const d = String(r.event_at).slice(0, 10);
        if (!byDate.has(d)) { const g = { date: d, items: [] }; byDate.set(d, g); groups.push(g); }
        byDate.get(d).items.push(r);
    });
    return json({
        from, to, days,
        events: rows,
        groups,
        countries: CAL_COUNTRIES,
        importance_labels: CAL_IMPORTANCE,
        templates: CAL_TEMPLATES,
        stats: {
            total: rows.length,
            high: rows.filter(r => r.importance === 3).length,
            upcoming_24h: rows.filter(r => r.epoch > now && r.epoch - now <= 86400000).length,
            unconfirmed: rows.filter(r => r.epoch > now && !String(r.actual || "").trim()).length
        },
        today
    });
}

async function saveCalendarEvent(request, env, user) {
    const body = await request.json().catch(() => ({}));
    const action = String(body.action || "create");

    if (action === "delete") {
        const id = Number(body.id) || 0;
        if (!id) return json({ success: false, message: "缺少事件 ID" }, 400);
        await env.DB.prepare("DELETE FROM eco_events WHERE id=?").bind(id).run();
        return json({ success: true });
    }
    if (action === "clear_past") {
        const before = normalizeEventAt(body.before || nowBeijing().slice(0, 10));
        await env.DB.prepare("DELETE FROM eco_events WHERE event_at < ?").bind(before || nowBeijing()).run();
        return json({ success: true });
    }

    // create / update
    const eventAt = normalizeEventAt(body.event_at);
    if (!eventAt) return json({ success: false, message: "时间格式不正确，应为 2026-11-05 20:30" }, 400);
    const name = cleanStr(body.name, 120);
    if (!name) return json({ success: false, message: "请填写事件名称" }, 400);
    const country = CAL_COUNTRIES.includes(body.country) ? body.country : "其他";
    const importance = Math.min(3, Math.max(1, Number(body.importance) || 2));
    const fields = [
        eventAt, country, name, importance,
        cleanStr(body.previous, 40), cleanStr(body.forecast, 40), cleanStr(body.actual, 40),
        cleanStr(body.unit, 16), cleanStr(body.note, 500)
    ];

    if (action === "update") {
        const id = Number(body.id) || 0;
        if (!id) return json({ success: false, message: "缺少事件 ID" }, 400);
        const old = await env.DB.prepare("SELECT * FROM eco_events WHERE id=?").bind(id).first();
        if (!old) return json({ success: false, message: "事件不存在" }, 404);
        // 时间改了要重置提醒标记，否则新时间不会再提醒
        const reset = old.event_at !== eventAt ? 0 : old.notified;
        await env.DB.prepare("UPDATE eco_events SET event_at=?,country=?,name=?,importance=?,previous=?,forecast=?,actual=?,unit=?,note=?,notified=? WHERE id=?")
            .bind(...fields, reset, id).run();
        return json({ success: true, id });
    }

    const res = await env.DB.prepare("INSERT INTO eco_events(event_at,country,name,importance,previous,forecast,actual,unit,note,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(...fields, user ? user.username : "").run();
    return json({ success: true, id: res.meta ? res.meta.last_row_id : 0 });
}

// —— 批量导入财经事件（JSON）——
//   便于把外部日历（自建脚本 / 手工整理）一次性灌进来，避免逐条录入。
//   去重口径：同一 event_at + 同一 name 视为同一条，已存在则跳过（可 overwrite=1 覆盖）。
async function importCalendarEvents(request, env, user) {
    const body = await request.json().catch(() => ({}));
    const list = Array.isArray(body.events) ? body.events : Array.isArray(body) ? body : null;
    if (!list) return json({ success: false, message: "请求体需为 { events: [...] } 或事件数组" }, 400);
    if (list.length > 500) return json({ success: false, message: "单次最多导入 500 条" }, 400);
    const overwrite = body.overwrite === 1 || body.overwrite === true;

    const existing = new Map();
    try {
        const r = await env.DB.prepare("SELECT id, event_at, name FROM eco_events").all();
        (r.results || []).forEach(e => existing.set(String(e.event_at) + "|" + e.name, e.id));
    } catch (e) { logWarn("calendar.importRead", e); }

    let imported = 0, updated = 0, skipped = 0;
    const errors = [];
    const ins = env.DB.prepare("INSERT INTO eco_events(event_at,country,name,importance,previous,forecast,actual,unit,note,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)");
    const upd = env.DB.prepare("UPDATE eco_events SET country=?,importance=?,previous=?,forecast=?,actual=?,unit=?,note=?,notified=0 WHERE id=?");
    const stmts = [];
    list.forEach((raw, idx) => {
        if (!raw || typeof raw !== "object") { errors.push(`第 ${idx + 1} 条格式不正确`); return; }
        // 支持 event_at 或 date(+time) 两种写法
        const datePart = String(raw.event_at || raw.date || "").trim();
        const timePart = String(raw.time || "").trim();
        const merged = datePart && timePart && !/\d{2}:\d{2}/.test(datePart) ? datePart + " " + timePart : datePart;
        const eventAt = normalizeEventAt(merged);
        const name = cleanStr(raw.name || raw.title, 120);
        if (!eventAt) { errors.push(`第 ${idx + 1} 条时间无法解析`); return; }
        if (!name) { errors.push(`第 ${idx + 1} 条缺少事件名称`); return; }
        const country = CAL_COUNTRIES.includes(raw.country) ? raw.country : "其他";
        const importance = Math.min(3, Math.max(1, Number(raw.importance) || 2));
        const previous = cleanStr(raw.previous, 40), forecast = cleanStr(raw.forecast, 40);
        const actual = cleanStr(raw.actual, 40), unit = cleanStr(raw.unit, 16), note = cleanStr(raw.note, 500);
        const key = eventAt + "|" + name;
        if (existing.has(key)) {
            if (!overwrite) { skipped++; return; }
            stmts.push(upd.bind(country, importance, previous, forecast, actual, unit, note, existing.get(key)));
            updated++;
            return;
        }
        stmts.push(ins.bind(eventAt, country, name, importance, previous, forecast, actual, unit, note, user ? user.username : ""));
        existing.set(key, 0);
        imported++;
    });
    if (stmts.length) {
        try { await env.DB.batch(stmts); }
        catch (e) { return json({ success: false, message: "写入失败：" + e.message, imported: 0, skipped, errors }, 500); }
    }
    return json({ success: true, imported, updated, skipped, errors: errors.slice(0, 20), total: list.length });
}

// 到点提醒：查未来 30 分钟内、尚未提醒的事件 → 写通知 + 推送
async function checkEcoReminders(env, windowMin = 30) {
    const now = Date.now();
    const fromStr = beijingStamp(now);
    const toStr = beijingStamp(now + windowMin * 60000);
    let rows = [];
    try {
        rows = (await env.DB.prepare("SELECT * FROM eco_events WHERE notified=0 AND event_at >= ? AND event_at <= ? ORDER BY event_at ASC LIMIT 20")
            .bind(fromStr, toStr).all()).results || [];
    } catch (e) { return { reminded: 0 }; }
    let reminded = 0;
    for (const e of rows) {
        const mins = Math.max(0, Math.round((beijingEpoch(e.event_at) - now) / 60000));
        const warn = e.importance === 3 ? "danger" : e.importance === 2 ? "warn" : "info";
        const when = String(e.event_at).slice(11, 16);
        const impLabel = ["", "低", "中", "高"][Number(e.importance) || 1] || "中";
        const parts = [
            `${e.country} · ${e.event_at}（${mins} 分钟后公布）`,
            `重要性：${impLabel}`,
            e.forecast ? `预期 ${e.forecast}${e.unit || ""}` : "",
            e.previous ? `前值 ${e.previous}${e.unit || ""}` : "",
            e.actual ? `公布值 ${e.actual}${e.unit || ""}` : "",
            e.note || ""
        ].filter(Boolean);
        const okPush = await pushNotification(env, {
            kind: "calendar",
            level: warn,
            title: `${mins} 分钟后公布：${e.name}`,
            body: parts.join("\n"),
            ref_type: "eco_event",
            ref_id: e.id,
            // 同一事件同一时间只提醒一次；改了时间会换 key
            dedup_key: `eco:${e.id}:${e.event_at}`
        });
        await env.DB.prepare("UPDATE eco_events SET notified=1 WHERE id=?").bind(e.id).run();
        if (okPush) reminded++;
    }
    return { reminded, scanned: rows.length };
}


// ============================================================
// 设置
// ============================================================
// 无设置权限的账号也需要「系统名称」来渲染品牌，只下发白名单字段。
// 之前这里直接 403，普通用户每次登录都会在控制台留下一条错误，且品牌名退回默认值。
async function getPublicSettings(env) {
    try {
        const row = await env.DB.prepare("SELECT value FROM settings WHERE key='system_name'").first();
        return json({ system_name: (row && row.value) || "稀有金属投资咨询平台" });
    } catch (e) { return json({ system_name: "稀有金属投资咨询平台" }); }
}

async function getSettings(env, user) {
    const rows = await env.DB.prepare("SELECT * FROM settings").all();
    let data = {};
    rows.results.forEach(item => { data[item.key] = item.value; });
    // 数据源启停以 data_sources 为唯一事实来源（与「数据采集」页同源），
    // 否则系统设置页会显示一份和实际抓取行为不符的开关状态。
    try {
        const srcs = (await env.DB.prepare("SELECT source_key, enabled FROM data_sources WHERE domain='news'").all()).results || [];
        if (srcs.length) data.news_sources = srcs.filter(s => s.enabled).map(s => NEWS_SOURCE_ALIAS[s.source_key]).filter(Boolean).join(",");
    } catch (e) { logWarn("settings.sources", e); }
    return json(data);
}
async function saveSettings(request, env) {
    const body = await request.json();
    const allowed = ["system_name", "news_keywords", "news_sources"];
    const writes = [];
    for (const key in body) {
        if (!allowed.includes(key)) continue;
        if (key === "system_name") body[key] = cleanStr(body[key], 60) || "稀有金属投资咨询平台";
        if (key === "news_keywords") body[key] = parseNewsKeywords(body[key]).join(",");
        if (key === "news_sources") body[key] = parseNewsSources(body[key]).join(",");
        writes.push(env.DB.prepare("INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, String(body[key])));
    }
    // news_sources 写透到 data_sources：抓取实际只认 data_sources.enabled，
    // 只写 settings 会让这个开关完全失效（旧实现的真实 bug）。
    if (allowed.includes("news_sources") && Object.prototype.hasOwnProperty.call(body, "news_sources")) {
        const picked = body.news_sources.split(",").filter(Boolean);
        const keys = Object.keys(NEWS_SOURCE_ALIAS).filter(k => picked.includes(NEWS_SOURCE_ALIAS[k]));
        if (keys.length) {
            writes.push(env.DB.prepare(`UPDATE data_sources SET enabled = CASE WHEN source_key IN (${keys.map(() => "?").join(",")}) THEN 1 ELSE 0 END WHERE domain='news'`)
                .bind(...keys));
        }
    }
    if (writes.length) await env.DB.batch(writes);
    return json({ success: true });
}

// ============================================================
// 贵金属行情：实时价格 / 看板 / 统计图 / 详细数据
// 数据源（全部免密钥，已实测）：
//   sina hq    — hq.sinajs.cn 实时报价（沪金主连、沪银主连）
//   sina fx    — fx_susdcny 美元兑人民币
//   eastmoney  — push2his 历史K线（klt=5 分钟 / 101 日 / 102 周 / 103 月）
// ============================================================
// 贵金属品种池：当前内置沪金 / 沪银；稀有金属使用独立品种池。
const METAL_INSTRUMENTS = [
    { symbol: "AU0", sina: "nf_AU0", name: "沪金主连", short_name: "沪金", market: "上海", kind: "黄金", unit: "元/克", currency: "CNY", em: "113.AUM" },
    { symbol: "AG0", sina: "nf_AG0", name: "沪银主连", short_name: "沪银", market: "上海", kind: "白银", unit: "元/千克", currency: "CNY", em: "113.AGM" }
];
const OZ_TO_GRAM = 31.1034768;   // 金衡盎司 → 克
// 上海品种的展示顺序。
const METAL_ORDER = ["AU0", "AG0"];
const METAL_KINDS = ["黄金", "白银"];
const METAL_MARKETS = ["上海"];
// 默认只采集内置贵金属品种。
const METAL_DEFAULT_SYMBOLS = ["AU0", "AG0"];
const METAL_DEFAULT_MARKETS = ["上海"];
// 快照环比的默认基准品种（沪金主连）
const METAL_DEFAULT_BASE = "AU0";
const METAL_SERIES_COLORS = { AU0: "#ef4444", AG0: "#14b8a6" };

// —— 稀有 / 战略金属（独立品种池）——
//   与贵金属共用新浪行情（nf_ 内盘期货）与东方财富 K 线通道，
//   但使用独立品种清单：不进入「贵金属」页面的类别筛选，避免污染主板统计。
//   仅收录有公开连续报价的期货品种；稀土氧化物、锑、锗、镓等无稳定免费行情源，
//   不在此虚构价格，改由「三情景策略框架」中的观察点覆盖。
const RARE_INSTRUMENTS = [
    { symbol: "LC0", sina: "nf_LC0", name: "碳酸锂主连", short_name: "碳酸锂", market: "广期所", kind: "锂", unit: "元/吨", currency: "CNY", em: "225.lcm", chain: "锂电" },
    { symbol: "SI0", sina: "nf_SI0", name: "工业硅主连", short_name: "工业硅", market: "广期所", kind: "硅", unit: "元/吨", currency: "CNY", em: "225.sim", chain: "光伏/硅基" },
    { symbol: "NI0", sina: "nf_NI0", name: "沪镍主连", short_name: "沪镍", market: "上期所", kind: "镍", unit: "元/吨", currency: "CNY", em: "113.NIM", chain: "不锈钢/三元" },
    { symbol: "SN0", sina: "nf_SN0", name: "沪锡主连", short_name: "沪锡", market: "上期所", kind: "锡", unit: "元/吨", currency: "CNY", em: "113.SNM", chain: "焊料/电子" }
];
const RARE_SYMBOLS = RARE_INSTRUMENTS.map(i => i.symbol);
// 行情解析时统一按全品种查表（贵金属 + 稀有金属）
const ALL_INSTRUMENTS = METAL_INSTRUMENTS.concat(RARE_INSTRUMENTS);
function instrumentOf(symbol) { return ALL_INSTRUMENTS.find(i => i.symbol === String(symbol || "").toUpperCase()) || null; }

// —— 品种注册表（库驱动，可配置）——
//   内置品种在建库时写入 metal_instruments 作为种子，此后一切以库为准：
//   用户可以在「稀有金属 → 品种管理」里新增 / 编辑 / 停用 / 删除品种，改完立即生效。
//   缓存 15 秒，写入时主动失效，避免每个请求都查一次表。
let INST_CACHE = { at: 0, list: null, pending: null };
const INST_CACHE_TTL_MS = 15000;
function invalidateInstruments() { INST_CACHE = { at: 0, list: null, pending: null }; }

async function instrumentRows(env) {
    if (INST_CACHE.list && Date.now() - INST_CACHE.at < INST_CACHE_TTL_MS) return INST_CACHE.list;
    if (INST_CACHE.pending) return INST_CACHE.pending;
    INST_CACHE.pending = (async () => {
        let list = [];
        try {
            list = (await env.DB.prepare("SELECT * FROM metal_instruments ORDER BY sort_order, symbol").all()).results || [];
        } catch (e) { logWarn("instruments.load", e); }
        // 库不可用（表还没建好）时退回内置清单，保证行情页不至于整页空白
        if (!list.length) {
            list = ALL_INSTRUMENTS.map((i, idx) => ({
                ...i, chain: i.chain || "",
                scope: RARE_SYMBOLS.includes(i.symbol) ? "rare" : "metal",
                enabled: 1, sort_order: idx * 10, builtin: 1
            }));
        }
        INST_CACHE = { at: Date.now(), list, pending: null };
        return list;
    })();
    return INST_CACHE.pending;
}

// scope: "metal" | "rare" | ""（全部）；默认只返回启用的品种
async function listInstruments(env, scope, opts) {
    const rows = await instrumentRows(env);
    const includeDisabled = !!(opts && opts.includeDisabled);
    return rows.filter(r => (!scope || r.scope === scope) && (includeDisabled || Number(r.enabled) === 1));
}
async function rareInstruments(env, includeDisabled) {
    return listInstruments(env, "rare", { includeDisabled: !!includeDisabled });
}

// 采集参数默认值（依赖 METAL_INSTRUMENTS / NEWS_CHANNELS，故声明于此处）
// 采集参数分组：同一域内按用途分区，避免十几个输入框平铺
const ACQUIRE_GROUPS = {
    news: [
        { key: "scope", label: "抓取范围", icon: "fa-crosshairs", desc: "决定每次抓什么、抓多少" },
        { key: "filter", label: "过滤规则", icon: "fa-filter", desc: "决定哪些抓到的东西留下" },
        { key: "runtime", label: "运行控制", icon: "fa-gauge", desc: "超时与失败保护" },
        { key: "lifecycle", label: "留存策略", icon: "fa-broom", desc: "老数据什么时候清掉" }
    ],
    metal: [
        { key: "scope", label: "采集范围", icon: "fa-crosshairs", desc: "采集与展示哪些品种、市场" },
        { key: "threshold", label: "异动阈值", icon: "fa-bolt", desc: "多大涨跌幅算异动、算明显波动" },
        { key: "runtime", label: "运行控制", icon: "fa-gauge", desc: "失败保护" },
        { key: "lifecycle", label: "留存与展示", icon: "fa-broom", desc: "快照、轨迹保留量，动态时间线窗口" },
        { key: "model", label: "分析模型", icon: "fa-square-root-variable", desc: "稀有金属三情景的风险预算" }
    ]
};

// 消息域采集参数文案 / 默认值集中在这里，migrate() 与 ACQUIRE_OPTION_DEFAULTS 共用，避免两处漂移。
//   存量库是 INSERT OR IGNORE 种子，改默认值必须靠 migrate() 的显式 UPDATE 兜底。
const NEWS_CHANNELS_DEFAULT = "metal,macro,forex,policy,ai";
const LEGACY_NEWS_KEYWORDS = "碳酸锂,工业硅,沪镍,沪锡,稀土,铜,铝,黄金,白银,美联储,加息,降息,通胀,美元指数,汇率";
// 上一版（含人名 / 公司名的 21 词）：2026-11-12 二次调整后要把存量库再迁一次到泛化词
const LEGACY_NEWS_KEYWORDS_V2 = "英伟达,黄仁勋,GPU,显卡,AI芯片,算力,碳酸锂,工业硅,沪镍,沪锡,稀土,铜,铝,黄金,白银,美联储,加息,降息,通胀,美元指数,汇率";
const LEGACY_NEWS_MAX_KEYWORDS = "12";
const LEGACY_NEWS_BLACKLIST = "董事,监事,辞职,辞去,调研快报,股份有限公司";
const NEWS_BLACKLIST_DEFAULT = [
    "辞去副总裁", "辞去副总经理", "辞去董事", "辞去监事", "辞去总经理",
    "副总裁辞职", "董事辞职", "监事辞职", "高管辞职", "调研快报", "股份有限公司"
].join(",");
const NEWS_KEYWORDS_DESC = "用于全网搜索财经资讯的关键词，逗号分隔，最多保留 24 个；只放泛化主题词，不放具体人名 / 高管名 / 公司名。AI 相关的直接事件与产业链 / 能源 / 政策等间接消息，由固定词「人工智能 / AI / 算力 / GPU / 显卡 / AI芯片 / 半导体 / 数据中心 / 液冷 / 光模块」始终补充检索";
const NEWS_MAX_KEYWORDS_DESC = "参与全网检索的关键词个数，取「关键词」的前 N 个；泛化 AI 主题词始终额外检索，不受该上限影响";
const NEWS_RELEVANCE_DESC = "开启后只留四类：贵金属 / 稀有金属品种行情与供需、中国政策与官方数据、直接定价金价的海外变量（美联储 / 实际利率 / 美元指数 / 通胀就业 / 避险）、AI 相关消息（泛化主题词，直接事件与产业链 / 能源 / 政策等间接消息都保留，词表不含具体人名）。日本 / 欧洲央行讲话、他国股市会被挡掉；判定只看标题";
const NEWS_BLACKLIST_DESC = "标题或摘要命中任一词即整条丢弃，逗号分隔。同时作用于采集入库与资讯中心列表（历史存量也会被隐藏）。默认值只挡低价值个股人事公告格式噪音；不再用「董事 / 监事 / 辞职 / 辞去」泛词，避免误伤 AI / 显卡重大公司事件";

const NEWS_PER_SOURCE_DESC = "每个资讯数据源单次最多抓取的条数，固定为 30 条，不可更改（30 条回溯窗口已覆盖约 60 秒采集间隔）";

const ACQUIRE_OPTION_DEFAULTS = [
    // —— 消息数据 · 抓取范围 ——
    // name 一律用短标签（页面上的控件名，≤3 字），完整语义放在 description（悬停 title 用）
    { domain: "news", group: "scope", key: "news_keywords", name: "关键词", value: DEFAULT_NEWS_KEYWORDS.join(","), type: "textarea", description: NEWS_KEYWORDS_DESC, sort: 10 },
    { domain: "news", group: "scope", key: "news_channels", name: "频道", value: NEWS_CHANNELS_DEFAULT, type: "list", options: JSON.stringify(Object.keys(NEWS_CHANNELS).map(k => ({ value: k, label: NEWS_CHANNELS[k].label }))), description: "仅保留这些频道的资讯；留空表示不过滤", sort: 20 },
    // 只读参数：固定 30 条，采集页只展示、不允许更改（保存接口会跳过 readonly 项）
    { domain: "news", group: "scope", key: "news_per_source", name: "单源条数", value: String(NEWS_PER_SOURCE_FIXED), type: "number", unit: "条", meta: JSON.stringify({ min: NEWS_PER_SOURCE_FIXED, max: NEWS_PER_SOURCE_FIXED, step: 1, readonly: true }), readonly: true, description: NEWS_PER_SOURCE_DESC, sort: 30 },
    { domain: "news", group: "scope", key: "news_max_keywords", name: "词数", value: "24", type: "number", unit: "个", meta: JSON.stringify({ min: 1, max: 24, step: 1 }), description: NEWS_MAX_KEYWORDS_DESC, sort: 40 },
    // —— 消息数据 · 过滤规则 ——
    { domain: "news", group: "filter", key: "news_relevance_only", name: "仅相关", value: "1", type: "bool", description: NEWS_RELEVANCE_DESC, sort: 45 },
    { domain: "news", group: "filter", key: "news_blacklist", name: "屏蔽词", value: NEWS_BLACKLIST_DEFAULT, type: "textarea", description: NEWS_BLACKLIST_DESC, sort: 50 },
    { domain: "news", group: "filter", key: "news_min_title_len", name: "标题", value: "6", type: "number", unit: "字", meta: JSON.stringify({ min: 0, max: 40, step: 1 }), description: "标题字数少于该值的资讯直接丢弃（快讯里大量「午评」这类碎标题）；填 0 表示不过滤", sort: 60 },
    { domain: "news", group: "filter", key: "news_auto_star_metal", name: "收藏", value: "1", type: "bool", description: "命中贵金属频道的消息自动加星标，不会被保留期清理", sort: 70 },
    // —— 消息数据 · 运行控制 ——
    { domain: "news", group: "runtime", key: "news_timeout_sec", name: "超时", value: "9", type: "number", unit: "秒", meta: JSON.stringify({ min: 3, max: 30, step: 1 }), description: "每个数据源单次 HTTP 请求的最长等待时间；网络慢时调大，避免整批抓取超时", sort: 80 },
    { domain: "news", group: "runtime", key: "news_fail_limit", name: "失败", value: "5", type: "number", unit: "次", meta: JSON.stringify({ min: 1, max: 50, step: 1 }), description: "任务连续失败达到该次数后自动停用，并发一条通知；修复后到「定时任务」重新启用即可清零", sort: 90 },
    { domain: "news", group: "runtime", key: "news_live_sec", name: "刷新", value: "10", type: "number", unit: "秒", meta: JSON.stringify({ min: 5, max: 300, step: 5 }), description: "资讯列表自动刷新与回源抓取的间隔，默认 10 秒；页面轮询最密 30 秒（统计聚合缓存 3 分钟，再快也是重复读缓存；标签页在后台时暂停轮询）", sort: 92 },
    { domain: "news", group: "runtime", key: "news_crawl_sec", name: "抓取", value: "60", type: "number", unit: "秒", meta: JSON.stringify({ min: 10, max: 3600, step: 10 }), description: "服务端多久真正回源抓取一次资讯；过短容易被数据源限流，建议 ≥30 秒（定时任务仍按分钟兜底）", sort: 94 },
    // —— 消息数据 · 重点消息 ——
    { domain: "news", group: "key", key: "news_key_notify_max", name: "外部推送上限", value: "5", type: "number", unit: "条", meta: JSON.stringify({ min: 1, max: 20, step: 1 }), description: "每次采集完成后，最多把多少条「新采集的重点消息」推送到外部通道（企业微信 / 钉钉 / 飞书机器人）；写入通知中心不受此限制 —— 全部重点消息都会进通知中心", sort: 95 },
    { domain: "news", group: "key", key: "news_key_notify_enabled", name: "重点推送", value: "1", type: "bool", description: "开启后：库内全部重点消息都会写入通知中心并点亮（未读），已读过的不会重复点亮；同时把本次新采集的重点消息推送到已配置的外部通道", sort: 96 },
    // —— 消息数据 · 留存策略 ——
    { domain: "news", group: "lifecycle", key: "news_retention_days", name: "消息保留", value: "90", type: "number", unit: "天", meta: JSON.stringify({ min: 1, max: 3650, step: 1 }), description: "默认数据保留时间：超过该天数的旧消息在抓取时自动清理（已加星标的不受影响）", sort: 100 },
    { domain: "news", group: "lifecycle", key: "fetch_log_retention_days", name: "日志保留", value: "30", type: "number", unit: "天", meta: JSON.stringify({ min: 1, max: 3650, step: 1 }), description: "采集日志保留天数：超过该天数的日志在每次采集后自动清理；也可到「数据保留」面板手动立即清理", sort: 101 },
    // —— 贵金属数据 · 采集范围 ——
    { domain: "metal", group: "scope", key: "metal_symbols", name: "品种", value: METAL_DEFAULT_SYMBOLS.join(","), type: "list", options: JSON.stringify(METAL_INSTRUMENTS.filter(i => i.symbol !== "XPD").map(i => ({ value: i.symbol, label: i.short_name + "（" + i.market + "）" }))), description: "需要采集并入库的贵金属品种；默认采集沪金 / 沪银，留空表示全部采集", sort: 10 },
    { domain: "metal", group: "scope", key: "metal_markets", name: "市场", value: METAL_DEFAULT_MARKETS.join(","), type: "list", options: JSON.stringify(METAL_MARKETS.map(m => ({ value: m, label: m }))), description: "贵金属页面展示的市场；当前内置贵金属为上海市场，留空表示全部展示", sort: 20 },
    { domain: "metal", group: "scope", key: "metal_kinds", name: "类别", value: "黄金,白银", type: "list", options: JSON.stringify(["黄金", "白银"].map(k => ({ value: k, label: k }))), description: "贵金属页面展示的金属类别；留空表示全部展示", sort: 30 },
    // —— 贵金属数据 · 异动阈值 ——
    { domain: "metal", group: "threshold", key: "metal_snapshot_base", name: "基准", value: METAL_DEFAULT_BASE, type: "select", options: JSON.stringify(METAL_INSTRUMENTS.filter(i => i.symbol !== "XPD").map(i => ({ value: i.symbol, label: i.short_name }))), description: "金价快照用于「环比上次采集」的基准品种；默认沪金主连", sort: 40 },
    { domain: "metal", group: "threshold", key: "metal_snapshot_alert", name: "异动", value: "0.8", type: "number", unit: "%", meta: JSON.stringify({ min: 0.1, max: 5, step: 0.1 }), description: "环比上次采集涨跌幅超过该值判定为大幅异动（行情快照等级：大幅异动）", sort: 50 },
    { domain: "metal", group: "threshold", key: "metal_snapshot_surge", name: "波动", value: "0.25", type: "number", unit: "%", meta: JSON.stringify({ min: 0.05, max: 3, step: 0.05 }), description: "环比上次采集涨跌幅超过该值判定为明显波动（行情快照等级：明显波动）；需小于「异动」阈值", sort: 60 },
    // —— 贵金属数据 · 运行控制 ——
    { domain: "metal", group: "runtime", key: "metal_fail_limit", name: "失败", value: "5", type: "number", unit: "次", meta: JSON.stringify({ min: 1, max: 50, step: 1 }), description: "行情任务连续失败达到该次数后自动停用，并发一条通知，避免对已失效的接口持续重试", sort: 70 },
    { domain: "metal", group: "runtime", key: "metal_live_sec", name: "刷新", value: "10", type: "number", unit: "秒", meta: JSON.stringify({ min: 5, max: 120, step: 5 }), description: "行情页轮询与服务端重新回源拉取行情的间隔，默认 10 秒；调小更实时，但会更频繁请求新浪行情接口。投资总览页最密 30 秒（聚合统计缓存 3 分钟）", sort: 75 },
    // —— 贵金属数据 · 留存与展示 ——
    { domain: "metal", group: "lifecycle", key: "metal_snapshot_keep", name: "快照条数", value: "2000", type: "number", unit: "条", meta: JSON.stringify({ min: 100, max: 20000, step: 100 }), description: "金价快照最多保留的条数；与快照天数哪个先到就按哪个清理", sort: 80 },
    { domain: "metal", group: "lifecycle", key: "metal_snapshot_days", name: "快照天数", value: "90", type: "number", unit: "天", meta: JSON.stringify({ min: 1, max: 3650, step: 1 }), description: "金价快照保留天数：超过该天数的快照自动清理；与快照条数哪个先到就按哪个清理", sort: 81 },
    { domain: "metal", group: "lifecycle", key: "metal_history_keep", name: "轨迹条数", value: "500", type: "number", unit: "条", meta: JSON.stringify({ min: 50, max: 5000, step: 50 }), description: "每个品种本地价格轨迹保留的条数；与轨迹天数哪个先到就按哪个清理", sort: 90 },
    { domain: "metal", group: "lifecycle", key: "metal_history_days", name: "轨迹天数", value: "30", type: "number", unit: "天", meta: JSON.stringify({ min: 1, max: 3650, step: 1 }), description: "价格轨迹保留天数：超过该天数的轨迹自动清理；与轨迹条数哪个先到就按哪个清理", sort: 91 },
    // —— 贵金属数据 · 分析模型 ——
    { domain: "metal", group: "model", key: "rare_risk_budget", name: "预算", value: "2", type: "number", unit: "%", meta: JSON.stringify({ min: 0.5, max: 10, step: 0.5 }), description: "三情景推演中折算「仓位上限」：上限 = 预算 ÷ 年化波动率，结果夹在 1%~25%", sort: 110 }
];
function numOf(v) { const n = parseFloat(v); return Number.isFinite(n) ? n : 0; }
function metalNum(v, digits) {
    const n = Number(v);
    if (!Number.isFinite(n) || n === 0) return "—";
    const d = digits == null ? (Math.abs(n) >= 100 ? 2 : Math.abs(n) >= 1 ? 3 : 4) : digits;
    return n.toLocaleString("zh-CN", { minimumFractionDigits: d, maximumFractionDigits: d });
}
function chgSignText(v) { const n = Number(v) || 0; return n > 0 ? "+" : ""; }
function decodeGbk(buf) {
    try { return new TextDecoder("gbk").decode(buf); }
    catch { return new TextDecoder("utf-8").decode(buf); }
}
function ymd(daysAgo) {
    const d = new Date(Date.now() + 8 * 3600 * 1000 - daysAgo * 86400000);
    return d.toISOString().slice(0, 10).replace(/-/g, "");
}
// 北京时间某天的日期串（带连字符 "YYYY-MM-DD"），offsetDays 正数=未来、负数=过去
function beijingDay(offsetDays) {
    const d = new Date(Date.now() + 8 * 3600 * 1000 + (offsetDays || 0) * 86400000);
    return d.toISOString().slice(0, 10);
}

// —— 拉取新浪实时报价（一次请求取全部品种 + 汇率）——
// symbols: 需要采集的品种 code 列表；为空表示 pool 内全部
// pool:    品种池（来自注册表，含 sina/name/unit 等元数据）；不传则用内置全量清单
async function fetchSinaMetalQuotes(symbols, pool) {
    const all = (Array.isArray(pool) && pool.length) ? pool : ALL_INSTRUMENTS;
    const instruments = (symbols && symbols.length)
        ? all.filter(i => symbols.includes(i.symbol))
        : all;
    if (!instruments.length) throw new Error("未配置任何采集品种");
    const url = "https://hq.sinajs.cn/list=" + instruments.map(i => i.sina).join(",") + ",fx_susdcny";
    const r = await fetchWithTimeout(url, { headers: { "Referer": "https://finance.sina.com.cn", "User-Agent": NEWS_UA } }, 9000);
    if (!r.ok) throw new Error("行情接口 HTTP " + r.status);
    const text = decodeGbk(await r.arrayBuffer());
    const out = {};
    for (const line of text.split("\n")) {
        const m = line.match(/var\s+hq_str_([A-Za-z0-9_]+)\s*=\s*"([^"]*)"/);
        if (!m) continue;
        const key = m[1], f = m[2].split(",");
        if (key === "fx_susdcny") { out.__fx = numOf(f[1]); continue; }
        const inst = instruments.find(i => i.sina === key);
        if (!inst || f.length < 6) continue;
        const fam = key.slice(0, 2);
        let price = 0, prev = 0, open = 0, high = 0, low = 0, bid = 0, ask = 0, vol = 0, oi = 0, qtime = "", qdate = "";
        if (fam === "hf") {
            // 0现价 1昨收 2买价 3卖价 4最高 5最低 6时间 7昨收 8开盘 12日期 13名称
            price = numOf(f[0]); prev = numOf(f[7]) || numOf(f[1]); open = numOf(f[8]);
            high = numOf(f[4]); low = numOf(f[5]); bid = numOf(f[2]); ask = numOf(f[3]);
            qtime = f[6] || ""; qdate = f[12] || "";
        } else if (fam === "nf") {
            // 0名称 2开盘 3最高 4最低 5现价 6买价 7卖价 8最新价 9结算价 10昨结算(涨跌基准) 13持仓量 14成交量 17日期
            price = numOf(f[8]) || numOf(f[5]); prev = numOf(f[10]);
            open = numOf(f[2]); high = numOf(f[3]); low = numOf(f[4]);
            bid = numOf(f[6]); ask = numOf(f[7]);
            oi = numOf(f[13]); vol = numOf(f[14]); qdate = f[17] || "";
        } else {
            // gds_ 上金所延期：0现价 2买价 3卖价 4最高 5最低 6时间 7昨收 8开盘 9成交量 12日期
            price = numOf(f[0]); prev = numOf(f[7]); open = numOf(f[8]);
            high = numOf(f[4]); low = numOf(f[5]); bid = numOf(f[2]); ask = numOf(f[3]);
            vol = numOf(f[9]); qtime = f[6] || ""; qdate = f[12] || "";
        }
        if (!(price > 0)) continue;
        const change = prev > 0 ? price - prev : 0;
        const change_pct = prev > 0 ? (change / prev) * 100 : 0;
        const amplitude = prev > 0 && high > 0 && low > 0 ? ((high - low) / prev) * 100 : 0;
        out[inst.symbol] = {
            symbol: inst.symbol, name: inst.name, short_name: inst.short_name, market: inst.market, kind: inst.kind,
            price, prev_close: prev, open, high, low, bid, ask, volume: vol, open_interest: oi,
            change, change_pct, amplitude, unit: inst.unit, currency: inst.currency,
            source: "sina", quote_date: qdate, quote_time: qtime
        };
    }
    return out;
}

// —— 拉取历史K线（东方财富，数值已缩放）——
async function fetchMetalKline(emSecid, klt, beg) {
    if (!emSecid) return [];
    try {
        const url = `https://push2his.eastmoney.com/api/qt/stock/kline/get?secid=${emSecid}&klt=${klt}&fqt=0&beg=${beg}&end=20500101&fields1=f1,f2,f3&fields2=f51,f52,f53,f54,f55,f56,f57,f58`;
        const r = await fetchWithTimeout(url, { headers: { "User-Agent": NEWS_UA } }, 10000);
        if (!r.ok) return [];
        const data = await r.json();
        const list = (data && data.data && data.data.klines) || [];
        const rows = [];
        let prevClose = 0;
        for (const line of list) {
            const f = line.split(",");
            const o = numOf(f[1]), c = numOf(f[2]), h = numOf(f[3]), l = numOf(f[4]);
            if (!(c > 0)) { prevClose = c; continue; }
            rows.push({
                t: f[0], o, c, h, l,
                v: numOf(f[5]), amount: numOf(f[6]),
                pct: prevClose > 0 ? ((c - prevClose) / prevClose) * 100 : 0
            });
            prevClose = c;
        }
        return rows;
    } catch { return []; }
}

// ============================================================
// 技术指标：全部在服务端一次算好下发，前端只负责画
//   - 序列长度与 kline 严格对齐，无效位置为 null（避免前端错位）
//   - 公式口径按国内看盘软件常用参数：
//     MA 简单均线；BOLL(20,2) 总体标准差；
//     MACD(12,26,9) 中 HIST = 2*(DIF-DEA)；
//     RSI / KDJ 用 SMA(X,N,1) 平滑（等价于 alpha=1/N 的 EMA）
// ============================================================
function round2(v) { return v == null || !Number.isFinite(v) ? null : Math.round(v * 100) / 100; }

function smaSeries(values, n) {
    const out = new Array(values.length).fill(null);
    if (n <= 0) return out;
    let sum = 0, cnt = 0;
    for (let i = 0; i < values.length; i++) {
        const v = values[i];
        if (v == null) { continue; }
        sum += v; cnt++;
        if (cnt > n) { sum -= values[i - n]; cnt = n; }
        if (cnt === n) out[i] = sum / n;
        else if (i + 1 >= n) {
            // 遇到 null 打断窗口时重新累积
            sum = 0; cnt = 0;
        }
    }
    return out;
}

function emaSeries(values, n) {
    const out = new Array(values.length).fill(null);
    const alpha = 2 / (n + 1);
    let prev = null;
    for (let i = 0; i < values.length; i++) {
        const v = values[i];
        if (v == null) continue;
        prev = prev == null ? v : alpha * v + (1 - alpha) * prev;
        out[i] = prev;
    }
    return out;
}

// 中国式 SMA(X,N,M)：Y = (M*X + (N-M)*Y') / N
function cnsSmaSeries(values, n, m = 1) {
    const out = new Array(values.length).fill(null);
    let prev = null;
    for (let i = 0; i < values.length; i++) {
        const v = values[i];
        if (v == null) continue;
        prev = prev == null ? v : (m * v + (n - m) * prev) / n;
        out[i] = prev;
    }
    return out;
}

function calcIndicators(rows) {
    const closes = rows.map(r => Number(r.c) || null);
    const highs = rows.map(r => Number(r.h) || null);
    const lows = rows.map(r => Number(r.l) || null);
    const len = rows.length;
    const empty = { ma: {}, boll: {}, macd: {}, rsi: {}, kdj: {} };
    if (len < 2) return empty;

    // —— MA ——
    const ma = {};
    for (const n of [5, 10, 20, 60]) ma["ma" + n] = smaSeries(closes, n).map(round2);

    // —— BOLL(20, 2) ——
    const boll = { mid: [], upper: [], lower: [] };
    const N = 20;
    for (let i = 0; i < len; i++) {
        if (i + 1 < N) { boll.mid.push(null); boll.upper.push(null); boll.lower.push(null); continue; }
        const win = closes.slice(i + 1 - N, i + 1);
        const mean = win.reduce((a, b) => a + b, 0) / N;
        const variance = win.reduce((a, b) => a + (b - mean) * (b - mean), 0) / N;
        const sd = Math.sqrt(variance);
        boll.mid.push(round2(mean));
        boll.upper.push(round2(mean + 2 * sd));
        boll.lower.push(round2(mean - 2 * sd));
    }

    // —— MACD(12, 26, 9) ——
    const ema12 = emaSeries(closes, 12);
    const ema26 = emaSeries(closes, 26);
    const dif = closes.map((_, i) => (ema12[i] == null || ema26[i] == null) ? null : ema12[i] - ema26[i]);
    const dea = emaSeries(dif, 9);
    const macd = { dif: [], dea: [], hist: [] };
    for (let i = 0; i < len; i++) {
        macd.dif.push(round2(dif[i]));
        macd.dea.push(round2(dea[i]));
        macd.hist.push(dif[i] == null || dea[i] == null ? null : round2(2 * (dif[i] - dea[i])));
    }

    // —— RSI(6 / 12 / 24)，SMA(X,N,1) 平滑 ——
    const gains = [null], losses = [null];
    for (let i = 1; i < len; i++) {
        const d = closes[i] - closes[i - 1];
        gains.push(d > 0 ? d : 0);
        losses.push(d < 0 ? -d : 0);
    }
    const rsi = {};
    for (const n of [6, 12, 24]) {
        const up = cnsSmaSeries(gains, n, 1);
        const dn = cnsSmaSeries(losses, n, 1);
        rsi["rsi" + n] = up.map((u, i) => {
            const d = dn[i];
            if (u == null || d == null) return null;
            if (u + d === 0) return 50;
            return round2((u / (u + d)) * 100);
        });
    }

    // —— KDJ(9, 3, 3) ——
    const rsv = [];
    for (let i = 0; i < len; i++) {
        if (i + 1 < 9) { rsv.push(null); continue; }
        const hh = Math.max(...highs.slice(i + 1 - 9, i + 1));
        const ll = Math.min(...lows.slice(i + 1 - 9, i + 1));
        rsv.push(hh === ll ? 50 : ((closes[i] - ll) / (hh - ll)) * 100);
    }
    const kSer = cnsSmaSeries(rsv, 3, 1);
    const dSer = cnsSmaSeries(kSer, 3, 1);
    const kdj = { k: [], d: [], j: [] };
    for (let i = 0; i < len; i++) {
        kdj.k.push(round2(kSer[i]));
        kdj.d.push(round2(dSer[i]));
        kdj.j.push(kSer[i] == null || dSer[i] == null ? null : round2(3 * kSer[i] - 2 * dSer[i]));
    }

    return { ma, boll, macd, rsi, kdj };
}

// 最新一根的指标快照 + 一句话解读（供详情页顶部展示）
function indicatorSummary(rows, ind) {
    const last = rows.length - 1;
    if (last < 0) return null;
    const pick = (arr) => (arr && arr[last] != null ? arr[last] : null);
    const c = Number(rows[last].c) || 0;
    const ma5 = pick(ind.ma.ma5), ma10 = pick(ind.ma.ma10), ma20 = pick(ind.ma.ma20), ma60 = pick(ind.ma.ma60);
    const dif = pick(ind.macd.dif), dea = pick(ind.macd.dea), hist = pick(ind.macd.hist);
    const rsi6 = pick(ind.rsi.rsi6), rsi12 = pick(ind.rsi.rsi12);
    const k = pick(ind.kdj.k), d = pick(ind.kdj.d), j = pick(ind.kdj.j);
    const bu = pick(ind.boll.upper), bl = pick(ind.boll.lower), bm = pick(ind.boll.mid);

    // 均线排列
    let maTrend = "均线数据不足";
    const mas = [ma5, ma10, ma20, ma60].filter(v => v != null);
    if (mas.length >= 3) {
        if (ma5 > ma10 && ma10 > ma20 && (ma60 == null || ma20 > ma60)) maTrend = "多头排列";
        else if (ma5 < ma10 && ma10 < ma20 && (ma60 == null || ma20 < ma60)) maTrend = "空头排列";
        else maTrend = "均线纠缠";
    }
    // MACD 状态
    let macdState = "—";
    if (dif != null && dea != null) {
        if (dif > dea && dif > 0) macdState = "零轴上金叉区";
        else if (dif > dea) macdState = "零轴下金叉区";
        else if (dif > 0) macdState = "零轴上死叉区";
        else macdState = "零轴下死叉区";
    }
    // RSI 区间
    let rsiState = "—";
    if (rsi12 != null) {
        if (rsi12 >= 80) rsiState = "超买";
        else if (rsi12 >= 60) rsiState = "偏强";
        else if (rsi12 > 40) rsiState = "中性";
        else if (rsi12 > 20) rsiState = "偏弱";
        else rsiState = "超卖";
    }
    // 布林位置
    let bollPos = "—";
    if (bu != null && bl != null && bu > bl) {
        const pos = (c - bl) / (bu - bl);
        if (pos >= 1) bollPos = "突破上轨";
        else if (pos >= 0.8) bollPos = "贴近上轨";
        else if (pos > 0.2) bollPos = "中轨附近";
        else if (pos > 0) bollPos = "贴近下轨";
        else bollPos = "跌破下轨";
    }

    // 综合倾向（只做描述，不给交易建议）
    let score = 0;
    if (maTrend === "多头排列") score += 2; else if (maTrend === "空头排列") score -= 2;
    if (macdState.includes("金叉")) score += 1; else if (macdState.includes("死叉")) score -= 1;
    if (rsiState === "超买") score -= 1; else if (rsiState === "超卖") score += 1;
    else if (rsiState === "偏强") score += 1; else if (rsiState === "偏弱") score -= 1;
    if (bollPos === "突破上轨") score += 1; else if (bollPos === "跌破下轨") score -= 1;
    const bias = score >= 2 ? "技术面偏强" : score <= -2 ? "技术面偏弱" : "技术面中性";

    return {
        date: rows[last].t,
        close: c,
        ma: { ma5, ma10, ma20, ma60 },
        boll: { upper: bu, mid: bm, lower: bl },
        macd: { dif, dea, hist },
        rsi: { rsi6, rsi12 },
        kdj: { k, d, j },
        tags: { maTrend, macdState, rsiState, bollPos },
        bias,
        score
    };
}

// —— 抓取并写入行情快照 ——
// —— 行情落库（贵金属与稀有金属共用；按 symbol UPSERT）——
const QUOTE_UPSERT_SQL = `INSERT INTO metal_quotes(symbol,name,short_name,market,kind,price,prev_close,open,high,low,bid,ask,volume,open_interest,change,change_pct,amplitude,unit,currency,source,quote_date,quote_time,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(symbol) DO UPDATE SET
        name=excluded.name, short_name=excluded.short_name, market=excluded.market, kind=excluded.kind,
        price=excluded.price, prev_close=excluded.prev_close, open=excluded.open, high=excluded.high, low=excluded.low,
        bid=excluded.bid, ask=excluded.ask, volume=excluded.volume, open_interest=excluded.open_interest,
        change=excluded.change, change_pct=excluded.change_pct, amplitude=excluded.amplitude,
        unit=excluded.unit, currency=excluded.currency, source=excluded.source,
        quote_date=excluded.quote_date, quote_time=excluded.quote_time, updated_at=CURRENT_TIMESTAMP`;
async function upsertQuotes(env, quotes) {
    if (!quotes.length) return 0;
    const upd = env.DB.prepare(QUOTE_UPSERT_SQL);
    await env.DB.batch(quotes.map(q => upd.bind(q.symbol, q.name, q.short_name, q.market, q.kind, q.price, q.prev_close,
        q.open, q.high, q.low, q.bid, q.ask, q.volume, q.open_interest, q.change, q.change_pct, q.amplitude,
        q.unit, q.currency, q.source, q.quote_date, q.quote_time)));
    return quotes.length;
}

// 贵金属与稀有金属共用本地价格轨迹和留存策略。
async function recordQuoteHistory(env, quotes) {
    if (!quotes.length) return 0;
    // 逐品种取「最后一条价格」：走 idx_metal_history_sym，每个品种只读 1 行。
    //   旧写法 `id IN (SELECT MAX(id) ... GROUP BY symbol)` 每次都要扫完整张轨迹表
    //   （实测 52 次 × 1,386 行 ≈ 7.2 万行/天），换成 batch 里一人一条。
    const lastMap = {};
    try {
        const res = await env.DB.batch(quotes.map(q => env.DB.prepare(
            "SELECT price FROM metal_history WHERE symbol=? ORDER BY id DESC LIMIT 1"
        ).bind(q.symbol)));
        (res || []).forEach((r, i) => {
            const row = r && r.results && r.results[0];
            if (row) lastMap[quotes[i].symbol] = Number(row.price);
        });
    } catch (e) { logWarn("metal.history.last", e); }
    const changed = quotes.filter(q => lastMap[q.symbol] !== Number(q.price));
    if (changed.length) {
        const his = env.DB.prepare("INSERT INTO metal_history(symbol,price,quote_time,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)");
        await env.DB.batch(changed.map(q => his.bind(q.symbol, q.price, q.quote_time)));
    }
    // 条数裁剪：按品种取「第 keep 条」的主键做边界，走 idx_metal_history_sym，只读 keep 行。
    //   旧写法用 ROW_NUMBER() 窗口函数分区排序，每次刷新都扫全表
    //   （实测 94 次 × 4,109 行 ≈ 38.6 万行/天，是读额度的第二大消耗）。
    const keep = await acquireNum(env, "metal", "metal_history_keep", 500, 50, 5000);
    try {
        await env.DB.batch(quotes.map(q => env.DB.prepare(
            "DELETE FROM metal_history WHERE symbol=? AND id < "
            + "(SELECT id FROM metal_history WHERE symbol=? ORDER BY id DESC LIMIT 1 OFFSET ?)"
        ).bind(q.symbol, q.symbol, Math.max(0, Math.floor(keep) - 1))));
    } catch (e) { logWarn("metal.history.prune", e); }
    // 按天清理（created_at 没有索引，是整表扫描）已挪到 pruneRetentionIfDue，每天只跑一次，
    //   不再跟着每次行情刷新扫一遍。
    return changed.length;
}

async function refreshMetalQuotes(env, preFetched) {
    // 品种池来自注册表（贵金属域）：内置 10 个品种，停用的不会出现在这里
    const pool = await listInstruments(env, "metal");
    const symbols = await acquireList(env, "metal", "metal_symbols");
    const raw = preFetched || await fetchSinaMetalQuotes(symbols, pool);
    const fx = Number(raw.__fx) || 0;
    const quotes = Object.keys(raw).filter(k => k !== "__fx").map(k => raw[k]);
    if (!quotes.length) throw new Error("行情接口未返回有效数据");
    quotes.sort((a, b) => METAL_ORDER.indexOf(a.symbol) - METAL_ORDER.indexOf(b.symbol));

    await upsertQuotes(env, quotes);

    // 本地历史轨迹：仅在价格变化时追加，统一贵金属与稀有金属的留存策略
    try { await recordQuoteHistory(env, quotes); }
    catch (e) { logWarn("metal.history", e); }

    if (fx > 0) {
        await env.DB.prepare("INSERT INTO settings(key,value) VALUES('metal_usdcny',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(String(fx)).run();
    }
    const stamp = nowBeijing();
    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('last_metal_refresh',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(stamp).run();
    // 行情落库后立即评估价格预警：命中则写站内通知并推送 Webhook
    const alertRes = await evaluateAlerts(env, quotes);
    return { success: true, updated: quotes.length, usdcny: fx, refreshed_at: stamp, alerts_triggered: alertRes.triggered || 0 };
}

// —— 派生指标（统计图 / 详细数据共用）——
function metalDerived(quotes, usdcny) {
    const by = {};
    quotes.forEach(q => { by[q.symbol] = q; });
    const ratio = (a, b) => (by[a] && by[b] && by[b].price > 0) ? by[a].price / by[b].price : null;
    const ldnGoldG = (by.XAU && usdcny > 0) ? by.XAU.price * usdcny / OZ_TO_GRAM : null;
    const ldnSilverG = (by.XAG && usdcny > 0) ? by.XAG.price * usdcny / OZ_TO_GRAM : null;
    const shGold = by.AU0 ? by.AU0.price : (by.AUTD ? by.AUTD.price : null);
    const shSilverG = by.AG0 ? by.AG0.price / 1000 : (by.AGTD ? by.AGTD.price / 1000 : null);
    // 金银比：有国际报价时优先采用国际口径，否则使用上海口径（沪金 / 沪银，换算为元/克）
    const intlRatio = ratio("XAU", "XAG");
    const shRatio = (shGold && shSilverG && shSilverG > 0) ? shGold / shSilverG : null;
    return {
        gold_silver_ratio: intlRatio || shRatio,
        gold_silver_ratio_source: intlRatio ? "intl" : (shRatio ? "sh" : ""),
        platinum_gold_ratio: ratio("XPT", "XAU"),
        palladium_gold_ratio: ratio("XPD", "XAU"),
        silver_gold_ratio: ratio("XAG", "XAU"),
        usdcny: usdcny || 0,
        london_gold_cny_per_gram: ldnGoldG,
        london_silver_cny_per_gram: ldnSilverG,
        shanghai_gold_premium: (ldnGoldG && shGold) ? (shGold - ldnGoldG) / ldnGoldG * 100 : null,
        shanghai_silver_premium: (ldnSilverG && shSilverG) ? (shSilverG - ldnSilverG) / ldnSilverG * 100 : null
    };
}
function metalStats(quotes) {
    const up = quotes.filter(q => q.change > 0).length;
    const down = quotes.filter(q => q.change < 0).length;
    const avg = quotes.length ? quotes.reduce((s, q) => s + q.change_pct, 0) / quotes.length : 0;
    const pick = (cmp) => quotes.reduce((m, q) => (!m || cmp(q, m)) ? q : m, null);
    return {
        count: quotes.length, up, down, flat: quotes.length - up - down,
        avg_change_pct: avg,
        best: pick((a, b) => a.change_pct > b.change_pct),
        worst: pick((a, b) => a.change_pct < b.change_pct),
        max_amplitude: pick((a, b) => a.amplitude > b.amplitude)
    };
}

async function getMetalBoard(env) { return json(await metalBoardData(env)); }

// ============================================================
// 实时刷新：页面轮询驱动 + 服务端按间隔回源
//   前端每 live_sec 秒请求一次只读接口，服务端比对「上次成功抓取时间」，
//   到点才真正回源。这样多个页面同时打开也不会把外部接口打爆，
//   而单个页面看到的又接近实时（默认 10 秒一档）。
// ============================================================
let METAL_REFRESH_INFLIGHT = null;
let NEWS_REFRESH_INFLIGHT = null;
let METAL_SNAP_INFLIGHT = null;

// 金价快照到期补采：按 fetch_tasks 中 metal_snapshot 的间隔（默认 30 分钟，可配 5～86400 秒），
// 页面任一次访问行情板时顺带检查是否到期，到期就补一次采集并写库。
//   作用：本地调试没有 cron 定时器、线上 cron 唤醒间隙，都能保证快照及时补采；
//   runFetchTask 内部会写采集日志并更新 last_run_at，cron 侧据其判断到期，不会重复采。
async function captureMetalSnapshotIfDue(env, cfg) {
    try {
        const tasks = await listFetchTasks(env);
        const task = tasks.find(t => t.task_key === "metal_snapshot");
        if (!task || !task.enabled || Number(task.run_at_hour) >= 0) return false;
        const intervalMs = taskIntervalSec(task) * 1000;
        const last = epochOf((cfg && cfg.last_metal_snapshot) || task.last_run_at || "");
        if (last && Date.now() - last < intervalMs) return false;
        if (METAL_SNAP_INFLIGHT) { try { await METAL_SNAP_INFLIGHT; } catch (e) { } return false; }
        METAL_SNAP_INFLIGHT = runFetchTask(env, "metal_snapshot", "cron");
        try { await METAL_SNAP_INFLIGHT; return true; }
        catch (e) { logWarn("metal.snapIfDue", e); return false; }
        finally { METAL_SNAP_INFLIGHT = null; }
    } catch (e) { logWarn("metal.snapIfDue", e); return false;
    }
}

async function liveIntervalSec(env, domain, key, fallback, min, max) {
    const n = parseInt(await acquireOption(env, domain, key, String(fallback)), 10);
    return Math.min(max, Math.max(min, Number.isFinite(n) ? n : fallback));
}

// —— 页面轮询补采的统一入口 ——
//   与定时任务共用同一套数据源/任务门禁，不更新 fetch_tasks 的调度状态，
//   避免 10 秒级轮询把定时任务的执行次数与下次执行时间冲乱。
//
//   —— 关于「只在失败时写日志」——
//   旧实现在成功路径也写一条 fetch_logs（trigger_type=page）。页面开着就按
//   metal_live_sec（默认 10 秒）轮询，单页单日 ≈ 8600 行；多开标签页 / 多台设备
//   成倍放大，直接打爆 D1 免费版「每天 10 万行写入」的账户级配额，导致所有写入失败。
//   轮询成功是「预期内的常态」，没有留痕价值；只在失败时记一行，既保住排障能力，
//   又让页面轮询的成功路径变成纯读，不再消耗写入配额。
async function runLiveRefresh(env, logKey, fn) {
    const startedAt = beijingStamp(Date.now());
    const t0 = Date.now();
    try {
        await fn();
        return true;
    } catch (e) {
        await writeFetchLog(env, {
            task_key: logKey, trigger_type: "page", started_at: startedAt,
            duration_ms: Date.now() - t0, status: "failed", message: String(e && e.message || e)
        });
        logWarn("live.refresh", e);
        return false;
    }
}

async function refreshMetalQuotesIfStale(env, cfg, liveSec) {
    const sec = liveSec || await liveIntervalSec(env, "metal", "metal_live_sec", 10, 5, 120);
    const last = epochOf((cfg && cfg.last_metal_refresh) || "");
    if (last && Date.now() - last < sec * 1000) return false;
    if (!await taskEnabled(env, "metal_quote") || !await sourceEnabled(env, "sina_quote")) return false;
    // 已有一次刷新在跑：等同一次结果，不重复打接口
    if (METAL_REFRESH_INFLIGHT) { try { await METAL_REFRESH_INFLIGHT; } catch (e) { } return false; }
    METAL_REFRESH_INFLIGHT = runLiveRefresh(env, METAL_LIVE_LOG_KEY, () => refreshMetalQuotes(env));
    try { return await METAL_REFRESH_INFLIGHT; }
    catch (e) { logWarn("metal.liveRefresh", e); return false; }
    finally { METAL_REFRESH_INFLIGHT = null; }
}

async function refreshNewsIfStale(env, cfg) {
    const sec = await liveIntervalSec(env, "news", "news_crawl_sec", 60, 10, 3600);
    const last = epochOf((cfg && cfg.last_news_refresh) || "");
    if (last && Date.now() - last < sec * 1000) return false;
    if (!await taskEnabled(env, "news_crawl")) return false;
    if (!(await enabledNewsSourceIds(env)).length) return false;
    if (NEWS_REFRESH_INFLIGHT) { try { await NEWS_REFRESH_INFLIGHT; } catch (e) { } return false; }
    NEWS_REFRESH_INFLIGHT = runLiveRefresh(env, NEWS_LIVE_LOG_KEY, () => crawlNews(env, {}));
    try { return await NEWS_REFRESH_INFLIGHT; }
    catch (e) { logWarn("news.liveRefresh", e); return false; }
    finally { NEWS_REFRESH_INFLIGHT = null; }
}

// 行情板数据（/api/metals 与 /api/dashboard 共用，避免两处过滤口径漂移）
async function metalBoardData(env) {
    const cfg0 = await settingsMap(env);
    const liveSec = await liveIntervalSec(env, "metal", "metal_live_sec", 10, 5, 120);
    // 到点回源：首次访问无数据时（last_metal_refresh 为空）同样会触发一次
    await refreshMetalQuotesIfStale(env, cfg0, liveSec);
    // 金价快照到期补采：按 metal_snapshot 任务的间隔（可配 1 分钟）自动落库
    await captureMetalSnapshotIfDue(env, cfg0);
    let rows = await env.DB.prepare("SELECT * FROM metal_quotes").all();
    // 四个配置读取彼此独立，并行执行
    const [kindRaw, marketRaw, symbolsRaw, cfg] = await Promise.all([
        acquireList(env, "metal", "metal_kinds"),
        acquireList(env, "metal", "metal_markets"),
        acquireList(env, "metal", "metal_symbols"),
        settingsMap(env)
    ]);
    // 「展示类别」配置：限定页面展示的贵金属种类
    const kindFilter = kindRaw.filter(k => METAL_KINDS.includes(k));
    // 「展示市场」配置：当前内置贵金属市场为上海
    const marketFilter = marketRaw.filter(m => METAL_MARKETS.includes(m));
    // 稀有金属品种（含已停用）：它们有自己的页面，不能混进贵金属板块
    const rareSet = new Set((await rareInstruments(env, true)).map(i => i.symbol));
    const all = rows.results.slice().sort((a, b) => METAL_ORDER.indexOf(a.symbol) - METAL_ORDER.indexOf(b.symbol));
    let quotes = all;
    // 只展示「当前在采集」的品种，避免未采集品种的旧价被当成实时价。
    //   列表为空（=什么都不采）时不加过滤，避免误伤尚未配置的新库。
    if (symbolsRaw.length) {
        const activeSet = new Set(symbolsRaw);
        quotes = quotes.filter(q => activeSet.has(q.symbol));
    }
    if (kindFilter.length) quotes = quotes.filter(q => kindFilter.includes(q.kind));
    if (marketFilter.length) quotes = quotes.filter(q => marketFilter.includes(q.market));
    // 陈旧标记：最近一次成功刷新比该行的 updated_at 晚太久，说明该行已不在采集结果里。
    //   注意时区：updated_at 由 SQLite CURRENT_TIMESTAMP 写入（UTC），last_metal_refresh 为北京时间。
    const refreshEpoch = epochOf(cfg.last_metal_refresh || "");
    const staleGapMs = Math.max(liveSec * 10, 120) * 1000;
    quotes.forEach(q => {
        const qEpoch = epochOf(q.updated_at) + 8 * 3600 * 1000;
        q.stale = refreshEpoch > 0 && qEpoch > 0 && (refreshEpoch - qEpoch) > staleGapMs;
    });
    const usdcny = Number(cfg.metal_usdcny) || 0;
    return {
        quotes,
        stats: metalStats(quotes),
        derived: metalDerived(quotes, usdcny),
        heatmap: buildHeatmap(quotes),
        kinds: METAL_KINDS,
        markets: METAL_MARKETS,
        kind_filter: kindFilter,
        market_filter: marketFilter,
        // 品种配色：前端以此为唯一来源，避免前后端各写一份而漂移
        series_colors: METAL_SERIES_COLORS,
        // 全部已入库品种（含被隐藏的市场），供前端提示与切换；稀有金属单独成页，不在此列
        available_symbols: all.filter(q => !rareSet.has(q.symbol)).map(q => q.symbol),
        last_refresh: cfg.last_metal_refresh || "",
        updated_at: quotes[0] ? quotes[0].updated_at : "",
        // 前端按该间隔轮询；服务端同样按该间隔回源，两边口径一致
        live_sec: liveSec
    };
}

// 默认展示品种：优先上海品种（沪金主连），随配置变化
async function defaultMetalSymbol(env) {
    const symbols = await acquireList(env, "metal", "metal_symbols");
    const list = symbols.length ? symbols : METAL_INSTRUMENTS.map(i => i.symbol);
    const preferred = ["AU0", "AG0"];
    return preferred.find(s => list.includes(s)) || list[0] || "AU0";
}

async function getMetalHistory(env, url) {
    const symbol = (url.searchParams.get("symbol") || await defaultMetalSymbol(env)).toUpperCase();
    const inst = METAL_INSTRUMENTS.find(i => i.symbol === symbol);
    if (!inst) return json({ error: "未知品种" }, 400);
    const range = url.searchParams.get("range") || "day";
    const cfgMap = { day: { klt: 101, days: 365 }, week: { klt: 102, days: 365 * 3 }, month: { klt: 103, days: 365 * 8 } };
    const cfg = cfgMap[range] || cfgMap.day;
    const rows = await fetchMetalKline(inst.em, cfg.klt, ymd(cfg.days));
    return json({ symbol, range, name: inst.name, unit: inst.unit, rows });
}

async function getMetalDetail(env, url) {
    const symbol = (url.searchParams.get("symbol") || await defaultMetalSymbol(env)).toUpperCase();
    // 内置贵金属清单之外，品种管理里自建的品种（稀有金属等）同样支持 K 线详情，
    // 前提是配置了东方财富 secid（em 字段），否则取不到历史 K 线。
    let inst = METAL_INSTRUMENTS.find(i => i.symbol === symbol);
    if (!inst) inst = (await instrumentRows(env)).find(i => i.symbol === symbol && i.em);
    if (!inst) return json({ error: "未知品种" }, 400);
    // 周期：日/周/月（东方财富 klt 101/102/103）；只有日线需要分时
    const period = ["day", "week", "month"].includes(String(url.searchParams.get("period") || "").toLowerCase())
        ? String(url.searchParams.get("period")).toLowerCase() : "day";
    const KLT = { day: 101, week: 102, month: 103 }[period];
    const BEG = { day: ymd(365), week: ymd(365 * 3), month: ymd(365 * 8) }[period];
    const quote = await env.DB.prepare("SELECT * FROM metal_quotes WHERE symbol=?").bind(symbol).first();
    const cfg = await settingsMap(env);
    const usdcny = Number(cfg.metal_usdcny) || 0;
    const [kline, intradayPack] = await Promise.all([
        fetchMetalKline(inst.em, KLT, BEG),
        // 分时（5 分钟）：东方财富以 beg=当天 查询当日 5 分钟线会返回空，需回退几天再按窗口截取
        // 分时与所选周期无关，任何周期下都提供当日走势；回看 12 天以覆盖长假期凌晨的窗口回退
        fetchMetalKline(inst.em, 5, ymd(12)).then(rows => {
            // 交易日口径：当日 09:00 开盘 → 次日 02:30 夜盘收盘
            // 凌晨 00:00–02:30 的数据属于前一交易日的夜盘，窗口应取昨日 09:00 → 今日 02:30
            const now = nowBeijing();
            const hm = Number(now.slice(11, 13)) * 100 + Number(now.slice(14, 16));
            const baseOff = hm <= 230 ? -1 : 0; // 凌晨时段归前一个交易日
            // 窗口内无数据（周末/节假日的凌晨）则往前多试几个交易日，仍无则退回末尾 78 根
            for (let off = baseOff; off >= baseOff - 5; off--) {
                const winStart = beijingDay(off) + " 09:00";
                const winEnd = beijingDay(off + 1) + " 02:30";
                const win = rows.filter(r => {
                    const t = String(r.t).slice(0, 16);
                    return t >= winStart && t <= winEnd;
                });
                // day 供前端铺「整个交易日」的固定时间轴（09:00 → 次日 02:30，未到的时间留空）
                if (win.length) return { rows: win, day: beijingDay(off) };
            }
            return { rows: rows.slice(-78), day: null };
        })
    ]);
    const intraday = intradayPack.rows;
    const intradayDay = intradayPack.day;
    let trail = [];
    try {
        const t = await env.DB.prepare("SELECT price, quote_time, created_at FROM metal_history WHERE symbol=? ORDER BY id DESC LIMIT 200").bind(symbol).all();
        trail = t.results.slice().reverse();
    } catch (e) {}
    const quotes = (await env.DB.prepare("SELECT * FROM metal_quotes").all()).results;
    // 技术指标基于同一份 K 线计算，避免前端各算一次导致口径不一致
    const indicators = calcIndicators(kline);
    return json({
        instrument: inst,
        quote: quote || null,
        period,
        kline, intraday, trail,
        intraday_day: intradayDay,
        indicators,
        indicator_summary: indicatorSummary(kline, indicators),
        derived: metalDerived(quotes, usdcny),
        stats: metalStats(quotes)
    });
}

async function getMetalCompare(env, url) {
    const fallback = (await defaultMetalSymbol(env));
    const wanted = String(url.searchParams.get("symbols") || fallback)
        .split(",").map(s => s.trim().toUpperCase()).filter(s => METAL_INSTRUMENTS.find(i => i.symbol === s)).slice(0, 5);
    const days = Math.min(730, Math.max(20, parseInt(url.searchParams.get("days")) || 90));
    const series = await Promise.all(wanted.map(async sym => {
        const inst = METAL_INSTRUMENTS.find(i => i.symbol === sym);
        const rows = await fetchMetalKline(inst.em, 101, ymd(days));
        const base = rows.length ? rows[0].c : 0;
        return {
            symbol: sym, name: inst.short_name, color: METAL_SERIES_COLORS[sym] || "#4f46e5",
            base,
            points: rows.map(r => ({ t: r.t, v: base > 0 ? (r.c / base) * 100 : 0, c: r.c, pct: r.pct }))
        };
    }));
    return json({ series: series.filter(s => s.points.length), days });
}

// ============================================================
// 板块热力图：把「报价列表」压成色块矩阵 + 分组聚合
//   颜色强度按涨跌幅绝对值分档（与 A 股习惯一致：涨红跌绿），
//   不按成交额放大色块面积 —— 内外盘单位不同（元/克、美元/盎司、元/吨），
//   面积加权会产生误导，故统一等尺寸、按强度着色。
// ============================================================
const HEAT_STEPS = [0.2, 0.6, 1.5];   // 涨跌幅分档阈值（%）
function heatLevel(pct) {
    const p = Math.abs(Number(pct) || 0);
    if (p < HEAT_STEPS[0]) return 0;
    if (p < HEAT_STEPS[1]) return 1;
    if (p < HEAT_STEPS[2]) return 2;
    return 3;
}
function heatTile(q) {
    const pct = Number(q.change_pct) || 0;
    return {
        symbol: q.symbol, name: q.short_name || q.name, kind: q.kind, market: q.market,
        price: q.price, unit: q.unit, change: q.change, change_pct: pct,
        amplitude: Number(q.amplitude) || 0,
        level: heatLevel(pct),
        dir: pct > 0 ? "up" : pct < 0 ? "down" : "flat"
    };
}
function heatGroups(tiles, keyName, labelOf) {
    const map = new Map();
    for (const t of tiles) {
        const k = t[keyName] || "其他";
        if (!map.has(k)) map.set(k, { key: k, label: labelOf ? labelOf(k) : k, items: [] });
        map.get(k).items.push(t);
    }
    return Array.from(map.values()).map(g => {
        const n = g.items.length;
        const avg = n ? g.items.reduce((s, x) => s + x.change_pct, 0) / n : 0;
        return {
            key: g.key, label: g.label, count: n,
            avg_pct: round2(avg),
            up: g.items.filter(x => x.change_pct > 0).length,
            down: g.items.filter(x => x.change_pct < 0).length,
            flat: g.items.filter(x => !x.change_pct).length,
            level: heatLevel(avg),
            dir: avg > 0 ? "up" : avg < 0 ? "down" : "flat",
            items: g.items.slice().sort((a, b) => b.change_pct - a.change_pct)
        };
    }).sort((a, b) => b.avg_pct - a.avg_pct);
}
function buildHeatmap(quotes) {
    const tiles = quotes.map(heatTile).sort((a, b) => b.change_pct - a.change_pct);
    const dist = [0, 0, 0, 0];   // 按强度档统计个数
    tiles.forEach(t => dist[t.level]++);
    return {
        tiles,
        by_kind: heatGroups(tiles, "kind"),
        by_market: heatGroups(tiles, "market"),
        dist,
        steps: HEAT_STEPS
    };
}

// ============================================================
// 稀有金属：行情 + 三情景策略框架
//   情景区间 = 对数正态假设下的 T 日漂移 + 波动率位移，不做点位预测。
// ============================================================
const RARE_SCENARIO_TTL = 10 * 60 * 1000;          // 情景缓存 10 分钟（K 线拉取较重）
const RARE_SCENARIO_CACHE = new Map();             // symbol|hours -> { at, data }

// 驱动因子框架：weight 只用于决定「关注优先级」的先后顺序（不对外展示为百分比），
// 「观察点」写明该因子当前该看什么数据，避免用静态数值冒充实时结论。
// 前端展示的行情 / 情景区间 / 波动率 / 仓位上限全部由当日数据现场计算。
const RARE_FRAMEWORK = {
    LC0: {
        chain: "锂电产业链（正极材料 → 电池 → 新能源车/储能）",
        drivers: [
            { name: "锂资源供给", weight: 30, watch: "澳洲锂辉石发运量、南美盐湖提锂复产进度、江西云母矿环保与复产节奏" },
            { name: "正极排产与储能需求", weight: 28, watch: "磷酸铁锂/三元正极厂月度排产、储能招标与电芯库存天数" },
            { name: "库存与仓单", weight: 17, watch: "广期所碳酸锂注册仓单量、社会库存（冶炼厂 + 下游）周度变化" },
            { name: "成本曲线", weight: 15, watch: "外采锂辉石与云母提锂现金成本，成本支撑位随矿价下移" },
            { name: "政策与出口", weight: 10, watch: "新能源车购置税/补贴、储能容量电价、锂产品出口关税与配额" }
        ],
        downside: "矿山减停产不及预期、储能招标价继续下行、仓单集中注销前的抛压",
        upside: "高成本产能出清、储能集中交付、下游补库周期启动"
    },
    SI0: {
        chain: "硅基材料（工业硅 → 多晶硅 → 光伏 / 有机硅）",
        drivers: [
            { name: "多晶硅开工与减产", weight: 32, watch: "多晶硅厂检修/减产公告、行业自律限产执行力度" },
            { name: "丰枯水期电力成本", weight: 24, watch: "云南/四川丰水期电价、新疆自备电成本、开工率季节性" },
            { name: "光伏装机与组件排产", weight: 20, watch: "国内月度新增装机、组件出口、硅片价格与库存" },
            { name: "库存与仓单", weight: 14, watch: "广期所仓单、社会库存、下游有机硅与铝合金开工" },
            { name: "出口与贸易政策", weight: 10, watch: "工业硅出口关税、海外光伏贸易壁垒" }
        ],
        downside: "丰水期复产超预期、多晶硅继续压产、仓单注册量攀升",
        upside: "枯水期成本抬升、光伏抢装、多晶硅自律限产落地"
    },
    NI0: {
        chain: "镍产业链（红土镍矿 → 镍铁/高冰镍 → 不锈钢 / 三元前驱体）",
        drivers: [
            { name: "印尼镍矿与政策", weight: 30, watch: "印尼 RKAB 审批额度、镍矿内贸升水、出口禁令与税费调整" },
            { name: "不锈钢排产", weight: 25, watch: "300 系不锈钢厂排产与利润、无锡/佛山库存" },
            { name: "新能源需求", weight: 20, watch: "三元前驱体产量、高镍路线渗透率、硫酸镍与纯镍价差" },
            { name: "显性库存", weight: 15, watch: "LME 镍库存与注销仓单占比、上期所仓单" },
            { name: "冶炼利润与产能投放", weight: 10, watch: "MHP/高冰镍新增产能投产节奏、一体化成本" }
        ],
        downside: "印尼放量超预期、不锈钢减产、LME 大幅交仓",
        upside: "印尼政策收紧、硫酸镍转产纯镍窗口打开、不锈钢旺季补库"
    },
    SN0: {
        chain: "锡产业链（锡矿 → 精锡 → 焊料 / 镀锡板 / 化工）",
        drivers: [
            { name: "缅甸佤邦锡矿复产", weight: 30, watch: "佤邦采矿证与选厂复产、边境口岸通关量" },
            { name: "印尼出口与政策", weight: 22, watch: "印尼精锡出口许可证发放、月度出口量" },
            { name: "电子焊料需求", weight: 20, watch: "半导体销售额、PCB 开工率、AI 服务器与消费电子出货" },
            { name: "库存水平", weight: 16, watch: "LME + 上期所锡库存、下游焊料厂原料库存天数" },
            { name: "矿端品位与成本", weight: 12, watch: "主力矿山品位下滑、锡精矿加工费（TC）" }
        ],
        downside: "佤邦复产放量、电子需求走弱、库存持续累积",
        upside: "矿端扰动再起、半导体周期上行、低库存下挤仓"
    }
};

function stdev(arr) {
    if (!arr || arr.length < 2) return 0;
    const m = arr.reduce((a, b) => a + b, 0) / arr.length;
    return Math.sqrt(arr.reduce((s, x) => s + (x - m) * (x - m), 0) / (arr.length - 1));
}
// T 日情景区间：以现价为锚，上下轨按 σ√T 位移（对数空间），
// 漂移不并入中枢（否则下跌趋势里「中性」会低于现价，容易误读），
// 改为单独输出 trend_center / drift_period_pct 作为动量信号。
function scenarioBands(price, closes, horizonDays) {
    const T = Math.max(1, Math.min(120, horizonDays || 21));
    const use = closes.filter(v => Number.isFinite(v) && v > 0).slice(-60);
    if (use.length < 10 || !(price > 0)) return null;
    const rets = [];
    for (let i = 1; i < use.length; i++) rets.push(Math.log(use[i] / use[i - 1]));
    const sigmaD = stdev(rets);
    const drift = rets.reduce((a, b) => a + b, 0) / rets.length;
    const sigmaT = sigmaD * Math.sqrt(T);
    const muT = drift * T;
    const at = (z) => price * Math.exp(z * sigmaT);
    const sigmaAnn = sigmaD * Math.sqrt(252) * 100;
    const driftPct = (Math.exp(muT) - 1) * 100;
    // 动量明显（漂移超过半个区间宽度）时提示情景概率应向一侧倾斜
    let bias = "neutral", bias_note = "近 60 日动量中性，三情景概率大体对称";
    if (muT > sigmaT * 0.5) { bias = "up"; bias_note = "近 60 日动量为正，实际分布向乐观情景倾斜"; }
    else if (muT < -sigmaT * 0.5) { bias = "down"; bias_note = "近 60 日动量为负，实际分布向悲观情景倾斜"; }
    return {
        horizon_days: T,
        spot: round2(price),
        sigma_daily_pct: round2(sigmaD * 100),
        sigma_annual_pct: round2(sigmaAnn),
        sigma_period_pct: round2(sigmaT * 100),
        drift_period_pct: round2(driftPct),
        trend_center: round2(price * Math.exp(muT)),
        center: round2(price),
        pessimistic: round2(at(-1)),
        neutral: round2(price),
        optimistic: round2(at(1)),
        tail_low: round2(at(-1.65)),
        tail_high: round2(at(1.65)),
        bias, bias_note,
        // 正态假设下的落区概率（非预测，仅说明区间含义）
        prob: { pessimistic: 15.9, neutral: 68.2, optimistic: 15.9 }
    };
}

async function fetchRareQuotesLive(env) {
    const insts = await rareInstruments(env);
    if (!insts.length) throw new Error("尚未配置任何稀有金属品种，请到「品种管理」添加");
    const raw = await fetchSinaMetalQuotes(insts.map(i => i.symbol), insts);
    const quotes = insts.map(i => raw[i.symbol]).filter(Boolean);
    if (!quotes.length) throw new Error("稀有金属行情接口未返回有效数据");
    await upsertQuotes(env, quotes);
    try { await recordQuoteHistory(env, quotes); }
    catch (e) { logWarn("rare.history", e); }
    await evaluateAlerts(env, quotes);
    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('last_rare_refresh',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(nowBeijing()).run();
    // 保持历史调用方的数组返回契约；预警结果通过通知中心体现。
    return quotes;
}

// 稀有金属行情刷新（带采集日志）：页面按需补采 / 手动刷新共用，保证采集日志可追溯。
async function refreshRareQuotesLogged(env, triggerType) {
    const startedAt = beijingStamp(Date.now());
    const t0 = Date.now();
    try {
        const quotes = await fetchRareQuotesLive(env);
        await writeFetchLog(env, {
            task_key: RARE_MANUAL_LOG_KEY, trigger_type: triggerType || "page", started_at: startedAt,
            duration_ms: Date.now() - t0, status: "success",
            fetched: quotes.length, inserted: quotes.length,
            message: `稀有金属行情更新 ${quotes.length} 个品种`
        });
        return quotes;
    } catch (e) {
        await writeFetchLog(env, {
            task_key: RARE_MANUAL_LOG_KEY, trigger_type: triggerType || "page", started_at: startedAt,
            duration_ms: Date.now() - t0, status: "failed", message: String(e && e.message || e)
        });
        throw e;
    }
}

// 读取稀有金属报价；超过 10 分钟未更新则自动补采一次（失败不影响展示）
async function readRareQuotes(env, force) {
    const insts = await rareInstruments(env);
    if (!insts.length) return [];
    const symbols = insts.map(i => i.symbol);
    const ph = symbols.map(() => "?").join(",");
    let rows = (await env.DB.prepare("SELECT * FROM metal_quotes WHERE symbol IN (" + ph + ")")
        .bind(...symbols).all()).results || [];
    const stale = rows.length < insts.length || rows.some(r => {
        const updated = epochOfUtcDb(r.updated_at);
        return !updated || Date.now() - updated >= 10 * 60 * 1000;
    });
    if (force || (stale && Date.now() - (readRareQuotes._lastTry || 0) > 60 * 1000)) {
        if (!await taskEnabled(env, "metal_quote") || !await sourceEnabled(env, "sina_quote")) return symbols.map(s => rows.find(r => r.symbol === s)).filter(Boolean);
        readRareQuotes._lastTry = Date.now();
        try {
            await refreshRareQuotesLogged(env, "page");
            rows = (await env.DB.prepare("SELECT * FROM metal_quotes WHERE symbol IN (" + ph + ")")
                .bind(...symbols).all()).results || [];
        } catch (e) { logWarn("rare.refresh", e); }
    }
    // 按注册表顺序输出，新加的品种即使还没采到价也会占位（前端显示为待采集）
    return symbols.map(s => rows.find(r => r.symbol === s)).filter(Boolean);
}

// ============================================================
// 概念 → 材料联想
//   输入「AI / 计算中心 / 光伏 / 人形机器人」这类行业或场景词，反查最相关的金属与材料。
//   纯本地知识库：不依赖外网，结果可解释（每种材料都给出在该场景里的具体用途），
//   只回答「用到什么材料、相关度多高」，不预测价格、不构成投资建议。
// ============================================================
// ==== MATERIAL_ENGINE_START ====
//   概念 → 材料联想引擎：纯本地知识库 + 可解释评分，不依赖外网、不预测价格。
//   结构：材料目录（类别）→ 别名（俗称）→ 场景权重表（行业/场景 → 材料强弱）→ 材料链（共现上下游）。
const MATERIAL_CATALOG = {
    基本金属: ["铜", "铝", "铅", "锌", "镍", "锡"],
    贵金属: ["金", "银", "铂", "钯", "铑", "钌", "铱"],
    稀有金属: ["锂", "钴", "钨", "钼", "锑", "锗", "镓", "铟", "钽", "铌", "钛", "锆", "铪", "铍", "铼", "铋", "硒", "碲", "镉", "锰", "铬", "钒", "镁"],
    稀土: ["稀土", "镨钕", "镝", "铽", "镧", "铈", "钕"],
    非金属材料: ["多晶硅", "工业硅", "硅", "石墨", "萤石", "磷", "石英砂", "碳化硅", "氮化镓", "砷化镓", "蓝宝石"],
    化工与农业原料: ["钾", "硫", "氟", "硼", "钠", "氧化铝"]
};

// 同义词 / 常见叫法：既用于直接命中材料，也用于把材料挂到已接入的行情品种上
const MATERIAL_ALIAS = {
    金: ["黄金"], 银: ["白银"], 铂: ["铂金", "白金"], 钯: ["钯金"], 铑: ["铑金"],
    锂: ["碳酸锂", "氢氧化锂"], 镍: ["电解镍", "硫酸镍"], 钴: ["硫酸钴", "电解钴"],
    锡: ["精锡", "焊锡"], 锰: ["电解锰", "硫酸锰"], 钨: ["钨精矿", "apt"], 钼: ["钼精矿"],
    钛: ["钛白粉", "海绵钛"], 镁: ["原镁"], 锑: ["锑锭"], 锗: ["金属锗"], 镓: ["金属镓"],
    铟: ["金属铟"], 镨钕: ["稀土", "氧化镨钕", "钕铁硼", "prnd"], 钕: ["钕铁硼"], 镝: ["镝铁"],
    工业硅: ["金属硅"], 多晶硅: ["硅料", "polysilicon"], 石墨: ["负极材料", "石墨负极", "人造石墨"],
    磷: ["磷矿", "磷酸铁", "磷化工"], 石英砂: ["高纯石英砂", "石英坩埚"], 碳化硅: ["sic"],
    氮化镓: ["gan"], 砷化镓: ["gaas"], 蓝宝石: ["刚玉"],
    硅: ["单晶硅", "晶体硅", "硅片"], 钾: ["钾肥", "氯化钾", "硫酸钾"], 硫: ["硫磺", "硫酸", "硫化物"],
    氟: ["氟化工", "氟化盐"], 硼: ["硼砂", "硼酸", "硼硅玻璃"], 钠: ["金属钠", "钠盐", "钠离子"],
    氧化铝: [" alumina", "ao"]
};

// 行业 / 场景 → 材料权重（0~100）。权重看两点：这个场景里用得多不多、有没有可替代。
const MATERIAL_TOPICS = [
    {
        key: "ai", label: "AI / 算力中心",
        alias: ["ai", "人工智能", "算力", "算力中心", "计算中心", "智算中心", "数据中心", "大模型", "gpu", "服务器", "英伟达", "nvidia", "openai", "chatgpt", "机器学习", "深度学习", "生成式", "超算", "idc", "云计算", "算力租赁"],
        items: [
            ["铜", 96, "供配电母线、机柜走线与液冷管路，算力密度越高单机用铜越多"],
            ["锡", 90, "芯片焊球与先进封装微凸点，GPU/内存堆叠的关键焊料"],
            ["镓", 90, "GaN 电源与射频器件，高频高效供电的核心材料"],
            ["银", 86, "导电浆料与高速连接器镀层，高频信号损耗最低"],
            ["锗", 84, "硅锗外延、红外测温与光纤预制棒"],
            ["钽", 80, "钽电容，GPU 供电滤波与瞬态响应"],
            ["稀土", 78, "散热风扇、伺服电机与硬盘音圈电机的永磁体（镨钕）"],
            ["铟", 74, "InP 光模块芯片与导热界面材料"],
            ["铝", 72, "机柜、散热器、冷板与结构件"],
            ["金", 70, "键合金丝与高可靠连接器镀层"],
            ["硅", 68, "晶圆衬底与硅基转接板"],
            ["钨", 62, "靶材、散热配重与屏蔽件"],
            ["石墨", 60, "导热膜、液冷板与等静压石墨热场"],
            ["钼", 58, "靶材与电极"],
            ["碳化硅", 56, "服务器电源与 UPS 的功率器件"],
            ["铪", 48, "先进制程高 k 栅介质"],
            ["钌", 46, "先进制程互连阻挡层"],
            ["铂", 45, "温度/气体传感器与催化剂"],
            ["钴", 40, "先进制程互连阻挡层"]
        ]
    },
    {
        key: "computer", label: "计算机 / 消费电子",
        alias: ["计算机", "电脑", "pc", "笔记本", "台式机", "手机", "智能手机", "消费电子", "平板", "智能终端", "硬件", "电子产品", "苹果", "华为", "小米", "联想", "富士康", "立讯"],
        items: [
            ["铜", 90, "PCB 线路、供电与散热"],
            ["锡", 86, "主板与连接器焊点"],
            ["铝", 80, "机箱、中框、散热鳍片"],
            ["金", 80, "金手指、按键触点与键合丝"],
            ["银", 76, "导电胶、触控浆料与高频走线"],
            ["稀土", 76, "扬声器、振动马达与硬盘磁体"],
            ["钽", 72, "钽电容与滤波器件"],
            ["硅", 70, "处理器与存储晶圆"],
            ["铟", 70, "ITO 透明导电膜（触控与显示）"],
            ["锂", 68, "电池正极与电解液"],
            ["钴", 60, "电池正极稳定元素"],
            ["镍", 58, "电池正极与接口镀层"],
            ["镁", 52, "轻薄本与平板外壳"],
            ["锗", 50, "光纤与红外传感"],
            ["钯", 48, "MLCC 内电极"],
            ["蓝宝石", 46, "摄像头盖板与指纹识别基片"],
            ["钨", 44, "振动马达配重块"]
        ]
    },
    {
        key: "semiconductor", label: "半导体 / 芯片",
        alias: ["半导体", "芯片", "集成电路", "晶圆", "ic", "制程", "封装", "光刻", "光刻机", "存储器", "dram", "cpu", "晶圆厂", "芯片制造", "台积电", "中芯国际", "阿斯麦"],
        items: [
            ["硅", 96, "晶圆衬底与大部分逻辑/存储芯片的基底"],
            ["镓", 90, "GaAs / GaN 化合物半导体，射频与功率的核心"],
            ["锗", 86, "硅锗外延、红外光学与衬底材料"],
            ["铜", 82, "先进制程互连与铜箔载板"],
            ["钽", 78, "扩散阻挡层与钽电容"],
            ["铪", 78, "高 k 栅介质（HfO2）"],
            ["钨", 70, "接触孔填充、栅极与靶材"],
            ["铟", 70, "InP 光芯片与低温焊料"],
            ["金", 66, "键合丝与镀层"],
            ["氮化镓", 66, "快充、射频与功率器件"],
            ["碳化硅", 64, "功率器件衬底（车规/工业）"],
            ["稀土", 62, "CMP 抛光粉（铈基）与靶材添加"],
            ["钌", 62, "先进互连阻挡层"],
            ["银", 60, "导电浆料与烧结银"],
            ["砷化镓", 60, "射频前端与光通信芯片"],
            ["铈", 58, "芯片抛光液主成分"],
            ["钼", 58, "靶材、电极与阻挡层"],
            ["钴", 56, "先进制程互连阻挡层"],
            ["锑", 54, "硅片掺杂与红外器件"],
            ["碲", 40, "化合物半导体与热电材料"]
        ]
    },
    {
        key: "pv", label: "光伏 / 太阳能",
        alias: ["光伏", "太阳能", "组件", "硅片", "电池片", "逆变器", "新能源发电", "太阳能电池", "hjt", "topcon", "隆基", "通威", "阳光电源"],
        items: [
            ["多晶硅", 98, "硅料，光伏产业链最上游"],
            ["银", 94, "正银浆料，电池片电极不可替代"],
            ["工业硅", 92, "多晶硅与有机硅的原料"],
            ["铝", 86, "组件边框与背板"],
            ["铜", 80, "焊带、汇流条与电缆"],
            ["石英砂", 74, "高纯石英砂，石英坩埚的核心原料"],
            ["锡", 72, "焊带镀锡"],
            ["石墨", 66, "热场、舟皿与坩埚"],
            ["铟", 56, "HJT / CIGS 的靶材与透明电极"],
            ["镓", 52, "CIGS 薄膜与靶材"],
            ["硒", 46, "CIGS 薄膜吸收层"],
            ["碲", 44, "CdTe 薄膜组件"],
            ["钨", 42, "金刚线母线"],
            ["钼", 40, "背电极与靶材"],
            ["镉", 38, "CdTe 薄膜组件"],
            ["稀土", 36, "逆变器磁材与玻璃着色"]
        ]
    },
    {
        key: "ev", label: "新能源车 / 动力电池",
        alias: ["新能源车", "电动车", "电动汽车", "动力电池", "锂电池", "汽车", "整车", "充电桩", "三元", "磷酸铁锂", "电池", "新能源", "车企", "特斯拉", "比亚迪", "宁德时代", "蔚来", "理想", "小鹏"],
        items: [
            ["锂", 98, "正极材料与电解液锂盐"],
            ["镍", 92, "三元正极提高能量密度"],
            ["稀土", 90, "驱动电机钕铁硼永磁体"],
            ["铜", 88, "铜箔、电机绕组与高压线束"],
            ["钴", 88, "三元正极稳定层状结构"],
            ["石墨", 86, "负极材料（人造/天然石墨）"],
            ["铝", 82, "车身轻量化、电池托盘与集流体"],
            ["锰", 76, "磷酸锰铁锂与前驱体"],
            ["磷", 70, "磷酸铁锂正极"],
            ["碳化硅", 64, "主驱逆变器功率器件"],
            ["锡", 58, "连接器与 BMS 焊点"],
            ["银", 54, "高压连接器镀层与烧结银"],
            ["硅", 52, "功率器件与 SiC 衬底原料"],
            ["铂", 48, "燃料电池催化剂"],
            ["萤石", 46, "六氟磷酸锂的氟源"],
            ["钯", 40, "尾气催化与传感器"]
        ]
    },
    {
        key: "storage", label: "储能",
        alias: ["储能", "储能电站", "液流电池", "钠电", "钠离子", "调峰", "电网侧储能", "工商业储能", "电化学储能"],
        items: [
            ["锂", 94, "磷酸铁锂电芯主材"],
            ["钒", 82, "全钒液流电池电解液"],
            ["石墨", 72, "负极材料"],
            ["铜", 70, "集流体与升压电缆"],
            ["镍", 64, "部分三元与钠电体系"],
            ["铝", 60, "结构件与集流体"],
            ["钴", 58, "三元体系稳定元素"],
            ["锌", 56, "锌溴液流电池"],
            ["磷", 55, "磷酸铁锂正极"],
            ["碳化硅", 48, "PCS 功率器件"],
            ["铂", 40, "氢储能燃料电池"]
        ]
    },
    {
        key: "wind", label: "风电",
        alias: ["风电", "风力发电", "风机", "海上风电", "桨叶", "风场", "风电机组"],
        items: [
            ["稀土", 94, "直驱永磁发电机磁体"],
            ["铜", 86, "发电机绕组、塔筒电缆与变压器"],
            ["铝", 70, "机舱罩与结构件"],
            ["镍", 66, "高强螺栓、齿轮钢与不锈钢"],
            ["钼", 62, "塔筒、铸件与齿轮箱钢"],
            ["锌", 56, "塔筒与基础镀锌防腐"],
            ["钛", 42, "海上防腐与连接件"],
            ["镁", 40, "轻量化部件"]
        ]
    },
    {
        key: "grid", label: "电网 / 特高压",
        alias: ["电网", "特高压", "输配电", "变压器", "电力设备", "电线电缆", "配电网", "智能电网", "变电站"],
        items: [
            ["铜", 96, "电缆、绕组与开关触头"],
            ["铝", 90, "架空导线与变电站构架"],
            ["硅", 62, "取向硅钢（硅铁合金）铁芯"],
            ["锌", 60, "铁塔与接地镀锌"],
            ["银", 52, "触头与导电镀层"],
            ["稀土", 48, "电抗器与互感器磁材"],
            ["镍", 44, "不锈钢部件"],
            ["钼", 38, "高强钢结构"]
        ]
    },
    {
        key: "defense", label: "军工 / 航空航天",
        alias: ["军工", "国防", "航空", "航天", "导弹", "战机", "无人机", "兵器", "雷达", "发动机", "航发", "卫星"],
        items: [
            ["钛", 94, "机身、起落架与发动机叶片"],
            ["稀土", 92, "永磁电机、激光晶体与隐身涂层"],
            ["钨", 90, "穿甲弹芯、配重与屏蔽"],
            ["镍", 82, "高温合金基体"],
            ["铼", 80, "单晶高温合金，发动机叶片不可替代"],
            ["钴", 76, "高温合金与硬质部件"],
            ["铝", 74, "航空铝合金蒙皮与结构"],
            ["钼", 72, "结构钢、喷管与高温部件"],
            ["钽", 66, "钽电容与穿甲弹药型罩"],
            ["锑", 62, "弹药、曳光剂与阻燃"],
            ["铌", 60, "高温合金与超导磁体"],
            ["锆", 58, "燃烧室涂层与结构陶瓷"],
            ["镁", 56, "轻量化机载结构件"],
            ["铍", 54, "惯性器件、光学镜坯与导热基板"],
            ["铪", 50, "核反应堆控制与航空涂层"]
        ]
    },
    {
        key: "robot", label: "机器人 / 人形机器人",
        alias: ["机器人", "人形机器人", "工业机器人", "伺服", "减速器", "自动化", "机械臂", "具身智能", "灵巧手"],
        items: [
            ["稀土", 92, "伺服电机与无框力矩电机磁体"],
            ["铜", 80, "电机绕组、线束与柔性电路"],
            ["铝", 74, "关节外壳与结构件"],
            ["镁", 66, "轻量化骨架"],
            ["钛", 60, "高强轻质关节件"],
            ["锡", 56, "控制板与连接器焊点"],
            ["钽", 50, "控制板钽电容"],
            ["银", 46, "触觉传感器与导电浆料"],
            ["钼", 44, "减速器与轴承钢"],
            ["钴", 40, "电机永磁与硬质部件"],
            ["铟", 38, "触觉与柔性传感"]
        ]
    },
    {
        key: "hydrogen", label: "氢能 / 燃料电池",
        alias: ["氢能", "氢燃料", "燃料电池", "电解槽", "绿氢", "制氢", "加氢站", "氢冶金"],
        items: [
            ["铂", 96, "燃料电池与电解水催化剂，用量少但不可替代"],
            ["铱", 82, "PEM 电解槽阳极催化剂"],
            ["石墨", 72, "双极板与气体扩散层"],
            ["钛", 68, "双极板与电解槽结构"],
            ["镍", 64, "碱性电解槽电极与催化剂"],
            ["钌", 62, "催化剂与耐蚀部件"],
            ["钯", 56, "储氢与氢气纯化"],
            ["稀土", 54, "储氢合金（镧系）"],
            ["镧", 50, "AB5 型储氢合金"],
            ["钴", 50, "储氢合金与耐热部件"]
        ]
    },
    {
        key: "nuclear", label: "核电 / 核聚变",
        alias: ["核电", "核能", "核电站", "核聚变", "反应堆", "铀", "可控核聚变", "托卡马克"],
        items: [
            ["锆", 96, "燃料棒包壳（锆合金），核级不可替代"],
            ["铪", 86, "控制棒与中子吸收体"],
            ["镍", 72, "蒸汽发生器传热管"],
            ["钛", 62, "冷凝器与海水管路"],
            ["铜", 58, "发电机绕组与电缆"],
            ["铟", 56, "控制棒银铟镉合金"],
            ["银", 52, "控制棒合金成分"],
            ["镉", 50, "控制棒与屏蔽"],
            ["铌", 48, "超导磁体（聚变）"],
            ["钨", 44, "第一壁与屏蔽材料"]
        ]
    },
    {
        key: "chem", label: "化工 / 催化 / 环保",
        alias: ["化工", "催化", "催化剂", "炼化", "石化", "脱硝", "尾气", "环保", "精细化工", "化学"],
        items: [
            ["钯", 90, "加氢与氧化催化剂"],
            ["铂", 86, "重整、脱硝与尾气催化"],
            ["铑", 82, "三元催化与羰基合成"],
            ["铈", 66, "储氧材料与抛光粉"],
            ["钼", 66, "加氢脱硫催化剂"],
            ["镍", 70, "加氢催化剂与耐蚀设备"],
            ["钒", 62, "脱硝催化剂与硫酸生产"],
            ["稀土", 60, "催化裂化与储氧材料"],
            ["钛", 58, "催化剂载体（钛白/分子筛）"],
            ["钴", 56, "羰基合成与脱硫催化剂"],
            ["银", 48, "环氧乙烷与甲醛催化剂"],
            ["钨", 44, "催化剂与耐蚀合金"]
        ]
    },
    {
        key: "steel", label: "钢铁 / 基建 / 地产",
        alias: ["钢铁", "基建", "地产", "房地产", "建筑", "螺纹钢", "不锈钢", "工程机械", "水泥", "钢材", "施工"],
        items: [
            ["锰", 88, "锰钢与脱氧合金化"],
            ["铬", 84, "不锈钢与耐蚀钢"],
            ["镍", 82, "不锈钢与高强钢"],
            ["锌", 80, "镀锌板与防腐"],
            ["钒", 78, "螺纹钢微合金化"],
            ["铝", 72, "门窗、幕墙与模板"],
            ["铜", 70, "电线电缆与管道"],
            ["钼", 70, "高强钢与耐热钢"],
            ["铌", 64, "高强钢微合金化"],
            ["钨", 52, "模具与耐磨件"],
            ["萤石", 48, "冶金助熔剂"],
            ["钛", 44, "建筑涂层与装饰"]
        ]
    },
    {
        key: "machining", label: "硬质合金 / 刀具 / 机床",
        alias: ["硬质合金", "刀具", "机床", "钨钢", "钻头", "模具", "数控", "切削", "精密制造"],
        items: [
            ["钨", 98, "碳化钨硬质合金，刀具与模具的主体"],
            ["钴", 86, "硬质合金粘结相"],
            ["钼", 60, "高速钢与模具钢"],
            ["钽", 56, "硬质合金添加剂与电容"],
            ["钛", 54, "涂层（TiN/TiAlN）"],
            ["铌", 50, "硬质合金添加剂"],
            ["钒", 42, "高速钢与工具钢"],
            ["锆", 40, "陶瓷刀具与涂层"]
        ]
    },
    {
        key: "telecom", label: "通信 / 5G / 光纤",
        alias: ["通信", "5g", "6g", "光纤", "光缆", "基站", "光模块", "网络设备", "射频", "天线", "华为", "中兴", "运营商"],
        items: [
            ["锗", 88, "光纤预制棒用四氯化锗"],
            ["铜", 86, "射频电缆、馈线与电源"],
            ["镓", 78, "基站 GaN 功放"],
            ["铟", 72, "InP 光模块与焊料"],
            ["铝", 66, "机柜、天线与散热"],
            ["硅", 62, "光芯片与基带芯片"],
            ["银", 58, "高频导体与镀层"],
            ["稀土", 56, "滤波器、磁材与光纤掺杂"],
            ["金", 54, "连接器镀层与键合"],
            ["钽", 50, "通信设备电容"]
        ]
    },
    {
        key: "display", label: "显示 / 面板 / LED",
        alias: ["显示", "面板", "lcd", "oled", "led", "microled", "屏幕", "电视", "显示屏", "投影"],
        items: [
            ["铟", 92, "ITO 透明导电靶材，几乎没有替代"],
            ["稀土", 76, "荧光粉（铕/铽）与抛光粉"],
            ["锡", 68, "ITO 靶材与焊料"],
            ["铜", 66, "驱动线路与铜制程"],
            ["镓", 64, "LED 与 MicroLED 外延"],
            ["银", 62, "触控与电极浆料"],
            ["钼", 62, "靶材与阻挡层"],
            ["铈", 58, "玻璃抛光粉"],
            ["铝", 56, "背板与结构件"],
            ["蓝宝石", 56, "LED 衬底与盖板"],
            ["石英砂", 50, "基板玻璃原料"]
        ]
    },
    {
        key: "medical", label: "医疗 / 医疗器械",
        alias: ["医疗", "医疗器械", "植入", "手术", "制药", "生物医药", "牙科", "骨科", "医用"],
        items: [
            ["钛", 92, "骨科植入与手术器械"],
            ["铂", 74, "支架、电极与抗癌药"],
            ["钽", 66, "植入标记与造影剂"],
            ["钴", 62, "钴铬合金关节"],
            ["银", 60, "抗菌敷料与器械镀层"],
            ["镍", 56, "不锈钢器械"],
            ["铱", 56, "放射治疗源"],
            ["金", 52, "牙科修复与诊断试剂"],
            ["锆", 52, "陶瓷牙与骨水泥"],
            ["钯", 44, "牙科合金与传感器"]
        ]
    },
    {
        key: "coating", label: "涂料 / 颜料 / 阻燃",
        alias: ["涂料", "颜料", "油漆", "阻燃", "塑料", "橡胶", "钛白粉", "改性塑料", "建材"],
        items: [
            ["钛", 94, "钛白粉，白色颜料主体"],
            ["锑", 78, "阻燃剂（三氧化二锑）"],
            ["锌", 70, "防腐涂料与锌粉"],
            ["铝", 60, "铝粉颜料与填料"],
            ["锆", 56, "陶瓷颜料与涂料助剂"],
            ["铜", 40, "防污涂料"],
            ["镁", 36, "阻燃与填料"]
        ]
    },
    {
        key: "glass", label: "玻璃 / 陶瓷",
        alias: ["玻璃", "陶瓷", "瓷砖", "坩埚", "釉料", "日用陶瓷", "建筑玻璃"],
        items: [
            ["石英砂", 90, "玻璃与陶瓷的基础原料"],
            ["锆", 74, "锆英砂、陶瓷增白与耐火"],
            ["铈", 70, "玻璃抛光粉"],
            ["稀土", 64, "着色、脱色与抛光"],
            ["锡", 54, "浮法玻璃成型"],
            ["蓝宝石", 52, "耐磨窗口与盖板"],
            ["铝", 46, "氧化铝陶瓷与釉料"]
        ]
    },
    {
        key: "magnet", label: "磁材 / 电机",
        alias: ["磁材", "永磁", "钕铁硼", "电机", "马达", "磁性材料", "铁氧体", "稀土永磁"],
        items: [
            ["稀土", 98, "钕铁硼永磁体的镨钕主成分"],
            ["镝", 70, "提高永磁体矫顽力与耐温"],
            ["铽", 66, "高矫顽力添加"],
            ["钴", 62, "钐钴磁体与耐温磁材"],
            ["镍", 52, "磁材镀层与软磁合金"],
            ["铜", 48, "绕组与换向器"]
        ]
    },
    {
        key: "recycle", label: "电池回收 / 再生",
        alias: ["电池回收", "回收", "再生", "梯次利用", "城市矿山", "循环利用"],
        items: [
            ["钴", 78, "回收价值最高的元素"],
            ["锂", 76, "湿法回收碳酸锂"],
            ["镍", 74, "硫酸镍再生"],
            ["铜", 66, "铜箔与线束回收"],
            ["锰", 62, "前驱体再生"],
            ["石墨", 58, "负极石墨提纯回用"],
            ["铝", 56, "外壳与集流体"],
            ["磷", 52, "磷酸铁锂回收"]
        ]
    },
    {
        key: "superconductor", label: "超导 / 前沿材料",
        alias: ["超导", "超导体", "超导线", "量子", "石墨烯", "新材料", "磁悬浮"],
        items: [
            ["铌", 90, "铌钛/铌三锡超导线材"],
            ["钛", 72, "超导磁体结构件"],
            ["稀土", 66, "钇钡铜氧高温超导"],
            ["铜", 62, "稳定体与基体"],
            ["铪", 50, "高温合金与涂层"],
            ["镁", 44, "二硼化镁超导"],
            ["银", 40, "超导带材包覆层"]
        ]
    },
    {
        key: "pcb", label: "PCB / 电子制造",
        alias: ["pcb", "电路板", "电子制造", "smt", "焊接", "连接器", "被动元件", "mlcc", "贴片", "电子组装"],
        items: [
            ["铜", 96, "铜箔与线路成形"],
            ["金", 82, "化金/沉金镀层"],
            ["锡", 80, "焊料与焊膏"],
            ["银", 64, "导电浆料与烧结"],
            ["钽", 60, "钽电容"],
            ["镍", 58, "镀层与阻焊"],
            ["钯", 56, "MLCC 内电极"],
            ["铟", 42, "低温焊料与导热"]
        ]
    },
    {
        key: "cooling", label: "液冷 / 散热 / 热管理",
        alias: ["散热", "液冷", "热管理", "冷却", "导热", "风冷", "冷板", "均热板"],
        items: [
            ["铜", 94, "热管、均热板与冷板"],
            ["铝", 86, "散热鳍片、机箱与冷板"],
            ["镓", 72, "液态金属导热膏"],
            ["石墨", 66, "导热膜与石墨烯散热片"],
            ["铟", 62, "导热界面材料"],
            ["银", 56, "导热胶与烧结层"],
            ["硅", 44, "导热硅脂与硅油"]
        ]
    },
    {
        key: "optical", label: "光学 / 红外 / 激光",
        alias: ["光学", "镜头", "红外", "激光", "摄像头", "镀膜", "光电", "夜视"],
        items: [
            ["锗", 92, "红外镜头与窗口，热成像核心"],
            ["镧", 78, "高折射光学玻璃"],
            ["蓝宝石", 72, "耐磨窗口与镜头盖"],
            ["石英砂", 66, "石英玻璃与光纤"],
            ["铈", 64, "光学抛光粉"],
            ["稀土", 58, "激光晶体与荧光材料"],
            ["铟", 56, "红外探测与透明电极"],
            ["铪", 54, "高折射镀膜"],
            ["钽", 50, "镀膜与靶材"]
        ]
    },
    {
        key: "jewelry", label: "黄金珠宝 / 避险",
        alias: ["黄金", "珠宝", "首饰", "金价", "避险", "通胀", "贵金属", "金条", "储备"],
        items: [
            ["金", 98, "首饰、投资金条与央行储备"],
            ["银", 82, "银饰、银器与投资银条"],
            ["铂", 76, "铂金首饰与工业催化"],
            ["铑", 66, "镀铑与催化"],
            ["钯", 58, "首饰合金与催化"],
            ["钌", 44, "首饰合金与电子"]
        ]
    },
    {
        key: "ship", label: "船舶 / 海工",
        alias: ["船舶", "造船", "海工", "海洋工程", "港口", "航运", "集装箱船"],
        items: [
            ["钛", 80, "海水管路与耐蚀结构"],
            ["镍", 74, "不锈钢与耐蚀合金"],
            ["铝", 70, "上层建筑与轻量化"],
            ["铜", 68, "海水管路与电缆"],
            ["锌", 62, "牺牲阳极与防腐"],
            ["钼", 58, "耐蚀钢与焊材"]
        ]
    },
    {
        key: "rail", label: "轨道交通",
        alias: ["轨道交通", "高铁", "地铁", "列车", "动车", "城轨", "铁路"],
        items: [
            ["铝", 90, "车体型材与轻量化"],
            ["铜", 80, "牵引电机、接触网与电缆"],
            ["镍", 66, "不锈钢车体与紧固件"],
            ["稀土", 62, "牵引电机磁材"],
            ["镁", 56, "内饰与轻量化件"],
            ["钛", 46, "连接件与制动部件"],
            ["银", 40, "受电弓与触头"]
        ]
    },
    {
        key: "hvac", label: "家电 / 制冷 / 空调",
        alias: ["家电", "空调", "制冷", "冰箱", "洗衣机", "压缩机", "热泵", "白色家电"],
        items: [
            ["铜", 94, "换热器铜管与压缩机绕组"],
            ["铝", 86, "翅片、外壳与微通道换热器"],
            ["稀土", 74, "压缩机与风扇电机磁体"],
            ["锌", 56, "镀锌板与防腐"],
            ["镍", 52, "不锈钢内胆"],
            ["银", 50, "触点与焊料"]
        ]
    },
    {
        key: "aluminum", label: "电解铝 / 铝加工",
        alias: ["电解铝", "铝加工", "铝型材", "氧化铝", "铝板", "铝箔", "铝锭"],
        items: [
            ["铝", 98, "电解铝与铝合金主体"],
            ["氧化铝", 92, "拜耳法产出的电解铝原料"],
            ["石墨", 72, "预焙阳极与阴极"],
            ["萤石", 62, "氟化铝与冰晶石"],
            ["铜", 48, "导电母线与设备"],
            ["镁", 40, "铝合金添加元素"]
        ]
    },
    {
        key: "sodium", label: "钠离子电池",
        alias: ["钠离子", "钠电", "钠电池", "钠盐", "sodium", "钠储能"],
        items: [
            ["钠", 96, "钠离子电池的钠源正极材料"],
            ["铝", 74, "铝箔集流体与钠电池壳体"],
            ["石墨", 62, "硬碳负极"],
            ["锂", 60, "与锂电路线共存，混合Pack里的锂电部分"],
            ["磷", 56, "钠盐前驱体与磷酸盐类正极"],
            ["稀土", 46, "永磁电机与伺服"],
            ["铜", 52, "极耳与连接件"]
        ]
    },
    {
        key: "solid", label: "固态电池",
        alias: ["固态电池", "全固态", "半固态", "硫化物电解质", "氧化物电解质", "固体电解质"],
        items: [
            ["锂", 96, "固态电池的锂源正极"],
            ["硫", 88, "硫化物电解质的主体成分"],
            ["硅", 80, "高比能硅碳负极"],
            ["锗", 58, "硅碳负极与部分硫化物体系"],
            ["银", 56, "复合电极导电剂"],
            ["铝", 58, "正负极集流体"],
            ["铜", 52, "集流体与封装"],
            ["磷", 54, "磷酸盐类正极与添加剂"],
            ["钛", 44, "涂覆与致密化层"]
        ]
    },
    {
        key: "agri", label: "农业 / 化肥 / 种植",
        alias: ["农业", "化肥", "肥料", "种植", "磷肥", "钾肥", "复合肥", "土壤", "粮食", "养殖"],
        items: [
            ["磷", 94, "磷肥与磷酸盐，作物刚需"],
            ["钾", 92, "钾肥，膨果与抗逆"],
            ["硫", 78, "硫酸铵等硫源肥料"],
            ["硼", 64, "硼肥与硼硅玻璃"],
            ["氟", 52, "氟化工与含氟农药"],
            ["硅", 46, "硅肥与土壤改良"],
            ["锌", 50, "微量元素肥料"],
            ["铝", 26, "土壤调理与铝矾"]
        ]
    },
    {
        key: "print3d", label: "3D 打印 / 增材制造",
        alias: ["3d打印", "增材制造", "3d", "金属打印", "粉末床", "激光成形", "成形"],
        items: [
            ["铝", 88, "铝镁合金粉末与轻量化结构件"],
            ["钛", 86, "钛合金打印，航空与医疗植入"],
            ["镍", 78, "Inconel 718 等镍基高温合金粉末"],
            ["钴", 72, "钴基高温合金与工具钢"],
            ["铜", 66, "铜合金打印与散热件"],
            ["钒", 62, "钛铝合金的合金元素"],
            ["钼", 58, "难熔元素提升强度"],
            ["钨", 56, "硬质合金与耐磨件"],
            ["铍", 50, "轻高强材料（毒性受限）"],
            ["镁", 46, "镁合金粉末"]
        ]
    },
    {
        key: "space", label: "商业航天 / 卫星",
        alias: ["航天", "卫星", "火箭", "商业航天", "空间站", "运载火箭", "遥感", "星座"],
        items: [
            ["铝", 90, "整流罩、贮箱与主结构"],
            ["镁", 82, "结构件与天线支架"],
            ["钛", 80, "贮箱、紧固件与发动机阀"],
            ["铜", 76, "线束、电源与母排"],
            ["镍", 70, "高温合金承力件"],
            ["镓", 66, "空间太阳能电池与射频器件"],
            ["锗", 62, "空间太阳能电池三结衬底"],
            ["铼", 56, "液体火箭发动机涡轮"],
            ["钨", 52, "配重与工装工具"]
        ]
    },
    {
        key: "sensor", label: "传感器 / 气体检测",
        alias: ["传感器", "气体检测", "湿度传感", "压力传感", "化学传感", "mems", "车载传感器"],
        items: [
            ["铂", 88, "氧传感器与电化学传感电极"],
            ["钯", 72, "氢气与一氧化碳检测"],
            ["锗", 70, "红外与热成像传感"],
            ["硅", 66, "MEMS 器件基底"],
            ["铟", 62, "InP 与 ITO 传感电极"],
            ["铑", 60, "高温稳定催化电极"],
            ["稀土", 58, "磁传感与磁弹性元件"],
            ["钽", 56, "电容式传感与滤波"],
            ["镍", 50, "应变片与合金基体"]
        ]
    },
    {
        key: "water", label: "水处理 / 环保装备",
        alias: ["水处理", "环保", "污水", "脱硫", "脱硝", "固废", "环卫", "净化", "除尘"],
        items: [
            ["钛", 72, "膜电极与耐蚀曝气设备"],
            ["铝", 58, "曝气、搅拌与水箱结构"],
            ["稀土", 54, "催化氧化与絮凝助剂"],
            ["铬", 50, "铬酸盐阻垢与钝化"],
            ["铜", 44, "电极与管路"],
            ["铂", 42, "高级氧化电极"],
            ["硅", 38, "硅藻土与过滤材料"]
        ]
    },
    {
        key: "light", label: "轻量化 / 一体化压铸",
        alias: ["轻量化", "一体化压铸", "压铸", "汽车轻量化", "结构件", "合金化"],
        items: [
            ["铝", 92, "一体化压铸与车身骨架"],
            ["镁", 80, "镁合金压铸件"],
            ["硅", 72, "铝硅合金与半固态成形"],
            ["锰", 58, "高强钢与镀层"],
            ["铜", 46, "导电结构件"],
            ["钛", 44, "连接件与耐蚀件"],
            ["稀土", 40, "耐蚀与阻燃添加剂"]
        ]
    }
];

// 材料 → 可一键接入的行情品种（只收录真实可用的新浪代码 + 东财 K 线，均已实测）。
//   材料联想里点「加入监测」时按这张表建品种；表里没有的材料 = 目前没有稳定的免费连续报价，
//   此时前端改为「手动接入」，打开品种管理预填名称与产业链，让用户自己填代码，绝不编价格。
const MATERIAL_SYMBOL_HINTS = {
    铜: { symbol: "CU0", sina: "nf_CU0", name: "沪铜主连", short_name: "沪铜", market: "上期所", kind: "铜", unit: "元/吨", em: "113.CUM", chain: "电缆/电网/供配电" },
    铝: { symbol: "AL0", sina: "nf_AL0", name: "沪铝主连", short_name: "沪铝", market: "上期所", kind: "铝", unit: "元/吨", em: "113.ALM", chain: "铝材/机柜/散热" },
    铅: { symbol: "PB0", sina: "nf_PB0", name: "沪铅主连", short_name: "沪铅", market: "上期所", kind: "铅", unit: "元/吨", em: "113.PBM", chain: "铅酸电池/蓄电池" },
    锌: { symbol: "ZN0", sina: "nf_ZN0", name: "沪锌主连", short_name: "沪锌", market: "上期所", kind: "锌", unit: "元/吨", em: "113.ZNM", chain: "镀锌/压铸合金" },
    锡: { symbol: "SN0", sina: "nf_SN0", name: "沪锡主连", short_name: "沪锡", market: "上期所", kind: "锡", unit: "元/吨", em: "113.SNM", chain: "焊料/锡膏/锡锑" },
    镍: { symbol: "NI0", sina: "nf_NI0", name: "沪镍主连", short_name: "沪镍", market: "上期所", kind: "镍", unit: "元/吨", em: "113.NIM", chain: "不锈钢/三元正极" },
    氧化铝: { symbol: "AO0", sina: "nf_AO0", name: "氧化铝主连", short_name: "氧化铝", market: "上期所", kind: "氧化铝", unit: "元/吨", em: "113.AOM", chain: "电解铝原料/耐火材料" },
    多晶硅: { symbol: "PS0", sina: "nf_PS0", name: "多晶硅主连", short_name: "多晶硅", market: "广期所", kind: "硅", unit: "元/吨", em: "225.psm", chain: "硅料/光伏" },
    工业硅: { symbol: "SI0", sina: "nf_SI0", name: "工业硅主连", short_name: "工业硅", market: "广期所", kind: "硅", unit: "元/吨", em: "225.sim", chain: "硅料/铝合金/硅碳负极" },
    锂: { symbol: "LC0", sina: "nf_LC0", name: "碳酸锂主连", short_name: "碳酸锂", market: "广期所", kind: "锂", unit: "元/吨", em: "225.lcm", chain: "锂盐/正极/电解液" },
    锰: { symbol: "SM0", sina: "nf_SM0", name: "锰硅主连", short_name: "锰硅", market: "郑商所", kind: "锰", unit: "元/吨", em: "115.SMM", chain: "锰硅合金/炼钢" }
};

// 材料链：同一批材料在产业链上经常同时出现、上下游相连。
//   作用：直接命中某个材料时，能顺着链子带出「配套材料」，这是联想的关键一步。
//   成员格式 [材料名, 在链上的角色]，角色用于解释「为什么它会跟这个材料一起出现」。
const MATERIAL_CHAINS = [
    {
        key: "battery", name: "锂电材料链", note: "正极 / 负极 / 电解液 / 集流体一整套",
        members: [
            ["锂", "正极与电解液"], ["镍", "三元正极"], ["钴", "三元正极稳定层"], ["锰", "磷酸锰铁锂"],
            ["磷", "磷酸铁锂正极"], ["石墨", "负极材料"], ["硅", "硅碳负极"], ["钠", "钠离子路线"],
            ["硫", "硫化物电解质"], ["铝", "集流体与外壳"], ["铜", "集流体与线束"], ["稀土", "永磁电机"], ["钛", "涂覆与隔膜"]
        ]
    },
    {
        key: "semi", name: "半导体材料链", note: "衬底 → 靶材 → 互连 → 封装",
        members: [
            ["硅", "晶圆衬底"], ["锗", "红外与光通讯衬底"], ["砷化镓", "射频与光芯片"], ["氮化镓", "射频与快充"],
            ["碳化硅", "功率器件衬底"], ["铜", "互连与铜箔"], ["钽", "扩散阻挡层与电容"], ["铪", "高 k 栅介质"],
            ["钨", "接触孔与靶材"], ["钼", "靶材与阻挡层"], ["锡", "焊料"], ["金", "键合与镀层"], ["稀土", "CMP 抛光粉"],
            ["铈", "抛光液主成分"], ["锑", "硅片掺杂"], ["碲", "化合物半导体"]
        ]
    },
    {
        key: "pv", name: "光伏材料链", note: "硅料 → 硅片 → 电池片 → 组件 → 电站",
        members: [
            ["工业硅", "多晶硅原料"], ["多晶硅", "硅料"], ["石英砂", "石英坩埚原料"], ["银", "正银浆料"],
            ["铝", "组件边框与背板"], ["铜", "焊带与汇流条"], ["锡", "焊带镀锡"], ["石墨", "热场与坩埚"],
            ["铟", "HJT 靶材"], ["镓", "CIGS 靶材"], ["硒", "CIGS 吸收层"], ["碲", "CdTe 吸收层"], ["镉", "CdTe 组件"], ["钨", "金刚线母线"]
        ]
    },
    {
        key: "magnet", name: "稀土永磁链", note: "矿 → 分离 → 金属 → 磁体 → 电机",
        members: [
            ["稀土", "分离与总量指标"], ["镨钕", "钕铁硼主成分"], ["钕", "钕铁硼"], ["镝", "耐温与矫顽力"],
            ["铽", "高矫顽力添加"], ["镧", "储氢与玻璃"], ["铈", "抛光与储氧"], ["钴", "钐钴磁体"],
            ["硅", "磁体添加与硅钢"], ["铝", "磁体包覆"], ["铜", "电机绕组"], ["锆", "陶瓷与包覆"], ["钒", "磁材添加"]
        ]
    },
    {
        key: "pgm", name: "铂族金属链", note: "矿 → 精炼 → 催化剂 / 首饰 / 玻璃",
        members: [
            ["铂", "催化剂与首饰"], ["钯", "加氢催化与首饰"], ["铑", "三元催化"], ["钌", "化工催化"],
            ["铱", "电解槽电极"], ["银", "电子与首饰合金"], ["铜", "催化剂载体"], ["镍", "耐蚀与催化剂"], ["铬", "催化剂前体"]
        ]
    },
    {
        key: "base", name: "基本金属链", note: "冶炼 → 加工 → 终端制造",
        members: [
            ["铜", "线缆与导体"], ["铝", "轻量化与导体"], ["锌", "镀锌与合金"], ["铅", "铅酸电池"], ["镍", "不锈钢与电池"],
            ["锡", "焊料"], ["镁", "轻量化与脱硫"], ["锰", "合金化"], ["铬", "不锈钢与电镀"], ["硅", "铝合金与硅钢"]
        ]
    },
    {
        key: "steel", name: "钢铁合金链", note: "合金化元素与耐蚀材料",
        members: [
            ["锰", "锰钢与脱氧"], ["铬", "不锈钢"], ["镍", "高强钢与不锈钢"], ["钒", "微合金化"], ["钼", "高强与耐热钢"],
            ["铌", "高强钢微合金化"], ["钛", "微合金化与防腐"], ["铜", "耐蚀与导电"], ["锌", "镀锌防腐"], ["锡", "镀锡板"], ["钨", "耐磨模具"]
        ]
    },
    {
        key: "superalloy", name: "高温合金链", note: "镍基 / 钴基高温合金与难熔金属",
        members: [
            ["镍", "镍基高温合金基体"], ["钴", "钴基高温合金"], ["铬", "耐蚀与抗氧化"], ["钼", "固溶强化"],
            ["钨", "固溶强化"], ["铼", "单晶叶片不可替代"], ["铌", "难熔与超导"], ["钽", "难熔与电容"], ["铪", "难熔与涂层"],
            ["钛", "钛合金部件"], ["铝", "γ′ 强化"], ["硼", "晶界强化"]
        ]
    },
    {
        key: "hardmetal", name: "硬质合金链", note: "碳化钨基硬质合金与涂层刀具",
        members: [
            ["钨", "碳化钨主体"], ["钴", "粘结相"], ["钼", "高速钢与模具钢"], ["钽", "添加剂与电容"],
            ["铌", "添加剂"], ["钛", "涂层 TiN/TiAlN"], ["钒", "工具钢"], ["锆", "陶瓷刀具"], ["镍", "基体"]
        ]
    },
    {
        key: "hydrogen", name: "氢能材料链", note: "制氢 → 储运 → 燃料电池",
        members: [
            ["铂", "燃料电池与电解水催化剂"], ["铱", "PEM 阳极催化剂"], ["钌", "催化剂与耐蚀"], ["钯", "储氢与提纯"],
            ["镍", "碱性电解槽电极"], ["钛", "双极板与结构"], ["石墨", "气体扩散层"], ["稀土", "储氢合金"], ["镧", "AB5 储氢合金"], ["钴", "储氢合金"]
        ]
    },
    {
        key: "nuclear", name: "核材料链", note: "燃料包壳 → 控制材料 → 结构与屏蔽",
        members: [
            ["锆", "燃料包壳"], ["铪", "控制棒吸收体"], ["镍", "传热管与合金"], ["钛", "冷凝器与管路"],
            ["铟", "控制棒合金"], ["银", "控制棒合金"], ["镉", "控制棒与屏蔽"], ["铍", "惯性与光学件"],
            ["铜", "发电机绕组"], ["钨", "第一壁与屏蔽"], ["铌", "超导磁体"], ["钼", "耐蚀结构"], ["镧", "储氢与玻璃"]
        ]
    },
    {
        key: "optical", name: "光学与光电子链", note: "光学玻璃 → 红外探测 → 光模块",
        members: [
            ["锗", "红外镜头与光纤预制棒"], ["镧", "高折射光学玻璃"], ["蓝宝石", "窗口与盖板"], ["石英砂", "石英玻璃"],
            ["铈", "光学抛光粉"], ["稀土", "激光晶体与荧光"], ["铟", "InP 光芯片与透明电极"], ["铪", "高折射镀膜"],
            ["钽", "镀膜靶材"], ["硅", "光芯片基底"], ["镓", "光电器件"], ["金", "连接器镀层"]
        ]
    },
    {
        key: "raremetal", name: "战略小金属链", note: "分散、难回收但关键的稀散金属",
        members: [
            ["锑", "阻燃剂与光伏玻璃"], ["钨", "硬质合金与刀具"], ["钼", "合金与靶材"], ["铋", "低熔点合金与医药"],
            ["硒", "光伏与玻璃"], ["碲", "CdTe 与热电"], ["镉", "CdTe 与镍镉电池"], ["铟", "ITO 与 InP"],
            ["镓", "GaN 与 CIGS"], ["锗", "红外与光纤"], ["铼", "航空发动机"], ["铪", "核与航空涂层"], ["铍", "光学与惯性器件"]
        ]
    },
    {
        key: "agri", name: "农业与化肥链", note: "磷钾肥 → 微量元素 → 包装与农膜",
        members: [
            ["磷", "磷肥与磷酸盐"], ["钾", "钾肥"], ["硫", "硫酸与硫磺"], ["硼", "硼肥与硼硅玻璃"],
            ["氟", "氟化工与含氟材料"], ["硅", "硅肥与土壤改良"], ["锌", "微量元素肥料"], ["铝", "土壤调理"]
        ]
    }
];

function materialHint(name) {
    const raw = MATERIAL_SYMBOL_HINTS[String(name || "").trim()];
    return raw ? Object.assign({}, raw) : null;
}

const MATERIAL_INDEX = new Map();
Object.keys(MATERIAL_CATALOG).forEach(cat => {
    MATERIAL_CATALOG[cat].forEach(n => MATERIAL_INDEX.set(n, cat));
});

const MATERIAL_EXAMPLES = ["AI", "算力中心", "光伏", "新能源车", "人形机器人", "半导体", "军工", "液冷", "氢能", "稀土", "固态电池", "钠离子电池", "3D打印", "商业航天", "化肥"];

// 归一化：小写、全角符号转空格、压缩空白
function normTerm(s) {
    return String(s == null ? "" : s).toLowerCase()
        .replace(/[\s\u3000]+/g, " ")
        .replace(/[()\[\]{}<>《》"'“”‘’·、,，。;；:：!！?？~`@#$%^&*+=|\\/_-]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();
}

// 查询与单个关键词的匹配度：完全相同 > 查询包含关键词 > 关键词包含查询
function termScore(cands, q) {
    let best = 0;
    for (const raw of cands) {
        const a = normTerm(raw);
        if (!a) continue;
        if (a === q) return 1;
        if (a.length >= 2 && q.indexOf(a) >= 0) {
            best = Math.max(best, Math.min(0.97, 0.6 + 0.3 * (a.length / Math.max(q.length, 1))));
        } else if (q.length >= 2 && a.indexOf(q) >= 0) {
            best = Math.max(best, 0.72);
        }
    }
    return best;
}

// 查询词拆分：支持「AI 液冷」「光伏+硅」「新能源车, 电机」这类组合输入
function splitQueryTokens(q) {
    return String(q || "").split(/[\s,，、;；/|]+/).map(s => normTerm(s)).filter(Boolean);
}

// 场景对一个查询词的匹配度：整串也试一次（多词别名整体命中更准）
function topicAliasScore(topic, tokens, whole) {
    let best = 0, via = "";
    const tryList = (src) => {
        for (const raw of topic.alias || []) {
            const sc = termScore([raw], src);
            if (sc > best) { best = sc; via = raw; }
        }
    };
    for (const tk of tokens) tryList(tk);
    if (tokens.length > 1) tryList(whole);
    // key 是英文短标识（如 rail），只能整词命中，不能被当作子串匹配，
    // 否则「ai」会误命中 rail / tail 这类内部标识。
    if (normTerm(topic.key) === whole) { best = 1; via = topic.key; }
    return { score: best, via };
}

// 纯函数：便于单测。返回 { q, tokens, matched, items, examples }
//   opts.heat: { 材料名: 近 7 天资讯条数 } —— 只给已在榜材料加权，不凭空造分
function matchMaterials(qRaw, limit, opts) {
    const o = opts || {};
    const lim = Math.max(1, Math.min(30, parseInt(limit, 10) || 12));
    const q = normTerm(qRaw);
    if (!q) return { q: "", tokens: [], matched: [], items: [], examples: MATERIAL_EXAMPLES };

    // 直接问类别（稀土 / 贵金属 / 非金属材料）时，按类别列全部成员
    const catHit = Object.keys(MATERIAL_CATALOG).find(c => normTerm(c) === q);
    if (catHit) {
        return {
            q, tokens: [q], category: catHit,
            matched: [{ key: "category", label: catHit + "（全部成员）", score: 1 }],
            items: MATERIAL_CATALOG[catHit].slice(0, lim).map((n, i) => ({
                rank: i + 1, name: n, cat: catHit,
                score: Math.max(60, 96 - i * 3), relevance: Math.max(60, 96 - i * 3),
                topics: [catHit], scene_weights: [],
                reason: "属于「" + catHit + "」类别",
                why: ["属于「" + catHit + "」类别"],
                direct: false, chains: [], heat: 0
            })),
            examples: MATERIAL_EXAMPLES
        };
    }

    const tokens = splitQueryTokens(q);
    const heat = o.heat || {};

    const bag = new Map();
    const bump = (name, score, reason, label) => {
        let cur = bag.get(name);
        if (!cur) { cur = { name, score: 0, reason: "", labels: [], sceneWeights: {}, chains: [] }; bag.set(name, cur); }
        if (label && cur.labels.indexOf(label) < 0) cur.labels.push(label);
        if (label) cur.sceneWeights[label] = Math.max(cur.sceneWeights[label] || 0, score);
        if (score > cur.score) { cur.score = score; cur.reason = reason; }
    };

    // ① 场景命中（组合查询时主场景满权、次场景折半，避免两个场景互相稀释）
    const hits = [];
    for (const t of MATERIAL_TOPICS) {
        const { score, via } = topicAliasScore(t, tokens, q);
        if (score > 0) hits.push({ topic: t, score, via });
    }
    hits.sort((a, b) => b.score - a.score);
    hits.forEach((h, idx) => {
        const w = idx === 0 ? 1 : 0.5;
        h.topic.items.forEach(it => bump(it[0], it[1] * h.score * w, it[2], h.topic.label));
    });

    // ② 直接命中材料名（如「碳酸锂」「沪铜」「稀土」）：该材料置顶
    const directNames = [];
    const collectDirect = (src) => {
        MATERIAL_INDEX.forEach((cat, name) => {
            const sc = termScore([name].concat(MATERIAL_ALIAS[name] || []), src);
            if (sc >= 0.8 && !directNames.some(d => d.name === name)) directNames.push({ name, cat, score: sc });
        });
    };
    collectDirect(q);
    // 组合查询里可能没有整串命中，逐个词再试一次（"AI 碳酸锂"）
    if (!directNames.length && tokens.length > 1) tokens.forEach(tk => collectDirect(tk));

    if (directNames.length) {
        directNames.forEach(d => {
            const cur = bag.get(d.name);
            if (cur) {
                cur.score = Math.max(cur.score, 100);
                cur.direct = true;
                if (!cur.reason) cur.reason = "直接命中材料名";
            } else {
                bag.set(d.name, { name: d.name, score: 100, reason: "直接命中材料名", labels: [], sceneWeights: {}, chains: [], direct: true });
            }
        });
        // ③ 材料链联动：顺着链子带出配套材料（这是「联想」最有价值的一步）
        //    同链加权递减：第一条链 +4，之后每条 +2，最多保留 3 条链，避免长名单灌水
        const usedChains = new Set();
        directNames.forEach(d => {
            MATERIAL_CHAINS.forEach(c => {
                if (usedChains.has(c.key)) return;
                if (!c.members.some(m => m[0] === d.name)) return;
                usedChains.add(c.key);
                c.members.forEach(([mn, role]) => {
                    if (mn === d.name) return;
                    const cur = bag.get(mn);
                    if (cur) {
                        if (cur.chains.length < 3) {
                            cur.score += cur.chains.length === 0 ? 4 : 2;
                            cur.chains.push({ chain: c.key, name: c.name, role });
                        }
                    } else {
                        bag.set(mn, {
                            name: mn, score: 54,
                            reason: "与「" + d.name + "」同属「" + c.name + "」",
                            labels: [], sceneWeights: {},
                            chains: [{ chain: c.key, name: c.name, role }]
                        });
                    }
                });
            });
        });
        // ④ 直接命中材料时，把它所在的重点场景（最多 2 个）带出来做邻居，
        //    这样结果里能看到「这个材料常出现在哪些场景、那些场景还牵动哪些材料」
        for (const d of directNames) {
            const tlist = [];
            for (const t of MATERIAL_TOPICS) {
                const it = t.items.find(x => x[0] === d.name);
                if (!it || it[1] < 70) continue;
                if (hits.some(h => h.topic === t)) continue;   // 该场景已被查询词命中，按满权算
                tlist.push({ t, w: it[1] });
            }
            tlist.sort((a, b) => b.w - a.w);
            tlist.slice(0, 2).forEach(({ t }) => {
                for (const x of t.items) {
                    const sc = x[1] * 0.45;
                    const cur = bag.get(x[0]);
                    if (cur) {
                        cur.score = Math.max(cur.score, sc);
                        if (!cur.labels.includes(t.label)) cur.labels.push(t.label);
                        cur.sceneWeights[t.label] = Math.max(cur.sceneWeights[t.label] || 0, sc);
                    } else {
                        bag.set(x[0], {
                            name: x[0], score: sc, reason: x[2],
                            labels: [t.label], sceneWeights: { [t.label]: sc }, chains: []
                        });
                    }
                }
            });
        }
    }

    // ⑤ 跨场景通用加分：同一材料被多个主题命中，说明它通用性强
    bag.forEach(v => {
        if (v.labels.length > 1) v.score += Math.min(15, (v.labels.length - 1) * 5);
    });

    // ⑤ 资讯热度加权：库内真有消息的材料往前排，没有就是没有，不估算
    bag.forEach(v => {
        const h = Number(heat[v.name]) || 0;
        v.heat = h;
        if (h > 0) v.score += Math.min(12, Math.log2(1 + h) * 4);
    });

    const picked = [...bag.values()]
        .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name, "zh"))
        .slice(0, lim);
    // 命中多个主题时分数会叠加（跨场景通用的材料更靠前），可能超过 100；
    // 这种情况按最高分等比压回 100，避免整列都是 100 看不出差别。
    const top = picked.length ? picked[0].score : 0;
    const items = picked.map((r, i) => {
        const scenes = Object.keys(r.sceneWeights || {}).sort((a, b) => r.sceneWeights[b] - r.sceneWeights[a]);
        const why = [];
        if (r.direct) why.push("直接命中材料名");
        if (scenes.length) why.push("命中场景：" + scenes.join("、"));
        if (r.labels.length > 1) why.push("跨场景通用：" + r.labels.length + " 个场景");
        (r.chains || []).forEach(c => why.push("同链：" + c.name + "（" + c.role + "）"));
        if (r.heat > 0) why.push("近 7 天库内资讯提及 " + r.heat + " 条");
        return {
            rank: i + 1, name: r.name,
            cat: MATERIAL_INDEX.get(r.name) || "",
            score: Math.round(r.score * 10) / 10,
            relevance: Math.max(1, Math.min(100, Math.round(top > 100 ? r.score * 100 / top : r.score))),
            topics: scenes.slice(0, 3),
            scene_weights: scenes.map(s => ({ label: s, weight: Math.round(r.sceneWeights[s]) })),
            reason: r.reason || "",
            why,
            direct: !!r.direct,
            chains: r.chains || [],
            heat: r.heat || 0
        };
    });

    return {
        q,
        tokens,
        matched: hits.slice(0, 4).map(h => ({ key: h.topic.key, label: h.topic.label, score: Math.round(h.score * 100) / 100, via: h.via })),
        items,
        examples: MATERIAL_EXAMPLES
    };
}

// 反向联想：给一个材料名，列出它用在哪些场景、属于哪些材料链、配套材料是谁。
function matchMaterialReverse(nameRaw) {
    const raw = String(nameRaw == null ? "" : nameRaw).trim();
    if (!raw) return { name: "", cat: "", aliases: [], scenes: [], chains: [], related: [] };
    const key = normTerm(raw);
    let real = raw, cat = MATERIAL_INDEX.get(raw) || "";
    if (!cat) {
        for (const k of Object.keys(MATERIAL_ALIAS)) {
            if ((MATERIAL_ALIAS[k] || []).some(a => normTerm(a) === key)) { real = k; cat = MATERIAL_INDEX.get(k) || ""; break; }
        }
    }
    if (!cat) {
        for (const k of MATERIAL_INDEX.keys()) {
            if (normTerm(k) === key) { real = k; cat = MATERIAL_INDEX.get(k) || ""; break; }
        }
    }
    const scenes = [];
    for (const t of MATERIAL_TOPICS) {
        const it = t.items.find(x => x[0] === real);
        if (!it) continue;
        scenes.push({ key: t.key, label: t.label, weight: it[1], reason: it[2] });
    }
    scenes.sort((a, b) => b.weight - a.weight);
    const chains = [];
    const related = new Map();
    for (const c of MATERIAL_CHAINS) {
        const hit = c.members.filter(m => m[0] === real);
        if (!hit.length) continue;
        const siblings = c.members.filter(m => m[0] !== real)
            .map(m => ({ name: m[0], role: m[1], cat: MATERIAL_INDEX.get(m[0]) || "" }));
        chains.push({ key: c.key, name: c.name, note: c.note, role: hit[0][1] || "", siblings });
        siblings.forEach(s => {
            if (!related.has(s.name)) related.set(s.name, { name: s.name, cat: s.cat, role: s.role, chains: [] });
            related.get(s.name).chains.push(c.name);
        });
    }
    const relatedList = [...related.values()].sort((a, b) => b.chains.length - a.chains.length || a.name.localeCompare(b.name, "zh"));
    return {
        name: real, cat,
        aliases: (MATERIAL_ALIAS[real] || []).slice(0, 8),
        scenes, chains, related: relatedList
    };
}
// ==== MATERIAL_ENGINE_END ====

// 给结果补上「已接入行情」的品种代码与最新价：材料名/别名能在品种名称、类别、产业链里找到即可
async function getRareMaterialMatch(env, url) {
    const q = cleanStr(url.searchParams.get("q"), 40);
    const limit = Math.max(1, Math.min(30, parseInt(url.searchParams.get("limit"), 10) || 12));
    let insts = [], quotes = {};
    try {
        insts = await listInstruments(env, "", {});
        const rows = (await env.DB.prepare("SELECT symbol,price,change_pct,unit,updated_at FROM metal_quotes").all()).results || [];
        rows.forEach(r => { quotes[r.symbol] = r; });
    } catch (e) { logWarn("rare.match.quotes", e); }

    // 近 7 天资讯提及：只统计库内真实抓到的消息，不再输出「相关度」这类凭空分数
    const since = beijingStamp(Date.now() - 7 * 86400000).slice(0, 10);
    let newsHay = [];
    try {
        const rows = (await env.DB.prepare("SELECT title, keywords FROM news WHERE substr(fetched_at,1,10) >= ? ORDER BY id DESC LIMIT 3000").bind(since).all()).results || [];
        newsHay = rows.map(r => (String(r.title || "") + " " + String(r.keywords || "")).toLowerCase());
    } catch (e) { logWarn("rare.match.news", e); }
    const countMentions = terms => {
        const list = terms.filter(Boolean);
        if (!list.length || !newsHay.length) return 0;
        let n = 0;
        for (const hay of newsHay) { if (list.some(t => hay.indexOf(t) >= 0)) n++; }
        return n;
    };
    // 提及词表：单字材料名（金/银/锂）直接做子串匹配会误命中「银行」「现金」等，只用别名统计
    const mentionTermsOf = name => {
        const names = [name].concat(MATERIAL_ALIAS[name] || []).map(n => String(n).toLowerCase());
        return String(name).length <= 1 && (MATERIAL_ALIAS[name] || []).length
            ? MATERIAL_ALIAS[name].map(n => String(n).toLowerCase())
            : names;
    };

    // 两遍匹配：第一遍拿到候选材料，算出真实资讯热度；第二遍把热度作为加权再排一次。
    //   热度只影响排序，不影响「是否相关」，避免没消息的好材料被挤掉。
    const first = matchMaterials(q, limit);
    const heat = {};
    first.items.forEach(it => { heat[it.name] = countMentions(mentionTermsOf(it.name)); });
    const res = matchMaterials(q, limit, { heat });

    res.items = res.items.map(it => {
        const names = [it.name].concat(MATERIAL_ALIAS[it.name] || []).map(n => String(n).toLowerCase());
        const mentions = countMentions(mentionTermsOf(it.name));
        const h = materialHint(it.name);
        // 有明确映射的材料只认映射里的代码：否则库里只加了「氧化铝」时，
        //   「铝」会被名称/类别包含匹配误判成已接入，反而加不了沪铝。
        const inst = h
            ? insts.find(i => i.symbol === h.symbol || i.name === h.name || i.short_name === h.short_name)
            : insts.find(i => {
                const hay = [i.name, i.short_name, i.kind, i.chain].join(" ").toLowerCase();
                return names.some(n => n && hay.indexOf(n) >= 0);
            });
        if (!inst) {
            // 还没接入：告诉前端「这个材料能不能一键接进来」
            return Object.assign({}, it, {
                news_7d: mentions,
                tradable: false,
                can_add: !!h,
                hint: h ? { symbol: h.symbol, name: h.name, market: h.market || "", unit: h.unit || "" } : null
            });
        }
        const qq = quotes[inst.symbol] || null;
        return Object.assign({}, it, {
            news_7d: mentions,
            tradable: true,
            can_add: false,
            symbol: inst.symbol,
            instrument: inst.short_name || inst.short_name || inst.name,
            unit: inst.unit || "",
            price: qq ? Number(qq.price) : null,
            change_pct: qq ? Number(qq.change_pct) : null,
            quoted: !!qq,
            quote_at: qq ? qq.updated_at : ""
        });
    });
    const summary = {
        total: res.items.length,
        tradable: res.items.filter(i => i.tradable).length,
        addable: res.items.filter(i => !i.tradable && i.can_add).length,
        manual: res.items.filter(i => !i.tradable && !i.can_add).length,
        news_win_from: since,
        news_rows: newsHay.length,
        scenes: (res.matched || []).map(m => m.label),
        chains: [...new Set(res.items.flatMap(i => (i.chains || []).map(c => c.name)))]
    };
    return json(Object.assign({}, res, { limit, summary, generated_at: nowBeijing() }));
}

// 场景目录：把知识库里的行业 / 场景、材料类别、材料链一次性下发给前端做导航
async function getRareTopics(env) {
    const topics = MATERIAL_TOPICS.map(t => ({
        key: t.key,
        label: t.label,
        alias: (t.alias || []).slice(0, 8),
        count: t.items.length,
        top: t.items.slice(0, 5).map(it => ({ name: it[0], weight: it[1] }))
    }));
    const categories = Object.keys(MATERIAL_CATALOG).map(c => ({
        name: c, count: MATERIAL_CATALOG[c].length, members: MATERIAL_CATALOG[c].slice(0, 12)
    }));
    const chains = MATERIAL_CHAINS.map(c => ({
        key: c.key, name: c.name, note: c.note, count: c.members.length,
        members: c.members.map(m => m[0])
    }));
    // 每个场景近 7 天有多少条库内消息，供前端标热度（没有就是 0，不估算）
    const since = beijingStamp(Date.now() - 7 * 86400000).slice(0, 10);
    const heat = {};
    try {
        const rows = (await env.DB.prepare("SELECT title, keywords FROM news WHERE substr(fetched_at,1,10) >= ? ORDER BY id DESC LIMIT 3000").bind(since).all()).results || [];
        const hay = rows.map(r => (String(r.title || "") + " " + String(r.keywords || "")).toLowerCase());
        topics.forEach(t => {
            const terms = (t.alias || []).map(a => String(a).toLowerCase()).filter(a => a.length >= 2);
            heat[t.key] = terms.length ? hay.filter(h => terms.some(x => h.indexOf(x) >= 0)).length : 0;
        });
    } catch (e) { logWarn("rare.topics.news", e); }
    topics.forEach(t => { t.news_7d = heat[t.key] || 0; });
    return json({
        topics, categories, chains,
        examples: MATERIAL_EXAMPLES,
        materials: [...MATERIAL_INDEX.keys()],
        total_materials: MATERIAL_INDEX.size,
        total_scenes: MATERIAL_TOPICS.length,
        generated_at: nowBeijing()
    });
}

// 反向联想：材料 → 用在哪些场景 / 属于哪些材料链 / 配套材料是谁
async function getRareMaterialReverse(env, url) {
    const name = cleanStr(url.searchParams.get("name"), 40);
    if (!name) return json({ error: "缺少材料名" }, 400);
    const rev = matchMaterialReverse(name);
    if (!rev.name) return json({ name: "", scenes: [], chains: [], related: [], message: "没有识别到这个材料" });
    let inst = null, quote = null;
    try {
        const insts = await listInstruments(env, "", {});
        const h = materialHint(rev.name);
        inst = h
            ? insts.find(i => i.symbol === h.symbol || i.name === h.name || i.short_name === h.short_name) || null
            : insts.find(i => {
                const hay = [i.name, i.short_name, i.kind, i.chain].join(" ").toLowerCase();
                return [rev.name].concat(MATERIAL_ALIAS[rev.name] || []).some(n => n && hay.indexOf(String(n).toLowerCase()) >= 0);
            }) || null;
        if (inst) {
            const qq = await env.DB.prepare("SELECT symbol,price,change_pct,unit,updated_at FROM metal_quotes WHERE symbol = ?").bind(inst.symbol).first();
            quote = qq || null;
        }
    } catch (e) { logWarn("rare.reverse", e); }
    const hint = materialHint(rev.name);
    return json(Object.assign({}, rev, {
        tradable: !!inst,
        can_add: !inst && !!hint,
        hint: hint ? { symbol: hint.symbol, name: hint.name, market: hint.market || "", unit: hint.unit || "" } : null,
        symbol: inst ? inst.symbol : "",
        instrument: inst ? (inst.short_name || inst.name) : "",
        price: quote ? Number(quote.price) : null,
        change_pct: quote ? Number(quote.change_pct) : null,
        unit: inst ? (inst.unit || "") : "",
        generated_at: nowBeijing()
    }));
}

async function getRareBoard(env, url) {
    const quotes = await readRareQuotes(env, url && url.searchParams.get("refresh") === "1");
    // 品种清单含停用项：前端「品种管理」要用，报价只算启用的
    const allInst = await rareInstruments(env, true);
    const enabled = allInst.filter(i => Number(i.enabled) === 1);
    const tiles = quotes.map(heatTile);
    const avg = tiles.length ? tiles.reduce((s, t) => s + t.change_pct, 0) / tiles.length : 0;
    return json({
        quotes: quotes.map(q => ({ ...q, direction: (Number(q.change_pct) || 0) >= 0 ? "up" : "down" })),
        heatmap: { tiles, steps: HEAT_STEPS },
        framework: RARE_FRAMEWORK,
        instruments: enabled,
        all_instruments: allInst,
        stats: {
            count: quotes.length,
            up: tiles.filter(t => t.dir === "up").length,
            down: tiles.filter(t => t.dir === "down").length,
            flat: tiles.filter(t => t.dir === "flat").length,
            avg_change_pct: round2(avg),
            best: tiles.slice().sort((a, b) => b.change_pct - a.change_pct)[0] || null,
            worst: tiles.slice().sort((a, b) => a.change_pct - b.change_pct)[0] || null
        },
        // 用最新的那条报价时间：新品种刚采到时首条可能还是旧的，取 max 才不会显示成「几小时前」
        updated_at: quotes.reduce((m, q) => (String(q.updated_at || "") > m ? String(q.updated_at) : m), ""),
        disclaimer: "情景区间为波动率推演，不是价格预测；不构成投资建议。"
    });
}

// 稀有金属：单品种 / 全品种三情景推演
async function getRareScenarios(env, url) {
    const only = String(url.searchParams.get("symbol") || "").toUpperCase();
    const horizon = Math.max(1, Math.min(120, parseInt(url.searchParams.get("days")) || 21));
    const pool = await rareInstruments(env);
    if (!pool.length) {
        return json({ horizon_days: horizon, risk_budget_pct: 0, items: [], skipped: [], note: "还没有启用任何稀有金属品种，去「品种管理」添加一个" });
    }
    const targets = only ? pool.filter(i => i.symbol === only) : pool;
    if (!targets.length) return json({ error: "未知品种" }, 400);
    // 没有东财 secid 的品种取不到历史 K 线，无法做波动率推演：单独列出来给前端提示
    const skipped = targets.filter(i => !i.em).map(i => ({ symbol: i.symbol, name: i.short_name || i.name }));
    const targetsK = targets.filter(i => i.em);
    const note = targetsK.length ? "" : "已配置的品种都没有填「东财 secid」，取不到历史 K 线，暂时无法推演（可在「品种管理」里补上）";
    const quotes = await readRareQuotes(env, false);
    const by = {};
    quotes.forEach(q => { by[q.symbol] = q; });
    const riskBudget = await acquireNum(env, "metal", "rare_risk_budget", 2, 0.5, 10);

    const items = await Promise.all(targetsK.map(async inst => {
        const cacheKey = inst.symbol + "|" + horizon;
        const hit = RARE_SCENARIO_CACHE.get(cacheKey);
        if (hit && Date.now() - hit.at < RARE_SCENARIO_TTL) return hit.data;
        let rows = [];
        try { rows = await fetchMetalKline(inst.em, 101, ymd(365)); } catch (e) { logWarn("rare.kline", e); }
        const closes = rows.map(r => Number(r.c)).filter(v => Number.isFinite(v) && v > 0);
        const q = by[inst.symbol] || {};
        const price = Number(q.price) || closes[closes.length - 1] || 0;
        const bands = scenarioBands(price, closes, horizon);
        // 技术面校验：均线与区间位置，用于判断当前处在哪一段
        const ma20 = closes.length >= 20 ? closes.slice(-20).reduce((a, b) => a + b, 0) / 20 : null;
        const ma60 = closes.length >= 60 ? closes.slice(-60).reduce((a, b) => a + b, 0) / 60 : null;
        const win = closes.slice(-120);
        const hi = win.length ? Math.max(...win) : 0, lo = win.length ? Math.min(...win) : 0;
        const pos = hi > lo ? ((price - lo) / (hi - lo)) * 100 : null;
        const data = {
            symbol: inst.symbol, name: inst.short_name, chain: inst.chain, unit: inst.unit,
            price, change_pct: Number(q.change_pct) || 0, prev_close: Number(q.prev_close) || 0,
            scenarios: bands,
            // 波动率约束下的仓位上限：单品种波动预算 / 年化波动率
            position_cap_pct: bands && bands.sigma_annual_pct > 0
                ? round2(Math.max(1, Math.min(25, (riskBudget / bands.sigma_annual_pct) * 100))) : null,
            risk_budget_pct: riskBudget,
            tech: {
                ma20: ma20 ? round2(ma20) : null,
                ma60: ma60 ? round2(ma60) : null,
                ma20_state: ma20 ? (price >= ma20 ? "价格在 MA20 上方" : "价格在 MA20 下方") : "样本不足",
                ma60_state: ma60 ? (price >= ma60 ? "价格在 MA60 上方" : "价格在 MA60 下方") : "样本不足",
                range_120: hi && lo ? { high: round2(hi), low: round2(lo) } : null,
                range_pos_pct: pos == null ? null : round2(pos)
            },
            framework: RARE_FRAMEWORK[inst.symbol] || null,
            kline_points: closes.slice(-60).map((c, i) => ({ i, c })),
            bars: closes.length
        };
        RARE_SCENARIO_CACHE.set(cacheKey, { at: Date.now(), data });
        return data;
    }));
    return json({
        horizon_days: horizon,
        risk_budget_pct: riskBudget,
        items,
        skipped,
        note,
        generated_at: nowBeijing(),
        disclaimer: "情景区间由近 60 个交易日对数收益率的漂移与波动率外推得到（假设近似对数正态），仅用于风险刻度参考，不构成任何投资建议。"
    });
}


// ============================================================
// 品种管理（稀有金属可配置）：列表 / 保存 / 删除 / 检测
//   品种元数据（代码、行情代码、名称、市场、类别、单位、东财 secid）
//   全部存 metal_instruments，改完立即清缓存，采集与展示同时生效。
// ============================================================
const SINA_PREFIXES = [
    { value: "nf", label: "内盘期货 nf_", hint: "沪镍、碳酸锂、工业硅等国内商品期货，如 nf_LC0" },
    { value: "hf", label: "外盘现货/期货 hf_", hint: "伦敦金银、纽约铂钯、COMEX，如 hf_XAU" },
    { value: "gds", label: "上金所延期 gds_", hint: "黄金/白银 T+D，如 gds_AUTD" }
];

function normalizeSinaKey(sinaRaw, prefixRaw, symbolRaw) {
    // 新浪的代码是大小写敏感的：前缀小写、代码大写（nf_LC0 / hf_XAU / gds_AUTD）
    const m = /^(nf|hf|gds)_([A-Za-z0-9]+)$/i.exec(String(sinaRaw || "").trim());
    if (m) return m[1].toLowerCase() + "_" + m[2].toUpperCase();
    const prefix = String(prefixRaw || "").trim().toLowerCase();
    if (!["nf", "hf", "gds"].includes(prefix)) return "";
    const code = String(symbolRaw || "").trim().replace(/[^A-Za-z0-9]/g, "").toUpperCase();
    return code ? prefix + "_" + code : "";
}

function instrumentPublic(r) {
    return {
        symbol: r.symbol, sina: r.sina, name: r.name, short_name: r.short_name || r.name,
        market: r.market || "", kind: r.kind || "", unit: r.unit || "",
        currency: r.currency || "CNY", em: r.em || "", chain: r.chain || "",
        scope: r.scope || "rare", enabled: Number(r.enabled) === 1 ? 1 : 0,
        sort_order: Number(r.sort_order) || 0, builtin: Number(r.builtin) === 1 ? 1 : 0,
        updated_at: r.updated_at || ""
    };
}

// —— 探测单个新浪行情代码（品种管理的「检测」用）——
//   返回解析后的现价 / 昨收 / 涨跌幅 / 报价时间，以及接口里带的品种中文名
async function probeSinaQuote(sinaKey) {
    const url = "https://hq.sinajs.cn/list=" + sinaKey;
    const r = await fetchWithTimeout(url, { headers: { "Referer": "https://finance.sina.com.cn", "User-Agent": NEWS_UA } }, 9000);
    if (!r.ok) throw new Error("行情接口 HTTP " + r.status);
    const text = decodeGbk(await r.arrayBuffer());
    const m = text.match(new RegExp("var\\s+hq_str_" + sinaKey + "\\s*=\\s*\"([^\"]*)\"", "i"));
    if (!m || !String(m[1] || "").trim()) throw new Error("新浪未返回该代码的行情，代码可能不存在或合约已下线");
    const f = m[1].split(",");
    const fam = sinaKey.slice(0, 2);
    let price = 0, prev = 0, high = 0, low = 0, qtime = "", qdate = "", name = "";
    if (fam === "hf") {
        price = numOf(f[0]); prev = numOf(f[7]) || numOf(f[1]);
        high = numOf(f[4]); low = numOf(f[5]);
        qtime = f[6] || ""; qdate = f[12] || ""; name = f[13] || "";
    } else if (fam === "nf") {
        name = f[0] || "";
        price = numOf(f[8]) || numOf(f[5]); prev = numOf(f[10]);
        high = numOf(f[3]); low = numOf(f[4]);
        qdate = f[17] || ""; qtime = "";
    } else {
        price = numOf(f[0]); prev = numOf(f[7]);
        high = numOf(f[4]); low = numOf(f[5]);
        qtime = f[6] || ""; qdate = f[12] || ""; name = f[13] || "";
    }
    if (!(price > 0)) throw new Error("该代码有返回但价格为 0，可能已停牌或代码有误");
    const change = prev > 0 ? price - prev : 0;
    return {
        sina: sinaKey,
        name: String(name || "").trim(),
        price,
        prev_close: prev,
        change,
        change_pct: prev > 0 ? round2(change / prev * 100) : 0,
        high, low,
        quote_date: qdate, quote_time: qtime
    };
}

async function getInstrumentList(env) {
    const rows = (await rareInstruments(env, true)).map(instrumentPublic);
    // 顺手带上最新报价：列表里能一眼看出「已采到 / 从未采到」
    const quotes = {};
    try {
        const q = (await env.DB.prepare("SELECT symbol,price,change_pct,quote_date,quote_time,updated_at FROM metal_quotes").all()).results || [];
        q.forEach(x => { quotes[x.symbol] = x; });
    } catch (e) { logWarn("instruments.quotes", e); }
    return json({
        rows: rows.map(r => ({ ...r, quote: quotes[r.symbol] || null })),
        kinds: [...new Set(rows.map(r => r.kind).filter(Boolean))],
        markets: [...new Set(rows.map(r => r.market).filter(Boolean))],
        prefixes: SINA_PREFIXES,
        summary: { total: rows.length, enabled: rows.filter(r => r.enabled).length, disabled: rows.filter(r => !r.enabled).length }
    });
}

// —— 材料一键加入监测 ——
//   材料联想里点「+ 监测」时走这里。只处理 MATERIAL_SYMBOL_HINTS 里明确有行情源的材料：
//   先探测新浪行情，探不到就不入库，避免把一个永远不会更新的死品种塞进采集队列。
//   支持 { name } 单个、{ names: [] } 批量（最多 12 个）。
async function quickAddInstrumentMaterial(request, env) {
    const b = await request.json().catch(() => ({}));
    const names = [];
    if (Array.isArray(b.names)) {
        b.names.slice(0, 12).forEach(n => { const v = cleanStr(n, 40); if (v && names.indexOf(v) < 0) names.push(v); });
    } else {
        const one = cleanStr(b.name, 40);
        if (one) names.push(one);
    }
    if (!names.length) return json({ success: false, message: "缺少材料名称" }, 400);

    const results = [];
    for (const name of names) {
        const h = materialHint(name);
        // 先判断「是不是已经在监测」：名称/类别/别名精确对上才算，
        //   不用子串匹配 —— 否则库里只有「氧化铝」时，点「铝」会被误判成已接入。
        const all = await listInstruments(env, "", { includeDisabled: true });
        const want = new Set([name].concat(MATERIAL_ALIAS[name] || []));
        const exist = all.find(i => {
            if (h && (i.symbol === h.symbol || i.name === h.name)) return true;
            const sn = String(i.short_name || ""), kn = String(i.kind || ""), nm = String(i.name || "");
            return want.has(sn) || want.has(kn) || want.has(nm) || want.has(nm.replace(/主连|连续/g, ""));
        });
        if (exist) {
            results.push({
                name, success: true, exists: true, symbol: exist.symbol,
                instrument: exist.short_name || exist.name, enabled: Number(exist.enabled) === 1
            });
            continue;
        }
        if (!h) {
            results.push({ name, success: false, need_manual: true, message: "暂无稳定的免费连续报价，可手动接入" });
            continue;
        }
        let probe;
        try { probe = await probeSinaQuote(h.sina); }
        catch (e) {
            results.push({ name, success: false, message: "探测行情失败：" + e.message });
            continue;
        }
        try {
            const mx = await env.DB.prepare("SELECT MAX(sort_order) AS m FROM metal_instruments WHERE scope='rare'").first();
            const order = (Number(mx && mx.m) || 0) + 10;
            await env.DB.prepare("INSERT INTO metal_instruments(symbol,sina,name,short_name,market,kind,unit,currency,em,chain,scope,enabled,sort_order,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'rare',1,?,0,?,?)")
                .bind(h.symbol, h.sina, h.name, h.short_name, h.market, h.kind, h.unit, "CNY", h.em, h.chain,
                    order, nowBeijing(), nowBeijing()).run();
        } catch (e) {
            results.push({ name, success: false, message: "写入失败：" + e.message });
            continue;
        }
        invalidateInstruments();
        RARE_SCENARIO_CACHE.clear();
        // 顺手把刚探到的报价落库，加完立刻能看到价格，不用等下一轮定时采集
        let quote = null;
        try {
            const inst = (await rareInstruments(env)).find(i => i.symbol === h.symbol);
            const raw = await fetchSinaMetalQuotes([h.symbol], inst ? [inst] : undefined);
            if (raw[h.symbol]) { await upsertQuotes(env, [raw[h.symbol]]); quote = raw[h.symbol]; }
        } catch (e) { logWarn("instrument.quickAddQuote", e); }
        results.push({
            name, success: true, created: true, symbol: h.symbol, instrument: h.short_name,
            price: quote ? quote.price : (probe.price || null),
            change_pct: quote ? quote.change_pct : (probe.change_pct || 0)
        });
    }

    const created = results.filter(r => r.success && r.created).length;
    const exists = results.filter(r => r.success && r.exists).length;
    const manual = results.filter(r => r.need_manual).length;
    const failed = results.filter(r => !r.success && !r.need_manual).length;
    const message = [
        created ? `新增 ${created} 个品种` : "",
        exists ? `${exists} 个已在监测` : "",
        manual ? `${manual} 个暂无行情源` : "",
        failed ? `${failed} 个失败` : ""
    ].filter(Boolean).join("，") || "没有可处理的材料";
    return json({ success: created + exists > 0, created, exists, manual, failed, results, message });
}

async function saveInstrument(request, env) {
    const b = await request.json().catch(() => ({}));
    const symbol = cleanStr(b.symbol, 20).toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (!symbol) return json({ success: false, message: "品种代码不能为空（如 LC0、NI0）" }, 400);
    if (!/^[A-Z0-9]{2,12}$/.test(symbol)) return json({ success: false, message: "品种代码只能是字母 / 数字，2~12 位" }, 400);
    const sina = normalizeSinaKey(b.sina, b.prefix, symbol);
    if (!sina) return json({ success: false, message: "行情代码格式应为 nf_LC0 / hf_XAU / gds_AUTD，或选择前缀后自动拼接" }, 400);
    const name = cleanStr(b.name, 40);
    if (!name) return json({ success: false, message: "品种名称不能为空" }, 400);
    const enabled = (b.enabled === false || b.enabled === 0 || b.enabled === "0") ? 0 : 1;
    // 名称里带「主连 / 连续」时给个更短的简称，列表更好排
    const shortName = cleanStr(b.short_name, 20) || name.replace(/主连|连续/g, "").slice(0, 12) || name;

    let cur = null;
    try {
        cur = await env.DB.prepare("SELECT * FROM metal_instruments WHERE symbol=? AND scope='rare'").bind(symbol).first();
    } catch (e) { logWarn("instrument.find", e); }

    try {
        if (cur) {
            await env.DB.prepare("UPDATE metal_instruments SET sina=?,name=?,short_name=?,market=?,kind=?,unit=?,currency=?,em=?,chain=?,enabled=?,updated_at=? WHERE symbol=? AND scope='rare'")
                .bind(sina, name, shortName, cleanStr(b.market, 20), cleanStr(b.kind, 20), cleanStr(b.unit, 20),
                    cleanStr(b.currency, 8).toUpperCase() === "USD" ? "USD" : "CNY",
                    cleanStr(b.em, 30), cleanStr(b.chain, 30), enabled, nowBeijing(), symbol).run();
        } else {
            const mx = await env.DB.prepare("SELECT MAX(sort_order) AS m FROM metal_instruments WHERE scope='rare'").first();
            const order = (Number(mx && mx.m) || 0) + 10;
            await env.DB.prepare("INSERT INTO metal_instruments(symbol,sina,name,short_name,market,kind,unit,currency,em,chain,scope,enabled,sort_order,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'rare',?,?,0,?,?)")
                .bind(symbol, sina, name, shortName, cleanStr(b.market, 20), cleanStr(b.kind, 20), cleanStr(b.unit, 20),
                    cleanStr(b.currency, 8).toUpperCase() === "USD" ? "USD" : "CNY",
                    cleanStr(b.em, 30), cleanStr(b.chain, 30), enabled, order, nowBeijing(), nowBeijing()).run();
        }
        invalidateInstruments();
        RARE_SCENARIO_CACHE.clear();
    } catch (e) {
        return json({ success: false, message: "保存失败：" + e.message }, 500);
    }

    // 保存后立刻补采一次该品种行情，不用再手动点「刷新行情」
    let quote = null;
    if (enabled) {
        try {
            if (await sourceEnabled(env, "sina_quote")) {
                const inst = (await rareInstruments(env)).find(i => i.symbol === symbol);
                const raw = await fetchSinaMetalQuotes([symbol], inst ? [inst] : undefined);
                if (raw[symbol]) { await upsertQuotes(env, [raw[symbol]]); quote = raw[symbol]; }
            }
        } catch (e) { logWarn("instrument.quoteAfterSave", e); }
    }
    return json({
        success: true, created: !cur, symbol, sina, quote,
        message: quote
            ? (cur ? "已保存，报价已更新" : "已新增并采到最新报价")
            : "已保存，但本次没采到报价 —— 建议点「检测」确认代码"
    });
}

async function deleteInstrument(request, env) {
    const b = await request.json().catch(() => ({}));
    const symbol = cleanStr(b.symbol, 20).toUpperCase();
    if (!symbol) return json({ success: false, message: "缺少品种代码" }, 400);
    const cur = await env.DB.prepare("SELECT * FROM metal_instruments WHERE symbol=? AND scope='rare'").bind(symbol).first();
    if (!cur) return json({ success: false, message: "品种不存在" }, 404);
    if (Number(cur.builtin) === 1) return json({ success: false, message: "内置品种不能删除，可以改成「停用」" }, 400);
    try {
        // 连带清掉报价与历史轨迹，避免删除后大屏 / 图表里还残留一条僵尸数据
        await env.DB.batch([
            env.DB.prepare("DELETE FROM metal_instruments WHERE symbol=? AND scope='rare'").bind(symbol),
            env.DB.prepare("DELETE FROM metal_quotes WHERE symbol=?").bind(symbol),
            env.DB.prepare("DELETE FROM metal_history WHERE symbol=?").bind(symbol),
            env.DB.prepare("DELETE FROM watchlist WHERE symbol=?").bind(symbol),
            env.DB.prepare("DELETE FROM trade_plans WHERE symbol=?").bind(symbol),
            env.DB.prepare("DELETE FROM positions WHERE symbol=?").bind(symbol),
            env.DB.prepare("DELETE FROM price_alerts WHERE symbol=?").bind(symbol)
        ]);
        invalidateInstruments();
        RARE_SCENARIO_CACHE.clear();
    } catch (e) { return json({ success: false, message: "删除失败：" + e.message }, 500); }
    return json({ success: true, symbol });
}

async function testInstrumentQuote(request, env) {
    const b = await request.json().catch(() => ({}));
    const sina = normalizeSinaKey(b.sina, b.prefix, b.symbol || b.code);
    if (!sina) return json({ success: false, message: "行情代码格式应为 nf_LC0 / hf_XAU / gds_AUTD" }, 400);
    let quote = null, message = "";
    try { quote = await probeSinaQuote(sina); }
    catch (e) { message = e && e.message ? e.message : String(e); }

    // 顺带验一下东财历史 K 线：三情景推演依赖它，代码对了但 K 线取不到同样白搭
    let kline = null;
    const em = cleanStr(b.em, 30);
    if (em) {
        try {
            const rows = await fetchMetalKline(em, 101, ymd(90));
            kline = rows.length
                ? { ok: true, bars: rows.length, message: `近 90 天取到 ${rows.length} 根日 K` }
                : { ok: false, bars: 0, message: "东方财富没有返回该 secid 的 K 线，检查 secid 是否正确" };
        } catch (e) {
            kline = { ok: false, bars: 0, message: "K 线请求失败：" + (e.message || e) };
        }
    }
    return json({
        success: !!quote, sina, quote, kline,
        message: quote ? `行情可用：${quote.name || sina} ${quote.price}` : (message || "未取到行情")
    });
}


// ============================================================
// 兼容保留的聚合接口：组合行情板、站内通知与预警状态，供旧客户端或外部调用。
//   当前前端通过工作台接口分别加载对应内容；各分区独立 try/catch，单块数据缺失不影响其他结果。
// ============================================================
async function getDashboard(env, url) {
    const hours = Math.max(1, Math.min(168, parseInt(url.searchParams.get("hours")) || 24));
    const out = { generated_at: nowBeijing(), hours };

    // 1) 行情板 + 热力图
    try {
        const board = await metalBoardData(env);
        out.board = {
            stats: board.stats, derived: board.derived, heatmap: board.heatmap,
            updated_at: board.updated_at, last_refresh: board.last_refresh
        };
    } catch (e) { logWarn("dashboard.board", e); out.board = null; }

    // 5) 站内通知
    try {
        const [unread, latest] = await Promise.all([
            env.DB.prepare("SELECT COUNT(*) n FROM notifications WHERE read=0").first(),
            env.DB.prepare("SELECT id,kind,level,title,body,created_at FROM notifications ORDER BY id DESC LIMIT 4").all()
        ]);
        out.notifications = { unread: Number(unread && unread.n) || 0, latest: latest.results || [] };
    } catch (e) { out.notifications = { unread: 0, latest: [] }; }

    // 6) 预警状态
    try {
        const todayBjStart = nowBeijing().slice(0, 10) + " 00:00:00";
        const [active, todayHit] = await Promise.all([
            env.DB.prepare("SELECT COUNT(*) n FROM price_alerts WHERE enabled=1").first(),
            env.DB.prepare("SELECT COUNT(*) n FROM notifications WHERE kind='alert' AND created_at >= ?").bind(todayBjStart).first()
        ]);
        out.alerts = { active: Number(active && active.n) || 0, triggered_today: Number(todayHit && todayHit.n) || 0 };
    } catch (e) { out.alerts = { active: 0, triggered_today: 0 }; }

    return json(out);
}


// ============================================================
// 金价快照：按 fetch_tasks 的实际间隔采集贵金属行情，生成一条快照落库
// ============================================================
const SNAPSHOT_INTERVAL_MIN = 30;          // 采集间隔默认分钟数（实际以 fetch_tasks 配置为准）
const SNAPSHOT_KEEP = 2000;                // 保留最近多少条快照

// 读取金价快照任务的实际间隔配置（秒）
async function snapshotIntervalSec(env) {
    try {
        const t = await env.DB.prepare("SELECT interval_sec, interval_min FROM fetch_tasks WHERE task_key='metal_snapshot'").first();
        if (t) return taskIntervalSec(t);
    } catch (e) { logWarn("snapshot.interval", e); }
    return SNAPSHOT_INTERVAL_MIN * 60;
}

// 北京时间戳 -> "YYYY-MM-DD HH:MM:SS"
function beijingStamp(epochMs) {
    const d = new Date((epochMs == null ? Date.now() : epochMs) + 8 * 3600 * 1000);
    return d.toISOString().slice(0, 19).replace("T", " ");
}
function epochOf(stamp) {
    const s = String(stamp || "").trim();
    // 带时区的 ISO 字符串按其显式时区解析；不能再按北京时间字符串处理。
    if (/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) {
        const t = Date.parse(s.replace(" ", "T"));
        return Number.isFinite(t) ? t : 0;
    }
    // "YYYY-MM-DD HH:MM:SS"（北京时间）-> 毫秒时间戳
    const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/.exec(s);
    if (!m) return 0;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) - 8 * 3600 * 1000;
}

// SQLite CURRENT_TIMESTAMP 产生 UTC 的无时区字符串；与应用写入的北京时间字符串分开处理。
function epochOfUtcDb(stamp) {
    const s = String(stamp || "").trim();
    if (!s) return 0;
    if (/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) return epochOf(s);
    const t = Date.parse(s.replace(" ", "T") + "Z");
    return Number.isFinite(t) ? t : 0;
}

// 依据「环比上次采集的涨跌幅」判定异动等级（阈值可配置）
function snapshotLevel(pct, surge, alert) {
    const p = Math.abs(Number(pct) || 0);
    const s = Number.isFinite(surge) ? surge : 0.25;
    const a = Number.isFinite(alert) ? alert : 0.8;
    if (p >= a) return "alert";              // 大幅异动
    if (p >= s) return "surge";              // 明显波动
    return "normal";                        // 平稳
}
const LEVEL_LABELS = { normal: "平稳", surge: "明显波动", alert: "大幅异动" };

// —— 采集一次金价快照（每 30 分钟一次）——
async function captureMetalSnapshot(env) {
    const symbols = await acquireList(env, "metal", "metal_symbols");
    const raw = await fetchSinaMetalQuotes(symbols, await listInstruments(env, "metal"));
    const fx = Number(raw.__fx) || 0;
    const quotes = Object.keys(raw).filter(k => k !== "__fx").map(k => raw[k]);
    if (!quotes.length) throw new Error("行情接口未返回有效数据");
    quotes.sort((a, b) => METAL_ORDER.indexOf(a.symbol) - METAL_ORDER.indexOf(b.symbol));
    const by = {};
    quotes.forEach(q => { by[q.symbol] = q; });
    const dv = metalDerived(quotes, fx);

    // —— 环比基准品种：配置的基准 → 若本次未采集到则按优先级回退 ——
    const configuredBase = await acquireOption(env, "metal", "metal_snapshot_base", METAL_DEFAULT_BASE);
    const BASE_FALLBACK = ["AU0", "AG0"];
    let baseSymbol = by[configuredBase] ? configuredBase : "";
    if (!baseSymbol) baseSymbol = BASE_FALLBACK.find(s => by[s] && by[s].price > 0) || quotes[0].symbol;
    const base = by[baseSymbol] || {};
    const basePrice = Number(base.price) || 0;
    const baseUnit = base.unit || "";

    // 上一次同基准品种的快照（用于环比）
    let prevBase = 0;
    try {
        const prev = await env.DB.prepare("SELECT base_price FROM metal_snapshots WHERE base_symbol=? ORDER BY epoch DESC, id DESC LIMIT 1").bind(baseSymbol).first();
        prevBase = prev ? Number(prev.base_price) || 0 : 0;
    } catch (e) { logWarn("snapshot.prevBase", e); }
    const interval_change = prevBase > 0 ? basePrice - prevBase : 0;
    const interval_change_pct = prevBase > 0 ? (interval_change / prevBase) * 100 : 0;
    const surgeThreshold = await acquireNum(env, "metal", "metal_snapshot_surge", 0.25, 0.05, 3);
    const alertThreshold = await acquireNum(env, "metal", "metal_snapshot_alert", 0.8, 0.1, 5);
    const level = snapshotLevel(interval_change_pct, surgeThreshold, alertThreshold);

    const epoch = Date.now();
    const batch_at = beijingStamp(epoch);
    const au0 = by.AU0 || {};
    const autd = by.AUTD || {};
    const xag = by.XAG || {};
    const ag0 = by.AG0 || {};

    // 处理结论：把这一轮的「金价情况」翻译成一句话
    const dir = interval_change_pct > 0 ? "上行" : interval_change_pct < 0 ? "回落" : "持平";
    const parts = [];
    if (base.price) parts.push(`${base.short_name || baseSymbol} ${metalNum(base.price)} ${baseUnit}（${chgSignText(base.change_pct)}${metalNum(base.change_pct, 2)}%）`);
    if (au0.price && baseSymbol !== "AU0") parts.push(`沪金 ${metalNum(au0.price)} 元/克（${chgSignText(au0.change_pct)}${metalNum(au0.change_pct, 2)}%）`);
    if (prevBase > 0) {
        parts.push(Math.abs(interval_change) < 1e-9
            ? "较上次采集持平"
            : `较上次采集${dir} ${metalNum(Math.abs(interval_change), 2)} ${baseUnit}（${chgSignText(interval_change_pct)}${metalNum(interval_change_pct, 2)}%）`);
    }
    if (dv.gold_silver_ratio) parts.push(`金银比 ${metalNum(dv.gold_silver_ratio, 2)}`);
    const summary = parts.join(" · ");

    const detail = JSON.stringify({
        quotes: quotes.map(q => ({
            symbol: q.symbol, name: q.name, short_name: q.short_name, market: q.market, kind: q.kind,
            price: q.price, prev_close: q.prev_close, change: q.change, change_pct: q.change_pct,
            amplitude: q.amplitude, unit: q.unit, currency: q.currency,
            quote_date: q.quote_date, quote_time: q.quote_time
        })),
        derived: dv
    });

    await env.DB.prepare(`INSERT INTO metal_snapshots
        (batch_at, epoch, xau_price, xau_change_pct, au0_price, au0_change_pct, autd_price, autd_change_pct,
         xag_price, silver_price, usdcny, gold_silver_ratio, shanghai_premium, day_high, day_low,
         prev_xau_price, prev_base_price, base_symbol, base_name, base_price, base_change_pct, base_unit,
         interval_change, interval_change_pct, level, summary, detail)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(batch_at) DO UPDATE SET
            epoch=excluded.epoch, xau_price=excluded.xau_price, xau_change_pct=excluded.xau_change_pct,
            au0_price=excluded.au0_price, au0_change_pct=excluded.au0_change_pct,
            autd_price=excluded.autd_price, autd_change_pct=excluded.autd_change_pct,
            xag_price=excluded.xag_price, silver_price=excluded.silver_price, usdcny=excluded.usdcny,
            gold_silver_ratio=excluded.gold_silver_ratio, shanghai_premium=excluded.shanghai_premium,
            day_high=excluded.day_high, day_low=excluded.day_low, prev_xau_price=excluded.prev_xau_price,
            prev_base_price=excluded.prev_base_price, base_symbol=excluded.base_symbol,
            base_name=excluded.base_name, base_price=excluded.base_price,
            base_change_pct=excluded.base_change_pct, base_unit=excluded.base_unit,
            interval_change=excluded.interval_change, interval_change_pct=excluded.interval_change_pct,
            level=excluded.level, summary=excluded.summary, detail=excluded.detail`).bind(
        batch_at, epoch,
        Number((by.XAU || {}).price) || 0, Number((by.XAU || {}).change_pct) || 0,
        Number(au0.price) || 0, Number(au0.change_pct) || 0,
        Number(autd.price) || 0, Number(autd.change_pct) || 0,
        Number(xag.price) || 0, Number(ag0.price) || 0,
        fx, Number(dv.gold_silver_ratio) || 0, Number(dv.shanghai_gold_premium) || 0,
        Number(au0.high) || 0, Number(au0.low) || 0,
        Number((by.XAU || {}).price) || 0, prevBase,
        baseSymbol, base.short_name || base.name || baseSymbol, basePrice, Number(base.change_pct) || 0, baseUnit,
        interval_change, interval_change_pct, level, summary, detail
    ).run();

    // 顺手更新当前行情表（保持行情看板同步；复用本次已抓取的数据，不重复请求）
    try { await refreshMetalQuotes(env, raw); } catch (e) { logWarn("snapshot.syncQuotes", e); }

    // 清理旧快照：并入每日节流的统一清理（边界删除 + 索引，见 pruneRetentionIfDue）
    try { await pruneRetentionIfDue(env); } catch (e) { logWarn("snapshot.cleanup", e); }

    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('last_metal_snapshot',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(batch_at).run();
    const snapSec = await snapshotIntervalSec(env);
    // 兼容旧字段：settings.metal_snapshot_interval 仍按分钟写（历史遗留，当前无读取方）
    await env.DB.prepare("INSERT INTO settings(key,value) VALUES('metal_snapshot_interval',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(String(Math.max(1, Math.round(snapSec / 60)))).run();

    return {
        success: true, batch_at, level, summary,
        interval_change, interval_change_pct,
        base_symbol: baseSymbol, base_name: base.short_name || base.name || baseSymbol,
        base_price: basePrice, base_unit: baseUnit,
        xau_price: Number((by.XAU || {}).price) || 0, au0_price: Number(au0.price) || 0
    };
}

// ============================================================
// 数据采集：数据源配置 / 定时任务 / 立即获取 / 采集日志
// ============================================================

// 采集日志保留条数：每一次采集（定时 / 手动 / 资讯页抓取）都会写一条 fetch_logs，
//   这里只做兜底淘汰，防止长期运行把 D1 撑爆。2 万条 ≈ 每天 200 次执行可存 3 个月。
const FETCH_LOG_KEEP = 20000;
// 资讯页「抓取最新」不是定时任务，但同样是一次真实采集，用独立任务键记日志便于追溯
const MANUAL_NEWS_LOG_KEY = "news_manual";
const MANUAL_NEWS_LOG_NAME = "资讯页手动抓取";
// 稀有金属行情不是独立定时任务（复用 metal_quote 的数据源门禁），
//   但页面按需补采/手动刷新同样是一次真实采集，用独立任务键记日志便于追溯。
const RARE_MANUAL_LOG_KEY = "rare_manual";
// 页面轮询驱动的「实时行情 / 资讯」补采：节奏（10~60 秒）远快于定时任务（600 秒），
//   因此只写采集日志、不改动 fetch_tasks 的 run_count / next_run_at / 失败计数 ——
//   否则定时任务的执行次数与成功率会被页面轮询淹没，next_run_at 也会被不断推后。
//   定时任务本身的失败保护仍由 cron 侧 runFetchTask 负责。
const METAL_LIVE_LOG_KEY = "metal_live";
const NEWS_LIVE_LOG_KEY = "news_live";
const LIVE_LOG_NAMES = { [METAL_LIVE_LOG_KEY]: "行情页轮询补采", [NEWS_LIVE_LOG_KEY]: "资讯页轮询补采" };

// ============================================================
// 数据保留清理：边界删除 + 每日节流（D1 免费额度优化）
//   背景：旧写法 `DELETE ... WHERE id NOT IN (SELECT id ... ORDER BY id DESC LIMIT 2万)`
//         每次采集都全表扫描。稳态下 fetch_logs 约 1.4 万行 × 每天数百次采集，
//         累积近千万 rows_read/天，会撞破 D1 免费版 500 万行/天上限。
//   做法：① 按主键/时间降序取「第 keep 条」作边界，再 DELETE WHERE key < 边界（走索引）；
//         ② 用 settings.last_cleanup_day 做每日节流，一天最多真正清一次。
// ============================================================
// 按排序字段保留最新 keep 条，删除更旧的。table/orderCol 均为内部硬编码常量，无注入风险。
async function trimByKeep(env, table, orderCol, keep) {
    try {
        const n = Math.max(0, Math.floor(Number(keep) || 0));
        if (!n) return 0;
        const row = await env.DB.prepare(`SELECT ${orderCol} AS bound FROM ${table} ORDER BY ${orderCol} DESC LIMIT 1 OFFSET ?`)
            .bind(n - 1).first();
        if (!row || row.bound == null) return 0;
        const r = await env.DB.prepare(`DELETE FROM ${table} WHERE ${orderCol} < ?`).bind(row.bound).run();
        return (r.meta && r.meta.changes) || 0;
    } catch (e) { logWarn("trimByKeep." + table, e); return 0; }
}

// 每日一次的留存清理（日志 + 贵金属快照）。任何采集链路都可调用，靠 last_cleanup_day 节流。
async function pruneRetentionIfDue(env) {
    const today = nowBeijing().slice(0, 10);
    let last = "";
    try {
        const r = await env.DB.prepare("SELECT value FROM settings WHERE key='last_cleanup_day'").first();
        last = r ? String(r.value || "") : "";
    } catch (e) { logWarn("prune.lastDay", e); }
    if (last === today) return false;

    // 采集日志：按天删除走 idx_fetch_logs_started，按条数兜底走主键索引
    try {
        const logDays = await acquireNum(env, "news", "fetch_log_retention_days", 30, 1, 3650);
        await env.DB.prepare("DELETE FROM fetch_logs WHERE started_at < ?")
            .bind(beijingStamp(Date.now() - logDays * 86400000)).run();
        await trimByKeep(env, "fetch_logs", "id", FETCH_LOG_KEEP);
    } catch (e) { logWarn("prune.logs", e); }

    // 贵金属快照：按天 + 按条数都走 idx_metal_snap_epoch
    try {
        const snapKeep = await acquireNum(env, "metal", "metal_snapshot_keep", SNAPSHOT_KEEP, 100, 20000);
        const snapDays = await acquireNum(env, "metal", "metal_snapshot_days", 90, 1, 3650);
        await env.DB.prepare("DELETE FROM metal_snapshots WHERE epoch < ?")
            .bind(Date.now() - snapDays * 86400000).run();
        await trimByKeep(env, "metal_snapshots", "epoch", snapKeep);
    } catch (e) { logWarn("prune.snapshots", e); }

    // 价格轨迹（metal_history）按天清理：created_at 上没有索引，属于整表扫描，
    //   从「每次行情刷新」挪到这里的每日一次（旧位置实测每天 4 万行读取，且基本删不到东西）。
    try {
        const hisDays = await acquireNum(env, "metal", "metal_history_days", 30, 1, 3650);
        const hisCutoff = new Date(Date.now() - hisDays * 86400000).toISOString().replace("T", " ").slice(0, 19);
        await env.DB.prepare("DELETE FROM metal_history WHERE created_at < ?").bind(hisCutoff).run();
    } catch (e) { logWarn("prune.metalHistory", e); }

    // 聚合缓存表只保留 7 天内写过的键（正常每天只有个位数到几十个键）
    try {
        await env.DB.prepare("DELETE FROM agg_cache WHERE at < ?").bind(Date.now() - 7 * 86400000).run();
    } catch (e) { logWarn("prune.aggCache", e); }

    // 记录本次清理日期：即使上面某项失败也记，避免每次采集都重试刷读行数
    try {
        await env.DB.prepare("INSERT INTO settings(key,value) VALUES('last_cleanup_day',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            .bind(today).run();
    } catch (e) { logWarn("prune.markDay", e); }
    return true;
}

// 数据源 key → 采集实现标识（供 crawlNews 等复用）
const NEWS_SOURCE_KEYS = ["eastmoney", "sina_news", "wscn"];
const NEWS_SOURCE_ALIAS = { eastmoney: "eastmoney", sina_news: "sina", wscn: "wscn" };

async function listDataSources(env) {
    try {
        const r = await env.DB.prepare("SELECT * FROM data_sources ORDER BY sort_order, id").all();
        return r.results || [];
    } catch (e) { return []; }
}
async function listFetchTasks(env) {
    try {
        const r = await env.DB.prepare("SELECT * FROM fetch_tasks ORDER BY sort_order, id").all();
        return r.results || [];
    } catch (e) { return []; }
}

// —— 采集参数（按域）——
// 读取全部参数（合并数据库值与代码默认值），返回 { domain: { key: value } }
//   一次 snapshot 采集要读 6~8 次参数，每次都整表 SELECT 会让 D1 查询数成倍膨胀，
//   因此加实例级短 TTL 缓存；保存配置时主动失效，保证「保存后立即生效」。
const OPTION_CACHE_TTL_MS = 30000;
let optionCache = { at: 0, map: null, pending: null };
function invalidateAcquireOptions() { optionCache = { at: 0, map: null, pending: null }; }

async function acquireOptionMap(env) {
    if (optionCache.map && Date.now() - optionCache.at < OPTION_CACHE_TTL_MS) return optionCache.map;
    // 并发请求共享同一次查询，避免缓存击穿
    if (optionCache.pending) return optionCache.pending;
    const load = (async () => {
        const map = {};
        for (const d of ACQUIRE_DOMAINS) map[d.key] = {};
        for (const o of ACQUIRE_OPTION_DEFAULTS) {
            map[o.domain] = map[o.domain] || {};
            map[o.domain][o.key] = o.value;
        }
        try {
            const rows = (await env.DB.prepare("SELECT domain,option_key,value FROM acquire_options").all()).results || [];
            rows.forEach(r => {
                if (!r.domain || !r.option_key) return;
                map[r.domain] = map[r.domain] || {};
                map[r.domain][r.option_key] = r.value == null ? "" : String(r.value);
            });
        } catch (e) { logWarn("acquire.optionMap", e); }
        optionCache = { at: Date.now(), map, pending: null };
        return map;
    })();
    optionCache.pending = load;
    try { return await load; }
    finally { if (optionCache.pending === load) optionCache.pending = null; }
}
// 读取单个参数（带默认值兜底）
async function acquireOption(env, domain, key, fallback) {
    const map = await acquireOptionMap(env);
    const v = map[domain] ? map[domain][key] : undefined;
    if (v === undefined || v === null || v === "") return fallback;
    return v;
}
// 读取数值型参数
async function acquireNum(env, domain, key, fallback, min, max) {
    const v = await acquireOption(env, domain, key, "");
    const n = Number(v);
    if (!Number.isFinite(n)) return fallback;
    if (min != null && n < min) return min;
    if (max != null && n > max) return max;
    return n;
}
// 读取列表型参数（逗号分隔）
async function acquireList(env, domain, key) {
    const v = await acquireOption(env, domain, key, "");
    return String(v).split(",").map(s => s.trim()).filter(Boolean);
}

// 已启用的资讯数据源（映射回 crawlNews 使用的 source 标识）
//   注意：data_sources 存在时以它为准；「全部停用」必须返回空数组，
//   否则停用开关等于没生效（旧实现会在这里回退成「全部启用」）。
async function enabledNewsSourceIds(env) {
    const sources = await listDataSources(env);
    if (!sources.length) return parseNewsSources((await settingsMap(env)).news_sources);
    return sources
        .filter(s => NEWS_SOURCE_KEYS.includes(s.source_key) && s.enabled)
        .map(s => NEWS_SOURCE_ALIAS[s.source_key])
        .filter(Boolean);
}
// 数据源是否启用（贵金属行情等使用）
async function sourceEnabled(env, key) {
    const sources = await listDataSources(env);
    if (!sources.length) return true;
    const row = sources.find(s => s.source_key === key);
    return row ? !!row.enabled : true;
}

// 任务开关门禁：页面自动补采与 Cron 共用；没有任务行时兼容旧库，按启用处理。
async function taskEnabled(env, key) {
    try {
        const row = await env.DB.prepare("SELECT enabled FROM fetch_tasks WHERE task_key=?").bind(key).first();
        return !row || Number(row.enabled) === 1;
    } catch (e) {
        logWarn("task.enabled", e);
        return true;
    }
}

// 任务采集间隔：以 interval_sec（秒）为唯一口径，旧字段 interval_min 只在缺失时兜底
//   1 分钟以下依赖「页面访问触发补采」（cron 最快 1 分钟唤醒），普通任务实际不低于 60 秒
function taskIntervalSec(task) {
    const s = Number(task && task.interval_sec);
    if (Number.isFinite(s) && s >= 1) return Math.round(s);
    const m = Number(task && task.interval_min);
    if (Number.isFinite(m) && m >= 1) return Math.round(m * 60);
    return 1800;
}

function nextRunStamp(task, fromMs) {
    const base = fromMs == null ? Date.now() : fromMs;
    if (Number(task.run_at_hour) >= 0) {
        // 每日固定时刻：对齐到下一个整点
        const h = Number(task.run_at_hour);
        const d = new Date(base + 8 * 3600 * 1000);
        const dayStart = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), h, 0, 0) - 8 * 3600 * 1000;
        return dayStart > base ? dayStart : dayStart + 86400000;
    }
    const last = task.last_run_at ? epochOf(task.last_run_at) : 0;
    const step = taskIntervalSec(task) * 1000;
    const from = last > 0 ? last + step : base;
    return from > base ? from : base + step;
}

// —— 采集日志统一写入 ——
//   所有采集入口（定时任务 / 立即执行 / 资讯页抓取）都必须落库，
//   否则「采集日志」页看到的只是部分执行，无法解释数据为什么没进库。
async function writeFetchLog(env, row) {
    const now = Date.now();
    const finishedAt = row.finished_at || beijingStamp(now);
    try {
        // 只写日志；清理并入每日节流的统一入口（边界删除 + 索引，见 pruneRetentionIfDue）
        await env.DB.prepare("INSERT INTO fetch_logs(task_key,trigger_type,started_at,finished_at,duration_ms,status,fetched,inserted,skipped,message) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(
                row.task_key, row.trigger_type || "manual",
                row.started_at || finishedAt, finishedAt,
                Math.max(0, Math.round(row.duration_ms || 0)),
                row.status || "success",
                row.fetched || 0, row.inserted || 0, row.skipped || 0,
                String(row.message || "").slice(0, 800)
            ).run();
    } catch (e) { logWarn("fetch.log", e); }
    try { await pruneRetentionIfDue(env); } catch (e) { logWarn("fetch.log.prune", e); }
}

// 资讯采集结果 → 一句人话说明（runFetchTask 与资讯页手动抓取共用，口径保持一致）
function newsLogMessage(r) {
    if (!r) return "无返回";
    if (r.skipped_reason) return r.skipped_reason;
    let msg = `抓回 ${r.crawled || 0} 条，新增 ${r.inserted || 0} 条，去重 ${r.skipped || 0} 条`;
    if (r.blocked) msg += `，屏蔽词拦 ${r.blocked} 条`;
    if (r.irrelevant) msg += `，不相关拦 ${r.irrelevant} 条`;
    if (r.too_short) msg += `，短标题拦 ${r.too_short} 条`;
    if (r.cleaned) msg += `，清理过期 ${r.cleaned} 条`;
    if (r.errors && r.errors.length) msg += `；异常 ${r.errors.length} 条：${r.errors[0]}`;
    return msg;
}

// ============================================================
// 银行金价采集 / 解析 / 落库 / 查询
//   单源独立 try/catch：采集失败不影响其他源，也不删除该源已有行。
// ============================================================
const BANK_GOLD_CALIBER = {
    bocom_base: "交通银行官网展示的上海黄金交易所 Au99.99 基础价，非交行零售报价、非投资金条售价；单位元/克（推断）。",
    bocom_market: code => `交通银行官网展示的上海黄金交易所 ${code} 合约行情，非交行零售报价；含官方涨跌额，官网涨跌幅字段不可用，未展示；单位元/克（推断）。`
};
const BANK_GOLD_COLS = ["symbol", "bank", "source_key", "name", "caliber", "price", "bid", "ask", "unit",
    "currency", "quote_stamp", "stamp_kind", "collected_at", "change", "change_pct", "prev_close",
    "open", "high", "low", "weight_g", "note", "status", "endpoint", "updated_at"];
const BANK_GOLD_UPSERT_SQL = `INSERT INTO bank_gold_quotes(${BANK_GOLD_COLS.join(",")}) VALUES(${BANK_GOLD_COLS.map(() => "?").join(",")})
    ON CONFLICT(symbol) DO UPDATE SET ${BANK_GOLD_COLS.filter(c => c !== "symbol").map(c => `${c}=excluded.${c}`).join(",")}`;

// 官网数值一律「取不到就是 NULL」：不得用 0、不得用上次采集值冒充新报价
function bankGoldNum(v) {
    if (v == null || v === "") return null;
    const n = Number(String(v).replace(/,/g, "").trim());
    return Number.isFinite(n) ? n : null;
}
function makeBankRow(source, o) {
    return {
        symbol: String(o.symbol),
        bank: o.bank || "",
        source_key: source.key,
        name: o.name || "",
        caliber: o.caliber || "",
        price: bankGoldNum(o.price),
        bid: bankGoldNum(o.bid),
        ask: bankGoldNum(o.ask),
        unit: o.unit || "",
        currency: o.currency || "CNY",
        quote_stamp: o.quote_stamp || "",
        stamp_kind: o.stamp_kind || "none",
        collected_at: o.collected_at || nowBeijing(),
        change: bankGoldNum(o.change),
        change_pct: bankGoldNum(o.change_pct),
        prev_close: bankGoldNum(o.prev_close),
        open: bankGoldNum(o.open),
        high: bankGoldNum(o.high),
        low: bankGoldNum(o.low),
        weight_g: bankGoldNum(o.weight_g),
        note: o.note || "",
        status: "ok",
        endpoint: source.endpoint,
        updated_at: nowBeijing()
    };
}
// Workers fetch 自动解压 gzip；官网源均为 UTF-8，禁止 GBK / TextDecoder('gbk')，会毁掉中文
async function bankGoldFetchText(endpoint, extraHeaders) {
    const r = await fetchWithTimeout(endpoint, {
        headers: { "User-Agent": NEWS_UA, ...(extraHeaders || {}) }
    }, 7000);
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.text();
}

// ③ 交行 JSON：必须校验 TRAN_SUCCESS === "1"（错误路径 HTTP 200 + TRAN_SUCCESS:"0"）
function parseBocom(text, source) {
    let d;
    try { d = JSON.parse(text); } catch (e) { throw new Error("交行响应不是合法 JSON：" + e.message); }
    const head = d && d.RSP_HEAD;
    if (!head || String(head.TRAN_SUCCESS) !== "1") {
        throw new Error("交行接口返回 TRAN_SUCCESS=" + (head && head.TRAN_SUCCESS) + " ERROR_CODE=" + (head && head.ERROR_CODE || ""));
    }
    const body = d.RSP_BODY || {};   // realIp 是请求方出口 IP，禁止入库 / 展示
    const metalList = body.metalList, metalNewList = body.metalNewList;
    // 业务成功标志 + 两个数组均非空才算成功：错误路径是 HTTP 200 + TRAN_SUCCESS:"0"
    if (!Array.isArray(metalList) || !metalList.length || !Array.isArray(metalNewList) || !metalNewList.length) {
        throw new Error("交行 RSP_BODY 缺少非空的 metalList / metalNewList 数组");
    }
    const rows = [];
    const base = metalList.find(x => String(x.baseCode || "").trim() === "Au99.99");
    if (base) {
        const price = bankGoldNum(base.basePrc);
        if (price != null) {
            rows.push(makeBankRow(source, {
                symbol: "BOCOM_BASE_AU9999", bank: "交通银行", name: "Au99.99 基础价",
                caliber: BANK_GOLD_CALIBER.bocom_base, price,
                unit: "元/克（推断）", currency: "CNY",
                quote_stamp: String(base.upTime || ""), stamp_kind: "official_quote",
                note: "交通银行官网展示的上金所合约行情/基准价，非交行零售报价、非投资金条售价；报价时间取自 metalList.upTime（YYYYMMDDHHMMSS 原文）；官网未提供涨跌。"
            }));
        }
    }
    for (const x of metalNewList) {
        const code = String(x.prodCode || "");
        if (!code.startsWith("Au")) continue;   // 排除 Ag(T+D)：与 metalList 银价单位相差 1000 倍
        const nz = ["newPrice", "openPrice", "highPrice", "lowPrice", "averPrice"].some(k => (bankGoldNum(x[k]) || 0) !== 0);
        if (!nz) continue;                       // 过滤整条全 0 的 Au99.95（停牌）
        const price = bankGoldNum(x.newPrice);
        if (price == null) continue;
        const stamp = [String(x.quoteDate || ""), String(x.quoteTime || "")].filter(Boolean).join(" ");
        rows.push(makeBankRow(source, {
            symbol: "BOCOM_MKT_" + code.replace(/[^A-Za-z0-9]/g, "").toUpperCase(),
            bank: "交通银行", name: code + " 合约行情",
            caliber: BANK_GOLD_CALIBER.bocom_market(code), price,
            prev_close: x.lastClose, open: x.openPrice, high: x.highPrice, low: x.lowPrice,
            change: x.upDown,          // 官方涨跌额，真实
            change_pct: null,          // upDownRate 恒 -0.01% 不可用；也禁止 upDown/lastClose 自算
            unit: "元/克（推断）", currency: "CNY", quote_stamp: stamp, stamp_kind: "official_quote",
            note: "交通银行官网展示的上金所合约行情/基准价，非交行零售报价、非投资金条售价；官网涨跌幅字段不可用，未展示；T+D 涨跌与昨收不自洽，不作验算；closePrice 为 0.00 占位不采用；报价时间来自 quoteDate+quoteTime（metalNewList 无 upTime）。"
        }));
    }
    if (!rows.length) throw new Error("交行未返回 Au99.99 基础价或 Au 系合约行情");
    return rows;
}

function parseBankSource(key, text) {
    const source = BANK_GOLD_SOURCES.find(s => s.key === key);
    if (!source) throw new Error("未知银行金价数据源：" + key);
    if (key === "bocom_metal") return parseBocom(text, source);
    throw new Error("未知银行金价数据源：" + key);
}

// 单源采集：网络失败或解析不到有效价格都算失败，重试 1 次；仍失败由调用方标记 stale
async function collectBankSource(source) {
    let lastErr = "未知错误";
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            const text = await bankGoldFetchText(source.endpoint);
            const rows = parseBankSource(source.key, text);
            return { key: source.key, ok: true, count: rows.length, rows, message: `解析成功，返回 ${rows.length} 条` };
        } catch (e) {
            lastErr = e && e.message ? e.message : String(e);
        }
    }
    return { key: source.key, ok: false, count: 0, rows: [], message: lastErr };
}

async function upsertBankGoldQuotes(env, rows) {
    if (!rows.length) return 0;
    const stmts = rows.map(r => env.DB.prepare(BANK_GOLD_UPSERT_SQL).bind(...BANK_GOLD_COLS.map(c => r[c])));
    for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
    return rows.length;
}

// 采集失败：不删除、不写 0/空价，保留上次成功行并标记 stale + 说明
async function markBankGoldStale(env, key, reason) {
    try {
        const old = (await env.DB.prepare("SELECT symbol, note, collected_at FROM bank_gold_quotes WHERE source_key=?").bind(key).all()).results || [];
        if (!old.length) return;
        const mark = `本次采集失败，显示上次成功值（采集时间 ${nowBeijing()}）；原因：${String(reason).slice(0, 160)}`;
        const stmts = old.map(r => {
            const base = String(r.note || "").replace(/；本次采集失败，显示上次成功值[\s\S]*$/, "").trim();
            const note = (base ? base + "；" : "") + mark;
            return env.DB.prepare("UPDATE bank_gold_quotes SET status='stale', note=? WHERE symbol=?").bind(note.slice(0, 1200), r.symbol);
        });
        for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
    } catch (e) { logWarn("bankGold.stale", e); }
}

async function bankGoldAnySourceEnabled(env) {
    const sources = await listDataSources(env);
    if (!sources.length) return true;
    return BANK_GOLD_SOURCE_KEYS.some(k => {
        const row = sources.find(s => s.source_key === k);
        return row ? !!row.enabled : true;
    });
}

async function fetchBankGoldQuotes(env) {
    const sources = await listDataSources(env);
    const active = BANK_GOLD_SOURCES.filter(s => {
        const row = sources.find(r => r.source_key === s.key);
        return row ? !!row.enabled : true;
    });
    if (!active.length) {
        return { success: false, results: [], updated: 0, refreshed_at: nowBeijing(), message: "银行金价数据源全部停用" };
    }
    const results = [];
    let freshRows = [];
    for (const s of active) {
        const r = await collectBankSource(s);
        results.push({ key: r.key, ok: r.ok, count: r.count, message: r.message });
        if (r.ok) freshRows = freshRows.concat(r.rows);
        else await markBankGoldStale(env, s.key, r.message);
    }
    // 成功源：先把该源已有行整体降为 stale，随后 upsert 本次成功行覆盖回 ok。
    // 官网本次未再返回的商品不会继续以 ok 身份冒充新报价。
    for (const r of results.filter(x => x.ok)) {
        try { await env.DB.prepare("UPDATE bank_gold_quotes SET status='stale' WHERE source_key=?").bind(r.key).run(); }
        catch (e) { logWarn("bankGold.preStale", e); }
    }
    const updated = await upsertBankGoldQuotes(env, freshRows);
    const okCount = results.filter(r => r.ok).length;
    return {
        success: okCount > 0, results, updated, refreshed_at: nowBeijing(),
        message: `银行金价采集完成：${okCount}/${active.length} 个源成功，写入 ${updated} 条${okCount < active.length ? "；失败源保留上次成功值并标记 stale" : ""}`
    };
}

async function getBankGold(env) {
    let quotes = [];
    try {
        quotes = (await env.DB.prepare("SELECT * FROM bank_gold_quotes ORDER BY source_key, symbol").all()).results || [];
    } catch (e) { logWarn("bankGold.list", e); }
    let last_refresh = "", collected_at = "";
    try {
        const r = await env.DB.prepare("SELECT MAX(updated_at) AS v, MAX(collected_at) AS c FROM bank_gold_quotes").first();
        last_refresh = (r && r.v) || "";
        collected_at = (r && r.c) || "";
    } catch (e) { logWarn("bankGold.meta", e); }
    const dbSources = await listDataSources(env);
    const sources = BANK_GOLD_SOURCES.map(s => {
        const row = dbSources.find(r => r.source_key === s.key);
        return {
            source_key: s.key, name: row ? row.name : s.name,
            endpoint: row ? row.endpoint : s.endpoint,
            description: row ? row.description : s.description,
            enabled: row ? !!row.enabled : true
        };
    });
    return json({
        success: true, quotes,
        banks: [...new Set(quotes.map(q => q.bank).filter(Boolean))],
        sources,
        meta: { last_refresh, collected_at, disclaimer: BANK_GOLD_DISCLAIMER }
    });
}

async function refreshBankGold(request, env) {
    const r = await fetchBankGoldQuotes(env);
    return json({ success: r.success, results: r.results, updated: r.updated, refreshed_at: r.refreshed_at, message: r.message });
}

// —— 执行一个采集任务（手动 / 定时共用）——
async function runFetchTask(env, taskKey, triggerType) {
    const tasks = await listFetchTasks(env);
    const task = tasks.find(t => t.task_key === taskKey);
    if (!task) return { success: false, message: "未知任务：" + taskKey };

    // —— 原子领取任务租约 ——
    //   条件更新只有命中「空闲或租约已过期」的行才会变更，多个 isolate 并发时只有一个成功。
    //   避免 cron / 页面补采 / 手动采集在任务到期窗口内重复请求上游、重复写库。
    const leaseMs = Math.max(120000, taskIntervalSec(task) * 1000 * 2);
    const nowMs = Date.now();
    try {
        const claim = await env.DB.prepare(
            "UPDATE fetch_tasks SET lease_until=? WHERE task_key=? AND (lease_until=0 OR lease_until IS NULL OR lease_until<=?)"
        ).bind(nowMs + leaseMs, taskKey, nowMs).run();
        if (!claim || !claim.meta || !claim.meta.changes) {
            return { success: false, skipped: true, task_key: taskKey, status: "skipped", message: "任务正在执行中，已跳过本次触发", fetched: 0, inserted: 0, duration_ms: 0, fail_streak: Number(task.fail_streak) || 0 };
        }
    } catch (e) {
        logWarn("fetch.lease", e);
        // 租约列缺失等异常时不阻断执行（旧库自愈前按无锁处理）
    }

    const startedAt = beijingStamp(Date.now());
    const t0 = Date.now();
    let status = "success", fetched = 0, inserted = 0, skipped = 0, message = "";

    try {
        if (taskKey === "metal_snapshot") {
            if (!await sourceEnabled(env, "sina_quote")) throw new Error("新浪实时行情数据源已停用");
            const r = await captureMetalSnapshot(env);
            fetched = 1; inserted = 1;
            message = r.summary || ("采集于 " + r.batch_at);
        } else if (taskKey === "metal_quote") {
            if (!await sourceEnabled(env, "sina_quote")) throw new Error("新浪实时行情数据源已停用");
            const r = await refreshMetalQuotes(env);
            fetched = r.updated || 0;
            message = `更新 ${fetched} 个品种报价，美元兑人民币 ${r.usdcny || "—"}`;
        } else if (taskKey === "news_crawl") {
            const ids = await enabledNewsSourceIds(env);
            const r = await crawlNews(env, { sources: ids.join(",") });
            if (r.status === "partial") status = "partial";
            fetched = r.crawled || 0; inserted = r.inserted || 0; skipped = r.skipped || 0;
            message = newsLogMessage(r);
        } else if (taskKey === "bank_gold_quote") {
            // 门禁不用 sina_quote：银行金价走 4 个独立官网源，至少 1 个启用才执行
            if (!await bankGoldAnySourceEnabled(env)) throw new Error("银行金价数据源全部停用");
            const r = await fetchBankGoldQuotes(env);
            fetched = r.results.reduce((n, x) => n + (x.ok ? x.count : 0), 0);
            inserted = r.updated;
            message = r.message;
            if (!r.success) throw new Error(r.message);
        } else {
            throw new Error("未实现的任务：" + taskKey);
        }
    } catch (e) {
        status = "failed";
        message = e && e.message ? e.message : String(e);
    }

    const duration = Date.now() - t0;
    const finishedAt = beijingStamp(Date.now());
    // 连续失败计数：成功即清零。用于「连续失败自动停用」保护
    const prevStreak = Number(task.fail_streak) || 0;
    const failStreak = status === "failed" ? prevStreak + 1 : 0;
    try {
        // 两条写入合并为一个 batch：要么都成功，要么都不生效，避免日志与任务状态不一致。
        //   日志裁剪已移出，改由 pruneRetentionIfDue 每日节流执行（边界删除，不扫全表）。
        await env.DB.batch([
            env.DB.prepare("INSERT INTO fetch_logs(task_key,trigger_type,started_at,finished_at,duration_ms,status,fetched,inserted,skipped,message) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(taskKey, triggerType || "manual", startedAt, finishedAt, duration, status, fetched, inserted, skipped, message),
            env.DB.prepare("UPDATE fetch_tasks SET last_run_at=?, last_status=?, last_message=?, next_run_at=?, run_count=run_count+1, fail_count=fail_count+?, fail_streak=?, lease_until=0 WHERE task_key=?")
                .bind(startedAt, status, message.slice(0, 300), beijingStamp(nextRunStamp(task, Date.now())),
                    status === "failed" ? 1 : 0, failStreak, taskKey)
        ]);
    } catch (e) { logWarn("fetch.log", e); }
    try { await pruneRetentionIfDue(env); } catch (e) { logWarn("fetch.log.prune", e); }

    // —— 连续失败自动停用 ——
    //   一个失效的数据源如果不刹车，会按任务间隔无限重试（10 分钟一次 ≈ 每天 144 次），
    //   既刷日志也耗额度。达到域内配置的上限后自动停用并发通知，人工修复后重新启用即清零。
    let autoDisabled = false;
    if (status === "failed" && task.enabled) {
        const domainKey = task.domain || "news";
        try {
            const limit = await acquireNum(env, domainKey, domainKey + "_fail_limit", 5, 1, 50);
            if (failStreak >= limit) {
                await env.DB.prepare("UPDATE fetch_tasks SET enabled=0, next_run_at='' WHERE task_key=?").bind(taskKey).run();
                autoDisabled = true;
                const rawMessage = message;
                message = `${message}｜已连续失败 ${failStreak} 次，任务自动停用`;
                await pushNotification(env, {
                    kind: "system", level: "warn",
                    title: `采集任务「${task.name}」已自动停用`,
                    body: `连续失败 ${failStreak} 次（阈值 ${limit} 次），最近一次错误：${rawMessage.slice(0, 300)}。修复后在「数据采集」页重新启用即可清零。`,
                    ref_type: "fetch_task", ref_id: task.id || 0,
                    dedup_key: `task_autodisabled:${taskKey}`
                });
            }
        } catch (e) { logWarn("fetch.autodisable", e); }
    }

    return { success: status !== "failed", task_key: taskKey, status, message, fetched, inserted, skipped, duration_ms: duration, fail_streak: failStreak, auto_disabled: autoDisabled, started_at: startedAt, finished_at: finishedAt };
}

// —— 数据采集总览（按域组织的配置 + 状态 + 日志）——
// 消息来源 key 与 news.source 的对应关系：数据源叫 sina_news，入库时 source 记作 sina
const SOURCE_STAT_ALIAS = {
    eastmoney: "eastmoney", sina_news: "sina", sina_quote: "sina", wscn: "wscn", em_kline: "eastmoney",
    bocom_metal: "bocom_metal"
};

async function getAcquireConfig(env) {
    const [sources, tasks, optionMap] = await Promise.all([
        listDataSources(env), listFetchTasks(env), acquireOptionMap(env)
    ]);
    // 近 60 条只服务于「某域最后一次执行」这类展示；所有统计口径一律走 SQL 聚合，
    //   否则日志一多，60 条窗口算出的「今日次数 / 成功率」会明显偏低。
    let logs = [];
    try {
        logs = (await env.DB.prepare("SELECT * FROM fetch_logs ORDER BY id DESC LIMIT 60").all()).results || [];
    } catch (e) { logWarn("acquire.logs", e); }
    const cfg = await settingsMap(env);
    const now = Date.now();

    const today = beijingStamp(now).slice(0, 10);
    const weekAgo = beijingStamp(now - 7 * 86400000);

    let todayAgg = { n: 0, ok: 0 }, weekAgg = { n: 0, ok: 0, avg: 0 };
    // 成功率口径：success 与 partial 都算「有产出」，skipped 不计入分母（未真正执行）。
    const OK_SQL = "SUM(CASE WHEN status IN ('success','partial') THEN 1 ELSE 0 END)";
    try {
        const [ta, wa] = await Promise.all([
            env.DB.prepare(`SELECT COUNT(*) AS n, ${OK_SQL} AS ok FROM fetch_logs WHERE started_at >= ? AND status<>'skipped'`).bind(today + " 00:00:00").first(),
            env.DB.prepare(`SELECT COUNT(*) AS n, ${OK_SQL} AS ok, AVG(duration_ms) AS avg FROM fetch_logs WHERE started_at >= ? AND status<>'skipped'`).bind(weekAgo).first()
        ]);
        todayAgg = { n: Number(ta && ta.n) || 0, ok: Number(ta && ta.ok) || 0 };
        weekAgg = { n: Number(wa && wa.n) || 0, ok: Number(wa && wa.ok) || 0, avg: Math.round(Number(wa && wa.avg) || 0) };
    } catch (e) { logWarn("acquire.agg", e); }

    // —— 近 7 天执行统计（按任务聚合，用于成功率与平均耗时）——
    const taskStat = {};
    try {
        const r = await env.DB.prepare(`SELECT task_key, COUNT(*) AS n, ${OK_SQL} AS ok,
            AVG(duration_ms) AS avg_ms, MAX(duration_ms) AS max_ms
            FROM fetch_logs WHERE started_at >= ? AND status<>'skipped' GROUP BY task_key`).bind(weekAgo).all();
        (r.results || []).forEach(x => { taskStat[x.task_key] = x; });
    } catch (e) { logWarn("acquire.taskStat", e); }

    // —— 近 7 天各来源实际入库量（news.source 维度）——
    const sourceCount = {};
    try {
        const r = await env.DB.prepare("SELECT source, COUNT(*) AS c FROM news WHERE fetched_at >= ? GROUP BY source").bind(weekAgo).all();
        (r.results || []).forEach(x => { sourceCount[x.source] = Number(x.c) || 0; });
    } catch (e) { logWarn("acquire.sourceCount", e); }
    const sourceTotal = Object.values(sourceCount).reduce((a, b) => a + b, 0);

    const stats = {
        sources_total: sources.length,
        sources_enabled: sources.filter(s => s.enabled).length,
        tasks_total: tasks.length,
        tasks_enabled: tasks.filter(t => t.enabled).length,
        tasks_abnormal: tasks.filter(t => t.enabled && (Number(t.fail_streak) || 0) >= 2).length,
        tasks_autostopped: tasks.filter(t => !t.enabled && (Number(t.fail_streak) || 0) > 0).length,
        runs_total: tasks.reduce((s, t) => s + (t.run_count || 0), 0),
        fails_total: tasks.reduce((s, t) => s + (t.fail_count || 0), 0),
        logs_today: todayAgg.n,
        success_today: todayAgg.ok,
        failed_today: Math.max(0, todayAgg.n - todayAgg.ok),
        // 7 天窗口（比「今日」更能反映稳定性，凌晨时今日样本可能为 0）
        logs_7d: weekAgg.n,
        success_7d: weekAgg.ok,
        avg_duration_7d: weekAgg.avg,
        log_retention: FETCH_LOG_KEEP,
        // 下次执行：所有启用任务里最近的那个时间点
        next_run_at: tasks.filter(t => t.enabled && t.next_run_at).map(t => t.next_run_at).sort()[0] || "",
        last_run_at: logs.length ? logs[0].started_at : "",
        last_metal_refresh: cfg.last_metal_refresh || "",
        last_metal_snapshot: cfg.last_metal_snapshot || "",
        last_news_refresh: cfg.last_news_refresh || "",
        news_total_7d: sourceTotal
    };
    const nextRunTask = tasks.filter(t => t.enabled && t.next_run_at).sort((a, b) => String(a.next_run_at).localeCompare(String(b.next_run_at)))[0];
    if (nextRunTask) {
        stats.next_run_task = nextRunTask.name;
        stats.next_run_in_sec = Math.max(0, Math.round((epochOf(nextRunTask.next_run_at) - now) / 1000));
        stats.next_run_overdue = epochOf(nextRunTask.next_run_at) <= now;
    }

    // 按域分组：数据源 / 任务 / 参数 / 日志
    const domains = ACQUIRE_DOMAINS.map(d => {
        const dsources = sources.filter(s => (s.domain || "news") === d.key).map(s => {
            // 「近 7 天贡献」只有消息域讲得通：news 表按 source 记录了入库量。
            // 贵金属域的两个源（报价 / K 线）不直接产出资讯，硬套会得到误导性占比，故置空。
            if (d.key !== "news") return { ...s, recent_7d: null, recent_7d_pct: null };
            const alias = SOURCE_STAT_ALIAS[s.source_key] || s.source_key;
            const c = sourceCount[alias] || 0;
            return {
                ...s,
                recent_7d: c,
                recent_7d_pct: sourceTotal > 0 ? Math.round((c / sourceTotal) * 1000) / 10 : 0
            };
        });
        const dtasks = tasks.filter(t => (t.domain || "news") === d.key).map(t => {
            const st = taskStat[t.task_key] || {};
            const n = Number(st.n) || 0;
            return {
                ...t,
                fail_streak: Number(t.fail_streak) || 0,
                runs_7d: n,
                success_rate_7d: n ? Math.round((Number(st.ok) || 0) / n * 1000) / 10 : null,
                avg_ms_7d: n ? Math.round(Number(st.avg_ms) || 0) : null,
                max_ms_7d: n ? Math.round(Number(st.max_ms) || 0) : null,
                // 存储的 next_run_at 可能因进程停摆而过期，负数会让前端显示成「-56 分钟」，
                // 统一夹到 0 并单独标记 overdue，语义更清楚：已到期、等待下一次调度
                next_run_in_sec: t.enabled && t.next_run_at ? Math.max(0, Math.round((epochOf(t.next_run_at) - now) / 1000)) : null,
                overdue: !!(t.enabled && t.next_run_at && epochOf(t.next_run_at) <= now)
            };
        });
        const dkeys = new Set(dtasks.map(t => t.task_key));
        // 资讯页手动抓取也算资讯域的采集，纳入域级统计与「最近一次执行」
        if (d.key === "news") { dkeys.add(MANUAL_NEWS_LOG_KEY); dkeys.add(NEWS_LIVE_LOG_KEY); }
        // 稀有金属按需补采/手动刷新与行情页轮询补采属于贵金属域
        if (d.key === "metal") { dkeys.add(RARE_MANUAL_LOG_KEY); dkeys.add(METAL_LIVE_LOG_KEY); }
        const groups = ACQUIRE_GROUPS[d.key] || [{ key: "", label: "采集参数", icon: "fa-sliders", desc: "" }];
        const opts = ACQUIRE_OPTION_DEFAULTS.filter(o => o.domain === d.key).map(o => ({
            key: o.key, name: o.name, type: o.type,
            value: optionMap[d.key] ? (optionMap[d.key][o.key] ?? o.value) : o.value,
            default: o.value,
            group: o.group || "",
            unit: o.unit || "",
            options: o.options || "", meta: o.meta || "", description: o.description || "", readonly: !!o.readonly
        }));
        const dlog = logs.filter(l => dkeys.has(l.task_key));
        // 域级 7 天统计直接累加 taskStat（SQL 聚合结果），不受 60 条展示窗口影响
        let d7n = 0, d7ok = 0, d7dur = 0;
        dkeys.forEach(k => {
            const st = taskStat[k];
            if (!st) return;
            const n = Number(st.n) || 0;
            d7n += n; d7ok += Number(st.ok) || 0; d7dur += (Number(st.avg_ms) || 0) * n;
        });
        return {
            key: d.key, name: d.name, icon: d.icon, desc: d.desc,
            sources: dsources, tasks: dtasks, options: opts, groups, logs: dlog,
            stats: {
                sources_total: dsources.length,
                sources_enabled: dsources.filter(s => s.enabled).length,
                tasks_total: dtasks.length,
                tasks_enabled: dtasks.filter(t => t.enabled).length,
                runs_total: dtasks.reduce((s, t) => s + (t.run_count || 0), 0),
                fails_total: dtasks.reduce((s, t) => s + (t.fail_count || 0), 0),
                runs_7d: d7n,
                success_rate_7d: d7n ? Math.round(d7ok / d7n * 1000) / 10 : null,
                avg_ms_7d: d7n ? Math.round(d7dur / d7n) : null,
                last_run_at: dlog.length ? dlog[0].started_at : ""
            }
        };
    });

    return json({
        sources, tasks, logs, stats, domains,
        groups: [...new Set(sources.map(s => s.group_name || "其它"))],
        news_keywords: parseNewsKeywords(optionMap.news ? optionMap.news.news_keywords : cfg.news_keywords)
    });
}

// —— 保存配置（数据源启停 / 任务间隔与启停 / 采集参数）——
async function saveAcquireConfig(request, env) {
    const body = await request.json().catch(() => ({}));
    // 所有写入语句先收集，最后用一次 batch 提交：减少 D1 往返次数，并保证整体原子性
    const writes = [];

    if (Array.isArray(body.sources)) {
        for (const s of body.sources) {
            const key = cleanStr(s.source_key, 40);
            if (!key) continue;
            writes.push(env.DB.prepare("UPDATE data_sources SET enabled=? WHERE source_key=?").bind(s.enabled ? 1 : 0, key));
        }
    }
    if (Array.isArray(body.tasks)) {
        // 先一次性读出所有任务，再统一计算（避免逐条 SELECT）
        const taskKeys = body.tasks.map(t => cleanStr(t.task_key, 40)).filter(Boolean);
        const curRows = taskKeys.length
            ? (await env.DB.prepare(`SELECT * FROM fetch_tasks WHERE task_key IN (${taskKeys.map(() => "?").join(",")})`).bind(...taskKeys).all()).results || []
            : [];
        const curMap = new Map(curRows.map(r => [r.task_key, r]));
        for (const t of body.tasks) {
            const key = cleanStr(t.task_key, 40);
            if (!key) continue;
            const cur = curMap.get(key);
            if (!cur) continue;
            // 采集间隔按秒：优先 interval_sec；旧客户端只传 interval_min 时按分钟换算
            const curSec = taskIntervalSec(cur);
            const rawSec = (t.interval_sec != null && t.interval_sec !== "")
                ? parseInt(t.interval_sec, 10)
                : ((t.interval_min != null && t.interval_min !== "") ? parseInt(t.interval_min, 10) * 60 : curSec);
            const sec = Math.min(86400, Math.max(5, Number.isFinite(rawSec) ? rawSec : curSec));
            const min = Math.max(1, Math.round(sec / 60));
            let hour = cur.run_at_hour;
            if (t.run_at_hour != null && t.run_at_hour !== "") {
                const parsedHour = Number(t.run_at_hour);
                hour = Number.isInteger(parsedHour) && parsedHour >= -1 && parsedHour <= 23 ? parsedHour : cur.run_at_hour;
            }
            const enabled = t.enabled == null ? cur.enabled : (t.enabled ? 1 : 0);
            // 重新启用（0 → 1）时把连续失败计数清零：自动停用的任务修复后再打开，
            //   不应该带着旧连击数立刻又被停掉。显式传 reset_streak 也走同一分支。
            const reEnable = (enabled && !cur.enabled) || t.reset_streak;
            const streak = reEnable ? 0 : (Number(cur.fail_streak) || 0);
            writes.push(env.DB.prepare("UPDATE fetch_tasks SET interval_sec=?, interval_min=?, enabled=?, run_at_hour=?, next_run_at=?, fail_streak=? WHERE task_key=?")
                .bind(sec, min, enabled, hour, enabled ? beijingStamp(nextRunStamp({ ...cur, interval_sec: sec, interval_min: min, run_at_hour: hour }, Date.now())) : "", streak, key));
        }
    }
    // —— 采集参数（按域）——
    if (body.options && typeof body.options === "object") {
        for (const domain of Object.keys(body.options)) {
            const defs = ACQUIRE_OPTION_DEFAULTS.filter(o => o.domain === domain);
            const values = body.options[domain] || {};
            for (const def of defs) {
                if (!Object.prototype.hasOwnProperty.call(values, def.key)) continue;
                if (def.readonly) continue; // 只读参数（如单源抓取条数固定 30）：忽略提交值，保持库内固定值
                let v = values[def.key];
                if (Array.isArray(v)) v = v.join(",");
                v = String(v == null ? "" : v);
                // 按类型做归一化与范围校验
                if (def.type === "number") {
                    const meta = (() => { try { return JSON.parse(def.meta || "{}"); } catch { return {}; } })();
                    let n = Number(v);
                    if (!Number.isFinite(n)) n = Number(def.value) || 0;
                    if (meta.min != null) n = Math.max(meta.min, n);
                    if (meta.max != null) n = Math.min(meta.max, n);
                    v = String(n);
                } else if (def.type === "bool") {
                    v = (v === "1" || v === true || v === 1 || v === "true") ? "1" : "0";
                } else if (def.type === "list") {
                    const allowed = (() => { try { return JSON.parse(def.options || "[]").map(o => o.value); } catch { return []; } })();
                    const picked = splitList(v);
                    v = (allowed.length ? picked.filter(x => allowed.includes(x)) : picked).join(",");
                } else if (def.type === "select") {
                    const allowed = (() => { try { return JSON.parse(def.options || "[]").map(o => o.value); } catch { return []; } })();
                    const picked = splitList(v);
                    v = allowed.length ? (allowed.includes(picked[0]) ? picked[0] : def.value) : (picked[0] || def.value);
                } else if (def.type === "textarea") {
                    // 关键词：空值回退默认（这是产品行为）；屏蔽词等其它列表字段：空就是空
                    v = (def.key === "news_keywords" ? parseNewsKeywords(v) : splitList(v)).join(",");
                } else {
                    v = cleanStr(v, 500);
                }
                writes.push(env.DB.prepare(`INSERT INTO acquire_options(domain,option_key,name,value,value_type,options,meta,description,sort_order,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                    ON CONFLICT(option_key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`)
                    .bind(domain, def.key, def.name, v, def.type, def.options || "", def.meta || "", def.description || "", def.sort));
            }
        }
    }
    // 兼容旧版：单独提交的 news_keywords 仍写入消息域
    if (Array.isArray(body.news_keywords)) {
        const kws = parseNewsKeywords(body.news_keywords.join(",")).join(",");
        writes.push(env.DB.prepare("INSERT INTO settings(key,value) VALUES('news_keywords',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(kws));
        writes.push(env.DB.prepare("INSERT INTO acquire_options(domain,option_key,name,value,value_type,description,sort_order,updated_at) VALUES('news','news_keywords','关注关键词',?,'textarea','用于全网搜索财经资讯的关键词',10,CURRENT_TIMESTAMP) ON CONFLICT(option_key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP").bind(kws));
    }
    // 一次性提交所有写入（D1 batch 单次最多 100 条语句，超出则分批）
    for (let i = 0; i < writes.length; i += 100) {
        await env.DB.batch(writes.slice(i, i + 100));
    }
    // 参数已落库，立即失效缓存，保证「保存后下一次执行即生效」
    invalidateAcquireOptions();
    return json({ success: true, updated: writes.length });
}

// —— 立即获取（手动触发）——
// body.task_key = 单个任务；body.domain = 按数据域批量执行该域全部启用的任务
async function runAcquireNow(request, env) {
    const body = await request.json().catch(() => ({}));
    const taskKey = cleanStr(body.task_key, 40);
    const domain = cleanStr(body.domain, 20);
    if (taskKey) {
        const result = await runFetchTask(env, taskKey, "manual");
        // 任务被其他执行占用（租约未释放）时返回 200 + skipped，避免误报成采集失败
        if (result.status === "skipped") return json(result, 200);
        return json(result, result.success ? 200 : 502);
    }
    if (domain) {
        const tasks = await listFetchTasks(env);
        const targets = tasks.filter(t => (t.domain || "news") === domain && t.enabled);
        if (!targets.length) return json({ success: false, message: "该数据域没有启用的任务" }, 400);
        const results = [];
        for (const t of targets) results.push(await runFetchTask(env, t.task_key, "manual"));
        const failed = results.filter(r => !r.success);
        return json({
            success: failed.length === 0,
            domain,
            total: results.length,
            failed: failed.length,
            results
        }, failed.length === 0 ? 200 : 502);
    }
    return json({ success: false, message: "缺少 task_key 或 domain" }, 400);
}

// —— 数据源连通性测试 ——
// —— 单源探测：抽出公共逻辑，单测与批量测源复用同一套判定 ——
//   返回 { ok, message }；网络异常会被捕获成 ok:false，不向外抛。
async function probeSource(env, key) {
    try {
        if (key === "sina_quote") {
            const symbols = await acquireList(env, "metal", "metal_symbols");
            const raw = await fetchSinaMetalQuotes(symbols, await listInstruments(env, "metal"));
            const n = Object.keys(raw).filter(k => k !== "__fx").length;
            return n > 0
                ? { ok: true, message: `返回 ${n} 个品种报价，汇率 ${raw.__fx || "—"}` }
                : { ok: false, message: "未返回有效报价" };
        }
        if (key === "em_kline") {
            // 取第一个「有东财 secid」的品种：铂金 / 钯金上游无 K 线，
            // 旧实现直接取 symbols[0]，若它是 XPT 就会报假失败。
            const symbols = await acquireList(env, "metal", "metal_symbols");
            const metalPool = await listInstruments(env, "metal");
            const pool = (symbols.length ? symbols.map(s => metalPool.find(i => i.symbol === s)).filter(Boolean) : metalPool);
            const inst = pool.find(i => i.em) || metalPool.find(i => i.em);
            const rows = await fetchMetalKline(inst.em, 101, ymd(30));
            return rows.length > 0
                ? { ok: true, message: `返回 ${rows.length} 根日K（${inst.short_name}）` }
                : { ok: false, message: "未返回K线数据" };
        }
        if (key === "eastmoney") {
            const kws = parseNewsKeywords(await acquireOption(env, "news", "news_keywords", "黄金"));
            const timeoutMs = Math.round(await acquireNum(env, "news", "news_timeout_sec", 9, 3, 30) * 1000);
            const rows = await emSearch(kws[0] || "黄金", 3, "default", timeoutMs);
            return rows.length > 0
                ? { ok: true, message: `搜索到 ${rows.length} 条结果（关键词「${kws[0] || "黄金"}」）` }
                : { ok: false, message: "未返回搜索结果" };
        }
        if (key === "sina_news") {
            const limit = await acquireNum(env, "news", "news_per_source", NEWS_PER_SOURCE_FIXED, NEWS_PER_SOURCE_FIXED, NEWS_PER_SOURCE_FIXED);
            const timeoutMs = Math.round(await acquireNum(env, "news", "news_timeout_sec", 9, 3, 30) * 1000);
            const rows = await sinaLives(limit, timeoutMs);
            return rows.length > 0 ? { ok: true, message: `返回 ${rows.length} 条快讯` } : { ok: false, message: "未返回快讯" };
        }
        if (key === "wscn") {
            const limit = await acquireNum(env, "news", "news_per_source", NEWS_PER_SOURCE_FIXED, NEWS_PER_SOURCE_FIXED, NEWS_PER_SOURCE_FIXED);
            const timeoutMs = Math.round(await acquireNum(env, "news", "news_timeout_sec", 9, 3, 30) * 1000);
            const rows = await wscnLives("global-channel", limit, timeoutMs);
            return rows.length > 0 ? { ok: true, message: `返回 ${rows.length} 条快讯` } : { ok: false, message: "未返回快讯" };
        }
        if (BANK_GOLD_SOURCE_KEYS.includes(key)) {
            // 真实请求官网并校验解析有效性，避免采集页「测试」显示「不支持连通性测试」
            const src = BANK_GOLD_SOURCES.find(s => s.key === key);
            const r = await collectBankSource(src);
            return r.ok
                ? { ok: true, message: `${src.name}：${r.message}` }
                : { ok: false, message: `${src.name}：${r.message}` };
        }
        return { ok: false, message: "该数据源不支持连通性测试" };
    } catch (e) {
        return { ok: false, message: e && e.message ? e.message : String(e) };
    }
}

// —— 单个数据源连通性测试 ——
async function testDataSource(request, env) {
    const body = await request.json().catch(() => ({}));
    const key = cleanStr(body.source_key, 40);
    if (!key) return json({ success: false, message: "缺少 source_key" }, 400);
    const sources = await listDataSources(env);
    const src = sources.find(s => s.source_key === key);
    if (!src) return json({ success: false, message: "未知数据源" }, 404);

    const t0 = Date.now();
    const r = await probeSource(env, key);
    const latency = Date.now() - t0;
    try {
        await env.DB.prepare("UPDATE data_sources SET last_status=?, last_checked_at=?, last_latency_ms=?, last_message=? WHERE source_key=?")
            .bind(r.ok ? "ok" : "failed", beijingStamp(Date.now()), latency, String(r.message).slice(0, 200), key).run();
    } catch (e) { logWarn("acquire.testStatus", e); }
    return json({ success: r.ok, source_key: key, latency_ms: latency, message: r.message });
}

// ============================================================
// 采集配置的辅助接口：日志检索 / 清空 / 批量测源 / 导出 / 导入 / 恢复默认
// ============================================================

// —— 采集日志检索（状态 / 触发方式 / 任务 / 关键字 / 时间范围 + 分页）——
//   每条采集记录都写在 fetch_logs 里，这里按「页码」切片返回：
//   默认每页 20 条，页码越界自动收敛到最后一页（不会出现空白页）。
async function getAcquireLogs(url, env) {
    const status = cleanStr(url.searchParams.get("status"), 20);
    const trigger = cleanStr(url.searchParams.get("trigger"), 20);
    const taskKey = cleanStr(url.searchParams.get("task_key"), 40);
    const q = cleanStr(url.searchParams.get("q"), 80);
    const domain = cleanStr(url.searchParams.get("domain"), 20);
    const days = Math.min(365, Math.max(0, parseInt(url.searchParams.get("days"), 10) || 0));

    // 每页条数：page_size 优先，兼容老的 limit；范围 5~200
    const sizeRaw = parseInt(url.searchParams.get("page_size") || url.searchParams.get("limit"), 10) || 20;
    const pageSize = Math.min(200, Math.max(5, sizeRaw));
    // page 优先；只看 offset 的老调用（如导出循环）换算成页码
    const hasPage = url.searchParams.has("page");
    let page = Math.max(1, parseInt(url.searchParams.get("page"), 10) || 1);
    if (!hasPage) page = Math.floor(Math.max(0, parseInt(url.searchParams.get("offset"), 10) || 0) / pageSize) + 1;

    const where = [], binds = [];
    if (status === "success" || status === "failed" || status === "partial" || status === "skipped") { where.push("status=?"); binds.push(status); }
    if (trigger === "manual" || trigger === "cron" || trigger === "page") { where.push("trigger_type=?"); binds.push(trigger); }
    // 按数据域过滤：日志表只有 task_key，域归属要通过任务表换算
    let domainKeys = null;
    if (domain) {
        const all = await listFetchTasks(env);
        domainKeys = all.filter(t => (t.domain || "news") === domain).map(t => t.task_key);
        // 资讯页「抓取最新」不属于任何定时任务，但属于资讯域，要一起出现在日志里
        if (domain === "news") {
            if (!domainKeys.includes(MANUAL_NEWS_LOG_KEY)) domainKeys.push(MANUAL_NEWS_LOG_KEY);
            if (!domainKeys.includes(NEWS_LIVE_LOG_KEY)) domainKeys.push(NEWS_LIVE_LOG_KEY);
        }
        // 稀有金属按需补采/手动刷新、行情页轮询补采同理，属于贵金属域
        if (domain === "metal") {
            if (!domainKeys.includes(RARE_MANUAL_LOG_KEY)) domainKeys.push(RARE_MANUAL_LOG_KEY);
            if (!domainKeys.includes(METAL_LIVE_LOG_KEY)) domainKeys.push(METAL_LIVE_LOG_KEY);
        }
        if (!domainKeys.length) {
            return json({
                rows: [], total: 0, page: 1, page_size: pageSize, total_pages: 0,
                has_prev: false, has_next: false, has_more: false, from: 0, to: 0,
                limit: pageSize, offset: 0, retention: FETCH_LOG_KEEP,
                health: { runs: 0, ok: 0, avg_ms: 0 }, task_names: {}
            });
        }
        where.push(`task_key IN (${domainKeys.map(() => "?").join(",")})`);
        binds.push(...domainKeys);
    }
    if (taskKey) { where.push("task_key=?"); binds.push(taskKey); }
    if (q) { where.push("(message LIKE ? OR task_key LIKE ?)"); binds.push("%" + q + "%", "%" + q + "%"); }
    if (days > 0) { where.push("started_at >= ?"); binds.push(beijingStamp(Date.now() - days * 86400000)); }
    const clause = where.length ? " WHERE " + where.join(" AND ") : "";

    // 先数总数再取当页：页数依赖总数，越界时要把页码夹回最后一页
    let rows = [], total = 0, totalPages = 0;
    try {
        const cnt = await env.DB.prepare(`SELECT COUNT(*) AS n FROM fetch_logs${clause}`).bind(...binds).first();
        total = Number(cnt && cnt.n) || 0;
        totalPages = Math.ceil(total / pageSize);
        if (totalPages > 0 && page > totalPages) page = totalPages;
        const offset = (page - 1) * pageSize;
        const list = await env.DB.prepare(`SELECT * FROM fetch_logs${clause} ORDER BY id DESC LIMIT ? OFFSET ?`)
            .bind(...binds, pageSize, offset).all();
        rows = list.results || [];
    } catch (e) { logWarn("acquire.logs.query", e); }
    const offset = (page - 1) * pageSize;

    // 近 24h 健康度：只受「数据域」影响，不受状态/关键字筛选影响，
    //   否则筛了「仅失败」之后成功率会变成 0%，失去参考意义。
    const since24 = beijingStamp(Date.now() - 86400000);
    let health = { runs: 0, ok: 0, avg_ms: 0 };
    try {
        const hWhere = ["started_at >= ?"];
        const hBinds = [since24];
        if (domainKeys) {
            hWhere.push(`task_key IN (${domainKeys.map(() => "?").join(",")})`);
            hBinds.push(...domainKeys);
        }
        const h = await env.DB.prepare(`SELECT COUNT(*) AS n, SUM(CASE WHEN status IN ('success','partial') THEN 1 ELSE 0 END) AS ok, AVG(duration_ms) AS avg_ms
            FROM fetch_logs WHERE ${hWhere.join(" AND ")} AND status<>'skipped'`).bind(...hBinds).first();
        health = { runs: Number(h && h.n) || 0, ok: Number(h && h.ok) || 0, avg_ms: Math.round(Number(h && h.avg_ms) || 0) };
    } catch (e) { logWarn("acquire.logs.health", e); }

    const tasks = await listFetchTasks(env);
    const names = tasks.reduce((m, t) => (m[t.task_key] = t.name, m), {});
    names[MANUAL_NEWS_LOG_KEY] = MANUAL_NEWS_LOG_NAME;
    names[RARE_MANUAL_LOG_KEY] = "稀有金属按需刷新";
    Object.keys(LIVE_LOG_NAMES).forEach(k => { names[k] = LIVE_LOG_NAMES[k]; });
    return json({
        rows, total, page, page_size: pageSize, total_pages: totalPages,
        has_prev: page > 1, has_next: page < totalPages, has_more: page < totalPages,
        from: total ? offset + 1 : 0, to: offset + rows.length,
        limit: pageSize, offset, retention: FETCH_LOG_KEEP,
        health,
        task_names: names
    });
}

// —— 清空采集日志（保留最近 N 条，默认 0 = 全清）——
async function clearAcquireLogs(request, env) {
    const body = await request.json().catch(() => ({}));
    const keep = Math.min(FETCH_LOG_KEEP, Math.max(0, parseInt(body.keep, 10) || 0));
    let removed = 0;
    try {
        if (keep > 0) {
            removed = await trimByKeep(env, "fetch_logs", "id", keep);
        } else {
            const r = await env.DB.prepare("DELETE FROM fetch_logs").run();
            removed = (r.meta && r.meta.changes) || 0;
        }
    } catch (e) { return json({ success: false, message: e.message }, 500); }
    return json({ success: true, removed, keep });
}

// —— 数据保留：手动立即清理（按天数）——
//   目的：降低数据库容积。一次清理三类数据：
//     · 采集日志 fetch_logs（started_at 北京时间）
//     · 旧消息 news（published_at 日期，星标保留，与自动清理口径一致）
//     · 过期重点通知 notifications（指向的消息已超出窗口）
//   贵金属快照 / 轨迹不在此手动清理（由各自采集链路按条数+天数自动淘汰）。
async function cleanupRetainedData(request, env) {
    const body = await request.json().catch(() => ({}));
    const days = Math.min(3650, Math.max(1, parseInt(body.days, 10) || 30));
    const now = Date.now();
    // 日志：started_at 是北京时间字符串
    const logCutoff = beijingStamp(now - days * 86400000);
    // 消息：published_at 取前 10 位日期，北京时间日期
    const newsCutoff = new Date(now + 8 * 3600 * 1000 - days * 86400000).toISOString().slice(0, 10);
    const result = { success: true, days, logs: 0, news: 0, message: "" };
    try {
        const r1 = await env.DB.prepare("DELETE FROM fetch_logs WHERE started_at < ?").bind(logCutoff).run();
        result.logs = (r1.meta && r1.meta.changes) || 0;
    } catch (e) { logWarn("cleanup.logs", e); }
    try {
        const r2 = await env.DB.prepare("DELETE FROM news WHERE substr(published_at,1,10) < ? AND starred=0").bind(newsCutoff).run();
        result.news = (r2.meta && r2.meta.changes) || 0;
        await env.DB.prepare("DELETE FROM notifications WHERE kind='news_key' AND ref_type='news' AND ref_id>0 AND ref_id NOT IN (SELECT id FROM news)").run();
    } catch (e) { logWarn("cleanup.news", e); }
    result.message = `已清理 ${result.logs} 条日志、${result.news} 条旧消息及失效通知（${days} 天前，星标消息保留）`;
    return json(result);
}

// —— 批量测试数据源（并发 4，避免同时打满外部接口）——
async function testAllDataSources(request, env) {
    const body = await request.json().catch(() => ({}));
    const domain = cleanStr(body.domain, 20);
    const sources = (await listDataSources(env)).filter(s => !domain || (s.domain || "news") === domain);
    if (!sources.length) return json({ success: false, message: "该数据域没有数据源" }, 400);

    const results = [];
    const queue = sources.slice();
    const worker = async () => {
        while (queue.length) {
            const src = queue.shift();
            const t0 = Date.now();
            let ok = false, msg = "";
            const r = await probeSource(env, src.source_key);
            ok = r.ok; msg = r.message;
            const latency = Date.now() - t0;
            results.push({ source_key: src.source_key, name: src.name, ok, message: msg, latency_ms: latency });
            try {
                await env.DB.prepare("UPDATE data_sources SET last_status=?, last_checked_at=?, last_latency_ms=?, last_message=? WHERE source_key=?")
                    .bind(ok ? "ok" : "failed", beijingStamp(Date.now()), latency, String(msg).slice(0, 200), src.source_key).run();
            } catch (e) { logWarn("acquire.testAll.status", e); }
        }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    results.sort((a, b) => a.source_key.localeCompare(b.source_key));
    const failed = results.filter(r => !r.ok).length;
    return json({ success: failed === 0, total: results.length, failed, results });
}

// —— 导出当前采集配置（便于备份 / 迁移到另一套部署）——
async function exportAcquireConfig(env) {
    const [sources, tasks, optionMap] = await Promise.all([
        listDataSources(env), listFetchTasks(env), acquireOptionMap(env)
    ]);
    const options = {};
    ACQUIRE_DOMAINS.forEach(d => {
        options[d.key] = {};
        ACQUIRE_OPTION_DEFAULTS.filter(o => o.domain === d.key).forEach(o => {
            options[d.key][o.key] = (optionMap[d.key] && optionMap[d.key][o.key] != null) ? optionMap[d.key][o.key] : o.value;
        });
    });
    return json({
        version: 1,
        exported_at: nowBeijing(),
        app: "resource-manager",
        sources: sources.map(s => ({ source_key: s.source_key, name: s.name, domain: s.domain || "news", enabled: s.enabled })),
        tasks: tasks.map(t => ({
            task_key: t.task_key, name: t.name, domain: t.domain || "news",
            enabled: t.enabled, interval_sec: taskIntervalSec(t), interval_min: t.interval_min, run_at_hour: t.run_at_hour
        })),
        options
    });
}

// —— 导入采集配置（只接受已知的 source_key / task_key / 参数键，未知项计入 ignored）——
async function importAcquireConfig(request, env) {
    const body = await request.json().catch(() => ({}));
    if (!body || typeof body !== "object") return json({ success: false, message: "请求体不是合法 JSON" }, 400);
    const knownSources = new Set((await listDataSources(env)).map(s => s.source_key));
    const knownTasks = new Set((await listFetchTasks(env)).map(t => t.task_key));
    const knownOpts = new Set(ACQUIRE_OPTION_DEFAULTS.map(o => o.key));

    const writes = [];
    let applied = 0, ignored = 0;

    if (Array.isArray(body.sources)) {
        for (const s of body.sources) {
            const key = cleanStr(s && s.source_key, 40);
            if (!key || !knownSources.has(key)) { ignored++; continue; }
            writes.push(env.DB.prepare("UPDATE data_sources SET enabled=? WHERE source_key=?").bind(s.enabled ? 1 : 0, key));
            applied++;
        }
    }
    if (Array.isArray(body.tasks)) {
        for (const t of body.tasks) {
            const key = cleanStr(t && t.task_key, 40);
            if (!key || !knownTasks.has(key)) { ignored++; continue; }
            const interval = Math.min(86400, Math.max(5,
                parseInt(t.interval_sec, 10) || (parseInt(t.interval_min, 10) * 60) || 1800));
            const min = Math.max(1, Math.round(interval / 60));
            const rawHour = Number(t.run_at_hour);
            const hour = Number.isInteger(rawHour) && rawHour >= -1 && rawHour <= 23 ? rawHour : -1;
            const enabled = t.enabled ? 1 : 0;
            const next = enabled ? beijingStamp(nextRunStamp({ interval_sec: interval, interval_min: min, run_at_hour: hour, last_run_at: "" }, Date.now())) : "";
            writes.push(env.DB.prepare("UPDATE fetch_tasks SET enabled=?, interval_sec=?, interval_min=?, run_at_hour=?, next_run_at=?, fail_streak=0 WHERE task_key=?")
                .bind(enabled, interval, min, hour, next, key));
            applied++;
        }
    }
    if (body.options && typeof body.options === "object") {
        for (const domain of ACQUIRE_DOMAINS.map(d => d.key)) {
            const values = body.options[domain];
            if (!values || typeof values !== "object") continue;
            for (const def of ACQUIRE_OPTION_DEFAULTS.filter(o => o.domain === domain)) {
                if (!Object.prototype.hasOwnProperty.call(values, def.key) || !knownOpts.has(def.key)) continue;
                if (def.readonly) continue; // 只读参数：不允许通过配置导入/应用修改
                let v = values[def.key];
                if (Array.isArray(v)) v = v.join(",");
                v = String(v == null ? "" : v);
                if (def.type === "number") {
                    const meta = (() => { try { return JSON.parse(def.meta || "{}"); } catch { return {}; } })();
                    let n = Number(v);
                    if (!Number.isFinite(n)) n = Number(def.value) || 0;
                    if (meta.min != null) n = Math.max(meta.min, n);
                    if (meta.max != null) n = Math.min(meta.max, n);
                    v = String(n);
                } else if (def.type === "bool") {
                    v = (v === "1" || v === true || v === 1 || v === "true") ? "1" : "0";
                } else if (def.type === "list") {
                    const allowed = (() => { try { return JSON.parse(def.options || "[]").map(o => o.value); } catch { return []; } })();
                    const picked = splitList(v);
                    v = (allowed.length ? picked.filter(x => allowed.includes(x)) : picked).join(",");
                } else if (def.type === "select") {
                    const allowed = (() => { try { return JSON.parse(def.options || "[]").map(o => o.value); } catch { return []; } })();
                    const picked = splitList(v);
                    v = allowed.length ? (allowed.includes(picked[0]) ? picked[0] : def.value) : (picked[0] || def.value);
                } else if (def.type === "textarea") {
                    v = (def.key === "news_keywords" ? parseNewsKeywords(v) : splitList(v)).join(",");
                }
                writes.push(env.DB.prepare(`INSERT INTO acquire_options(domain,option_key,name,value,value_type,options,meta,description,sort_order,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                    ON CONFLICT(option_key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`)
                    .bind(domain, def.key, def.name, v, def.type, def.options || "", def.meta || "", def.description || "", def.sort));
                applied++;
            }
        }
    }
    for (let i = 0; i < writes.length; i += 100) await env.DB.batch(writes.slice(i, i + 100));
    invalidateAcquireOptions();
    // 屏蔽词 / 相关性开关可能被改：聚合条件与 relevant 标记都会变，统计缓存直接失效
    await invalidateAggCache(env);
    return json({ success: true, applied, ignored, message: applied ? `已应用 ${applied} 项配置` : "没有可应用的配置项" });
}

// —— 参数恢复默认（按域，或只恢复某几个键）——
async function resetAcquireParams(request, env) {
    const body = await request.json().catch(() => ({}));
    const domain = cleanStr(body.domain, 20);
    const keys = Array.isArray(body.keys) ? body.keys.map(k => cleanStr(k, 60)).filter(Boolean) : null;
    const defs = ACQUIRE_OPTION_DEFAULTS.filter(o =>
        (!domain || o.domain === domain) && (!keys || keys.includes(o.key)));
    if (!defs.length) return json({ success: false, message: "没有匹配的参数" }, 400);
    await env.DB.batch(defs.map(o => env.DB.prepare(`INSERT INTO acquire_options(domain,option_key,name,value,value_type,options,meta,description,sort_order,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(option_key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`)
        .bind(o.domain, o.key, o.name, o.value, o.type, o.options || "", o.meta || "", o.description || "", o.sort)));
    invalidateAcquireOptions();
    await invalidateAggCache(env);
    return json({ success: true, reset: defs.map(o => o.key), defaults: defs.reduce((m, o) => (m[o.key] = o.value, m), {}) });
}

// —— 定时调度：判断哪些任务到期（由 cron 每分钟唤醒一次，见 wrangler.toml）——
async function runDueTasks(env, triggerType) {
    const tasks = await listFetchTasks(env);
    const now = Date.now();
    const ran = [];
    for (const t of tasks) {
        if (!t.enabled) continue;
        const next = t.next_run_at ? epochOf(t.next_run_at) : 0;
        const interval = taskIntervalSec(t) * 1000;
        const last = t.last_run_at ? epochOf(t.last_run_at) : 0;
        let due;
        if (Number(t.run_at_hour) >= 0) {
            // 固定时刻任务缺少 next_run_at 时，先初始化到下一个时刻，不能立即执行。
            if (!next) {
                const nextStamp = beijingStamp(nextRunStamp(t, now));
                await env.DB.prepare("UPDATE fetch_tasks SET next_run_at=? WHERE task_key=? AND (next_run_at IS NULL OR next_run_at='')")
                    .bind(nextStamp, t.task_key).run();
                continue;
            }
            due = next <= now;
        } else {
            due = !last || now - last >= interval;
        }
        if (!due) continue;
        const r = await runFetchTask(env, t.task_key, triggerType || "cron");
        ran.push({ task_key: t.task_key, name: t.name, status: r.status, message: r.message });
    }
    return ran;
}

// ============================================================
// 路由
// ============================================================
async function apiRouter(request, env, user) {
    const url = new URL(request.url);
    switch (url.pathname) {
        case "/api/login": return handleLogin(request, env);
        case "/api/auth": return handleAuth(request, env);
        case "/api/logout": return json({ success: true });
        case "/api/change-password": return handleChangePassword(request, env);
        case "/api/news":
            if (request.method === "GET") return can(user, "news.view") ? getNews(url, env) : forbidden();
            return saveNews(request, env, user);
        case "/api/news/refresh": return refreshNews(request, env, user);
        case "/api/news/meta": return can(user, "news.view") ? getNewsMeta(env) : forbidden();
        case "/api/metals":
            return can(user, "market.view") ? getMetalBoard(env) : forbidden();
        case "/api/metals/refresh": {
            if (!can(user, "market.refresh")) return forbidden();
            try {
                // 与定时任务保持同一口径：停用「新浪实时行情」后手动刷新也必须失败
                if (!await sourceEnabled(env, "sina_quote")) return json({ success: false, message: "新浪实时行情数据源已停用" }, 502);
                // refreshMetalQuotes 内部已写入 last_metal_refresh，无需重复写
                return json(await refreshMetalQuotes(env));
            } catch (e) {
                return json({ success: false, message: "行情刷新失败：" + e.message }, 502);
            }
        }
        case "/api/metals/history": return can(user, "market.view") ? getMetalHistory(env, url) : forbidden();
        case "/api/metals/compare": return can(user, "market.view") ? getMetalCompare(env, url) : forbidden();
        case "/api/metals/detail": return can(user, "market.view") ? getMetalDetail(env, url) : forbidden();
        case "/api/bank-gold":
            return can(user, "market.view") ? getBankGold(env) : forbidden();
        case "/api/bank-gold/refresh":
            return can(user, "market.refresh") ? refreshBankGold(request, env) : forbidden();
        case "/api/users": return handleUsers(request, env, user);
        case "/api/permissions": return json({ permissions: ALL_PERMISSIONS, defaults: ROLE_PERMISSIONS });
        case "/api/acquire/config":
            if (request.method === "GET") return can(user, "market.view") ? getAcquireConfig(env) : forbidden();
            return can(user, "market.config") ? saveAcquireConfig(request, env) : forbidden();
        case "/api/acquire/run":
            if (!can(user, "market.refresh")) return forbidden();
            return runAcquireNow(request, env);
        case "/api/acquire/test":
            if (!can(user, "market.refresh")) return forbidden();
            return testDataSource(request, env);
        case "/api/acquire/test-all":
            if (!can(user, "market.refresh")) return forbidden();
            return testAllDataSources(request, env);
        case "/api/acquire/logs":
            if (!can(user, "market.view")) return forbidden();
            return getAcquireLogs(url, env);
        case "/api/acquire/logs/clear":
            if (!can(user, "market.config")) return forbidden();
            return clearAcquireLogs(request, env);
        case "/api/acquire/cleanup":
            if (!can(user, "market.config")) return forbidden();
            return cleanupRetainedData(request, env);
        case "/api/acquire/export":
            if (!can(user, "market.view")) return forbidden();
            return exportAcquireConfig(env);
        case "/api/acquire/import":
            if (!can(user, "market.config")) return forbidden();
            return importAcquireConfig(request, env);
        case "/api/acquire/params/reset":
            if (!can(user, "market.config")) return forbidden();
            return resetAcquireParams(request, env);
        case "/api/alerts": return can(user, "market.view") ? handleAlerts(request, env, user, url) : forbidden();
        case "/api/notifications": return handleNotifications(request, env, user, url);
        case "/api/calendar":
            if (request.method === "GET") return can(user, "market.view") ? getCalendar(env, url) : forbidden();
            // 事件维护属配置类操作，与「数据采集」一致按 market.config 校验
            return can(user, "market.config") ? saveCalendarEvent(request, env, user) : forbidden();
        case "/api/calendar/check":
            if (!can(user, "market.refresh")) return forbidden();
            return json(await checkEcoReminders(env));
        case "/api/calendar/import":
            return can(user, "market.config") ? importCalendarEvents(request, env, user) : forbidden();
        case "/api/rare":
            return can(user, "market.view") ? getRareBoard(env, url) : forbidden();
        case "/api/rare/refresh": {
            if (!can(user, "market.refresh")) return forbidden();
            try {
                if (!await sourceEnabled(env, "sina_quote")) return json({ success: false, message: "新浪实时行情数据源已停用" }, 502);
                const quotes = await refreshRareQuotesLogged(env, "manual");
                RARE_SCENARIO_CACHE.clear();
                return json({ success: true, updated: quotes.length, refreshed_at: nowBeijing() });
            } catch (e) {
                return json({ success: false, message: "稀有金属行情刷新失败：" + e.message }, 502);
            }
        }
        case "/api/rare/scenarios":
            return can(user, "market.view") ? getRareScenarios(env, url) : forbidden();
        case "/api/rare/match":
            return can(user, "market.view") ? getRareMaterialMatch(env, url) : forbidden();
        case "/api/rare/match/reverse":
            return can(user, "market.view") ? getRareMaterialReverse(env, url) : forbidden();
        case "/api/rare/topics":
            return can(user, "market.view") ? getRareTopics(env) : forbidden();
        case "/api/rare/instruments":
            if (request.method === "GET") return can(user, "market.view") ? getInstrumentList(env) : forbidden();
            return can(user, "market.config") ? saveInstrument(request, env) : forbidden();
        case "/api/rare/instruments/delete":
            return can(user, "market.config") ? deleteInstrument(request, env) : forbidden();
        case "/api/rare/instruments/quick-add":
            // 一键加入监测 = 写品种表，按配置权限
            return can(user, "market.config") ? quickAddInstrumentMaterial(request, env) : forbidden();
        case "/api/rare/instruments/test":
            // 检测要打外部行情接口：配置人员与可执行刷新的人都放行
            return (can(user, "market.config") || can(user, "market.refresh")) ? testInstrumentQuote(request, env) : forbidden();
        case "/api/dashboard":
            return can(user, "market.view") ? getDashboard(env, url) : forbidden();
        case "/api/notify-channels": return can(user, "settings.view") ? handleNotifyChannels(request, env, user) : forbidden();
        case "/api/positions": return can(user, "market.view") ? handlePositions(request, env, user) : forbidden();
        case "/api/instruments": return can(user, "market.view") ? getSymbolCatalog(env) : forbidden();
        case "/api/watchlist": return handleWatchlist(request, env, user);
        case "/api/trade-plans": return handleTradePlans(request, env, user, url);
        case "/api/desk": return can(user, "market.view") ? getDesk(env, user, url) : forbidden();
        case "/api/settings":
            if (request.method === "GET") return can(user, "settings.view") ? getSettings(env, user) : getPublicSettings(env);
            return can(user, "settings.edit") ? saveSettings(request, env) : forbidden();
        case "/api/health": return json({ status: "ok", version: "2.0" });
        default: return json({ error: "API NOT FOUND" }, 404);
    }
}

export default {
    async fetch(request, env) {
        if (request.method === "OPTIONS") return json({ success: true });
        const url = new URL(request.url);
        if (url.pathname.startsWith("/api/")) {
            await migrate(env);
            const publicAPI = ["/api/login", "/api/auth", "/api/health"];
            // 用户身份只解析一次，透传给路由（避免重复查库）
            const user = publicAPI.includes(url.pathname) ? null : await currentUser(request, env);
            if (!publicAPI.includes(url.pathname) && !user) return json({ error: "Unauthorized" }, 401);
            return apiRouter(request, env, user);
        }
        return env.ASSETS.fetch(request);
    },

    // Cron 定时调度
    //   wrangler.toml 配置 "* * * * *" → 每分钟唤醒一次，
    //   由 fetch_tasks 的间隔配置决定具体执行哪些任务（间隔、启停均可在「数据采集」页配置）。
    //   自愈：若某次唤醒失败，下次唤醒会依据 last_run_at 重新判断是否到期，不会漏采。
    async scheduled(event, env, ctx) {
        ctx.waitUntil((async () => {
            await migrate(env);
            const cron = String((event && event.cron) || "");
            // 本地调试（无 cron 参数）或非 5 分钟档位时同样走到期判断
            try {
                await runDueTasks(env, "cron");
            } catch (e) {}
            // 财经日历到点提醒（未来 30 分钟内的经济事件）
            try { await checkEcoReminders(env); } catch (e) {}
            // 稀有金属报价补采（内部有 10 分钟新鲜度判断，未过期不发请求）
            try { await readRareQuotes(env, false); } catch (e) {}
        })().catch(() => {}));
    }
};
