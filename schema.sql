PRAGMA foreign_keys = ON;

-- ============================================================
-- 稀有金属投资咨询平台 — D1 数据库初始化
-- 系统定位：稀有 / 贵金属行情与产业链资讯的投资咨询工作台。
-- 共 21 张表，按用途分组：
--   认证 / 菜单 / 设置：users、login_attempts、menus、settings
--   资讯：news
--   行情与品种：metal_quotes、metal_history、metal_instruments、metal_snapshots
--   银行金价：bank_gold_quotes（独立表，数值列允许 NULL）
--   采集配置：data_sources、fetch_tasks、fetch_logs、acquire_options
--   通知预警：notifications、notify_channels、price_alerts
--   持仓决策：positions、watchlist、trade_plans
--   财经日历：eco_events
-- 不含任何真实用户、密码哈希或私有数据。
-- 公开注册已下线：本文件不 INSERT INTO users，空库全新部署须手工写入首个 admin
--   （密码格式 pbkdf2$100000$salt$hash，或旧格式 sha256(pwd:salt) 由 worker.js 登录时自动升级）。
-- 种子一致性：本文件的默认设置 / 菜单 / 数据源 / 任务 / 品种 / 采集参数必须与
--   worker.js 的 migrate() 与 ACQUIRE_OPTION_DEFAULTS 保持一致（21 张表、27 个采集参数）。
--   migrate() 全部用 INSERT OR IGNORE，若先执行本文件，则本文件的种子会「胜出」且
--   migrate() 不会覆盖（菜单例外：migrate() 用 UPDATE / DELETE 强制纠正）。
--   建议空库直接让 migrate() 自愈；若先跑本文件，请务必核对两边种子一致。
-- ============================================================

-- 贵金属实时行情快照（每个品种一行，抓取时 upsert）
CREATE TABLE IF NOT EXISTS metal_quotes (
    symbol TEXT PRIMARY KEY,               -- AU0/AG0（贵金属）+ 稀有金属品种（LC0/SI0/NI0/SN0/CU0/AL0/PS0）
    name TEXT NOT NULL,                    -- 品种全称，如「沪金主连」
    short_name TEXT DEFAULT '',            -- 简称，如「沪金」
    market TEXT DEFAULT '',                -- 市场 / 交易所
    kind TEXT DEFAULT '',                  -- 黄金 / 白银 / 稀有金属类别
    price REAL NOT NULL DEFAULT 0,         -- 最新价
    prev_close REAL NOT NULL DEFAULT 0,    -- 昨收（涨跌基准）
    open REAL NOT NULL DEFAULT 0,          -- 开盘价
    high REAL NOT NULL DEFAULT 0,          -- 最高价
    low REAL NOT NULL DEFAULT 0,           -- 最低价
    bid REAL NOT NULL DEFAULT 0,           -- 买价
    ask REAL NOT NULL DEFAULT 0,           -- 卖价
    volume REAL NOT NULL DEFAULT 0,        -- 成交量
    open_interest REAL NOT NULL DEFAULT 0, -- 持仓量
    change REAL NOT NULL DEFAULT 0,        -- 涨跌额
    change_pct REAL NOT NULL DEFAULT 0,    -- 涨跌幅（%）
    amplitude REAL NOT NULL DEFAULT 0,     -- 振幅（%）
    unit TEXT DEFAULT '',                  -- 美元/盎司、元/克、元/千克
    currency TEXT DEFAULT 'USD',
    source TEXT DEFAULT 'sina',
    quote_date TEXT DEFAULT '',
    quote_time TEXT DEFAULT '',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bank_gold_quotes (
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
);

-- 贵金属本地历史轨迹（每次刷新追加，用于走势图；每品种保留最近 500 条）
CREATE TABLE IF NOT EXISTS metal_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    price REAL NOT NULL DEFAULT 0,
    quote_time TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_metal_history_sym ON metal_history(symbol, id DESC);

-- 品种注册表：贵金属 / 稀有金属的品种池（页面可增删改，采集与展示都以它为准）
--   内置品种由建库脚本写入（builtin=1），用户自建品种 builtin=0，可删除；内置的只能停用。
CREATE TABLE IF NOT EXISTS metal_instruments (
    symbol TEXT PRIMARY KEY,              -- 品种代码，同时是 metal_quotes 的主键，如 AU0 / LC0
    sina TEXT NOT NULL DEFAULT '',        -- 新浪行情代码：nf_ 内盘期货 / hf_ 外盘 / gds_ 上金所延期
    name TEXT NOT NULL DEFAULT '',        -- 全称，如「氧化铝主连」
    short_name TEXT NOT NULL DEFAULT '',  -- 简称，如「氧化铝」
    market TEXT NOT NULL DEFAULT '',      -- 市场 / 交易所
    kind TEXT NOT NULL DEFAULT '',        -- 类别：黄金 / 白银 / 锂 / 镍 / 锡 / 铝 …
    unit TEXT NOT NULL DEFAULT '',        -- 计价单位：元/吨、元/克、美元/盎司
    currency TEXT NOT NULL DEFAULT 'CNY',
    em TEXT NOT NULL DEFAULT '',          -- 东方财富 secid，用于历史 K 线与三情景推演（可空）
    chain TEXT NOT NULL DEFAULT '',       -- 产业链标签，如「锂电」「光伏/硅基」
    scope TEXT NOT NULL DEFAULT 'rare',   -- metal = 贵金属，rare = 稀有金属（决定归属哪个页面）
    enabled INTEGER NOT NULL DEFAULT 1,   -- 0 = 停用：不采集、页面不展示
    sort_order INTEGER NOT NULL DEFAULT 0,
    builtin INTEGER NOT NULL DEFAULT 0,   -- 1 = 内置品种（不可删除）
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);

-- 金价采集快照（默认每 30 分钟一次，间隔可在「数据采集」页配置为 5～86400 秒；一条 = 一个采集批次的处理结果）
--   注：下面的 prev_base_price / base_* 基准字段本文件已内置；migrate() 靠 ensureColumns 补列，旧库升级时自动对齐。
CREATE TABLE IF NOT EXISTS metal_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_at TEXT NOT NULL,               -- 采集时刻（北京时间 YYYY-MM-DD HH:MM）
    epoch INTEGER NOT NULL DEFAULT 0,     -- 采集时刻时间戳（便于排序/区间筛选）
    xau_price REAL NOT NULL DEFAULT 0,    -- 兼容历史快照字段
    xau_change_pct REAL NOT NULL DEFAULT 0,   -- 兼容历史快照字段
    au0_price REAL NOT NULL DEFAULT 0,    -- 沪金（元/克）
    au0_change_pct REAL NOT NULL DEFAULT 0,    -- 沪金当日涨跌幅 %
    autd_price REAL NOT NULL DEFAULT 0,   -- 兼容历史快照字段
    autd_change_pct REAL NOT NULL DEFAULT 0, -- 兼容历史快照字段
    xag_price REAL NOT NULL DEFAULT 0,    -- 兼容历史快照字段
    silver_price REAL NOT NULL DEFAULT 0, -- 沪银（元/千克）
    usdcny REAL NOT NULL DEFAULT 0,       -- 美元兑人民币
    gold_silver_ratio REAL NOT NULL DEFAULT 0,  -- 金银比
    shanghai_premium REAL NOT NULL DEFAULT 0,   -- 兼容历史快照字段
    day_high REAL NOT NULL DEFAULT 0,     -- 本批采集时沪金当日最高
    day_low REAL NOT NULL DEFAULT 0,      -- 本批采集时沪金当日最低
    prev_xau_price REAL NOT NULL DEFAULT 0,   -- 兼容历史快照字段
    prev_base_price REAL NOT NULL DEFAULT 0,  -- 上一次采集的基准品种价格（用于环比）
    base_symbol TEXT DEFAULT '',               -- 环比基准品种标识（如 AU0）
    base_name TEXT DEFAULT '',                 -- 基准品种展示名
    base_price REAL NOT NULL DEFAULT 0,       -- 基准品种最新价
    base_change_pct REAL NOT NULL DEFAULT 0,  -- 基准品种当日涨跌幅 %
    base_unit TEXT DEFAULT '',                 -- 基准品种计价单位
    interval_change REAL NOT NULL DEFAULT 0,   -- 环比上次采集的涨跌额
    interval_change_pct REAL NOT NULL DEFAULT 0, -- 环比上次采集的涨跌幅 %
    level TEXT DEFAULT 'normal',          -- 异动等级：normal/surge/alert
    summary TEXT DEFAULT '',               -- 处理结论（一句话摘要）
    detail TEXT DEFAULT '',                -- 该批次完整 JSON 明细（各品种快照）
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_metal_snap_batch ON metal_snapshots(batch_at);
CREATE INDEX IF NOT EXISTS idx_metal_snap_epoch ON metal_snapshots(epoch DESC);

-- 资讯消息（多平台抓取，用于宏观 / 行情 / 政策跟踪）
CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,                    -- 标题
    summary TEXT DEFAULT '',                -- 摘要 / 正文节选
    url TEXT DEFAULT '',                    -- 原文链接
    source TEXT DEFAULT '',                 -- 数据源标识：eastmoney / sina / wscn / manual
    platform TEXT DEFAULT '',               -- 展示用来源，如「每日经济新闻」
    channel TEXT NOT NULL DEFAULT 'other',  -- 频道：equity/fund/bond/metal/macro/forex/property/policy/other
    keywords TEXT DEFAULT '',               -- 命中关键词，逗号分隔
    published_at TEXT,                      -- 发布时间
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    hash TEXT UNIQUE,                       -- 去重指纹
    symbols TEXT DEFAULT '',                -- 关联标的（逗号分隔的品种代码，如 "AU0"）
    sentiment TEXT DEFAULT '',              -- 整体情绪：bullish（利多）/ bearish（利空）/ neutral（中性）
    sentiment_map TEXT DEFAULT '',          -- 按标的的情绪明细 JSON：{"AU0":{"label":"bullish","score":2,"hits":["上涨"],"manual":0}}
    starred INTEGER NOT NULL DEFAULT 0,      -- 是否收藏
    note TEXT DEFAULT '',                   -- 个人批注
    relevant INTEGER NOT NULL DEFAULT 1,    -- 相关性标记：标题是否命中四类白名单（1 相关 / 0 无关）
    impact TEXT DEFAULT '',                 -- 消息影响研判 JSON：方向/强度/影响标的/传导链/依据（与 sentiment 并存，互不污染；存量库由 migrate 补列并回填）
    key_score INTEGER NOT NULL DEFAULT 0,   -- 重点综合分（0-100）：方向强度+影响范围+事件权重+信号词+来源+时效
    is_key INTEGER NOT NULL DEFAULT 0,      -- 是否为「重点消息」（score>=55 且具备方向或强信号）
    key_reasons TEXT DEFAULT '',             -- 挑选理由 JSON：{score,isKey,reasons[],dims}
    key_brief TEXT DEFAULT ''                -- 重点消息简明摘要（一句话：发生了什么→影响谁→偏涨偏跌），入库时生成并随通知中心推送
);
CREATE INDEX IF NOT EXISTS idx_news_pub ON news(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_channel ON news(channel, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_source ON news(source);
CREATE INDEX IF NOT EXISTS idx_news_starred ON news(starred, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_day ON news(substr(published_at,1,10));
CREATE INDEX IF NOT EXISTS idx_news_key ON news(is_key, key_score DESC, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_rel ON news(relevant, published_at DESC);

-- ============================================================
-- 数据采集配置
-- ============================================================

-- 数据源（可启停、可单独测试连通性）
CREATE TABLE IF NOT EXISTS data_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT NOT NULL UNIQUE,        -- 唯一标识：sina_quote / em_kline / eastmoney / sina_news / wscn
    name TEXT NOT NULL,                     -- 展示名称
    group_name TEXT DEFAULT '其它',          -- 分组：贵金属行情 / 历史K线 / 财经资讯
    domain TEXT NOT NULL DEFAULT 'news',   -- 所属数据域：news（消息数据）/ metal（贵金属数据）
    endpoint TEXT DEFAULT '',               -- 接口地址（展示用）
    description TEXT DEFAULT '',            -- 说明
    enabled INTEGER NOT NULL DEFAULT 1,      -- 是否启用
    sort_order INTEGER NOT NULL DEFAULT 0,
    last_status TEXT DEFAULT '',            -- 最近一次测试结果：ok / failed
    last_checked_at TEXT DEFAULT '',        -- 最近测试时间
    last_latency_ms INTEGER NOT NULL DEFAULT 0,
    last_message TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 定时任务（可配置间隔、启停）
CREATE TABLE IF NOT EXISTS fetch_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_key TEXT NOT NULL UNIQUE,          -- 唯一标识：metal_snapshot / news_crawl / metal_quote
    name TEXT NOT NULL,                     -- 任务名称
    description TEXT DEFAULT '',            -- 任务说明
    domain TEXT NOT NULL DEFAULT 'news',   -- 所属数据域：news / metal
    interval_min INTEGER NOT NULL DEFAULT 30, -- 执行间隔（分钟，兼容旧字段，由 interval_sec 同步写入）
    interval_sec INTEGER,                     -- 执行间隔（秒，唯一口径；为空时按 interval_min × 60 兜底）
    enabled INTEGER NOT NULL DEFAULT 1,      -- 是否启用
    run_at_hour INTEGER NOT NULL DEFAULT -1, -- 每日固定执行时刻（-1 = 不限定，按间隔执行）
    last_run_at TEXT DEFAULT '',            -- 上次执行时间
    last_status TEXT DEFAULT '',            -- 上次执行结果：success / failed / skipped
    last_message TEXT DEFAULT '',           -- 上次执行摘要
    next_run_at TEXT DEFAULT '',            -- 下次计划执行时间
    run_count INTEGER NOT NULL DEFAULT 0,   -- 累计执行次数
    fail_count INTEGER NOT NULL DEFAULT 0,  -- 累计失败次数
    fail_streak INTEGER NOT NULL DEFAULT 0, -- 连续失败次数（成功即清零，用于自动停用保护）
    lease_until INTEGER NOT NULL DEFAULT 0,  -- 执行租约到期时间（epoch 毫秒，0=空闲）；防止 cron/页面补采/手动采集多 isolate 并发重复执行
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 采集参数（按数据域存储的细粒度抓取配置）
CREATE TABLE IF NOT EXISTS acquire_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,                   -- 数据域：news（消息数据）/ metal（贵金属数据）
    option_key TEXT NOT NULL UNIQUE,        -- 参数键
    name TEXT NOT NULL,                     -- 显示名
    value TEXT DEFAULT '',                  -- 当前值（统一按字符串存储）
    value_type TEXT DEFAULT 'text',         -- 类型：text / textarea / number / list / bool
    options TEXT DEFAULT '',                -- 候选项 JSON（list 类型用）：[{"value":"x","label":"y"}]
    meta TEXT DEFAULT '',                   -- 附加元数据 JSON：{"min":1,"max":60}
    description TEXT DEFAULT '',            -- 说明
    sort_order INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_acquire_options_domain ON acquire_options(domain, sort_order);

-- 采集日志（每一次执行的明细记录）
CREATE TABLE IF NOT EXISTS fetch_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_key TEXT NOT NULL,                 -- 关联任务 task_key
    trigger_type TEXT NOT NULL DEFAULT 'cron', -- 触发方式：cron（定时）/ manual（手动）
    started_at TEXT NOT NULL,               -- 开始时间
    finished_at TEXT DEFAULT '',            -- 结束时间
    duration_ms INTEGER NOT NULL DEFAULT 0, -- 耗时（毫秒）
    status TEXT NOT NULL DEFAULT 'success', -- 结果：success / failed
    fetched INTEGER NOT NULL DEFAULT 0,    -- 抓取条数
    inserted INTEGER NOT NULL DEFAULT 0,   -- 新增入库条数
    skipped INTEGER NOT NULL DEFAULT 0,    -- 去重跳过条数
    message TEXT DEFAULT ''                 -- 结果摘要 / 错误信息
);
CREATE INDEX IF NOT EXISTS idx_fetch_logs_task ON fetch_logs(task_key, id DESC);
CREATE INDEX IF NOT EXISTS idx_fetch_logs_started ON fetch_logs(started_at DESC);

-- 系统设置
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- 系统菜单
CREATE TABLE IF NOT EXISTS menus (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    menu_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    icon TEXT DEFAULT 'fa-newspaper',
    parent_key TEXT DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    is_system INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 用户
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'visitor',
    permissions TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 登录失败限流（D1 持久化，多实例共享；窗口内失败过多即拒绝）
CREATE TABLE IF NOT EXISTS login_attempts (
    key TEXT PRIMARY KEY,
    fails INTEGER NOT NULL DEFAULT 0,
    first_at INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);

-- 价格预警（目标价 / 涨跌幅阈值）
CREATE TABLE IF NOT EXISTS price_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    name TEXT DEFAULT '',
    direction TEXT NOT NULL DEFAULT 'above',
    target REAL NOT NULL DEFAULT 0,
    cooldown_min INTEGER NOT NULL DEFAULT 30,
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT DEFAULT '',
    trigger_count INTEGER NOT NULL DEFAULT 0,
    last_trigger_epoch INTEGER NOT NULL DEFAULT 0,
    last_trigger_at TEXT DEFAULT '',
    last_trigger_price REAL NOT NULL DEFAULT 0,
    created_by TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alerts_enabled ON price_alerts(enabled, symbol);

-- 站内通知（dedup_key 用于冷却窗口内去重）
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'system',
    level TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    body TEXT DEFAULT '',
    ref_type TEXT DEFAULT '',
    ref_id INTEGER NOT NULL DEFAULT 0,
    dedup_key TEXT DEFAULT '',
    read INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(id DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(read, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedup ON notifications(dedup_key) WHERE dedup_key <> '';

-- 推送通道（企业微信 / 钉钉 / 飞书 / 通用 Webhook）
CREATE TABLE IF NOT EXISTS notify_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    channel_type TEXT NOT NULL DEFAULT 'wecom',
    webhook_url TEXT NOT NULL DEFAULT '',
    secret TEXT DEFAULT '',
    events TEXT DEFAULT 'alert',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_status TEXT DEFAULT '',
    last_sent_at TEXT DEFAULT '',
    last_message TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 持仓（按 created_by 隔离）
CREATE TABLE IF NOT EXISTS positions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    name TEXT DEFAULT '',
    qty REAL NOT NULL DEFAULT 0,
    cost REAL NOT NULL DEFAULT 0,
    fee REAL NOT NULL DEFAULT 0,
    opened_at TEXT DEFAULT '',
    note TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_positions_owner ON positions(created_by, id DESC);

-- 自选观察池：投资决策的入口（先观察，再决定建仓），按用户隔离
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,
    note TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(created_by, symbol)
);
CREATE INDEX IF NOT EXISTS idx_watchlist_owner ON watchlist(created_by, symbol);

-- 建仓计划：自选 / 持仓的「准备怎么买」——目标价、止损价、分批价位
CREATE TABLE IF NOT EXISTS trade_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol TEXT NOT NULL,                   -- 品种代码，如 "AU0"
    name TEXT DEFAULT '',                   -- 品种名称（冗余，便于列表展示）
    target_price REAL NOT NULL DEFAULT 0,   -- 目标价（止盈）
    stop_loss REAL NOT NULL DEFAULT 0,      -- 止损价
    entry_price REAL NOT NULL DEFAULT 0,    -- 计划建仓均价（参考）
    tranches TEXT DEFAULT '',               -- 分批价位 JSON：[{"price":100,"qty":10,"pct":30}]
    status TEXT DEFAULT 'planning',         -- planning（准备中）/ active（执行中）/ done（已完成）/ cancelled（已取消）
    note TEXT DEFAULT '',                   -- 备注
    created_by TEXT DEFAULT '',             -- 归属用户
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_trade_plans_owner ON trade_plans(created_by, id DESC);
CREATE INDEX IF NOT EXISTS idx_trade_plans_symbol ON trade_plans(symbol);

-- 默认系统设置（须与 worker.js migrate() 的 settingDefaults 完全一致，共 7 项）
INSERT OR IGNORE INTO settings(key, value) VALUES
    ('system_name', '稀有金属投资咨询平台'),
    ('news_keywords', '人工智能,AI,算力,GPU,显卡,AI芯片,半导体,数据中心,碳酸锂,工业硅,沪镍,沪锡,稀土,铜,铝,黄金,白银,美联储,加息,降息,通胀,汇率'),
    ('news_sources', 'eastmoney,sina,wscn'),
    ('last_news_refresh', ''),
    ('last_metal_refresh', ''),
    ('last_metal_snapshot', ''),
    ('metal_snapshot_interval', '30');

-- 系统菜单（兼容数据）：前端导航由 static/js/app.js 的 NAV_ITEMS 定义，运行时不读取本表。
INSERT OR IGNORE INTO menus(menu_key, name, url, icon, parent_key, sort_order, enabled, is_system) VALUES
    ('calendar', '财经日历', '#calendar', 'fa-calendar-days', '', 8, 1, 1),
    ('acquire', '数据采集', '#acquire', 'fa-download', '', 9, 1, 1),
    ('acquire-news', '消息数据', '#acquire-news', 'fa-newspaper', 'acquire', 10, 1, 1),
    ('acquire-metal', '贵金属数据', '#acquire-metal', 'fa-coins', 'acquire', 11, 1, 1),
    ('news', '消息中心', '#news', 'fa-newspaper', '', 20, 1, 1),
    ('users', '用户管理', '#users', 'fa-users', '', 50, 1, 1),
    ('settings', '系统设置', '#settings', 'fa-sliders', '', 60, 1, 1);

-- 与 worker.js 的 migrate() 一致，清理不再使用的历史菜单记录。
DELETE FROM menus WHERE menu_key='metals';
DELETE FROM menus WHERE menu_key IN ('dashboard','quote','rare','feed');

-- 默认数据源
INSERT OR IGNORE INTO data_sources(source_key, name, group_name, domain, endpoint, description, enabled, sort_order) VALUES
    ('sina_quote', '新浪财经 · 实时行情', '贵金属行情', 'metal', 'https://hq.sinajs.cn/list=nf_AU0,nf_AG0', '沪金 / 沪银实时报价 + 美元兑人民币汇率', 1, 10),
    ('em_kline', '东方财富 · 历史K线', '历史K线', 'metal', 'https://push2his.eastmoney.com/api/qt/stock/kline/get', '日K / 周K / 月K / 5分钟K线，支撑详细数据页的蜡烛图与分时图', 1, 20),
    ('eastmoney', '东方财富 · 财经搜索', '财经资讯', 'news', 'https://search-api-web.eastmoney.com/search/jsonp', '按关注关键词 + 泛化 AI 主题词全网搜索财经资讯，覆盖媒体最广', 1, 30),
    ('sina_news', '新浪财经 · 7×24快讯', '财经资讯', 'news', 'https://zhibo.sina.com.cn/api/zhibo/feed', '宏观政策与盘中异动快讯', 1, 40),
    ('wscn', '华尔街见闻 · 7×24', '财经资讯', 'news', 'https://api-one-wscn.awtmt.com/apiv1/content/lives', '全球宏观与商品频道快讯', 1, 50),
    -- 银行金价源：仅保留交通银行（上金所 Au99.99 基础价 + Au 系合约行情）。
    --   建设银行两源与平安银行已于 2026-11-11 按用户决定彻底移除，worker.js 的 migrate() 会幂等删除存量库残留行。
    ('bocom_metal', '交通银行 · 贵金属行情', '银行金价', 'metal', 'https://www.bankcomm.com/SITE/getNobleMetalNew.do', '交行官网展示的上海黄金交易所 Au99.99 基础价与 Au 系合约行情（元/克（推断））；非交行零售报价、非投资金条售价；含官方涨跌额，官网涨跌幅字段不可用，未展示；无投资金条零售价。', 1, 80);

-- 默认定时任务（interval_sec 与 interval_min 同写，秒为唯一口径）
INSERT OR IGNORE INTO fetch_tasks(task_key, name, description, domain, interval_min, interval_sec, enabled, run_at_hour, sort_order) VALUES
    ('metal_snapshot', '金价快照采集', '拉取贵金属实时行情，生成一条金价快照并计算环比涨跌、异动等级与处理结论，写入 metal_snapshots', 'metal', 30, 1800, 1, -1, 10),
    ('metal_quote', '贵金属行情刷新', '拉取贵金属实时报价并更新行情看板的现价、涨跌幅、振幅、持仓量等字段', 'metal', 10, 600, 1, -1, 20),
    ('news_crawl', '财经资讯抓取', '按关注关键词从启用的资讯数据源抓取财经快讯，按标题指纹去重后入库', 'news', 10, 600, 1, -1, 30),
    ('bank_gold_quote', '银行金价采集', '抓取交通银行官网贵金属行情并写入 bank_gold_quotes', 'metal', 10, 600, 1, -1, 40);

-- 默认品种注册表（贵金属 2 个 + 稀有金属 4 个）
--   稀有金属品种可在「稀有金属研究 → 品种管理」中继续新增。
INSERT OR IGNORE INTO metal_instruments(symbol, sina, name, short_name, market, kind, unit, currency, em, chain, scope, enabled, sort_order, builtin) VALUES
    -- 出厂默认贵金属仅保留沪金 / 沪银；稀有金属品种可在页面中扩展。
    ('AU0',  'nf_AU0',  '沪金主连',           '沪金',      '上海',  '黄金', '元/克',    'CNY', '113.AUM',   '',           'metal', 1,  70, 1),
    ('AG0',  'nf_AG0',  '沪银主连',           '沪银',      '上海',  '白银', '元/千克',  'CNY', '113.AGM',   '',           'metal', 1,  80, 1),
    ('LC0',  'nf_LC0',  '碳酸锂主连',         '碳酸锂',    '广期所','锂',   '元/吨',    'CNY', '225.lcm',   '锂电',       'rare',  1,  10, 1),
    ('SI0',  'nf_SI0',  '工业硅主连',         '工业硅',    '广期所','硅',   '元/吨',    'CNY', '225.sim',   '光伏/硅基',  'rare',  1,  20, 1),
    ('NI0',  'nf_NI0',  '沪镍主连',           '沪镍',      '上期所','镍',   '元/吨',    'CNY', '113.NIM',   '不锈钢/三元','rare',  1,  30, 1),
    ('SN0',  'nf_SN0',  '沪锡主连',           '沪锡',      '上期所','锡',   '元/吨',    'CNY', '113.SNM',   '焊料/电子',  'rare',  1,  40, 1);

--   采集参数共 27 项（消息域 16 项、贵金属域 11 项）。
--   必须与 worker.js 的 ACQUIRE_OPTION_DEFAULTS 完全一致；因 migrate() 用 INSERT OR IGNORE，
--   先执行本文件时以本文件种子为准。name = 页面上的控件短标签，description = 悬停说明全文。
INSERT OR IGNORE INTO acquire_options(domain, option_key, name, value, value_type, options, meta, description, sort_order) VALUES
    -- 消息数据 · 抓取范围,
    ('news', 'news_keywords', '关键词', '人工智能,AI,算力,GPU,显卡,AI芯片,半导体,数据中心,碳酸锂,工业硅,沪镍,沪锡,稀土,铜,铝,黄金,白银,美联储,加息,降息,通胀,汇率', 'textarea', '', '', '用于全网搜索财经资讯的关键词，逗号分隔，最多保留 24 个；只放泛化主题词，不放具体人名 / 高管名 / 公司名。AI 相关的直接事件与产业链 / 能源 / 政策等间接消息，由固定词「人工智能 / AI / 算力 / GPU / 显卡 / AI芯片 / 半导体 / 数据中心 / 液冷 / 光模块」始终补充检索', 10),
    ('news', 'news_channels', '频道', 'metal,macro,forex,policy,ai', 'list', '[{"value":"equity","label":"股市·权益"},{"value":"fund","label":"基金·ETF"},{"value":"bond","label":"债券·固收"},{"value":"metal","label":"贵金属"},{"value":"macro","label":"宏观·美联储"},{"value":"forex","label":"外汇·汇率"},{"value":"property","label":"房地产"},{"value":"policy","label":"政策·监管"},{"value":"ai","label":"AI·算力"},{"value":"other","label":"综合"}]', '', '仅保留这些频道的资讯；留空表示不过滤', 20),
    -- 单源抓取条数固定 30（与 worker.js 的 NEWS_PER_SOURCE_FIXED 对齐）：上限 = 默认值 = 30，只读参数，采集页只展示不允许更改,
    ('news', 'news_per_source', '单源条数', '30', 'number', '', '{"min":30,"max":30,"step":1,"readonly":true}', '每个资讯数据源单次最多抓取的条数，固定为 30 条，不可更改（30 条回溯窗口已覆盖约 60 秒采集间隔）', 30),
    ('news', 'news_max_keywords', '词数', '24', 'number', '', '{"min":1,"max":24,"step":1}', '参与全网检索的关键词个数，取「关键词」的前 N 个；泛化 AI 主题词始终额外检索，不受该上限影响', 40),
    -- 消息数据 · 过滤规则,
    ('news', 'news_relevance_only', '仅相关', '1', 'bool', '', '', '开启后只留四类：贵金属 / 稀有金属品种行情与供需、中国政策与官方数据、直接定价金价的海外变量（美联储 / 实际利率 / 美元指数 / 通胀就业 / 避险）、AI 相关消息（泛化主题词，直接事件与产业链 / 能源 / 政策等间接消息都保留，词表不含具体人名）。日本 / 欧洲央行讲话、他国股市会被挡掉；判定只看标题', 45),
    ('news', 'news_blacklist', '屏蔽词', '辞去副总裁,辞去副总经理,辞去董事,辞去监事,辞去总经理,副总裁辞职,董事辞职,监事辞职,高管辞职,调研快报,股份有限公司', 'textarea', '', '', '标题或摘要命中任一词即整条丢弃，逗号分隔。同时作用于采集入库与资讯中心列表（历史存量也会被隐藏）。默认值只挡低价值个股人事公告格式噪音；不再用「董事 / 监事 / 辞职 / 辞去」泛词，避免误伤 AI / 显卡重大公司事件', 50),
    ('news', 'news_min_title_len', '标题', '6', 'number', '', '{"min":0,"max":40,"step":1}', '标题字数少于该值的资讯直接丢弃（快讯里大量「午评」这类碎标题）；填 0 表示不过滤', 60),
    ('news', 'news_auto_star_metal', '收藏', '1', 'bool', '', '', '命中贵金属频道的消息自动加星标，不会被保留期清理', 70),
    -- 消息数据 · 运行控制,
    ('news', 'news_timeout_sec', '超时', '9', 'number', '', '{"min":3,"max":30,"step":1}', '每个数据源单次 HTTP 请求的最长等待时间；网络慢时调大，避免整批抓取超时', 80),
    ('news', 'news_fail_limit', '失败', '5', 'number', '', '{"min":1,"max":50,"step":1}', '任务连续失败达到该次数后自动停用，并发一条通知；修复后到「定时任务」重新启用即可清零', 90),
    -- 消息数据 · 运行控制（页面与服务端刷新间隔，见 worker.js ACQUIRE_OPTION_DEFAULTS）,
    ('news', 'news_live_sec', '刷新', '10', 'number', '', '{"min":5,"max":300,"step":5}', '资讯列表自动刷新的间隔，只读数据库不抓源，默认 10 秒', 92),
    ('news', 'news_crawl_sec', '抓取', '60', 'number', '', '{"min":10,"max":3600,"step":10}', '服务端多久真正回源抓取一次资讯；过短容易被数据源限流，建议 ≥30 秒（定时任务仍按分钟兜底）', 94),
    -- 消息数据 · 重点消息,
    ('news', 'news_key_notify_max', '外部推送上限', '5', 'number', '', '{"min":1,"max":20,"step":1}', '每次采集完成后，最多把多少条「新采集的重点消息」推送到外部通道（企业微信 / 钉钉 / 飞书机器人）；写入通知中心不受此限制 —— 全部重点消息都会进通知中心', 95),
    ('news', 'news_key_notify_enabled', '重点推送', '1', 'bool', '', '', '开启后：库内全部重点消息都会写入通知中心并点亮（未读），已读过的不会重复点亮；同时把本次新采集的重点消息推送到已配置的外部通道', 96),
    -- 消息数据 · 留存策略,
    ('news', 'news_retention_days', '消息保留', '90', 'number', '', '{"min":1,"max":3650,"step":1}', '默认数据保留时间：超过该天数的旧消息在抓取时自动清理（已加星标的不受影响）', 100),
    ('news', 'fetch_log_retention_days', '日志保留', '30', 'number', '', '{"min":1,"max":3650,"step":1}', '采集日志保留天数：超过该天数的日志在每次采集后自动清理；也可到「数据保留」面板手动立即清理', 101),
    -- 贵金属数据 · 采集范围,
    ('metal', 'metal_symbols', '品种', 'AU0,AG0', 'list', '[{"value":"AU0","label":"沪金（上海）"},{"value":"AG0","label":"沪银（上海）"}]', '', '需要采集并入库的贵金属品种；默认采集沪金 / 沪银，留空表示全部采集', 10),
    ('metal', 'metal_markets', '市场', '上海', 'list', '[{"value":"上海","label":"上海"}]', '', '贵金属页面展示的市场；当前内置贵金属为上海市场，留空表示全部展示', 20),
    ('metal', 'metal_kinds', '类别', '黄金,白银', 'list', '[{"value":"黄金","label":"黄金"},{"value":"白银","label":"白银"}]', '', '贵金属页面展示的金属类别；留空表示全部展示', 30),
    -- 贵金属数据 · 异动阈值,
    ('metal', 'metal_snapshot_base', '基准', 'AU0', 'select', '[{"value":"AU0","label":"沪金"},{"value":"AG0","label":"沪银"}]', '', '金价快照用于「环比上次采集」的基准品种；默认沪金主连', 40),
    ('metal', 'metal_snapshot_alert', '异动', '0.8', 'number', '', '{"min":0.1,"max":5,"step":0.1}', '环比上次采集涨跌幅超过该值判定为大幅异动（行情快照等级：大幅异动）', 50),
    ('metal', 'metal_snapshot_surge', '波动', '0.25', 'number', '', '{"min":0.05,"max":3,"step":0.05}', '环比上次采集涨跌幅超过该值判定为明显波动（行情快照等级：明显波动）；需小于「异动」阈值', 60),
    -- 贵金属数据 · 运行控制,
    ('metal', 'metal_fail_limit', '失败', '5', 'number', '', '{"min":1,"max":50,"step":1}', '行情任务连续失败达到该次数后自动停用，并发一条通知，避免对已失效的接口持续重试', 70),
    -- 贵金属数据 · 运行控制（行情页刷新间隔，见 worker.js ACQUIRE_OPTION_DEFAULTS）,
    ('metal', 'metal_live_sec', '刷新', '10', 'number', '', '{"min":5,"max":120,"step":5}', '页面轮询与服务端重新回源拉取行情的间隔，默认 10 秒；调小更实时，但会更频繁请求新浪行情接口', 75),
    -- 贵金属数据 · 留存与展示,
    ('metal', 'metal_snapshot_keep', '快照条数', '2000', 'number', '', '{"min":100,"max":20000,"step":100}', '金价快照最多保留的条数；与快照天数哪个先到就按哪个清理', 80),
    ('metal', 'metal_snapshot_days', '快照天数', '90', 'number', '', '{"min":1,"max":3650,"step":1}', '金价快照保留天数：超过该天数的快照自动清理；与快照条数哪个先到就按哪个清理', 81),
    ('metal', 'metal_history_keep', '轨迹条数', '500', 'number', '', '{"min":50,"max":5000,"step":50}', '每个品种本地价格轨迹保留的条数；与轨迹天数哪个先到就按哪个清理', 90),
    ('metal', 'metal_history_days', '轨迹天数', '30', 'number', '', '{"min":1,"max":3650,"step":1}', '价格轨迹保留天数：超过该天数的轨迹自动清理；与轨迹条数哪个先到就按哪个清理', 91),
    -- 贵金属数据 · 分析模型,
    ('metal', 'rare_risk_budget', '预算', '2', 'number', '', '{"min":0.5,"max":10,"step":0.5}', '三情景推演中折算「仓位上限」：上限 = 预算 ÷ 年化波动率，结果夹在 1%~25%', 110);

-- 财经日历（经济事件日程）
CREATE TABLE IF NOT EXISTS eco_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_at TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '美国',
    name TEXT NOT NULL,
    importance INTEGER NOT NULL DEFAULT 2,
    previous TEXT DEFAULT '',
    forecast TEXT DEFAULT '',
    actual TEXT DEFAULT '',
    unit TEXT DEFAULT '',
    note TEXT DEFAULT '',
    notified INTEGER NOT NULL DEFAULT 0,
    created_by TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_eco_events_at ON eco_events(event_at);

