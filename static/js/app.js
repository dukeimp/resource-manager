// ============================================================
// 稀有金属投资咨询平台 — 前端 SPA（行情 / 研究 / 资讯 / 情景 / 计划）
// ============================================================
const TOKEN_KEY = "rm_token";

const state = { token: null, user: null, brand: "稀有金属投资咨询平台", newsMeta: null };
// 当前路由的查询串（#news?symbol=AU0 这类跳转用）
let routerQuery = new URLSearchParams();

// ---------- 工具 ----------
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function el(html) { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; }
function $(sel) { return document.querySelector(sel); }
// URL 安全：仅允许 http/https，阻断 javascript: / data: 伪协议
function safeUrl(v) {
    const s = String(v == null ? "" : v).trim();
    if (!s) return "";
    try {
        const u = new URL(s, location.origin);
        if (u.protocol !== "http:" && u.protocol !== "https:") return "";
        return u.href;
    } catch { return ""; }
}
// 统一的加载中 / 空态 / 错误态模板（避免各页面重复书写）
const LOADING_HTML = `<div class="empty"><i class="fa-solid fa-spinner fa-spin"></i> 加载中…</div>`;
const emptyHtml = (msg = "暂无数据") => `<div class="empty">${esc(msg)}</div>`;
const errorHtml = (msg = "加载失败") => `<div class="empty">${esc(msg)}</div>`;

async function api(path, method = "GET", body = null) {
    const headers = { "Content-Type": "application/json" };
    if (state.token) headers["Authorization"] = "Bearer " + state.token;
    let res;
    try {
        res = await fetch("/api" + path, { method, headers, body: body ? JSON.stringify(body) : null });
    } catch (e) {
        // 网络层失败（离线 / 服务不可达）——显式抛出，避免调用方拿到 ok=false 却无原因
        throw new Error("网络请求失败，请检查网络或服务状态");
    }
    let data = {};
    try { data = await res.json(); } catch { data = {}; }
    if (res.status === 401) { logout(); throw new Error("登录已失效，请重新登录"); }
    if (!res.ok && !data.message) data.message = `请求失败（HTTP ${res.status}）`;
    return { ok: res.ok, status: res.status, data };
}

function toast(msg, type = "info") {
    const root = $("#toast-root");
    const node = el(`<div class="toast ${type}">${esc(msg)}</div>`);
    root.appendChild(node);
    setTimeout(() => { node.style.opacity = "0"; node.style.transition = "opacity .3s"; setTimeout(() => node.remove(), 300); }, 2800);
}

// ---------- 认证 ----------
async function startup() {
    state.token = localStorage.getItem(TOKEN_KEY);
    if (!state.token) { showAuth(); return; }
    try {
        const { data } = await api("/auth");
        if (data.success) { state.user = data.user; await enterApp(); }
        else { showAuth(); }
    } catch { showAuth(); }
}

function showAuth() {
    $("#app-view").style.display = "none";
    $("#auth-view").style.display = "flex";
}

function setupAuthEvents() {
    $("#login-form").addEventListener("submit", async e => {
        e.preventDefault();
        const username = $("#login-username").value.trim();
        const password = $("#login-password").value;
        if (!username || !password) return toast("请输入账号和密码", "error");
        const { ok, data } = await api("/login", "POST", { username, password });
        if (ok) { state.token = data.token; state.user = data.user; localStorage.setItem(TOKEN_KEY, data.token); await enterApp(); }
        else toast(data.message || "登录失败", "error");
    });
    $("#logout-btn").addEventListener("click", () => { closeUserMenu(); logout(); });
    $("#change-pwd-btn").addEventListener("click", () => { closeUserMenu(); openChangePassword(); });
    $("#avatar-btn").addEventListener("click", e => { e.stopPropagation(); toggleUserMenu(); });
    // 菜单内部点击不再冒泡到 document，避免刚展开就被关闭
    $("#user-dropdown").addEventListener("click", e => e.stopPropagation());
    $("#bell-btn").addEventListener("click", e => { e.stopPropagation(); toggleNotifDrawer(); });
    // 点击任意其他区域关闭通知抽屉 / 账号菜单
    document.addEventListener("click", () => { if (notifOpen) closeNotifDrawer(); closeUserMenu(); });
    $("#menu-toggle").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
}

// 右上角账号菜单：头像即入口（用户信息 + 修改密码 + 退出登录都在菜单里）
function toggleUserMenu() {
    const dd = $("#user-dropdown"), btn = $("#avatar-btn");
    if (!dd) return;
    const open = dd.hidden;
    dd.hidden = !open;
    if (btn) btn.setAttribute("aria-expanded", String(open));
}
function closeUserMenu() {
    const dd = $("#user-dropdown"), btn = $("#avatar-btn");
    if (!dd || dd.hidden) return;
    dd.hidden = true;
    if (btn) btn.setAttribute("aria-expanded", "false");
}
function renderUserMenu() {
    const u = state.user || {};
    const roleLabel = { admin: "管理员", user: "普通用户", visitor: "访客" }[u.role] || u.role || "";
    const name = u.display_name || u.username || "未登录";
    const initial = (String(name).trim().charAt(0) || "U").toUpperCase();
    ["#avatar-initial", "#avatar-initial-lg"].forEach(sel => { const n = $(sel); if (n) n.textContent = initial; });
    const nameEl = $("#ud-name"); if (nameEl) nameEl.textContent = name;
    const roleEl = $("#ud-role"); if (roleEl) roleEl.textContent = roleLabel ? "角色：" + roleLabel : "";
    const btn = $("#avatar-btn"); if (btn) btn.title = roleLabel ? `${name} · ${roleLabel}` : name;
}

function logout() { localStorage.removeItem(TOKEN_KEY); state.token = null; state.user = null; showAuth(); }

// 旧书签 → 工作台标签页的别名表：实时行情 / 稀有金属都已并入工作台
const LEGACY_TAB_ALIASES = { quote: "quote", rare: "rare", metals: "quote", dashboard: "overview", screen: "overview" };

async function enterApp() {
    $("#auth-view").style.display = "none";
    $("#app-view").style.display = "flex";
    try {
        const s = await api("/settings"); if (s.ok && s.data.system_name) state.brand = s.data.system_name;
    } catch {}
    $("#brand-name").textContent = state.brand;
    renderSidebar();
    // 图表引擎：监听 DOM 变化，自动初始化后插入的 .echart 容器
    initChartEngine();
    // 通知轮询：进入应用后先拉一次未读数，之后每 60 秒刷新
    refreshBell();
    if (bellTimer) clearInterval(bellTimer);
    bellTimer = setInterval(refreshBell, 60000);
    // 默认落在左侧菜单第一项（投资总览）。
    // 若无 market.view 权限（总览与行情都会 403），退回到该用户可见的第一个菜单。
    const allowed = new Set();
    visibleItems().forEach(i => { allowed.add(i.hash); (i.children || []).forEach(c => allowed.add(c.hash)); });
    // 旧书签的 hash 也要放行，否则刷新旧链接会被直接踢回首页（跳转交给 router 的别名表处理）
    Object.keys(LEGACY_TAB_ALIASES).forEach(k => allowed.add("#" + k));
    const landing = visibleItems()[0] ? visibleItems()[0].hash : "#desk";
    // hash 可能带查询串（#desk?tab=rare / #desk?symbol=AU0），判定权限时只看基础部分，否则刷新会丢标签页
    const curView = String(location.hash || "").split("?")[0];
    const hash = location.hash && allowed.has(curView) ? location.hash : landing;
    location.hash = hash;
    router();
}

// ---------- 侧边栏 ----------
const NAV_ITEMS = [
    // —— 咨询主线：按「看什么 → 研究什么 → 跟踪什么 → 执行什么」排序 ——
    { key: "desk", label: "投资总览", icon: "fa-solid fa-compass-drafting", perm: "market.view", hash: "#desk" },
    { key: "desk-rare", label: "稀有金属研究", icon: "fa-solid fa-gem", perm: "market.view", hash: "#desk?tab=rare" },
    { key: "material", label: "材料联想", icon: "fa-solid fa-wand-magic-sparkles", perm: "market.view", hash: "#material" },
    { key: "desk-quote", label: "实时行情", icon: "fa-solid fa-chart-line", perm: "market.view", hash: "#desk?tab=quote" },
    { key: "news", label: "资讯中心", icon: "fa-solid fa-newspaper", perm: "news.view", hash: "#news" },
    { key: "calendar", label: "财经日历", icon: "fa-solid fa-calendar-days", perm: "market.view", hash: "#calendar" },
    { key: "portfolio", label: "持仓与计划", icon: "fa-solid fa-briefcase", perm: "market.view", hash: "#portfolio" },
    // —— 后台：采集运维与账号管理，放最后 ——
    {
        key: "acquire", label: "数据采集", icon: "fa-solid fa-download", perm: "market.view", hash: "#acquire"
    },
    { key: "users", label: "用户管理", icon: "fa-solid fa-users", perm: "users.view", hash: "#users" },
    { key: "notify", label: "通知与集成", icon: "fa-solid fa-paper-plane", perm: "settings.view", hash: "#notify" },
    { key: "settings", label: "系统设置", icon: "fa-solid fa-sliders", perm: "settings.view", hash: "#settings" }
];
// 分组展开状态（保留兼容，当前导航已无二级分组）
const navState = { expanded: { acquire: true } };
const canSee = i => !i.perm || !!(state.user && (state.user.role === "admin" || state.user.permissions.includes(i.perm)));
const visibleItems = () => NAV_ITEMS.filter(canSee);

function renderSidebar() {
    const nav = $("#sidebar-nav");
    nav.innerHTML = "";
    const cur = (location.hash || "").replace("#", "");
    visibleItems().forEach(i => {
        // —— 带二级菜单的分组 ——
        if (i.children && i.children.length) {
            const inside = i.children.some(c => c.key === cur);
            const expanded = !!navState.expanded[i.key];
            const group = document.createElement("div");
            group.className = "nav-group";
            const head = el(`<div class="nav-item nav-item-parent${inside ? " active" : ""}" data-group="${esc(i.key)}" title="${esc(i.label)}">
                <i class="${i.icon}"></i><span>${esc(i.label)}</span>
                <i class="fa-solid fa-chevron-down nav-caret${expanded ? " open" : ""}"></i></div>`);
            head.addEventListener("click", () => {
                const open = !!navState.expanded[i.key];
                const inGroup = i.children.some(c => c.key === (location.hash || "").replace("#", ""));
                if (!open || !inGroup) {
                    // 展开并进入首个二级菜单
                    navState.expanded[i.key] = true;
                    renderSidebar();
                    location.hash = i.children[0].hash;
                } else {
                    navState.expanded[i.key] = false;
                    renderSidebar();
                }
            });
            group.appendChild(head);
            if (expanded) {
                i.children.forEach(c => {
                    const sub = el(`<div class="nav-item nav-item-sub${c.key === cur ? " active" : ""}" data-hash="${c.hash}">
                        <i class="fa-solid ${c.icon}"></i><span>${esc(c.label)}</span></div>`);
                    sub.addEventListener("click", () => {
                        location.hash = c.hash;
                        if (window.innerWidth <= 860) $(".sidebar").classList.remove("open");
                    });
                    group.appendChild(sub);
                });
            }
            nav.appendChild(group);
            return;
        }
        // —— 普通菜单项 ——
        const node = el(`<div class="nav-item${i.hash === "#" + cur ? " active" : ""}" data-hash="${i.hash}"><i class="${i.icon}"></i><span>${esc(i.label)}</span></div>`);
        node.addEventListener("click", () => { location.hash = i.hash; if (window.innerWidth <= 860) $(".sidebar").classList.remove("open"); });
        nav.appendChild(node);
    });
    // 侧栏只保留导航，用户信息与退出登录已收进右上角头像菜单
    renderUserMenu();
}
// 路由变化时同步侧边栏高亮 / 分组展开
function syncNav(hash) {
    const cur = (hash || "").replace("#", "");
    let changed = false;
    visibleItems().forEach(i => {
        if (!i.children || !i.children.length) return;
        if (i.children.some(c => c.key === cur) && !navState.expanded[i.key]) {
            navState.expanded[i.key] = true;
            changed = true;
        }
    });
    if (changed) renderSidebar();
    // 高亮规则：带查询串的菜单项（如 #desk?tab=rare）要求与当前 hash 完整匹配；
    // 普通项匹配基础视图（#desk）。同一视图下两者互斥，避免「投资总览」和「稀有金属研究」同时点亮。
    const full = (location.hash || hash || "#").replace(/^#/, "");
    const nodes = Array.from(document.querySelectorAll(".nav-item[data-hash]"));
    const exact = nodes.some(n => n.dataset.hash.includes("?") && n.dataset.hash === "#" + full);
    nodes.forEach(n => {
        const hasQuery = n.dataset.hash.includes("?");
        const active = hasQuery ? n.dataset.hash === "#" + full : (!exact && n.dataset.hash === "#" + cur);
        n.classList.toggle("active", active);
    });
    document.querySelectorAll(".nav-item-parent").forEach(p => {
        const item = NAV_ITEMS.find(i => i.key === p.dataset.group);
        p.classList.toggle("active", !!(item && item.children.some(c => c.key === cur)));
    });
}

// ---------- 路由 ----------
// 快速切换菜单时，上一个页面的异步响应可能晚于新页面返回并覆盖 DOM。
// 每次导航递增序号，各页面的 loader 在 await 前后校验序号，过期响应直接丢弃。
let routerSeq = 0;
// 总览 / 稀有金属的自动刷新定时器：切页时必须停掉，否则会往已卸载的 DOM 写数据
let viewTimer = null;
function stopViewTimer() {
    if (viewTimer) { clearTimeout(viewTimer); clearInterval(viewTimer); viewTimer = null; }
}
// 资讯中心「看过即已读」的观察器：切页或重新渲染列表时必须断开，
//   否则旧观察器还在往已卸载的 DOM 上打标记，白白发一堆 read_refs 请求。
let newsSeenObserver = null;
function stopNewsSeen() { if (newsSeenObserver) { newsSeenObserver.disconnect(); newsSeenObserver = null; } }
window.addEventListener("hashchange", router);
async function router() {
    const seq = ++routerSeq;
    stopViewTimer();
    stopNewsSeen();
    // 切换页面时收起弹窗：否则从弹窗里点链接跳转，遮罩会一直盖在新页面上
    if ($("#modal-root") && $("#modal-root").children.length) closeModal();
    let hash = location.hash || "#desk";
    // 兼容旧书签：实时行情 / 稀有金属都已合并为工作台内的标签页
    //   #quote → #desk?tab=quote   #rare → #desk?tab=rare   #metals → #desk?tab=quote   #dashboard → #desk
    const legacyTab = LEGACY_TAB_ALIASES[hash.replace("#", "")];
    if (legacyTab) { location.hash = "#desk?tab=" + legacyTab; return; }
    // 兼容旧地址：消息数据 / 贵金属数据两个采集页已合并为一页
    if (hash === "#acquire-news" || hash === "#acquire-metal") { location.hash = "#acquire"; return; }
    // 允许带查询串（如 #news?symbol=AU0），用于从工作台跳到「只看这个标的的消息」
    const [view, qs = ""] = hash.replace("#", "").split("?");
    routerQuery = new URLSearchParams(qs);
    syncNav("#" + view);
    const titles = {
        desk: "投资总览", quote: "实时行情", rare: "稀有金属研究",
        portfolio: "持仓与计划", calendar: "财经日历",
        acquire: "数据采集", news: "资讯中心", users: "用户管理", settings: "系统设置",
        material: "材料联想", notify: "通知与集成"
    };
    $("#view-title").textContent = titles[view] || "投资总览";
    const container = $("#view-container");
    container.innerHTML = LOADING_HTML;
    try {
        if (view === "desk") await viewDesk(container);
        else if (view === "news") await viewNews(container);
        else if (view === "portfolio") await viewPortfolio(container);
        else if (view === "calendar") await viewCalendar(container);
        else if (view === "acquire") await viewAcquirePage(container);
        else if (view === "users") await viewUsers(container);
        else if (view === "settings") await viewSettings(container);
        else if (view === "notify") await viewNotifications(container);
        else if (view === "material") await viewMaterial(container);
        else await viewDesk(container);
    } catch (e) {
        if (seq !== routerSeq) return;
        container.innerHTML = `<div class="empty">加载失败：${esc(e.message)}</div>`;
    }
}

// ============================================================
// 贵金属：实时行情（#desk?tab=quote）
// ============================================================
const METAL_KIND_CLASS = { 黄金: "mt-gold", 白银: "mt-silver" };
// 品种配色由 /api/metals 响应的 series_colors 下发，本地值仅作接口异常时的兜底
const METAL_SERIES_COLORS_FALLBACK = { AU0: "#ef4444", AG0: "#14b8a6" };
let METAL_SERIES_COLORS = { ...METAL_SERIES_COLORS_FALLBACK };
const metalPage = { keyword: "", kind: "", market: "", sort: "default", sortDesc: true };

// A 股习惯：涨=红，跌=绿
function chgColor(v) { return Number(v) >= 0 ? "var(--up)" : "var(--down)"; }
function chgSign(v) { return Number(v) >= 0 ? "+" : ""; }
function metalNum(v, digits) {
    const n = Number(v);
    if (!Number.isFinite(n)) return "—";
    if (n === 0 && digits == null) return "—";
    const d = digits == null ? (Math.abs(n) >= 100 ? 2 : Math.abs(n) >= 1 ? 3 : 4) : digits;
    return n.toLocaleString("zh-CN", { minimumFractionDigits: d, maximumFractionDigits: d });
}
// 金额格式化：千分位 + 两位小数（持仓市值 / 盈亏）
function money(v) {
    const n = Number(v || 0);
    if (!Number.isFinite(n)) return "—";
    return n.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
// 百分比数值：0 显示为 0.000 而不是破折号
function metalPct(v, digits) {
    const n = Number(v);
    if (!Number.isFinite(n)) return "—";
    const d = digits == null ? 2 : digits;
    return n.toLocaleString("zh-CN", { minimumFractionDigits: d, maximumFractionDigits: d });
}

// ============================================================
// 图表引擎：Apache ECharts 5.5（本地 vendor/echarts.min.js，不依赖 CDN）
//   · 声明式：绘图函数返回一个占位 div，内容挂载后由 MutationObserver 统一 init
//   · 保留原手写 SVG 作为 echarts 缺失时的兜底，页面不会白屏
// ============================================================
const CHART_UP = "#dc2626";     // 涨 = 红（A 股 / 国内习惯）
const CHART_DOWN = "#16a34a";   // 跌 = 绿
const CHART_MUTED = "#94a3b8";
const CHART_TEXT = "#64748b";
const CHART_LINE = "#eef2f7";
const CHART_AXIS = "#e2e8f0";

const chartJobs = new Map();    // id -> { kind, payload }（未挂载的绘图任务）
const chartLive = new Set();    // 已初始化的实例，用于 resize 与回收
let chartSeq = 0;
let chartMountTimer = 0;

const hasECharts = () => typeof window !== "undefined" && !!window.echarts;

// ============================================================
// K 线补齐交易日：把「实际有数据的日期」铺到「应有的交易日」上
//   问题：东方财富返回的日线本身就有缺口——交割/结算日不生成 K 线、
//   外加周末与法定假日。类目轴的语义是「一个值一个等宽格子」，缺的日期
//   不存在，于是 09-24 和 09-28 会并排紧挨：价格跳空但时间轴上没有空位，
//   看起来就是「断断续续、连不上」。
//   做法：按周期生成完整的时间刻度，缺数据的位置留 null。ECharts 的
//   candlestick 遇到 null 不画，但格子仍然占位 —— 缺口就变成一个可见的空档，
//   语义从「莫名跳空」变成「这天没有数据」。
//   注意：只补「日历上应有的位置」，不补真实休市（周末/长假）之外的空洞，
//   所以补位后仍是稀疏的交易日刻度，而不是逐个自然日铺满（那会把图拉得很空）。
// ============================================================
// 把日期字符串解析成本地零点，避免 new Date("2026-09-25") 被当成 UTC 而产生 8 小时偏移
function ymdToDate(s) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(s || ""));
    return m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null;
}
function dateToYmd(d) {
    const p = n => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
// 周线：补到「每周最后一根」的位置。上游周线的时间戳是该周最后一个交易日，
//   跳过的周（长假整周休市）也应当留空位，否则相邻两周会挤在一起。
function weekKeyOf(ymdStr) {
    const d = ymdToDate(ymdStr);
    if (!d) return "";
    const dow = (d.getDay() + 6) % 7;          // 周一 = 0
    d.setDate(d.getDate() - dow + 4);           // 取该周周五作为「周标识」，只用于比较
    return dateToYmd(d);
}
// 月线：直接按月标识补位
function monthKeyOf(ymdStr) { return String(ymdStr || "").slice(0, 7); }

// 返回与 rows 等长对齐的「补位后」数据结构：
//   { dates: [...类目轴], fills: 与 dates 对应的原始行或 null, gaps: [{at, missing}] }
//   调用方把 bars 里的每个字段都按 fills 展开即可（null 位置留空）。
function padKlineRows(rows, period) {
    const src = Array.isArray(rows) ? rows : [];
    if (!src.length) return { dates: [], fills: [], gaps: [] };
    const p = String(period || "day");
    // 月线 / 周线的原始时间戳是「周期末日」，直接用它们的标识比较
    const keyOf = p === "month" ? monthKeyOf : p === "week" ? weekKeyOf : (t => String(t).slice(0, 10));

    const byKey = new Map();
    src.forEach(r => {
        const k = keyOf(r.t);
        if (!k) return;
        byKey.set(k, r);            // 同周期多行时保留最后一根（实际不会发生，防御性处理）
    });

    // —— 生成完整刻度 ——
    //   日线：从首根到末根，跳过周末（周六/周日真实休市，不占格子，否则小长假会拉出大片空白）
    //   周线：按周递增；月线：按月递增。长假/停牌造成的空洞保留为空位。
    const ticks = [], fills = [];
    const first = ymdToDate(src[0].t), last = ymdToDate(src[src.length - 1].t);
    if (!first || !last) {
        // 时间戳无法解析：按原样返回，不做补位（宁可空档也不画错位置）
        return { dates: src.map(r => r.t), fills: src.slice(), gaps: [] };
    }

    if (p === "day") {
        for (const cur = new Date(first); cur <= last; cur.setDate(cur.getDate() + 1)) {
            const dow = cur.getDay();
            if (dow === 0 || dow === 6) continue;   // 周末休市，不占位
            const k = dateToYmd(cur);
            ticks.push(k); fills.push(byKey.get(k) || null);
        }
    } else if (p === "week") {
        for (const cur = new Date(first); cur <= last; cur.setDate(cur.getDate() + 1)) {
            const k = weekKeyOf(dateToYmd(cur));
            if (ticks.length && ticks[ticks.length - 1] === k) continue;
            ticks.push(k); fills.push(byKey.get(k) || null);
        }
    } else {
        const cur = new Date(first.getFullYear(), first.getMonth(), 1);
        const endM = last.getFullYear() * 12 + last.getMonth();
        for (; cur.getFullYear() * 12 + cur.getMonth() <= endM; cur.setMonth(cur.getMonth() + 1)) {
            const k = `${cur.getFullYear()}-${String(cur.getMonth() + 1).padStart(2, "0")}`;
            ticks.push(k); fills.push(byKey.get(k) || null);
        }
    }

    // —— 长假期折叠 ——
    //   国庆/春节连休会产生连续多天空位。逐日铺开会在图上拉出一大片空白，
    //   把有数据的蜡烛挤到两侧，反而更难看。这里把「连续 N 格以上的空洞」
    //   折成 1 格，既保留「这里断过」的视觉信号，又不浪费画布。
    //   阈值按周期取：日线要连续 4 个交易日（≈ 一周长假）才折叠，单日缺口保留原样；
    //   周/月线的每一格本身代表很长的时间，缺 2 格就该折叠。
    //   轴标签显示「起→止」，tooltip 也提示连续多少个交易日无数据。
    const COLLAPSE_AT = p === "day" ? 4 : 2;
    const outDates = [], outFills = [], outLabels = [];
    const gaps = [];
    let run = 0, runStart = 0;
    const flushRun = () => {
        if (!run) return;
        if (run >= COLLAPSE_AT) {
            const from = ticks[runStart], to = ticks[runStart + run - 1];
            outDates.push(from);
            outFills.push(null);
            outLabels.push(`${from} → ${to}`);
            gaps.push({ at: outFills.length - 1, missing: run, from, to });
        } else {
            for (let j = 0; j < run; j++) {
                outDates.push(ticks[runStart + j]);
                outFills.push(null);
                outLabels.push(ticks[runStart + j]);
                gaps.push({ at: outFills.length - 1, missing: 1, from: ticks[runStart + j], to: ticks[runStart + j] });
            }
        }
        run = 0;
    };
    for (let i = 0; i < ticks.length; i++) {
        if (fills[i]) {
            flushRun();
            outDates.push(ticks[i]);
            outFills.push(fills[i]);
            // 周/月线的刻度是「周期标识」，真实日期用该周期最后一根 K 线的日期
            outLabels.push(fills[i].t);
        } else {
            if (!run) runStart = i;
            run++;
        }
    }
    flushRun();
    return { dates: outDates, labels: outLabels, fills: outFills, gaps };
}

function chartSlot(kind, payload, height) {
    if (!hasECharts()) return "";
    const id = "ec" + (++chartSeq);
    chartJobs.set(id, { kind, payload });
    return `<div class="echart" id="${id}" style="height:${height}px"></div>`;
}

// 把所有已进入文档、尚未实例化的 .echart 初始化/更新
function mountCharts() {
    if (!hasECharts()) return;
    chartLive.forEach(inst => {
        if (!inst.isDisposed() && !document.contains(inst.getDom())) { inst.dispose(); chartLive.delete(inst); }
    });
    document.querySelectorAll(".echart[id]").forEach(el => {
        const job = chartJobs.get(el.id);
        if (!job) return;
        if (!el.clientWidth || !el.clientHeight) return;   // 尚未排版，等下一次调度
        let inst = window.echarts.getInstanceByDom(el);
        if (!inst) {
            inst = window.echarts.init(el, null, { renderer: "canvas" });
            chartLive.add(inst);
        }
        try { inst.setOption(buildChartOption(job), true); }
        catch (e) { console.warn("chart.render", el.id, e && e.message); }
    });
    chartJobs.forEach((_, id) => { if (!document.getElementById(id)) chartJobs.delete(id); });
}

function scheduleMount() {
    if (chartMountTimer) return;
    chartMountTimer = setTimeout(() => { chartMountTimer = 0; mountCharts(); }, 16);
}

function initChartEngine() {
    if (!hasECharts() || !window.MutationObserver) return;
    const ob = new MutationObserver(muts => {
        for (const m of muts) {
            if (m.type !== "childList") continue;
            for (const n of m.addedNodes) {
                if (n.nodeType !== 1) continue;
                if (n.classList.contains("echart") || (n.querySelector && n.querySelector(".echart"))) { scheduleMount(); return; }
            }
        }
    });
    ob.observe(document.body, { childList: true, subtree: true });
    let rt = 0;
    window.addEventListener("resize", () => {
        clearTimeout(rt);
        rt = setTimeout(() => chartLive.forEach(i => { if (!i.isDisposed()) i.resize(); }), 120);
    });
}

function buildChartOption(job) {
    if (job.kind === "bar") return optBar(job.payload);
    if (job.kind === "vbar") return optVBar(job.payload);
    if (job.kind === "line") return optLine(job.payload);
    if (job.kind === "candle") return optCandle(job.payload);
    return {};
}

// —— 通用 tooltip 外观 ——
const TIP_BASE = {
    backgroundColor: "rgba(255,255,255,.97)",
    borderColor: "#e6e9f0", borderWidth: 1, padding: [8, 11],
    textStyle: { color: "#1f2733", fontSize: 12 }, confine: true,
    extraCssText: "border-radius:9px;box-shadow:0 8px 24px rgba(16,24,40,.12);"
};
const tipRow = (k, v, c) => `<div style="display:flex;gap:16px;justify-content:space-between;line-height:1.75"><span style="color:#64748b">${k}</span><b style="color:${c || "#1f2733"};font-variant-numeric:tabular-nums">${v}</b></div>`;

// 横向对比条：涨跌幅 / 振幅 / 环比跳动
function optBar({ items, suffix = "%", digits = 2 }) {
    const rows = items || [];
    if (!rows.length) return {};
    return {
        animationDuration: 420,
        grid: { left: 4, right: 74, top: 8, bottom: 4, containLabel: true },
        tooltip: {
            ...TIP_BASE, trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: "rgba(79,70,229,.05)" } },
            formatter: ps => {
                const p = ps[0], it = rows[p.dataIndex];
                return tipRow(esc(it.label), esc(it.display != null ? it.display : p.value + suffix));
            }
        },
        xAxis: {
            type: "value", axisLine: { show: false }, axisTick: { show: false },
            splitLine: { lineStyle: { color: CHART_LINE } },
            axisLabel: { color: CHART_MUTED, fontSize: 10, formatter: v => v + suffix }
        },
        yAxis: {
            type: "category", data: rows.map(i => i.label), inverse: true,
            axisLine: { lineStyle: { color: CHART_AXIS } }, axisTick: { show: false },
            axisLabel: { color: "#475569", fontSize: 12 }
        },
        series: [{
            type: "bar", barMaxWidth: 18,
            data: rows.map(i => {
                const v = Number(i.value) || 0;
                // 品类自带配色（如振幅用中性灰）优先，否则按涨跌上色
                const base = i.color || (v >= 0 ? CHART_UP : CHART_DOWN);
                return { value: v, itemStyle: { color: base, borderRadius: v >= 0 ? [0, 3, 3, 0] : [3, 0, 0, 3] } };
            }),
            label: {
                show: true, position: "right", color: "#475569", fontSize: 11,
                formatter: p => (p.value > 0 ? "+" : "") + Number(p.value).toFixed(digits) + suffix
            }
        }]
    };
}

// 竖向柱：近 14 天消息量
function optVBar({ items, color = "#4f46e5", unit = " 条" }) {
    const rows = items || [];
    if (!rows.length) return {};
    return {
        animationDuration: 400,
        grid: { left: 4, right: 8, top: 12, bottom: 4, containLabel: true },
        tooltip: {
            ...TIP_BASE, trigger: "axis", axisPointer: { type: "shadow", shadowStyle: { color: "rgba(79,70,229,.05)" } },
            formatter: ps => { const it = rows[ps[0].dataIndex]; return tipRow(esc(String(it.date)), (it.count || 0) + unit); }
        },
        xAxis: {
            type: "category", data: rows.map(i => String(i.date || "").slice(5)),
            axisLine: { lineStyle: { color: CHART_AXIS } }, axisTick: { show: false },
            axisLabel: { color: CHART_MUTED, fontSize: 9, hideOverlap: true }
        },
        yAxis: {
            type: "value", minInterval: 1,
            axisLine: { show: false }, axisTick: { show: false },
            splitLine: { lineStyle: { color: CHART_LINE } },
            axisLabel: { color: CHART_MUTED, fontSize: 9 }
        },
        series: [{
            type: "bar", barMaxWidth: 16,
            data: rows.map(i => ({
                value: i.count || 0,
                itemStyle: { color: (i.count || 0) > 0 ? color : "#e2e8f0", borderRadius: [3, 3, 0, 0] }
            }))
        }]
    };
}

// 多系列折线（联动走势 / 分时 / 采集轨迹 / 采集走势）
function optLine({ series, opts = {} }) {
    const list = (series || []).filter(s => s.points && s.points.length);
    if (!list.length) return {};
    // opts.axis：外部给定的完整刻度（分时图用「整个交易日」铺轴，未到的时间留空）
    const fixed = Array.isArray(opts.axis) && opts.axis.length > 1;
    const dates = fixed ? opts.axis.slice() : [...new Set(list.flatMap(s => s.points.map(p => p.t)))].sort();
    const maps = list.map(s => new Map(s.points.map(p => [p.t, p.v])));
    const fmt = opts.label || (t => String(t).slice(2));
    const digits = opts.digits == null ? 1 : opts.digits;
    // opts.axisTicks：固定刻度下只在这些时间点显示标签（整点 + 时段端点），避免按索引抽样挤出零散时间
    const tickSet = fixed && Array.isArray(opts.axisTicks) && opts.axisTicks.length ? new Set(opts.axisTicks) : null;
    const multi = list.length > 1;
    const zoom = !!opts.zoom && dates.length > 40;
    // —— 分时小缺口填充 ——
    //   东财 klt=5 每个交易日的上午都缺 10:20/10:25/10:30 三根（实测每交易日 27/30），
    //   这些 null 会让折线断开，看起来像「分时断了」。
    //   但休市断点不能连——它在轴上是一个零宽字符占位格（日期以 ​ 开头），
    //   作用就是让折线在 11:30 与 13:35 之间断开。
    //   做法：把「夹在两个有值点之间、且不是断点占位格」的 null 按线性插值填上，
    //   占位格保持 null（connectNulls 默认 false，断点照旧断开）。
    //   只对 fixed 轴生效：非固定轴（采集轨迹 / 联动走势）的数据点是连续的，无需处理。
    const isBreakSlot = t => String(t).startsWith("​");
    const fillData = arr => {
        if (!fixed || !arr.length) return arr;
        const out = arr.slice();
        for (let i = 1; i < out.length - 1; i++) {
            if (out[i] != null || isBreakSlot(dates[i])) continue;
            let lo = i - 1, hi = i + 1;
            while (hi < out.length && out[hi] == null && !isBreakSlot(dates[hi])) hi++;
            if (lo < 0 || hi >= out.length || out[lo] == null || out[hi] == null) continue;
            if (isBreakSlot(dates[lo]) || isBreakSlot(dates[hi])) continue; // 跨休市不插值
            for (let j = i; j < hi; j++) {
                const w = (j - lo) / (hi - lo);
                out[j] = out[lo] + (out[hi] - out[lo]) * w;
            }
        }
        return out;
    };
    return {
        animationDuration: 420,
        color: list.map(s => s.color),
        grid: { left: 6, right: 16, top: multi ? 28 : 10, bottom: zoom ? 46 : 6, containLabel: true },
        legend: multi
            ? { top: 0, itemWidth: 12, itemHeight: 8, icon: "roundRect", textStyle: { color: CHART_TEXT, fontSize: 11 } }
            : { show: false },
        tooltip: {
            ...TIP_BASE, trigger: "axis",
            axisPointer: { type: "line", lineStyle: { color: "#cbd5e1", type: "dashed" } },
            formatter: ps => {
                // 固定刻度下未到的时间点没有值，整列都是空则不弹提示
                const rows = ps.filter(p => p.value != null);
                if (!rows.length) return "";
                const head = `<div style="color:${CHART_MUTED};font-size:11px;margin-bottom:3px">${esc(String(rows[0].axisValue))}</div>`;
                return head + rows.map(p => tipRow(esc(p.seriesName), Number(p.value).toFixed(digits))).join("");
            }
        },
        xAxis: {
            type: "category", data: dates, boundaryGap: false,
            axisLine: { lineStyle: { color: CHART_AXIS } }, axisTick: { show: false },
            axisLabel: {
                color: CHART_MUTED, fontSize: 10, formatter: v => fmt(v), hideOverlap: true,
                ...(tickSet ? { interval: (i, v) => tickSet.has(String(v).slice(11, 16)) } : {})
            }
        },
        yAxis: {
            type: "value", scale: true,
            axisLine: { show: false }, axisTick: { show: false },
            splitLine: { lineStyle: { color: CHART_LINE } },
            axisLabel: { color: CHART_MUTED, fontSize: 10, formatter: v => Number(v).toFixed(digits) }
        },
        dataZoom: zoom ? [
            { type: "inside", start: 55, end: 100 },
            { type: "slider", height: 16, bottom: 6, borderColor: "transparent", fillerColor: "rgba(79,70,229,.10)", handleStyle: { color: "#fff" }, textStyle: { color: CHART_MUTED, fontSize: 10 } }
        ] : [],
        series: list.map((s, i) => ({
            name: s.name, type: "line", showSymbol: false, symbolSize: 5,
            lineStyle: { width: 1.8, color: s.color }, itemStyle: { color: s.color },
            areaStyle: multi ? null : { color: s.color, opacity: 0.09 },
            emphasis: { focus: "series" },
            data: fillData(dates.map(d => (maps[i].has(d) ? maps[i].get(d) : null)))
        }))
    };
}

// K 线：主图蜡烛 + MA/BOLL 叠加，副图成交量/MACD/RSI/KDJ，多 grid 十字光标联动
//   period 决定补位粒度（day/week/month），缺失交易日在轴上留空位而不是挤压相邻蜡烛。
function optCandle({ rows, indicators, ma, boll, sub, period }) {
    const bars = rows || [];
    if (!bars.length) return {};
    const ind = indicators || {};
    // —— 补齐交易日 ——
    //   bars 是「实际有数据的」序列；pad 把它铺到完整刻度上，缺的位置是 null。
    //   所有主图 series（蜡烛 / MA / BOLL）都要按同一个 dates 展开，否则会和轴错位。
    //   指标数组与 bars 一一对应（后端基于同一份 kline 计算），同样要按 fills 展开。
    const pad = padKlineRows(bars, period);
    // 类目轴用 dates（可能是「2026-10-01 → 2026-10-07」这样的折叠段），
    // 真实日期在 labels 里，轴标签与 tooltip 都用 labels，避免显示折叠段标识。
    const dates = pad.dates.length ? pad.dates : bars.map(r => r.t);
    const labels = pad.labels && pad.labels.length ? pad.labels : dates;
    const labelOf = i => String(labels[i] == null ? "" : labels[i]);
    // 把「与 bars 等长」的数组映射到补位后的刻度：只有在 fills 命中原始行时才取值
    const idxOf = new Map(bars.map((r, i) => [r, i]));
    const alignTo = arr => pad.fills.map(f => {
        if (!f || !arr) return null;
        const i = idxOf.get(f);
        return i === undefined ? null : (arr[i] === undefined ? null : arr[i]);
    });
    const maList = (ma || []).filter(n => ind.ma && ind.ma["ma" + n]);
    const showBoll = !!boll && ind.boll;
    const subKind = sub === undefined ? "vol" : sub;
    const hasSub = subKind !== "none";

    const mainGrid = hasSub
        ? { left: 10, right: 62, top: 22, height: "48%" }
        : { left: 10, right: 62, top: 24, height: "68%" };
    const grids = hasSub
        ? [mainGrid, { left: 10, right: 62, top: "64%", height: "15%" }]
        : [mainGrid];

    // 轴标签取 labels 里对应的真实日期：dates 是类目轴的值（含折叠段标识），
//   同一个类目值在 labels 里有真实日期或「起→止」折叠段说明。
    const labelIndex = new Map();
    dates.forEach((d, i) => { if (!labelIndex.has(d)) labelIndex.set(d, labels[i]); });
    const axisFmt = v => String(labelIndex.has(v) ? labelIndex.get(v) : v).slice(2, 10);

    const xAxes = [{
        type: "category", data: dates, gridIndex: 0, boundaryGap: true,
        axisLine: { lineStyle: { color: CHART_AXIS } }, axisTick: { show: false },
        axisLabel: { show: !hasSub, color: CHART_MUTED, fontSize: 10, formatter: axisFmt, hideOverlap: true },
        splitLine: { show: false },
        axisPointer: { label: { show: false } }
    }];
    // 主图纵轴交给 ECharts 自适应：dataZoom 缩放到近 120 根时，
    // 轴范围要按「当前可见数据」重算，否则会被 2025 年的历史高点整段拉高、蜡烛挤成一条线
    const yAxes = [{
        type: "value", gridIndex: 0, scale: true, splitNumber: 4,
        position: "right", axisLine: { show: false }, axisTick: { show: false },
        splitLine: { lineStyle: { color: CHART_LINE } },
        axisLabel: { color: CHART_MUTED, fontSize: 10, formatter: v => Number(v).toFixed(2) },
        axisPointer: { label: { formatter: p => Number(p.value).toFixed(2) } }
    }];
    if (hasSub) {
        xAxes.push({
            type: "category", data: dates, gridIndex: 1, boundaryGap: true,
            axisLine: { lineStyle: { color: CHART_AXIS } }, axisTick: { show: false },
            axisLabel: { color: CHART_MUTED, fontSize: 10, formatter: axisFmt, hideOverlap: true },
            splitLine: { show: false }, axisPointer: { label: { show: false } }
        });
        const ySub = {
            type: "value", gridIndex: 1, position: "right", splitNumber: 2, minInterval: 0,
            axisLine: { show: false }, axisTick: { show: false },
            splitLine: { lineStyle: { color: CHART_LINE } },
            // 副图只有 50~60px 高，刻度必须裁掉一半以上，否则会糊成一列
            axisLabel: { color: CHART_MUTED, fontSize: 9, hideOverlap: true, showMaxLabel: true }
        };
        if (subKind === "rsi") { ySub.min = 0; ySub.max = 100; ySub.interval = 50; }
        if (subKind === "kdj") { ySub.scale = true; }
        if (subKind === "vol") ySub.axisLabel.formatter = v => (v >= 10000 ? Math.round(v / 10000) + "万" : v);
        yAxes.push(ySub);
    }

    const series = [{
        name: "K线", type: "candlestick", xAxisIndex: 0, yAxisIndex: 0,
        // 缺口位置为 "-"：ECharts 的 candlestick 不画空值，但格子仍占位，
        //   于是缺口表现为一个可见的空档，而不是把前后两根蜡烛挤在一起、看着像跳空
        data: pad.fills.map(r => (r ? [r.o, r.c, r.l, r.h] : "-")),
        itemStyle: { color: CHART_UP, color0: CHART_DOWN, borderColor: CHART_UP, borderColor0: CHART_DOWN, borderWidth: 1 },
        // 官方示例同款：hover 时高亮该根
        emphasis: { itemStyle: { borderWidth: 2 } }
    }];

    maList.forEach(n => {
        series.push({
            name: "MA" + n, type: "line", xAxisIndex: 0, yAxisIndex: 0,
            data: alignTo(ind.ma["ma" + n]), showSymbol: false, smooth: true,
            lineStyle: { width: 1.3, color: IND_COLORS["ma" + n] || "#888" },
            itemStyle: { color: IND_COLORS["ma" + n] || "#888" },
            emphasis: { focus: "series" }
        });
    });
    if (showBoll) {
        [["BOLL上轨", "upper"], ["BOLL中轨", "mid"], ["BOLL下轨", "lower"]].forEach(([name, key]) => {
            series.push({
                name, type: "line", xAxisIndex: 0, yAxisIndex: 0,
                data: alignTo(ind.boll[key]), showSymbol: false, smooth: true,
                lineStyle: { width: key === "mid" ? 1 : 1.1, color: IND_COLORS[key], type: key === "mid" ? "solid" : "dashed" },
                itemStyle: { color: IND_COLORS[key] },
                emphasis: { focus: "series" }
            });
        });
    }

    if (hasSub) {
        if (subKind === "vol") {
            series.push({
                name: "成交量", type: "bar", xAxisIndex: 1, yAxisIndex: 1, barMaxWidth: 10,
                data: pad.fills.map(r => (r ? {
                    value: r.v || 0,
                    itemStyle: { color: r.c >= r.o ? "rgba(220,38,38,.5)" : "rgba(22,163,74,.5)" }
                } : "-")),
                emphasis: { itemStyle: { opacity: 0.85 } }
            });
        } else if (subKind === "macd") {
            const mc = ind.macd || {};
            const all = [...(mc.hist || []), ...(mc.dif || []), ...(mc.dea || [])].filter(v => v != null);
            const m = Math.max(1e-9, ...all.map(v => Math.abs(v))) * 1.15;
            yAxes[1].min = -m; yAxes[1].max = m;
            series.push({
                name: "MACD柱", type: "bar", xAxisIndex: 1, yAxisIndex: 1, barMaxWidth: 10,
                data: alignTo(mc.hist).map(v => ({
                    value: v == null ? "-" : v,
                    itemStyle: { color: v >= 0 ? "rgba(220,38,38,.6)" : "rgba(22,163,74,.6)" }
                }))
            });
            [["DIF", "dif"], ["DEA", "dea"]].forEach(([name, key]) => {
                series.push({
                    name, type: "line", xAxisIndex: 1, yAxisIndex: 1,
                    data: mc[key] || [], showSymbol: false,
                    lineStyle: { width: 1.2, color: IND_COLORS[key] }, itemStyle: { color: IND_COLORS[key] },
                    emphasis: { focus: "series" }
                });
            });
        } else if (subKind === "rsi") {
            const rs = ind.rsi || {};
            [["RSI6", "rsi6", IND_COLORS.ma5], ["RSI12", "rsi12", IND_COLORS.ma10], ["RSI24", "rsi24", IND_COLORS.ma20]].forEach(([name, key, color]) => {
                series.push({
                    name, type: "line", xAxisIndex: 1, yAxisIndex: 1,
                    data: alignTo(rs[key] || []), showSymbol: false,
                    lineStyle: { width: 1.3, color }, itemStyle: { color },
                    markLine: name === "RSI6" ? {
                        silent: true, symbol: "none",
                        lineStyle: { color: "#cbd5e1", type: "dashed", width: 1 },
                        label: { color: CHART_MUTED, fontSize: 9, formatter: "{c}" },
                        data: [{ yAxis: 30 }, { yAxis: 50 }, { yAxis: 70 }]
                    } : undefined
                });
            });
        } else if (subKind === "kdj") {
            const kd = ind.kdj || {};
            [["K", "k", IND_COLORS.k], ["D", "d", IND_COLORS.d], ["J", "j", IND_COLORS.j]].forEach(([name, key, color]) => {
                series.push({
                    name, type: "line", xAxisIndex: 1, yAxisIndex: 1,
                    data: alignTo(kd[key] || []), showSymbol: false,
                    lineStyle: { width: 1.3, color }, itemStyle: { color },
                    markLine: name === "K" ? {
                        silent: true, symbol: "none",
                        lineStyle: { color: "#cbd5e1", type: "dashed", width: 1 },
                        label: { color: CHART_MUTED, fontSize: 9, formatter: "{c}" },
                        data: [{ yAxis: 20 }, { yAxis: 80 }]
                    } : undefined
                });
            });
        }
    }

    // 默认展示最近 120 根，全量可拖动 dataZoom（按补位后的刻度算，缺口也计一根）
    const maxShow = 120;
    const total = dates.length;
    const startPct = total > maxShow ? Math.round((1 - maxShow / total) * 100) : 0;

    return {
        animation: false,
        grid: grids,
        xAxis: xAxes,
        yAxis: yAxes,
        axisPointer: { link: [{ xAxisIndex: "all" }], label: { backgroundColor: "#334155", fontSize: 10 } },
        tooltip: {
            ...TIP_BASE, trigger: "axis",
            axisPointer: { type: "cross", crossStyle: { color: "#94a3b8" }, lineStyle: { color: "#cbd5e1", type: "dashed" } },
            formatter: ps => {
                const i = ps[0].dataIndex;
                // 补位后 dataIndex 对应的是「刻度位置」，不是原始行下标。
                //   缺口位置 fills[i] 为 null，明确告诉用户是「这天没有数据」，
                //   而不是弹出一堆 0 或空行让人以为价格真的归零。
                const r = pad.fills[i];
                if (!r) {
                    // 连续多个交易日无数据时会被折叠成 1 格，提示里说明「连续多少天」，
                    //   免得用户以为只缺一天
                    const g = (pad.gaps || []).find(x => x.at === i);
                    const n = g && g.missing > 1 ? `连续 ${g.missing} 个交易日` : "该交易日";
                    return `<div style="font-size:11px;color:${CHART_MUTED};margin-bottom:4px">${esc(labelOf(i))}</div>`
                        + `<div style="font-size:11px;color:${CHART_MUTED}">${esc(n)}无数据（休市或上游未提供）</div>`;
                }
                // 指标数组按原始行下标取值
                const ri = idxOf.get(r);
                const pct = r.pct != null ? Number(r.pct) : (r.o ? (r.c - r.o) / r.o * 100 : 0);
                const pc = pct >= 0 ? CHART_UP : CHART_DOWN;
                let h = `<div style="font-size:11px;color:${CHART_MUTED};margin-bottom:4px">${esc(String(r.t))}</div>`;
                h += tipRow("开盘", metalNum(r.o, 2));
                h += tipRow("最高", metalNum(r.h, 2), CHART_UP);
                h += tipRow("最低", metalNum(r.l, 2), CHART_DOWN);
                h += tipRow("收盘", metalNum(r.c, 2), pc);
                h += tipRow("涨跌幅", (pct >= 0 ? "+" : "") + pct.toFixed(2) + "%", pc);
                if (r.v) h += tipRow("成交量", metalNum(r.v, 0));
                const at = k => (ri === undefined || !k ? null : k[ri]);
                maList.forEach(n => { const v = at(ind.ma["ma" + n]); if (v != null) h += tipRow("MA" + n, metalNum(v, 2), IND_COLORS["ma" + n]); });
                if (showBoll) {
                    ["upper", "mid", "lower"].forEach(k => {
                        const v = at(ind.boll[k]);
                        if (v != null) h += tipRow("BOLL" + ({ upper: "上", mid: "中", lower: "下" }[k]), metalNum(v, 2), IND_COLORS[k]);
                    });
                }
                if (subKind === "macd" && ind.macd) {
                    ["dif", "dea", "hist"].forEach(k => {
                        const v = at(ind.macd[k]);
                        if (v != null) h += tipRow(k.toUpperCase(), metalNum(v, 3), IND_COLORS[k]);
                    });
                }
                if (subKind === "rsi" && ind.rsi) {
                    ["rsi6", "rsi12", "rsi24"].forEach(k => {
                        const v = at(ind.rsi[k]);
                        if (v != null) h += tipRow(k.toUpperCase(), metalNum(v, 2));
                    });
                }
                if (subKind === "kdj" && ind.kdj) {
                    ["k", "d", "j"].forEach(k => {
                        const v = at(ind.kdj[k]);
                        if (v != null) h += tipRow(k.toUpperCase(), metalNum(v, 2), IND_COLORS[k]);
                    });
                }
                return h;
            }
        },
        dataZoom: [
            { type: "inside", xAxisIndex: hasSub ? [0, 1] : [0], start: startPct, end: 100 },
            {
                type: "slider", xAxisIndex: hasSub ? [0, 1] : [0], start: startPct, end: 100,
                bottom: 4, height: 14, borderColor: "transparent",
                fillerColor: "rgba(79,70,229,.10)", handleStyle: { color: "#fff", borderColor: "#cbd5e1" },
                dataBackground: { lineStyle: { color: "#cbd5e1" }, areaStyle: { color: "#f1f5f9" } },
                textStyle: { color: CHART_MUTED, fontSize: 10 }
            }
        ],
        series
    };
}

// ---------- SVG 图表（echarts 不可用时的兜底） ----------
function metalBarSvg(items) {
    // 优先走 ECharts：带坐标轴刻度、tooltip 与数值标签
    const slot = (items && items.length) ? chartSlot("bar", { items, suffix: "%" }, Math.max(132, items.length * 34 + 46)) : "";
    if (slot) return slot;
    if (!items.length) return `<div class="empty">暂无数据</div>`;
    const W = 660, rowH = 26, padL = 104, padR = 104, padT = 8, padB = 20;
    const H = padT + items.length * rowH + padB;
    const vals = items.map(i => Number(i.value) || 0);
    const maxV = Math.max(...vals, 0), minV = Math.min(...vals, 0);
    const span = (maxV - minV) || 1;
    const hasNeg = minV < 0;
    const plotW = W - padL - padR;
    const zeroX = hasNeg ? padL + (0 - minV) / span * plotW : padL;
    const bars = items.map((it, i) => {
        const y = padT + i * rowH + 4, h = rowH - 11;
        const v = Number(it.value) || 0;
        const w = Math.max(2, Math.abs(v) / span * plotW);
        const x = hasNeg ? (v >= 0 ? zeroX : zeroX + v / span * plotW) : zeroX;
        const color = it.color || (v >= 0 ? "var(--up)" : "var(--down)");
        const tx = hasNeg && v < 0 ? x - 6 : x + w + 6;
        const anchor = hasNeg && v < 0 ? "end" : "start";
        return `<text x="${padL - 8}" y="${y + h / 2 + 4}" text-anchor="end" font-size="11" fill="var(--text-soft)">${esc(it.label)}</text>`
            + `<rect x="${x.toFixed(1)}" y="${y}" width="${w.toFixed(1)}" height="${h}" rx="3" fill="${color}" opacity="0.88"/>`
            + `<text x="${tx.toFixed(1)}" y="${y + h / 2 + 4}" text-anchor="${anchor}" font-size="11" fill="var(--text)">${esc(it.display)}</text>`;
    }).join("");
    const axis = hasNeg ? `<line x1="${zeroX.toFixed(1)}" y1="${padT}" x2="${zeroX.toFixed(1)}" y2="${(H - padB).toFixed(1)}" stroke="var(--border)" stroke-width="1"/>` : "";
    return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto">${axis}${bars}</svg>`;
}

function metalLinesSvg(series, opts = {}) {
    // 优先走 ECharts：多系列图例、十字光标、缩放
    const valid = (series || []).filter(s => s.points && s.points.length);
    const slot = valid.length ? chartSlot("line", { series: valid, opts }, (opts.height || 268) + 16) : "";
    if (slot) return slot;
    if (!valid.length) return `<div class="empty">暂无走势数据</div>`;
    const W = 660, H = opts.height || 268, padL = 48, padR = 18, padT = 14, padB = 26;
    const dates = [...new Set(valid.flatMap(s => s.points.map(p => p.t)))].sort();
    const plotW = W - padL - padR, plotH = H - padT - padB;
    let min = Infinity, max = -Infinity;
    valid.forEach(s => s.points.forEach(p => { if (p.v < min) min = p.v; if (p.v > max) max = p.v; }));
    if (!Number.isFinite(min)) { min = 0; max = 1; }
    const pad = (max - min) * 0.08 || 1;
    const top = max + pad, bottom = min - pad, span = (top - bottom) || 1;
    const idx = new Map(dates.map((d, i) => [d, i]));
    const xOf = i => padL + (dates.length === 1 ? plotW / 2 : i / (dates.length - 1) * plotW);
    const yOf = v => padT + plotH - (v - bottom) / span * plotH;
    const grid = [0, 0.25, 0.5, 0.75, 1].map(t => {
        const y = padT + plotH * t, val = top - span * t;
        return `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${y.toFixed(1)}" stroke="var(--border)" stroke-width="1" stroke-dasharray="3 3"/>`
            + `<text x="${padL - 6}" y="${(y + 4).toFixed(1)}" text-anchor="end" font-size="10" fill="var(--text-soft)">${val.toFixed(opts.digits == null ? 1 : opts.digits)}</text>`;
    }).join("");
    const lines = valid.map(s => {
        const pts = s.points.map(p => `${xOf(idx.get(p.t)).toFixed(1)},${yOf(p.v).toFixed(1)}`).join(" ");
        const area = `${padL},${(padT + plotH).toFixed(1)} ${pts} ${(W - padR)},${(padT + plotH).toFixed(1)}`;
        const last = s.points[s.points.length - 1];
        return `${s.points.length > 1 ? `<polygon points="${area}" fill="${s.color}" opacity="0.07"></polygon>` : ""}`
            + `<polyline fill="none" stroke="${s.color}" stroke-width="1.8" points="${pts}"></polyline>`
            + `<circle cx="${xOf(idx.get(last.t)).toFixed(1)}" cy="${yOf(last.v).toFixed(1)}" r="3" fill="${s.color}"><title>${esc(last.t)}</title></circle>`;
    }).join("");
    const fmt = opts.label || (t => String(t).slice(2));
    const xlabels = [...new Set([0, Math.floor(dates.length / 2), dates.length - 1])].map(i => {
        const d = dates[i]; if (d == null) return "";
        return `<text x="${xOf(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" font-size="10" fill="var(--text-soft)">${esc(fmt(d))}</text>`;
    }).join("");
    const legend = valid.map(s => `<span class="legend-item"><i style="background:${s.color}"></i>${esc(s.name)}</span>`).join("");
    return `<div class="chart-legend">${legend}</div><svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto">${grid}${lines}${xlabels}</svg>`;
}

// 指标线配色（与后端序列一一对应）
const IND_COLORS = {
    ma5: "#f59e0b", ma10: "#3b82f6", ma20: "#a855f7", ma60: "#94a3b8",
    dif: "#f59e0b", dea: "#3b82f6",
    k: "#f59e0b", d: "#3b82f6", j: "#a855f7",
    upper: "#ef4444", mid: "#94a3b8", lower: "#22c55e"
};
const PERIOD_LABEL = { day: "日K", week: "周K", month: "月K" };
const SUB_LABEL = { vol: "成交量", macd: "MACD", rsi: "RSI", kdj: "KDJ", none: "无" };

// 把「含 null 的序列」画成可断开的折线（指标前期无值时不能连到 0）
function polySegments(arr, xOf, yOf, color, width = 1.4) {
    if (!arr) return "";
    const segs = [];
    let cur = [];
    for (let i = 0; i < arr.length; i++) {
        const v = arr[i];
        if (v == null || !Number.isFinite(v)) {
            if (cur.length > 1) segs.push(cur.join(" "));
            cur = [];
            continue;
        }
        cur.push(`${xOf(i).toFixed(1)},${yOf(v).toFixed(1)}`);
    }
    if (cur.length > 1) segs.push(cur.join(" "));
    return segs.map(p => `<polyline fill="none" stroke="${color}" stroke-width="${width}" stroke-linejoin="round" points="${p}"/>`).join("");
}

// 蜡烛图：主图（叠加 MA / BOLL）+ 副图（成交量 / MACD / RSI / KDJ）
//   opts = { indicators, ma:[5,20], boll:true, sub:"vol"|"macd"|"rsi"|"kdj"|"none", period:"day"|"week"|"month" }
//   period 用于补齐交易日刻度：缺失的交易日留空位，避免相邻两根被挤在一起被误读成跳空。
function metalCandleSvg(rows, opts = {}) {
    if (!rows || !rows.length) return `<div class="empty">暂无历史数据</div>`;
    const subMode = opts.sub === undefined ? "vol" : opts.sub;
    // 优先走 ECharts：官方同款多 grid 联动、十字光标、缩放
    const slot = chartSlot("candle", {
        rows, indicators: opts.indicators || {}, ma: opts.ma || [], boll: !!opts.boll, sub: subMode,
        period: opts.period || "day"
    }, subMode === "none" ? 312 : 366);
    if (slot) return slot;
    const ind = opts.indicators || {};
    const maList = (opts.ma || []).filter(n => ind.ma && ind.ma["ma" + n]);
    const showBoll = !!opts.boll && ind.boll;
    const sub = opts.sub === undefined ? "vol" : opts.sub;

    const W = 660, padL = 8, padR = 62, padT = 12, padB = 22, subGap = 12;
    const mainH = 208;
    const subH = sub === "none" ? 0 : 76;
    const H = padT + mainH + (subH ? subGap + subH : 0) + padB;
    const plotW = W - padL - padR;

    // —— 主图纵轴：把叠加指标也纳入范围，避免均线被裁掉 ——
    let max = -Infinity, min = Infinity;
    rows.forEach(r => { if (r.h > max) max = r.h; if (r.l < min) min = r.l; });
    const extra = [];
    maList.forEach(n => extra.push(...ind.ma["ma" + n].filter(v => v != null)));
    if (showBoll) extra.push(...ind.boll.upper.filter(v => v != null), ...ind.boll.lower.filter(v => v != null));
    if (extra.length) { max = Math.max(max, ...extra); min = Math.min(min, ...extra); }
    if (!Number.isFinite(max) || !Number.isFinite(min)) { max = 1; min = 0; }
    const pad = (max - min) * 0.05 || Math.abs(max) * 0.01 || 1;
    const top = max + pad, bottom = min - pad, span = (top - bottom) || 1;
    const yOf = v => padT + mainH - (v - bottom) / span * mainH;
    const bw = Math.max(1.2, Math.min(12, plotW / rows.length * 0.66));
    const xOf = i => padL + (i + 0.5) * (plotW / rows.length);

    // —— 蜡烛 ——
    const candles = rows.map((r, i) => {
        const x = xOf(i), up = r.c >= r.o;
        const col = up ? "var(--up)" : "var(--down)";
        const yH = yOf(r.h), yL = yOf(r.l), yO = yOf(r.o), yC = yOf(r.c);
        const bodyY = Math.min(yO, yC), bodyH = Math.max(1, Math.abs(yC - yO));
        const title = `${r.t} 开${r.o} 高${r.h} 低${r.l} 收${r.c}`;
        return `<g><title>${esc(title)}</title>`
            + `<line x1="${x.toFixed(1)}" y1="${yH.toFixed(1)}" x2="${x.toFixed(1)}" y2="${yL.toFixed(1)}" stroke="${col}" stroke-width="1"/>`
            + `<rect x="${(x - bw / 2).toFixed(1)}" y="${bodyY.toFixed(1)}" width="${bw.toFixed(1)}" height="${bodyH.toFixed(1)}" fill="${col}" opacity="0.82" rx="1"/></g>`;
    }).join("");

    const grid = [0, 0.25, 0.5, 0.75, 1].map(t => {
        const y = padT + mainH * t, val = top - span * t;
        return `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${y.toFixed(1)}" stroke="var(--border)" stroke-dasharray="3 3"/>`
            + `<text x="${(W - padR + 6).toFixed(1)}" y="${(y + 4).toFixed(1)}" font-size="10" fill="var(--text-soft)">${val.toFixed(2)}</text>`;
    }).join("");

    // —— 叠加线 ——
    let overlay = "";
    maList.forEach(n => { overlay += polySegments(ind.ma["ma" + n], xOf, yOf, IND_COLORS["ma" + n] || "#888", 1.3); });
    if (showBoll) {
        overlay += polySegments(ind.boll.upper, xOf, yOf, IND_COLORS.upper, 1.1);
        overlay += polySegments(ind.boll.mid, xOf, yOf, IND_COLORS.mid, 1);
        overlay += polySegments(ind.boll.lower, xOf, yOf, IND_COLORS.lower, 1.1);
    }

    // —— 副图 ——
    let subSvg = "", subLegend = "";
    const subTop = padT + mainH + subGap;
    if (subH > 0) {
        const subBottom = subTop + subH;
        const sY = (v, lo, hi) => subBottom - ((v - lo) / ((hi - lo) || 1)) * subH;
        const frame = `<rect x="${padL}" y="${subTop}" width="${plotW}" height="${subH}" fill="none" stroke="var(--border)" stroke-width="1"/>`;

        if (sub === "vol") {
            const maxVol = Math.max(...rows.map(r => r.v || 0), 1);
            subSvg = frame + rows.map((r, i) => {
                const vh = ((r.v || 0) / maxVol) * (subH - 4);
                const up = r.c >= r.o;
                return `<rect x="${(xOf(i) - bw / 2).toFixed(1)}" y="${(subBottom - vh).toFixed(1)}" width="${bw.toFixed(1)}" height="${vh.toFixed(1)}" fill="${up ? "var(--up)" : "var(--down)"}" opacity="0.45"/>`;
            }).join("");
            subLegend = `<span class="legend-item"><i style="background:var(--text-soft);opacity:.45"></i>成交量</span>`;
        } else if (sub === "macd") {
            const mc = ind.macd || {};
            const hist = mc.hist || [];
            const vals = [...hist, ...(mc.dif || []), ...(mc.dea || [])].filter(v => v != null);
            const m = Math.max(1e-6, ...vals.map(v => Math.abs(v))) * 1.1;
            const zY = sY(0, -m, m);
            subSvg = frame
                + `<line x1="${padL}" y1="${zY.toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${zY.toFixed(1)}" stroke="var(--border)"/>`
                + hist.map((v, i) => {
                    if (v == null) return "";
                    const y1 = sY(v, -m, m), h = Math.abs(y1 - zY) || 0.6;
                    return `<rect x="${(xOf(i) - bw / 2).toFixed(1)}" y="${Math.min(y1, zY).toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" fill="${v >= 0 ? "var(--up)" : "var(--down)"}" opacity="0.6"/>`;
                }).join("")
                + polySegments(mc.dif, xOf, v => sY(v, -m, m), IND_COLORS.dif, 1.3)
                + polySegments(mc.dea, xOf, v => sY(v, -m, m), IND_COLORS.dea, 1.3);
            if (!vals.length) subSvg = frame + `<text x="${(padL + plotW / 2).toFixed(1)}" y="${(subTop + subH / 2).toFixed(1)}" text-anchor="middle" font-size="11" fill="var(--text-soft)">该周期数据不足，无法计算 MACD</text>`;
            subLegend = `<span class="legend-item"><i style="background:${IND_COLORS.dif}"></i>DIF</span><span class="legend-item"><i style="background:${IND_COLORS.dea}"></i>DEA</span><span class="legend-item"><i style="background:var(--up)"></i>红柱</span><span class="legend-item"><i style="background:var(--down)"></i>绿柱</span>`;
        } else if (sub === "rsi") {
            const rsis = ind.rsi || {};
            const sY2 = v => sY(v, 0, 100);
            subSvg = frame
                + [30, 50, 70].map(lv => `<line x1="${padL}" y1="${sY2(lv).toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${sY2(lv).toFixed(1)}" stroke="var(--border)" stroke-dasharray="${lv === 50 ? "2 4" : "4 3"}"/>`
                    + `<text x="${(W - padR + 6).toFixed(1)}" y="${(sY2(lv) + 3).toFixed(1)}" font-size="9" fill="var(--text-soft)">${lv}</text>`).join("")
                + polySegments(rsis.rsi6, xOf, sY2, IND_COLORS.ma5, 1.3)
                + polySegments(rsis.rsi12, xOf, sY2, IND_COLORS.ma10, 1.3)
                + polySegments(rsis.rsi24, xOf, sY2, IND_COLORS.ma20, 1.3);
            subLegend = `<span class="legend-item"><i style="background:${IND_COLORS.ma5}"></i>RSI6</span><span class="legend-item"><i style="background:${IND_COLORS.ma10}"></i>RSI12</span><span class="legend-item"><i style="background:${IND_COLORS.ma20}"></i>RSI24</span>`;
        } else if (sub === "kdj") {
            const kdj = ind.kdj || {};
            const all = [...(kdj.k || []), ...(kdj.d || []), ...(kdj.j || [])].filter(v => v != null);
            const lo = Math.min(0, ...all), hi = Math.max(100, ...all);
            const sY3 = v => sY(v, lo, hi);
            subSvg = frame
                + [20, 80].map(lv => `<line x1="${padL}" y1="${sY3(lv).toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${sY3(lv).toFixed(1)}" stroke="var(--border)" stroke-dasharray="4 3"/>`
                    + `<text x="${(W - padR + 6).toFixed(1)}" y="${(sY3(lv) + 3).toFixed(1)}" font-size="9" fill="var(--text-soft)">${lv}</text>`).join("")
                + polySegments(kdj.k, xOf, sY3, IND_COLORS.k, 1.3)
                + polySegments(kdj.d, xOf, sY3, IND_COLORS.d, 1.3)
                + polySegments(kdj.j, xOf, sY3, IND_COLORS.j, 1.1);
            subLegend = `<span class="legend-item"><i style="background:${IND_COLORS.k}"></i>K</span><span class="legend-item"><i style="background:${IND_COLORS.d}"></i>D</span><span class="legend-item"><i style="background:${IND_COLORS.j}"></i>J</span>`;
        }
    }

    const xlabels = [...new Set([0, Math.floor(rows.length / 2), rows.length - 1])].map(i => {
        const r = rows[i]; if (!r) return "";
        const txt = String(r.t).length > 7 ? String(r.t).slice(2, 10) : String(r.t);
        return `<text x="${xOf(i).toFixed(1)}" y="${H - 6}" text-anchor="middle" font-size="10" fill="var(--text-soft)">${esc(txt)}</text>`;
    }).join("");

    const legend = `<span class="legend-item"><i style="background:var(--up)"></i>阳线</span><span class="legend-item"><i style="background:var(--down)"></i>阴线</span>`
        + maList.map(n => `<span class="legend-item"><i style="background:${IND_COLORS["ma" + n]}"></i>MA${n}</span>`).join("")
        + (showBoll ? `<span class="legend-item"><i style="background:${IND_COLORS.upper}"></i>BOLL上轨</span><span class="legend-item"><i style="background:${IND_COLORS.mid}"></i>中轨</span><span class="legend-item"><i style="background:${IND_COLORS.lower}"></i>下轨</span>` : "")
        + subLegend;

    return `<div class="chart-legend">${legend}</div>`
        + `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto">${grid}${candles}${overlay}${subSvg}${xlabels}</svg>`;
}

// ---------- 银行金价（官网一手数据，独立区块） ----------
// 与 metal_quotes 完全隔离：不做高频轮询（官网不宜频繁抓），只在进入页面时加载一次 + 手动刷新。
// 所有数值单元格统一判空显示「—」，且不着色；不复用 chgColor/chgSign/pctBadge（其入参多为行情对象）。
const BANK_GOLD_DISCLAIMER = "以上为交通银行官网展示的上海黄金交易所行情（Au99.99 基础价 + Au 系合约），非交行零售报价、非投资金条售价，不能代表银行金条售价；官网未提供的涨跌幅按原样留空（—），不作推算；仅供参考，不构成投资建议。";
const bankGoldState = { data: null, refreshing: false, error: "" };

function bankVal(v, digits) {
    if (v == null || v === "") return "—";
    return digits == null ? metalNum(v) : metalNum(v, digits);
}
// 官网报价时间格式化：交行基础价接口给的是 14 位数字串（20261111153000），
//   原样展示没人读得懂；这里只做显示层转换，不改数据本身。
function bankStampFmt(v) {
    if (!v) return "—";
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(String(v).trim());
    return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}` : String(v);
}
function bankGoldHtml() {
    const st = bankGoldState;
    const btn = `<button class="btn btn-ghost btn-sm" id="bank-gold-refresh" type="button" ${st.refreshing ? "disabled" : ""}><i class="fa-solid ${st.refreshing ? "fa-spinner fa-spin" : "fa-rotate"}"></i> ${st.refreshing ? "刷新中…" : "刷新"}</button>`;
    const head = `<div class="panel-head"><h3><i class="fa-solid fa-building-columns"></i> 银行金价（官网一手数据）</h3>
        <span class="text-muted">交通银行官网 · 上金所行情，非银行零售价</span>${btn}</div>`;
    if (!st.data) {
        return `<div class="panel">${head}<div class="panel-body">${st.error ? `<div class="empty">${esc(st.error)}</div>` : LOADING_HTML}
            <p class="text-muted" style="margin-top:10px">${esc(BANK_GOLD_DISCLAIMER)}</p></div></div>`;
    }
    const quotes = st.data.quotes || [];
    const meta = st.data.meta || {};
    const rows = quotes.map(q => {
        const stale = q.status === "stale";
        const pct = bankVal(q.change_pct, 2);
        // 口径 / 代码 / 备注等长文案收进 title，不再占单元格行高（用户要求表格紧凑）
        const detail = [q.symbol, q.caliber, q.note, stale ? "上次成功值" : "", q.quote_stamp ? "" : "官网未提供报价时间"].filter(Boolean).join(" · ");
        return `<tr class="${stale ? "text-muted" : ""}">
            <td><b>${esc(q.bank || "—")}</b></td>
            <td><b title="${esc(detail)}">${esc(q.name || q.symbol)}</b></td>
            <td class="text-right"><b>${bankVal(q.price)}</b></td>
            <td class="text-muted">${esc(q.unit || "—")}</td>
            <td class="text-right text-muted" title="买入 / 卖出">${bankVal(q.bid)} / ${bankVal(q.ask)}</td>
            <td class="text-right">${bankVal(q.change, 2)}</td>
            <td class="text-right">${pct === "—" ? "—" : pct + "%"}</td>
            <td class="text-muted">${esc(bankStampFmt(q.quote_stamp))}</td>
            <td class="text-muted">${esc(q.collected_at || "—")}</td>
        </tr>`;
    }).join("") || `<tr><td colspan="9" class="empty">暂无银行金价数据，点「刷新」采集一次</td></tr>`;
    return `<div class="panel">${head}<div class="panel-body">
        <div class="table-wrap"><table class="bank-gold-table">
            <thead><tr>
                <th>银行</th><th>产品 · 口径</th><th class="text-right">最新价</th><th>单位</th>
                <th class="text-right" title="买入 / 卖出">买入·卖出</th><th class="text-right">涨跌额</th><th class="text-right">涨跌幅</th>
                <th>报价时间</th><th>采集时间（非官方报价时间）</th>
            </tr></thead><tbody>${rows}</tbody>
        </table></div>
        <div class="bank-gold-notes">
            <p class="text-muted">共 ${quotes.length} 条 · 最近写入 ${esc(meta.last_refresh || "—")} · 采集时刻 ${esc(meta.collected_at || "—")}。「报价时间」为官网原文（14 位数字已转为可读格式），显示 — 表示该源官网未提供（非系统缺失）；无涨跌额 / 涨跌幅的源按原样留空，绝不用两次采集值推算。</p>
            <p class="text-muted">${esc(meta.disclaimer || BANK_GOLD_DISCLAIMER)}</p>
        </div>
        </div></div>`;
}
function renderBankGoldBox() {
    const box = $("#bank-gold-box");
    if (box) box.innerHTML = bankGoldHtml();
}
async function loadBankGold() {
    bankGoldState.refreshing = true;
    renderBankGoldBox();
    try {
        const { ok, data } = await api("/bank-gold");
        if (!ok) throw new Error(data.message || "银行金价加载失败");
        bankGoldState.data = data;
        bankGoldState.error = "";
    } catch (e) {
        bankGoldState.error = e && e.message ? e.message : "银行金价加载失败";
    } finally {
        bankGoldState.refreshing = false;
        renderBankGoldBox();
    }
}

// ---------- 实时行情（统计卡 + 报价表 + 银行金价） ----------
// 页面结构（自上而下）：工具栏 → 统计卡（后端 stats / derived，此前算好了却从未渲染）→
//   报价表（12 列核心数据，买卖价 / 持仓量并入对应列的副行；点表头排序）→ 银行金价独立区块。
// 两条铁律：
//   1) 轮询只 patch 单元格文本、不重建 DOM —— 横向滚动位置 / 文字选中 / 行 hover 全部保留；
//   2) 银行金价块只在进页与手动刷新时渲染，绝不随贵金属轮询重绘。

// 价格类字段：0 与空同视为缺失（metal_quotes 各列 NOT NULL DEFAULT 0，新浪没给的入库为 0），
//   显示灰色「—」。缺失值绝不能直接喂 chgColor / chgSign —— Number(null) === 0 会被渲染成红色「+0.00%」。
function mtNum(v, digits) {
    const n = Number(v);
    if (!Number.isFinite(n) || n === 0) return `<span class="text-muted">—</span>`;
    return metalNum(n, digits);
}
function mtPctNum(v) {
    const n = Number(v);
    if (!Number.isFinite(n) || n === 0) return `<span class="text-muted">—</span>`;
    return metalNum(n, 2) + "%";
}
// 涨跌类字段：空 →「—」；真实 0（平盘）→ 灰色 0.00；非 0 → 红涨绿跌 + 正负号
function mtChg(v, digits, pct) {
    if (v == null || v === "") return `<span class="text-muted">—</span>`;
    const n = Number(v);
    if (!Number.isFinite(n)) return `<span class="text-muted">—</span>`;
    if (n === 0) return `<span class="text-muted">0.00${pct ? "%" : ""}</span>`;
    return `<span style="color:${chgColor(n)}">${chgSign(n)}${metalNum(n, digits)}${pct ? "%" : ""}</span>`;
}
// 报价时间：非交易时段 quote_time 常为空；日期时间都缺 →「—」（原来会渲染成一个空格）
//   内盘 nf_ 行情只有日期没有时分，此时用采集时间（UTC → 北京时间）兜底，避免只显示半截时间。
function mtStamp(q) {
    const d = String(q.quote_date || "").trim(), t = String(q.quote_time || "").trim();
    if (d && t) return esc(d + " " + t);
    if (d) return esc(d + " " + (dbUtcTime(q.updated_at) || "").replace(/^\d{2}-\d{2}\s/, "")).trim();
    if (t) return esc(t);
    return `<span class="text-muted">—</span>`;
}

// 表头排序（default = 后端品种序，即行情重要性序）
const MT_SORTS = {
    default: null,
    price: (a, b) => (b.price || 0) - (a.price || 0),
    chg: (a, b) => (b.change || 0) - (a.change || 0),
    pct: (a, b) => (b.change_pct || 0) - (a.change_pct || 0),
    open: (a, b) => (b.open || 0) - (a.open || 0),
    high: (a, b) => (b.high || 0) - (a.high || 0),
    low: (a, b) => (b.low || 0) - (a.low || 0),
    prev: (a, b) => (b.prev_close || 0) - (a.prev_close || 0),
    amp: (a, b) => (b.amplitude || 0) - (a.amplitude || 0),
    vol: (a, b) => (b.volume || 0) - (a.volume || 0)
};
function mtSorted(list) {
    const cmp = MT_SORTS[metalPage.sort];
    const out = list.slice();
    if (cmp) out.sort((a, b) => (metalPage.sortDesc ? cmp(a, b) : cmp(b, a)));
    return out;
}
function mtTableHead() {
    const th = (f, label, right) => {
        const active = metalPage.sort === f;
        const cls = [right ? "text-right" : "", "sortable", active ? "active" : ""].filter(Boolean).join(" ");
        return `<th data-sort="${f}" class="${cls}" title="点击排序">${label}${active ? (metalPage.sortDesc ? " ↓" : " ↑") : ""}</th>`;
    };
    return `<thead><tr>
        <th>品种</th>${th("price", "最新价", true)}${th("chg", "涨跌额", true)}${th("pct", "涨跌幅", true)}
        ${th("open", "今开", true)}${th("high", "最高", true)}${th("low", "最低", true)}${th("prev", "昨收", true)}
        ${th("amp", "振幅", true)}${th("vol", "成交量", true)}<th>报价时间</th><th>操作</th>
    </tr></thead>`;
}

// 统计卡：涨跌家数 / 领涨领跌 / 金银比
function mtKpiHtml(d) {
    const s = d.stats || {}, dv = d.derived || {};
    const card = (key, label, main, sub) =>
        `<div class="mt-kpi-card"><span>${esc(label)}</span><b data-k="${key}">${main}</b><small class="text-muted">${sub}</small></div>`;
    const avg = Number.isFinite(Number(s.avg_change_pct)) ? `${chgSign(s.avg_change_pct)}${metalNum(s.avg_change_pct, 2)}%` : "—";
    const side = q => q ? `<span style="color:${chgColor(q.change_pct)}">${esc(q.short_name || q.symbol)} ${chgSign(q.change_pct)}${metalNum(q.change_pct, 2)}%</span>` : `<span class="text-muted">—</span>`;
    const gsr = dv.gold_silver_ratio == null ? null : Number(dv.gold_silver_ratio);
    const hasGsr = gsr != null && Number.isFinite(gsr) && gsr > 0;
    const gsrSrc = dv.gold_silver_ratio_source === "sh" ? "沪金 / 沪银（元/克）" : "";
    return `<div class="mt-kpi">
        ${card("breadth", "涨跌家数", `<span class="mt-up-n">${s.up || 0} 涨</span><span class="mt-dn-n">${s.down || 0} 跌</span><span class="text-muted">${s.flat || 0} 平</span>`, `平均涨跌幅 ${avg}`)}
        ${card("best", "领涨 / 领跌", `${side(s.best)} <span class="text-muted">/</span> ${side(s.worst)}`, "按当日涨跌幅")}
        ${card("gsr", "金银比", hasGsr ? metalNum(gsr, 2) : `<span class="text-muted">—</span>`, gsrSrc)}
    </div>`;
}

// 单行单元格工厂：首帧渲染与轮询 patch 共用同一份输出，保证两条路径渲染结果完全一致。
//   买卖价并入「最新价」副行、持仓量并入「成交量」副行 —— 17 列瘦身到 12 列，横向滚动基本消除。
function mtRowCells(q, maxAbsPct) {
    const hasQuote = Number(q.change_pct) !== 0 || Number(q.change) !== 0;
    const bar = (hasQuote && maxAbsPct > 0)
        ? `<i class="mt-bar" style="height:${Math.max(6, Math.round(Math.abs(q.change_pct) / maxAbsPct * 20))}px;background:${chgColor(q.change_pct)}"></i>` : "";
    return {
        name: `<b>${esc(q.short_name || q.name)}</b> <span class="badge ${METAL_KIND_CLASS[q.kind] || ""}">${esc(q.kind)}</span>
            <div class="text-muted" style="font-size:11px">${esc(q.symbol)} · ${esc(q.market)}</div>`,
        price: `<b>${mtNum(q.price)}</b>
            ${(Number(q.bid) !== 0 && Number(q.ask) !== 0) ? `<div class="text-muted" style="font-size:11px">买 ${metalNum(q.bid)} / 卖 ${metalNum(q.ask)}</div>` : ""}`,
        chg: mtChg(q.change, 2),
        pct: `<span class="mt-pct">${mtChg(q.change_pct, 2, true)}${bar}</span>`,
        open: mtNum(q.open), high: mtNum(q.high), low: mtNum(q.low), prev: mtNum(q.prev_close),
        amp: mtPctNum(q.amplitude),
        vol: Number(q.volume) !== 0 ? `<b>${metalNum(q.volume, 0)}</b>${Number(q.open_interest) !== 0 ? `<div class="text-muted" style="font-size:11px">持仓 ${metalNum(q.open_interest, 0)}</div>` : ""}` : `<span class="text-muted">—</span>`,
        stamp: `${mtStamp(q)}${q.stale ? ` <span class="badge badge-stale" title="该行不在最近一次采集结果里，价格可能已过期">陈旧</span>` : ""}`
    };
}
function mtRowHtml(q, maxAbsPct) {
    const c = mtRowCells(q, maxAbsPct);
    return `<tr data-sym="${esc(q.symbol)}" class="mt-row${q.stale ? " mt-stale" : ""}" style="cursor:pointer">
        <td data-f="name">${c.name}</td>
        <td class="text-right" data-f="price">${c.price}</td>
        <td class="text-right" data-f="chg">${c.chg}</td>
        <td class="text-right" data-f="pct">${c.pct}</td>
        <td class="text-right" data-f="open">${c.open}</td>
        <td class="text-right" data-f="high">${c.high}</td>
        <td class="text-right" data-f="low">${c.low}</td>
        <td class="text-right" data-f="prev">${c.prev}</td>
        <td class="text-right" data-f="amp">${c.amp}</td>
        <td class="text-right" data-f="vol">${c.vol}</td>
        <td class="text-muted" data-f="stamp">${c.stamp}</td>
        <td><button class="btn btn-ghost btn-sm" data-detail="${esc(q.symbol)}" title="K线 / 技术指标 / 分时明细"><i class="fa-solid fa-chart-column"></i></button></td>
    </tr>`;
}
const MT_TABLE_NOTE = "本表数据源：新浪财经实时行情 + 美元兑人民币汇率；历史K线来自东方财富。银行官网金价见下方「银行金价」独立区块，二者口径不同（元/克 交易所行情 vs 实物金条参考价），不可混用；行情均为实时公开报价，仅供参考，不构成投资建议。";
let mtCache = null;   // 最近一次 /api/metals 响应：排序 / 筛选切换时直接本地重绘，不再重复请求

async function viewMetalsQuote(container) {
    const canRefresh = state.user.role === "admin" || state.user.permissions.includes("market.refresh");
    const mySeq = routerSeq;
    container.innerHTML = `
        <div class="toolbar">
            <div class="field grow"><label>搜索品种</label><input id="mt-keyword" placeholder="如：沪金 / 沪银" value="${esc(metalPage.keyword)}"></div>
            <div class="field"><label>类别</label><select id="mt-kind"><option value="">全部类别</option></select></div>
            <div class="field"><label>市场</label><select id="mt-market"><option value="">全部市场</option></select></div>
            <div class="field"><label>&nbsp;</label><button class="btn btn-primary" id="mt-search"><i class="fa-solid fa-magnifying-glass"></i> 查询</button></div>
            ${canRefresh ? `<div class="field"><label>&nbsp;</label><button class="btn btn-ghost" id="mt-refresh"><i class="fa-solid fa-rotate"></i> 刷新行情</button></div>` : ""}
            <div class="field"><label>&nbsp;</label><button class="btn btn-ghost" id="mt-alerts"><i class="fa-solid fa-bell"></i> 价格预警</button></div>
        </div>
        <div id="mt-kpi"></div>
        <div id="mt-table">${LOADING_HTML}</div>
        <div id="bank-gold-box">${bankGoldHtml()}</div>`;

    let liveSec = 10;      // 由服务端下发（数据采集 → 贵金属数据区 → 行情页刷新间隔）
    let lastRowsKey = "";  // 行集合 + 排序签名：不变时轮询走 patch 路径，不重建 DOM

    const filterRows = (quotes) => {
        const kw = metalPage.keyword.trim().toLowerCase();
        return quotes.filter(q =>
            (!metalPage.kind || q.kind === metalPage.kind) &&
            (!metalPage.market || q.market === metalPage.market) &&
            (!kw || (q.name + q.short_name + q.symbol + q.market + q.kind).toLowerCase().includes(kw)));
    };

    const render = (data) => {
        const kpiBox = $("#mt-kpi");
        if (kpiBox) kpiBox.innerHTML = mtKpiHtml(data);
        const box = $("#mt-table");
        if (!box) return;
        const quotes = (data && data.quotes) || [];
        // 下拉选项按后端实际返回动态生成；选项集合没变就不重建（避免轮询时丢失展开状态）
        const kindSel = $("#mt-kind"), marketSel = $("#mt-market");
        const kindKey = [...new Set(quotes.map(q => q.kind))].join(",");
        const marketKey = [...new Set(quotes.map(q => q.market))].join(",");
        if (kindSel && kindSel.dataset.key !== kindKey) {
            kindSel.dataset.key = kindKey;
            kindSel.innerHTML = `<option value="">全部类别</option>${[...new Set(quotes.map(q => q.kind))].map(k => `<option value="${esc(k)}" ${metalPage.kind === k ? "selected" : ""}>${esc(k)}</option>`).join("")}`;
        }
        if (marketSel && marketSel.dataset.key !== marketKey) {
            marketSel.dataset.key = marketKey;
            marketSel.innerHTML = `<option value="">全部市场</option>${[...new Set(quotes.map(q => q.market))].map(k => `<option value="${esc(k)}" ${metalPage.market === k ? "selected" : ""}>${esc(k)}</option>`).join("")}`;
        }

        const rows = mtSorted(filterRows(quotes));
        const maxAbsPct = Math.max(0, ...rows.map(r => Math.abs(Number(r.change_pct) || 0)));
        const key = metalPage.sort + (metalPage.sortDesc ? "+" : "-") + "|" + rows.map(r => r.symbol).join(",");
        if (key !== lastRowsKey) {
            // 首帧 / 筛选 / 排序变化：全量渲染
            box.innerHTML = `<div class="panel"><div class="panel-head"><h3><i class="fa-solid fa-table-list"></i> 实时行情明细</h3>
                <span class="text-muted">点表头排序 · 点行看K线与技术指标 · 买卖价 / 持仓量在对应列下方小字</span></div>
                <div class="panel-body"><div class="table-wrap"><table class="data-table">
                    ${mtTableHead()}<tbody>${rows.map(q => mtRowHtml(q, maxAbsPct)).join("") || `<tr><td colspan="12" class="empty">没有符合条件的品种</td></tr>`}</tbody>
                </table></div>
                <p class="text-muted" style="margin-top:10px">${MT_TABLE_NOTE}</p>
                </div></div>`;
            box.querySelectorAll("tr[data-sym]").forEach(tr => tr.addEventListener("click", () => openMetalDetail(tr.dataset.sym)));
            lastRowsKey = key;
        } else {
            // 轮询：行集合未变，只更新内容变化的单元格 —— 滚动位置 / 选中文字 / hover 全保留
            const bySym = {};
            rows.forEach(r => { bySym[r.symbol] = r; });
            box.querySelectorAll("tr[data-sym]").forEach(tr => {
                const q = bySym[tr.dataset.sym];
                if (!q) return;
                const c = mtRowCells(q, maxAbsPct);
                Object.keys(c).forEach(f => {
                    const td = tr.querySelector(`td[data-f="${f}"]`);
                    if (td && td.innerHTML !== c[f]) td.innerHTML = c[f];
                });
            });
        }
    };

    const load = async () => {
        const { ok, data } = await api("/metals");
        if (mySeq !== routerSeq) return;
        if (!ok) {
            const box = $("#mt-table");
            if (box) box.innerHTML = `<div class="empty">加载失败：${esc((data && data.message) || "接口异常")}</div>`;
            return;
        }
        liveSec = Number(data.live_sec) || liveSec;
        // 品种配色由后端统一下发（避免前后端两份常量漂移）
        if (data.series_colors && typeof data.series_colors === "object") {
            METAL_SERIES_COLORS = { ...METAL_SERIES_COLORS_FALLBACK, ...data.series_colors };
        }
        mtCache = data;
        render(data);
    };

    $("#mt-search").addEventListener("click", () => {
        metalPage.keyword = $("#mt-keyword").value.trim();
        metalPage.kind = $("#mt-kind").value;
        metalPage.market = $("#mt-market").value;
        render(mtCache || {});
    });
    container.querySelectorAll(".toolbar input").forEach(i => i.addEventListener("keydown", e => { if (e.key === "Enter") { metalPage.keyword = $("#mt-keyword").value.trim(); render(mtCache || {}); } }));
    $("#mt-kind").addEventListener("change", () => { metalPage.kind = $("#mt-kind").value; render(mtCache || {}); });
    $("#mt-market").addEventListener("change", () => { metalPage.market = $("#mt-market").value; render(mtCache || {}); });
    // 表头排序：事件委托（表头随首帧重建，不能直接绑），排序键本地生效、不重新请求
    container.addEventListener("click", e => {
        const th = e.target.closest("th[data-sort]");
        if (!th || !mtCache) return;
        const f = th.dataset.sort;
        if (metalPage.sort === f) metalPage.sortDesc = !metalPage.sortDesc;
        else { metalPage.sort = f; metalPage.sortDesc = true; }
        render(mtCache);
    });
    if ($("#mt-alerts")) $("#mt-alerts").addEventListener("click", () => openAlertsDialog());
    if (canRefresh && $("#mt-refresh")) $("#mt-refresh").addEventListener("click", async () => {
        const btn = $("#mt-refresh");
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> 刷新中…`;
        const { ok, data } = await api("/metals/refresh", "POST", {});
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-rotate"></i> 刷新行情`;
        if (ok) { toast(`行情已刷新：${data.updated} 个品种 · 美元兑人民币 ${metalNum(data.usdcny, 4)}`, "success"); load(); }
        else toast(data.message || "刷新失败", "error");
    });
    // 银行区块「刷新」：事件委托绑定在 container 上，render() 重绘 #mt-table 不会丢监听。
    // 只在这里触发一次采集，绝不加入下面贵金属表格的轮询回调。
    container.addEventListener("click", async e => {
        const btn = e.target && e.target.closest ? e.target.closest("#bank-gold-refresh") : null;
        if (!btn || bankGoldState.refreshing) return;
        bankGoldState.refreshing = true;
        renderBankGoldBox();
        const { ok, data } = await api("/bank-gold/refresh", "POST", {});
        bankGoldState.refreshing = false;
        if (!ok) { toast(data.message || "银行金价刷新失败", "error"); renderBankGoldBox(); return; }
        toast(`银行金价已刷新：${data.updated || 0} 条`, "success");
        await loadBankGold();
    });
    // 自动刷新：按服务端配置的间隔轮询（默认 10 秒），只拉贵金属表格，不重复请求银行接口
    const tick = () => {
        if (mySeq !== routerSeq) return;
        // 标签页在后台时不轮询行情（数据没人看，回来一个周期内自动补上）
        if (document.hidden) { viewTimer = setTimeout(tick, Math.max(5, liveSec) * 1000); return; }
        load().catch(() => {}).then(() => {
            if (mySeq !== routerSeq) return;
            viewTimer = setTimeout(tick, Math.max(5, liveSec) * 1000);
        });
    };
    // 进入页面：贵金属表格加载一次 → 银行金价独立加载一次（后续仅靠手动刷新）→ 启动贵金属轮询
    (async () => {
        await load().catch(() => {});
        await loadBankGold().catch(() => {});
        if (mySeq === routerSeq) viewTimer = setTimeout(tick, Math.max(5, liveSec) * 1000);
    })();
}

// ---------- 贵金属详细数据 ----------
// ---------- 贵金属详细数据（多周期 + 技术指标） ----------
// 分时图固定刻度：一个完整交易日 09:00 → 次日 02:30，5 分钟一格
// 上午 09:05–11:30（30）、下午 13:35–15:00（18）、夜盘 21:05–23:55（35）、跨日 00:00–02:30（31），共 114 格
// 第三项 gap = 该时段前面有休市（午休 / 盘后），轴上要断开；夜盘 23:55 → 跨日 00:00 是连续交易，不断开
const INTRADAY_SESSIONS = [["09:05", "11:30", false], ["13:35", "15:00", true], ["21:05", "23:55", true], ["24:00", "26:30", false]];
// 轴上标刻度的时间点：开盘/收盘 + 整点；休市段在轴上被压成一步，15:00 与 21:05 相邻会互相压住，只留 15:00
const INTRADAY_TICKS = ["09:05", "10:00", "11:00", "11:30", "14:00", "15:00", "23:00", "00:00", "01:00", "02:00", "02:30"];
function intradaySlots(day) {
    if (!day) return [];
    const base = Date.parse(day + "T00:00:00Z"); // 用 UTC 零点做基准，只做纯分钟运算，避免本地时区干扰
    if (!Number.isFinite(base)) return [];
    const toMin = s => Number(s.slice(0, 2)) * 60 + Number(s.slice(3, 5));
    const out = [];
    INTRADAY_SESSIONS.forEach(([a, b, gap], si) => {
        // 休市段在轴上只占一步；插一个空刻度让折线在这里断开，而不是把 11:30 和 13:35 直接连起来
        //   用零宽字符 + 序号做占位，保证刻度值唯一（不重复），标签格式化后为空
        if (gap) out.push("\u200b" + si);
        for (let m = toMin(a); m <= toMin(b); m += 5) {
            out.push(new Date(base + m * 60000).toISOString().slice(0, 16).replace("T", " "));
        }
    });
    return out;
}
async function openMetalDetail(symbol) {
    const st = {
        symbol,
        period: "day",
        ma: [5, 20],
        boll: false,
        sub: "vol",
        data: null
    };
    const loadData = async (period) => {
        const { ok, data } = await api(`/metals/detail?symbol=${encodeURIComponent(symbol)}&period=${period}`);
        if (!ok) return false;
        st.data = data;
        st.period = data.period || period;
        return true;
    };
    if (!(await loadData("day"))) { toast("加载失败", "error"); return; }

    const body = `<div id="md-head"></div><div id="md-tools"></div><div id="md-chart"></div><div id="md-table"></div>`;
    const overlay = openModal(`${symbol} · 详细数据`, body, `<button class="btn btn-ghost" data-close>关闭</button>`, null);
    // K 线 + 指标工具栏 + 9 列表格，默认 560px 太窄
    overlay.querySelector(".modal")?.classList.add("lg");
    const headBox = overlay.querySelector("#md-head");
    const toolsBox = overlay.querySelector("#md-tools");
    const chartBox = overlay.querySelector("#md-chart");
    const tableBox = overlay.querySelector("#md-table");

    // —— 顶部：价格 + 指标摘要 ——
    const paintHead = () => {
        const d = st.data, q = d.quote || {}, inst = d.instrument || {}, dv = d.derived || {};
        const s = d.indicator_summary;
        const pct = Number(q.change_pct) || 0;
        const metric = (label, value, extra) => `<div class="mt-metric"><span>${esc(label)}</span><b>${value}</b>${extra ? `<em>${extra}</em>` : ""}</div>`;
        const tag = (txt, color) => `<span class="ind-tag" style="border-color:${color};color:${color}">${esc(txt)}</span>`;
        const biasColor = s ? (s.bias.includes("偏强") ? "var(--up)" : s.bias.includes("偏弱") ? "var(--down)" : "var(--text-soft)") : "var(--text-soft)";
        const num = v => (v == null ? "—" : metalNum(v, 2));

        headBox.innerHTML = `
            <div class="mt-head">
                <div class="mt-price">
                    <span class="badge ${METAL_KIND_CLASS[q.kind] || ""}">${esc(q.kind || "")}</span>
                    <div>
                        <div class="mt-price-main" style="color:${chgColor(pct)}">${metalNum(q.price)}<small>${esc(q.unit || "")}</small></div>
                        <div class="text-muted">${chgSign(q.change)}${metalNum(q.change)} · ${chgSign(pct)}${metalNum(pct, 2)}% · ${esc(q.market || "")} · ${esc(q.symbol || "")}</div>
                    </div>
                </div>
                <div class="text-muted" style="text-align:right">报价时间<br><b style="color:var(--text)">${esc((q.quote_date || "") + " " + (q.quote_time || ""))}</b></div>
            </div>
            <div class="ind-summary">
                <div class="ind-bias" style="color:${biasColor}">
                    <i class="fa-solid fa-gauge-high"></i>
                    <b>${s ? esc(s.bias) : "指标数据不足"}</b>
                    <span class="text-muted">${s ? `综合分 ${s.score > 0 ? "+" : ""}${s.score} · 基准 ${esc(s.date)}` : ""}</span>
                </div>
                <div class="ind-tags">
                    ${s ? [s.tags.maTrend, s.tags.macdState, s.tags.rsiState, s.tags.bollPos].map(t => tag(t, "var(--text-soft)")).join("") : ""}
                </div>
                <div class="ind-kv">
                    <span>MA5 <b>${s ? num(s.ma.ma5) : "—"}</b></span>
                    <span>MA20 <b>${s ? num(s.ma.ma20) : "—"}</b></span>
                    <span>MA60 <b>${s ? num(s.ma.ma60) : "—"}</b></span>
                    <span>RSI12 <b>${s ? num(s.rsi.rsi12) : "—"}</b></span>
                    <span>MACD <b>${s && s.macd.hist != null ? num(s.macd.hist) : "—"}</b></span>
                    <span>KDJ-J <b>${s ? num(s.kdj.j) : "—"}</b></span>
                    <span>BOLL <b>${s && s.boll.lower != null ? `${num(s.boll.lower)} ~ ${num(s.boll.upper)}` : "—"}</b></span>
                </div>
            </div>
            <details class="mt-more">
                <summary>全部行情明细（13 项）</summary>
            <div class="mt-metrics">
                ${metric("开盘价", metalNum(q.open), q.unit)}
                ${metric("最高价", metalNum(q.high), q.unit)}
                ${metric("最低价", metalNum(q.low), q.unit)}
                ${metric("昨收", metalNum(q.prev_close), q.unit)}
                ${metric("振幅", metalNum(q.amplitude, 2) + "%")}
                ${metric("买价", metalNum(q.bid), q.unit)}
                ${metric("卖价", metalNum(q.ask), q.unit)}
                ${metric("买卖价差", metalNum(Math.abs((q.ask || 0) - (q.bid || 0)), 4))}
                ${metric("成交量", q.volume ? metalNum(q.volume, 0) : "—")}
                ${metric("持仓量", q.open_interest ? metalNum(q.open_interest, 0) : "—")}
                ${metric("金银比", dv.gold_silver_ratio ? metalNum(dv.gold_silver_ratio, 2) : "—", dv.gold_silver_ratio_source === "sh" ? "沪金/沪银 克价比" : "")}
                ${metric("美元兑人民币", dv.usdcny ? metalNum(dv.usdcny, 4) : "—")}
            </div>
            </details>`;
        const h3 = overlay.querySelector(".modal-head h3");
        if (h3) h3.textContent = `${inst.name || q.name || symbol} · ${symbol}`;
    };

    // —— 指标工具栏 ——
    // 周期 / 叠加 / 副图 只作用于 K 线；分时是固定 5 分钟线，这三组对它无效，分时标签下隐藏
    const paintTools = () => {
        const chip = (label, active, attr) => `<button class="chip-btn ${active ? "active" : ""}" ${attr}>${label}</button>`;
        const klineTools = activeTab !== "kline" ? "" : `
            <div class="md-group"><span class="md-lb">周期</span>
                ${["day", "week", "month"].map(p => chip(PERIOD_LABEL[p], st.period === p, `data-period="${p}"`)).join("")}
            </div>
            <div class="md-group"><span class="md-lb">叠加</span>
                ${[5, 10, 20, 60].map(n => chip("MA" + n, st.ma.includes(n), `data-ma="${n}"`)).join("")}
                ${chip("BOLL", st.boll, `data-boll="1"`)}
            </div>
            <div class="md-group"><span class="md-lb">副图</span>
                ${["vol", "macd", "rsi", "kdj", "none"].map(k => chip(SUB_LABEL[k], st.sub === k, `data-sub="${k}"`)).join("")}
            </div>`;
        toolsBox.innerHTML = `<div class="md-tools">${klineTools}</div>`;
        toolsBox.querySelectorAll("[data-period]").forEach(b => b.addEventListener("click", async () => {
            const p = b.dataset.period;
            if (p === st.period) return;
            chartBox.innerHTML = LOADING_HTML;
            if (!(await loadData(p))) { toast("该周期加载失败", "error"); paintTools(); renderChart(); return; }
            paintHead(); paintTools(); renderChart();
        }));
        toolsBox.querySelectorAll("[data-ma]").forEach(b => b.addEventListener("click", () => {
            const n = Number(b.dataset.ma);
            st.ma = st.ma.includes(n) ? st.ma.filter(x => x !== n) : [...st.ma, n].sort((a, b2) => a - b2);
            paintTools(); renderChart();
        }));
        const bollBtn = toolsBox.querySelector("[data-boll]");
        bollBtn && bollBtn.addEventListener("click", () => { st.boll = !st.boll; paintTools(); renderChart(); });
        toolsBox.querySelectorAll("[data-sub]").forEach(b => b.addEventListener("click", () => {
            st.sub = b.dataset.sub; paintTools(); renderChart();
        }));
        // 标签页随工具栏一起重建（paintTools 会覆盖 innerHTML，必须放最后）
        paintTabs();
    };

    // —— 图表区 ——
    const renderChart = () => {
        const d = st.data;
        chartBox.innerHTML = metalCandleSvg(d.kline || [], {
            indicators: d.indicators || {},
            ma: st.ma,
            boll: st.boll,
            sub: st.sub,
            // 周期决定补位粒度：日线跳过周末补位、周/月线按周/月补位
            period: st.period
        });
        if (!(d.kline || []).length) {
            chartBox.innerHTML = `<div class="empty">该周期暂无 K 线数据（上游可能未提供）</div>`;
        }
    };

    // —— 明细表（含均线值，便于核对） ——
    const renderTable = () => {
        const d = st.data;
        const rows = (d.kline || []).slice(-40).reverse();
        const ind = d.indicators || {};
        const at = (arr, idx) => (arr && arr[idx] != null ? metalNum(arr[idx], 2) : "—");
        const n = (d.kline || []).length;
        tableBox.innerHTML = `<div class="table-wrap"><table>
            <thead><tr><th>日期</th><th class="text-right">开盘</th><th class="text-right">最高</th><th class="text-right">最低</th><th class="text-right">收盘</th><th class="text-right">涨跌幅</th><th class="text-right">成交量</th><th class="text-right">MA5</th><th class="text-right">MA20</th></tr></thead>
            <tbody>${rows.map((r, i) => {
                const idx = n - 1 - i;
                return `<tr>
                <td class="text-muted">${esc(r.t)}</td>
                <td class="text-right">${metalNum(r.o)}</td>
                <td class="text-right">${metalNum(r.h)}</td>
                <td class="text-right">${metalNum(r.l)}</td>
                <td class="text-right"><b>${metalNum(r.c)}</b></td>
                <td class="text-right" style="color:${chgColor(r.pct)}">${chgSign(r.pct)}${metalNum(r.pct, 2)}%</td>
                <td class="text-right text-muted">${r.v ? metalNum(r.v, 0) : "—"}</td>
                <td class="text-right text-muted">${at(ind.ma && ind.ma.ma5, idx)}</td>
                <td class="text-right text-muted">${at(ind.ma && ind.ma.ma20, idx)}</td>
            </tr>`;
            }).join("") || `<tr><td colspan="9" class="empty">暂无历史明细</td></tr>`}</tbody>
        </table></div>`;
    };

    // —— 分时（始终取当日 5 分钟线，与所选周期无关） ——
    //   轴按整个交易日铺满（09:00 → 次日 02:30），尚未走到的时间留空，方便看当前在一天里的位置
    const renderIntraday = () => {
        const d = st.data, inst = d.instrument || {};
        const pts = (d.intraday || []).map(x => ({ t: x.t, v: x.c }));
        const axis = intradaySlots(d.intraday_day);
        chartBox.innerHTML = pts.length > 1
            ? metalLinesSvg([{ name: `${inst.name || symbol} 5分钟`, color: METAL_SERIES_COLORS[symbol] || "#4f46e5", points: pts }], { label: t => String(t).slice(11, 16), digits: 2, height: 260, axis, axisTicks: INTRADAY_TICKS })
            : `<div class="empty">暂无分时数据（非交易时段或上游未返回）</div>`;
        tableBox.innerHTML = "";
    };

    const renderTrail = () => {
        const pts = (st.data.trail || []).map(x => ({ t: dbUtcTime(x.created_at) || String(x.created_at || "").replace("T", " ").slice(5, 16), v: x.price }));
        chartBox.innerHTML = pts.length > 1
            ? metalLinesSvg([{ name: "本机采集轨迹", color: "#4f46e5", points: pts }], { label: t => String(t), digits: 2, height: 240 })
            : `<div class="empty">本机采集轨迹不足两点（每次「刷新行情」若价格变动会记录一点）。可点击看板右上「刷新行情」累积。</div>`;
        tableBox.innerHTML = "";
    };

    const tabs = ["intraday", "kline", "table", "trail"];
    let activeTab = "intraday";
    const renderTab = () => {
        if (activeTab === "kline") { renderChart(); tableBox.innerHTML = ""; }
        else if (activeTab === "intraday") renderIntraday();
        else if (activeTab === "table") { chartBox.innerHTML = ""; renderTable(); }
        else renderTrail();
    };

    // 标签页：必须能被重复渲染。paintTools() 会覆盖 toolsBox.innerHTML，
    // 若只在这一处插入一次，任何一次工具栏重绘都会把标签页抹掉（历史 bug）
    const paintTabs = () => {
        const old = toolsBox.querySelector("#mt-tabs");
        if (old) old.remove();
        const items = [["intraday", "fa-chart-line", "分时"], ["kline", "fa-chart-column", "K线"], ["table", "fa-table-list", "明细数据"], ["trail", "fa-clock-rotate-left", "采集轨迹"]];
        toolsBox.insertAdjacentHTML("beforeend", `<div class="tabs" id="mt-tabs">
            ${items.map(([k, icon, label]) => `<button class="tab ${k === activeTab ? "active" : ""}" data-r="${k}"><i class="fa-solid ${icon}"></i> ${label}</button>`).join("")}
        </div>`);
        toolsBox.querySelectorAll("#mt-tabs .tab").forEach(b => b.addEventListener("click", () => {
            activeTab = b.dataset.r;
            paintTools(); // 内含 paintTabs，顺带带出/收起 K 线专属工具栏
            renderTab();
        }));
    };

    paintHead();
    paintTools();
    renderTab(); // 默认首屏是「分时」，不能直接 renderChart()
}

function acxOptMap(domain) {
    const map = {};
    (domain.options || []).forEach(o => { map[o.key] = o; });
    return map;
}
function acxVal(map, key) {
    const o = map[key];
    return o && o.value != null ? String(o.value) : "";
}
// 悬停说明（title）：优先调用点传入的 hint，否则用后端 acquire_options.description —— 单一事实来源
function acxTip(o, hint) {
    const t = String((hint || (o && o.description)) || "").trim();
    return t ? ` title="${esc(t)}"` : "";
}
// 紧凑数值格：标签与输入同一行，说明收进 title（悬停可见）—— 高级设置网格用
function acxNum(map, key, label, unit, min, max, dis, hint) {
    const o = map[key] || {};
    const v = acxVal(map, key);
    return `<label class="acx-kcell"${acxTip(o, hint)}>
        <span class="acx-kcell-lb">${esc(label)}</span>
        <span class="acx-in"><input type="number" class="acx-num" data-opt="${esc(key)}" value="${esc(v === "" ? String(o.default == null ? "" : o.default) : v)}" min="${min}" max="${max}" ${dis}><i class="acx-unit">${esc(unit)}</i></span>
    </label>`;
}
// 紧凑字段：标签、输入、单位同一行，说明收进 title —— 顶部设置条用，避免每格都带一行小字把面板撑高
function acxNumC(map, key, label, unit, min, max, dis, hint) {
    const o = map[key] || {};
    const v = acxVal(map, key);
    return `<label class="acx-cell"${acxTip(o, hint)}>
        <span class="acx-cell-lb">${esc(label)}</span>
        <span class="acx-in"><input type="number" class="acx-num" data-opt="${esc(key)}" value="${esc(v === "" ? String(o.default == null ? "" : o.default) : v)}" min="${min}" max="${max}" ${dis}><i class="acx-unit">${esc(unit)}</i></span>
    </label>`;
}
// 与后端 worker.js 的 NEWS_PER_SOURCE_FIXED 对齐（2026-11-13 定稿）：固定 30，只读
const ACX_NEWS_PER_SOURCE_FIXED = 30;
// 只读数值格子：固定参数只展示、不允许更改。刻意不带 data-opt，
//   这样既不会进入 readAcxOptions 的提交值，也不会触发脏标记 / 保存按钮。
function acxNumFixed(label, unit, value, hint) {
    return `<label class="acx-cell"${hint ? ` title="${esc(hint)}"` : ""}>
        <span class="acx-cell-lb">${esc(label)}</span>
        <span class="acx-in"><input type="number" class="acx-num" value="${esc(String(value))}" readonly tabindex="-1" aria-readonly="true"><i class="acx-unit">${esc(unit)}</i></span>
    </label>`;
}
// 间隔秒数 → 人话（45 秒 / 5 分钟 / 1.5 分钟）
function acxSecText(sec) {
    const s = Math.max(1, Math.round(Number(sec) || 0));
    if (s < 60) return s + " 秒";
    const m = s / 60;
    return (Number.isInteger(m) ? m : m.toFixed(1)) + " 分钟";
}
// 任务间隔统一按秒：后端 interval_sec 为准，存量数据用 interval_min × 60 兜底
function acxTaskSec(task) {
    const s = Number(task && task.interval_sec);
    if (Number.isFinite(s) && s >= 1) return Math.round(s);
    const m = Number(task && task.interval_min);
    if (Number.isFinite(m) && m >= 1) return Math.round(m * 60);
    return 1800;
}
function acxBool(map, key, label, dis, hint) {
    const o = map[key] || {};
    const on = (acxVal(map, key) || "0") === "1";
    return `<div class="acx-field acx-field-switch"${acxTip(o, hint)}>
        <label>${esc(label)}</label>
        <label class="switch"><input type="checkbox" class="acx-chk" data-opt="${esc(key)}" ${on ? "checked" : ""} ${dis}><span></span></label>
    </div>`;
}
// 多行文本：标签在上，文本框在下，说明只走 title（悬停可见）
function acxText(map, key, label, dis, rows) {
    const o = map[key] || {};
    return `<div class="acx-block"${acxTip(o)}>
        <label>${esc(label)}</label>
        <textarea class="acx-ta" data-opt="${esc(key)}" rows="${rows || 2}" ${dis}>${esc(acxVal(map, key))}</textarea>
    </div>`;
}
function acxSelect(map, key, label, dis) {
    const o = map[key] || {};
    const choices = parseMetaJson(o.options, []);
    const cur = acxVal(map, key);
    return `<div class="acx-field"${acxTip(o)}>
        <label>${esc(label)}</label>
        <select data-opt="${esc(key)}" ${dis}>${choices.map(c => `<option value="${esc(c.value)}"${c.value === cur ? " selected" : ""}>${esc(c.label || c.value)}</option>`).join("")}</select>
    </div>`;
}
// 采集状态中文标签：success / partial / failed / skipped
function acxStatusLabel(status) {
    if (status === "success") return { text: "成功", cls: "ok", icon: "fa-check" };
    if (status === "partial") return { text: "部分", cls: "warn", icon: "fa-circle-half-stroke" };
    if (status === "skipped") return { text: "跳过", cls: "warn", icon: "fa-forward" };
    return { text: "失败", cls: "bad", icon: "fa-xmark" };
}
// 任务副标题：下次执行 + 最近一次结果
function acxTaskSub(t) {
    if (!t || !t.enabled) return "已关闭";
    const next = t.next_run_in_sec == null ? "等待调度"
        : (t.overdue ? "已到期，等待调度" : fmtCountdown(t.next_run_in_sec, false));
    const st = acxStatusLabel(t.last_status);
    const last = t.last_run_at
        ? `上次 ${fmtNewsTime(t.last_run_at)} ${st.text}`
        : "未运行过";
    return `${next} · ${last}`;
}
// 数据源列表（两个域共用，折叠展示）
function acxSourcesHtml(domain, dis, canRun) {
    const srcs = domain.sources || [];
    const bad = srcs.filter(s => s.last_status && s.last_status !== "ok").length;
    const rows = srcs.map(s => {
        const tested = !!s.last_status;
        const ok = s.last_status === "ok";
        return `<div class="acx-src">
            <label class="switch"><input type="checkbox" class="acx-src-en" value="${esc(s.source_key)}" ${s.enabled ? "checked" : ""} ${dis}><span></span></label>
            <div class="acx-src-main"><b>${esc(s.name)}</b><small title="${esc(s.endpoint || "")}">${esc(s.endpoint || "")}</small>${s.description ? `<small title="${esc(s.description)}">${esc(s.description)}</small>` : ""}</div>
            ${s.recent_7d == null ? "" : `<span class="acx-src-c">近 7 天 ${s.recent_7d} 条</span>`}
            <span class="acx-src-state${tested ? (ok ? " ok" : " bad") : ""}">${tested ? (ok ? "正常" : "异常") : "未测试"}</span>
            ${canRun ? `<button type="button" class="btn btn-ghost btn-sm" data-acx-test="${esc(s.source_key)}">测试</button>` : ""}
        </div>`;
    }).join("") || `<div class="acx-src"><span class="acx-empty-note">暂无数据源</span></div>`;
    return acxFoldHtml("src", `数据源 · ${srcs.length} 个`,
        bad ? `<span class="acx-fold-badge bad">${bad} 个异常</span>` : `<span class="acx-fold-badge ok">全部正常</span>`,
        `<div style="padding:2px 0">${rows}</div>`);
}
// —— 全站统一分页条（2026-11-12）——
// 形态：‹ 1 2 3 4 5 › 跳转[输入] │ 每页 [下拉] · 共 N 条
// 用法：容器.innerHTML = pagerHtml({ cur, pages, total, size })；再 bindPager(容器, ctx, onPage, onSize)
// 约定：onPage(n) 收「页码」而不是 offset，各页面自行换算（资讯用 offset/limit，采集日志用 page/page_size）
const PAGER_SIZES = [10, 20, 50, 100];

function pagerHtml(o) {
    const size = Number(o.size) || PAGER_SIZES[0];
    const total = Math.max(0, Number(o.total) || 0);
    const pages = Math.max(1, Number(o.pages) || Math.ceil(total / size) || 1);
    const cur = Math.min(pages, Math.max(1, Number(o.cur) || 1));
    const sizes = o.sizes || PAGER_SIZES;
    // 页码窗口固定 5 格，尽量让当前页居中
    const from = Math.max(1, Math.min(cur - 2, pages - 4));
    const to = Math.min(pages, from + 4);
    let nums = "";
    for (let i = from; i <= to; i++) {
        nums += `<button class="pg-num${i === cur ? " on" : ""}" data-pg="${i}"${i === cur ? ' aria-current="page"' : ""}>${i}</button>`;
    }
    return `<div class="pager">
        <button class="pg-nav" data-pg="${cur - 1}" ${cur > 1 ? "" : "disabled"} title="上一页" aria-label="上一页"><i class="fa-solid fa-chevron-left"></i></button>
        ${nums}
        <button class="pg-nav" data-pg="${cur + 1}" ${cur < pages ? "" : "disabled"} title="下一页" aria-label="下一页"><i class="fa-solid fa-chevron-right"></i></button>
        <label class="pg-jump">跳转<input type="number" class="pg-jump-input" min="1" max="${pages}" value="${cur}" inputmode="numeric" aria-label="跳转到第几页"></label>
        <span class="pg-sep"></span>
        <label class="pg-limit">每页<select class="pg-select" aria-label="每页条数">${sizes.map(n => `<option value="${n}" ${n === size ? "selected" : ""}>${n} 条</option>`).join("")}</select></label>
        <span class="pg-total">· 共 ${total} 条</span>
    </div>`;
}

// ctx 传 pagerHtml 用过的同一组 { cur, pages, size }，用于纠偏与「点了当前页不重复请求」
function bindPager(root, ctx, onPage, onSize) {
    if (!root) return;
    const cur = Math.max(1, Number(ctx.cur) || 1);
    const pages = Math.max(1, Number(ctx.pages) || 1);
    root.querySelectorAll("[data-pg]").forEach(b => b.addEventListener("click", () => {
        if (b.disabled) return;
        const n = Number(b.dataset.pg);
        if (!(n >= 1 && n <= pages) || n === cur) return;
        onPage(n);
    }));
    const inp = root.querySelector(".pg-jump-input");
    if (inp) {
        const apply = () => {
            let n = parseInt(inp.value, 10);
            if (!Number.isFinite(n)) n = cur;
            n = Math.min(pages, Math.max(1, n));
            inp.value = String(n);
            if (n !== cur) onPage(n);
        };
        inp.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); apply(); } });
        inp.addEventListener("blur", () => { apply(); });
    }
    const sel = root.querySelector(".pg-select");
    if (sel) sel.addEventListener("change", () => onSize(parseInt(sel.value, 10) || Number(ctx.size) || PAGER_SIZES[0]));
}

// 折叠面板（数据源 / 最近采集共用）；默认展开，用户仍可手动折叠
function acxFoldHtml(kind, title, badge, body) {
    return `<details class="acx-fold" open>
        <summary><i class="fa-solid fa-chevron-right acx-fold-arrow"></i><span class="acx-fold-title">${esc(title)}</span>${badge}</summary>
        <div class="acx-fold-body">${body}</div>
    </details>`;
}
// ===== 数据保留面板（采集页顶部，跨域集中管理留存策略）=====
// 说明收进 title（悬停可见），标签 ≤3 字，沿用 acx 紧凑数值格风格。
function retVal(map, key, def) {
    const v = acxVal(map, key);
    return v === "" ? String(def) : v;
}
// 带默认值的紧凑数值格（新参数在存量库可能缺失，用 def 兜底显示）
function retNum(map, key, label, unit, def, min, max, dis) {
    const o = map[key] || {};
    return `<label class="acx-kcell"${acxTip(o)}>
        <span class="acx-kcell-lb">${esc(label)}</span>
        <span class="acx-in"><input type="number" class="acx-num" data-opt="ret:${esc(key)}" value="${esc(retVal(map, key, def))}" min="${min}" max="${max}" ${dis}><i class="acx-unit">${esc(unit)}</i></span>
    </label>`;
}
// 数据保留面板 HTML。news / metal 为域对象（含 options 数组）。
function acxRetentionHtml(news, metal, canConfig, canRun) {
    const dis = canConfig ? "" : "disabled";
    const nm = acxOptMap(news || {}), mm = acxOptMap(metal || {});
    const defDays = retVal(nm, "fetch_log_retention_days", 30);
    return `<section class="panel" id="acx-retention" style="margin-bottom:14px">
        <div class="panel-head">
            <h3><i class="fa-solid fa-database"></i> 数据保留</h3>
            <span class="muted">控制数据库容积：过期数据自动清理，也可手动立即清理</span>
            <div class="acx-head-actions">
                ${canConfig ? `<button class="btn btn-primary btn-sm" id="ret-save" disabled><i class="fa-solid fa-floppy-disk"></i> 保存</button>` : ""}
            </div>
        </div>
        <div class="panel-body">
            <div class="ret-group">
                <div class="ret-group-title"><i class="fa-solid fa-broom"></i> 立即清理</div>
                <div class="ret-row">
                    <label class="acx-cell" title="立即删除 N 天前的采集日志与旧消息（星标消息保留）。用于快速降低数据库容积，不影响贵金属快照 / 轨迹。">
                        <span class="acx-cell-lb">清理</span>
                        <span class="acx-in"><input type="number" class="acx-num" id="ret-clean-days" value="${esc(defDays)}" min="1" max="3650" ${dis}><i class="acx-unit">天前</i></span>
                    </label>
                    <button class="btn btn-ghost btn-sm" id="ret-clean" type="button" ${canConfig ? "" : "disabled"}><i class="fa-solid fa-broom"></i> 立即清理日志与旧消息</button>
                    <span class="muted ret-clean-note" id="ret-clean-note"></span>
                </div>
            </div>
            <div class="ret-group">
                <div class="ret-group-title"><i class="fa-solid fa-clock-rotate-left"></i> 自动保留</div>
                <div class="acx-grid ret-grid">
                    ${retNum(nm, "news_retention_days", "消息", "天", 90, 1, 3650, dis)}
                    ${retNum(nm, "fetch_log_retention_days", "日志", "天", 30, 1, 3650, dis)}
                </div>
            </div>
            <div class="ret-group">
                <div class="ret-group-title"><i class="fa-solid fa-coins"></i> 贵金属</div>
                <div class="acx-grid ret-grid">
                    ${retNum(mm, "metal_snapshot_keep", "快照", "条", 2000, 100, 20000, dis)}
                    ${retNum(mm, "metal_snapshot_days", "快照天", "天", 90, 1, 3650, dis)}
                    ${retNum(mm, "metal_history_keep", "轨迹", "条", 500, 50, 5000, dis)}
                    ${retNum(mm, "metal_history_days", "轨迹天", "天", 30, 1, 3650, dis)}
                </div>
            </div>
        </div>
    </section>`;
}

// 绑定数据保留面板：脏标记、保存（拆分两域提交）、立即清理
function bindRetention(box, { seq, load }) {
    const panel = box.querySelector("#acx-retention");
    if (!panel) return;
    const saveBtn = panel.querySelector("#ret-save");
    const inputs = [...panel.querySelectorAll('[data-opt^="ret:"]')];
    const keyOf = el => el.dataset.opt.slice(4);
    // 脏标记：值变化启用保存
    inputs.forEach(i => i.addEventListener("input", () => { if (saveBtn) saveBtn.disabled = false; }));

    if (saveBtn) saveBtn.addEventListener("click", async () => {
        const options = { news: {}, metal: {} };
        const newsKeys = ["news_retention_days", "fetch_log_retention_days"];
        inputs.forEach(i => {
            const k = keyOf(i);
            options[newsKeys.includes(k) ? "news" : "metal"][k] = i.value;
        });
        const old = saveBtn.innerHTML;
        saveBtn.disabled = true;
        saveBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> 保存中…`;
        const { ok, data } = await api("/acquire/config", "POST", { options });
        saveBtn.innerHTML = old;
        if (ok) {
            toast("数据保留设置已保存", "success");
            if (seq === routerSeq) await load();
        } else {
            toast(data.message || "保存失败", "error");
            saveBtn.disabled = false;
        }
    });

    const cleanBtn = panel.querySelector("#ret-clean");
    const daysInput = panel.querySelector("#ret-clean-days");
    const note = panel.querySelector("#ret-clean-note");
    if (cleanBtn) cleanBtn.addEventListener("click", () => {
        const days = Math.min(3650, Math.max(1, parseInt(daysInput && daysInput.value, 10) || 30));
        const hint = `${days} 天前的采集日志与旧消息将被永久删除（星标消息保留），不可恢复。`;
        confirmDelete(`${days} 天前的日志与旧消息`, async () => {
            const old = cleanBtn.innerHTML;
            cleanBtn.disabled = true;
            cleanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> 清理中…`;
            const { ok, data } = await api("/acquire/cleanup", "POST", { days });
            cleanBtn.disabled = false;
            cleanBtn.innerHTML = old;
            if (ok) {
                if (note) note.textContent = data.message || `已清理 ${days} 天前数据`;
                toast(data.message || "清理完成", "success");
                if (seq === routerSeq) {
                    await load();
                    ["news", "metal"].forEach(dk => loadAcxLogs(box, dk, seq));
                }
            } else toast(data.message || "清理失败", "error");
        }, hint);
    });
}

// 最近采集面板（两个域共用，默认展开；日志在渲染时已一次性拉取，不依赖展开事件）
function acxLogsHtml(dk) {
    return `<details class="acx-fold" id="acx-fold-log-${dk}" open>
        <summary><i class="fa-solid fa-chevron-right acx-fold-arrow"></i><span class="acx-fold-title">最近采集</span>
            <button class="btn btn-ghost btn-sm" id="acx-log-reload-${dk}" type="button" style="margin-left:auto"><i class="fa-solid fa-rotate"></i> 刷新</button></summary>
        <div class="acx-fold-body">
            <div class="table-wrap" style="border:0;border-radius:0">
                <table>
                    <thead><tr><th style="width:112px">时间</th><th style="width:84px">结果</th><th style="width:64px">触发</th>
                        <th class="text-right" style="width:64px">抓取</th><th class="text-right" style="width:64px">新增</th>
                        <th class="text-right" style="width:76px">耗时</th><th>说明</th></tr></thead>
                    <tbody id="acx-log-body-${dk}"><tr><td colspan="7" class="empty">加载中…</td></tr></tbody>
                </table>
            </div>
            <div class="acx-pager" id="acx-pager-${dk}"></div>
        </div>
    </details>`;
}

// —— 消息数据域 ——
function acxNewsHtml(domain, canConfig, canRun) {
    const dis = canConfig ? "" : "disabled";
    const map = acxOptMap(domain);
    const task = (domain.tasks || []).find(t => t.task_key === "news_crawl") || (domain.tasks || [])[0] || {};
    const enabled = !!task.enabled;
    const sec = acxTaskSec(task);
    const chOpt = map.news_channels || {};
    const chChoices = parseMetaJson(chOpt.options, []);
    const chPicked = new Set(String(chOpt.value || "").split(",").map(s => s.trim()).filter(Boolean));
    return `
    <div id="acx-sec-news">
    <section class="panel">
        <div class="panel-head">
            <h3><span class="acx-dot${enabled ? "" : " off"}"></span> 消息采集${enabled ? "运行中" : "已关闭"}</h3>
            <span class="muted">每 ${acxSecText(sec)}一次 · ${esc(acxTaskSub(enabled ? task : null))}</span>
            <div class="acx-head-actions">
                ${canRun ? `<button class="btn btn-ghost btn-sm" id="acx-run-news"><i class="fa-solid fa-bolt"></i> 立即采集</button>` : ""}
                ${canConfig ? `<button class="btn btn-ghost btn-sm" id="acx-save-news" disabled><i class="fa-solid fa-floppy-disk"></i> 保存</button>` : ""}
            </div>
        </div>
        <div class="panel-body">
            <div class="acx-bar">
                <label class="acx-cell acx-cell-sw" title="关闭后不再定时抓取，仍可手动采集">
                    <span class="switch"><input type="checkbox" id="acx-enabled" ${enabled ? "checked" : ""} ${dis}><span></span></span>
                    <span class="acx-cell-lb">自动采集</span>
                </label>
                <span class="acx-sep"></span>
                <label class="acx-cell" title="两次抓取的最小间隔。小于 60 秒时由页面访问触发补采；定时唤醒每分钟一次">
                    <span class="acx-cell-lb">采集频率</span>
                    <span class="acx-in"><input type="number" id="acx-interval" value="${sec}" min="5" max="86400" step="5" ${dis}><i class="acx-unit">秒</i></span>
                </label>
                <span class="acx-sep"></span>
                ${acxNumFixed("单源条数", "条", ACX_NEWS_PER_SOURCE_FIXED, "固定 30 条，不可更改：各快讯源单次最多抓取 30 条；30 条的回溯窗口已覆盖约 60 秒采集间隔")}
            </div>

            <div class="acx-block"${acxTip(map.news_keywords)}>
                <label>关键词</label>
                <textarea class="acx-ta" data-opt="news_keywords" rows="2" placeholder="如：人工智能, AI, 算力, GPU, 半导体, 数据中心, 碳酸锂, 稀土" ${dis}>${esc(acxVal(map, "news_keywords"))}</textarea>
                <div class="acx-tags" id="acx-kw-tags"></div>
            </div>

            <div class="acx-block"${acxTip(map.news_channels)}>
                <label>频道</label>
                <div class="acx-chips">${chChoices.map(c => `<label class="ac-chip${chPicked.has(c.value) ? " on" : ""}">
                    <input type="checkbox" class="acx-ch" data-opt="news_channels" value="${esc(c.value)}" ${chPicked.has(c.value) ? "checked" : ""} ${dis}><span>${esc(c.label)}</span></label>`).join("")}</div>
            </div>

            <details class="acx-more" open>
                <summary>高级设置</summary>
                <div class="acx-grid">
                    ${acxNum(map, "news_max_keywords", "词数", "个", 1, 24, dis)}
                    ${acxNum(map, "news_min_title_len", "标题", "字", 0, 40, dis)}
                    ${acxNum(map, "news_timeout_sec", "超时", "秒", 3, 30, dis)}
                    ${acxNum(map, "news_fail_limit", "失败", "次", 1, 50, dis)}
                    ${acxNum(map, "news_live_sec", "刷新", "秒", 5, 300, dis)}
                    ${acxNum(map, "news_crawl_sec", "抓取", "秒", 10, 3600, dis)}
                </div>
                ${acxBool(map, "news_relevance_only", "仅相关", dis)}
                ${acxText(map, "news_blacklist", "屏蔽词", dis, 2)}
                <div class="acx-grid">
                    ${acxBool(map, "news_auto_star_metal", "收藏", dis)}
                </div>
                <div class="acx-grid">
                    ${acxBool(map, "news_key_notify_enabled", "重点推送", dis, "开启后：库内全部重点消息都会写入通知中心并点亮（未读），已读过的不会重复点亮；同时把本次新采集的重点消息推送到已配置的外部通道")}
                    ${acxNum(map, "news_key_notify_max", "外部推送上限", "条", 1, 20, dis, "每次采集完成后，最多把多少条「新采集的重点消息」推送到外部通道；写入通知中心不受此限制")}
                </div>
            </details>
        </div>
    </section>

    ${acxSourcesHtml(domain, dis, canRun)}
    ${acxLogsHtml("news")}
    </div>`;
}

// —— 贵金属数据域 ——
function acxMetalHtml(domain, canConfig, canRun) {
    const dis = canConfig ? "" : "disabled";
    const map = acxOptMap(domain);
    const tasks = domain.tasks || [];
    const snap = tasks.find(t => t.task_key === "metal_snapshot") || { interval_sec: 1800 };
    const quote = tasks.find(t => t.task_key === "metal_quote") || { interval_sec: 600 };
    const bank = tasks.find(t => t.task_key === "bank_gold_quote") || { interval_sec: 600 };
    const snapEn = !!snap.enabled, quoteEn = !!quote.enabled, bankEn = !!bank.enabled;
    const snapSec = acxTaskSec(snap);
    const quoteSec = acxTaskSec(quote);
    const bankSec = acxTaskSec(bank);
    const anyEn = snapEn || quoteEn || bankEn;
    return `
    <div id="acx-sec-metal">
    <section class="panel">
        <div class="panel-head">
            <h3><span class="acx-dot${anyEn ? "" : " off"}"></span> 贵金属采集${anyEn ? "运行中" : "已关闭"}</h3>
            <div class="acx-head-actions">
                ${canRun ? `<button class="btn btn-ghost btn-sm" id="acx-run-metal"><i class="fa-solid fa-bolt"></i> 立即采集</button>` : ""}
                ${canConfig ? `<button class="btn btn-ghost btn-sm" id="acx-save-metal" disabled><i class="fa-solid fa-floppy-disk"></i> 保存</button>` : ""}
            </div>
        </div>
        <div class="panel-body">
            <div class="acx-bar">
                <label class="acx-cell acx-cell-sw" title="按间隔抓取金价快照入库，驱动走势图与异动判定">
                    <span class="switch"><input type="checkbox" id="acx-snap-en" ${snapEn ? "checked" : ""} ${dis}><span></span></span>
                    <span class="acx-cell-lb">金价快照</span>
                </label>
                <label class="acx-cell" title="快照采集间隔。小于 60 秒时由页面访问触发补采；定时唤醒每分钟一次">
                    <span class="acx-cell-lb">快照间隔</span>
                    <span class="acx-in"><input type="number" id="acx-snap-interval" value="${snapSec}" min="5" max="86400" step="5" ${dis}><i class="acx-unit">秒</i></span>
                </label>
                <span class="acx-sep"></span>
                <label class="acx-cell acx-cell-sw" title="实时行情页读库展示，不再每次请求行情接口">
                    <span class="switch"><input type="checkbox" id="acx-quote-en" ${quoteEn ? "checked" : ""} ${dis}><span></span></span>
                    <span class="acx-cell-lb">实时行情</span>
                </label>
                <label class="acx-cell" title="行情刷新间隔。小于 60 秒时由页面轮询触发补采；定时唤醒每分钟一次">
                    <span class="acx-cell-lb">行情间隔</span>
                    <span class="acx-in"><input type="number" id="acx-quote-interval" value="${quoteSec}" min="5" max="86400" step="5" ${dis}><i class="acx-unit">秒</i></span>
                </label>
                <span class="acx-sep"></span>
                <label class="acx-cell acx-cell-sw" title="定时抓取交通银行官网贵金属行情并写入 bank_gold_quotes">
                    <span class="switch"><input type="checkbox" id="acx-bank-en" ${bankEn ? "checked" : ""} ${dis}><span></span></span>
                    <span class="acx-cell-lb">银行金价</span>
                </label>
                <label class="acx-cell" title="银行官网金价采集间隔（秒）">
                    <span class="acx-cell-lb">银行间隔</span>
                    <span class="acx-in"><input type="number" id="acx-bank-interval" value="${bankSec}" min="5" max="86400" step="5" ${dis}><i class="acx-unit">秒</i></span>
                </label>
            </div>

            <div class="acx-block"${acxTip(map.metal_symbols)}>
                <label>品种</label>
                <textarea class="acx-ta" data-opt="metal_symbols" rows="1" placeholder="如：AU0, AG0" ${dis}>${esc(acxVal(map, "metal_symbols"))}</textarea>
                <div class="acx-tags" id="acx-sym-tags"></div>
            </div>

            <details class="acx-more" open>
                <summary>高级设置</summary>
                <div class="acx-grid">
                    ${acxNum(map, "metal_snapshot_surge", "波动", "%", 0.05, 3, dis)}
                    ${acxNum(map, "metal_snapshot_alert", "异动", "%", 0.1, 5, dis)}
                    ${acxNum(map, "rare_risk_budget", "预算", "%", 0.5, 10, dis)}
                    ${acxNum(map, "metal_fail_limit", "失败", "次", 1, 50, dis)}
                    ${acxNum(map, "metal_live_sec", "刷新", "秒", 5, 120, dis)}
                </div>
                <div class="acx-grid" style="margin-top:10px">
                    ${acxText(map, "metal_kinds", "类别", dis, 1)}
                    ${acxText(map, "metal_markets", "市场", dis, 1)}
                    ${acxSelect(map, "metal_snapshot_base", "基准", dis)}
                </div>
            </details>
        </div>
    </section>

    ${acxSourcesHtml(domain, dis, canRun)}
    ${acxLogsHtml("metal")}
    </div>`;
}

// 采集页（数据采集）状态：当前激活标签 + 未保存改动的选项集合（标识形如 "metal:metal_symbols"）
const acxState = { tab: "news", dirty: new Set() };
// 采集日志每页条数：按数据域记住（news / metal 各自独立），与资讯中心共用同一组分页档位
const acxLogSize = { news: 10, metal: 10 };
// 采集日志请求序号：防止「换条数」与「翻页」并发时旧响应覆盖新结果
const acxLogTick = { news: 0, metal: 0 };

async function viewAcquirePage(container) {
    const canRun = state.user.role === "admin" || state.user.permissions.includes("market.refresh");
    const canConfig = state.user.role === "admin" || state.user.permissions.includes("market.config");
    const seq = routerSeq;
    acxState.dirty.clear();
    // 域切换标签：两个域的 DOM 都保留，只切换显示，未保存的改动不会丢
    acxState.tab = acxState.tab || "news";
    container.innerHTML = `
    <div class="acx-tabs">
        <button type="button" class="acx-tab" data-acx-tab="news"><i class="fa-solid fa-newspaper"></i> 消息数据</button>
        <button type="button" class="acx-tab" data-acx-tab="metal"><i class="fa-solid fa-coins"></i> 贵金属数据</button>
    </div>
    <div id="acx-body">${LOADING_HTML}</div>`;

    const showTab = key => {
        acxState.tab = key;
        container.querySelectorAll(".acx-tab").forEach(b => b.classList.toggle("on", b.dataset.acxTab === key));
        const news = container.querySelector("#acx-sec-news");
        const metal = container.querySelector("#acx-sec-metal");
        if (news) news.style.display = key === "news" ? "" : "none";
        if (metal) metal.style.display = key === "metal" ? "" : "none";
    };
    container.querySelectorAll(".acx-tab").forEach(b => b.addEventListener("click", () => showTab(b.dataset.acxTab)));

    const load = async () => {
        const { ok, data } = await api("/acquire/config");
        if (seq !== routerSeq) return;
        const box = container.querySelector("#acx-body");
        if (!box) return;
        if (!ok) { box.innerHTML = errorHtml(data.message || "采集配置加载失败"); return; }
        const domains = data.domains || [];
        const news = domains.find(d => d.key === "news");
        const metal = domains.find(d => d.key === "metal");
        if (!news && !metal) { box.innerHTML = errorHtml("未找到采集配置"); return; }
        // 只保留存在的域对应的标签
        container.querySelectorAll(".acx-tab").forEach(b => {
            b.style.display = (b.dataset.acxTab === "news" && !news) || (b.dataset.acxTab === "metal" && !metal) ? "none" : "";
        });
        if ((acxState.tab === "metal" && !metal) || (acxState.tab === "news" && !news)) acxState.tab = news ? "news" : "metal";
        acxState.dirty.clear();
        box.innerHTML = acxRetentionHtml(news, metal, canConfig, canRun)
            + (news ? acxNewsHtml(news, canConfig, canRun) : "")
            + (metal ? acxMetalHtml(metal, canConfig, canRun) : "");
        if (canConfig) bindRetention(box, { seq, load });
        if (news) bindAcxSec(box, news, "news", { seq, load, canConfig, canRun });
        if (metal) bindAcxSec(box, metal, "metal", { seq, load, canConfig, canRun });
        syncAcxSave(box);
        showTab(acxState.tab);
        if (news) {
            const kw = box.querySelector('#acx-sec-news [data-opt="news_keywords"]');
            if (kw) renderAcxTags(box.querySelector("#acx-sec-news"), kw, "acx-kw-tags", "还没有关键词，采集会退化为拉取各源最新快讯");
        }
        if (metal) {
            const syms = box.querySelector('#acx-sec-metal [data-opt="metal_symbols"]');
            if (syms) renderAcxTags(box.querySelector("#acx-sec-metal"), syms, "acx-sym-tags", "留空表示采集全部品种");
        }
        if (news) loadAcxLogs(box, "news", seq);
        if (metal) loadAcxLogs(box, "metal", seq);
    };
    load();
}

// 文本框内容实时预览成小标签
function renderAcxTags(sec, ta, wrapId, emptyHint) {
    const wrap = sec.querySelector("#" + wrapId);
    if (!wrap || !ta) return;
    const list = ta.value.split(/[,，\n]/).map(s => s.trim()).filter(Boolean);
    wrap.innerHTML = list.length
        ? list.map(t => `<span class="acx-tag">${esc(t)}</span>`).join("")
        : `<span class="acx-empty-note">${esc(emptyHint)}</span>`;
}

function syncAcxSave(box) {
    ["news", "metal"].forEach(dk => {
        const btn = box.querySelector("#acx-save-" + dk);
        if (!btn) return;
        const n = [...acxState.dirty].filter(k => k.startsWith(dk + ":")).length;
        btn.disabled = n === 0;
        btn.className = "btn " + (n ? "btn-primary" : "btn-ghost");
        btn.innerHTML = n ? `<i class="fa-solid fa-floppy-disk"></i> 保存 · ${n} 项改动` : `<i class="fa-solid fa-floppy-disk"></i> 保存`;
    });
}

function readAcxOptions(sec, domain) {
    const out = {};
    (domain.options || []).forEach(o => {
        const els = [...sec.querySelectorAll(`[data-opt="${o.key}"]`)];
        // 页面上没有渲染该参数的控件时**不要提交**：否则会被当成「未勾选」写成 0 / 空串，
        //   把库里的值静默覆盖掉（历史上 news_key_notify_enabled 就是这样被关掉的）。
        if (!els.length) return;
        if (o.type === "bool") {
            out[o.key] = els[0] && els[0].checked ? "1" : "0";
        } else if (o.type === "list") {
            const boxes = els.filter(i => i.type === "checkbox");
            out[o.key] = boxes.length
                ? boxes.filter(i => i.checked).map(i => i.value).join(",")
                : (els[0] ? els[0].value : String(o.value || ""));
        } else {
            out[o.key] = els[0] ? els[0].value : String(o.value || "");
        }
    });
    return out;
}

function acxTaskBody(sec, key, enSel, ivSel) {
    const en = sec.querySelector(enSel);
    const iv = sec.querySelector(ivSel);
    return {
        task_key: key,
        enabled: !!(en && en.checked),
        // 间隔按秒提交（后端 interval_sec 为准，最小 5 秒、最大 1 天）
        interval_sec: Math.min(86400, Math.max(5, parseInt((iv && iv.value) || "600", 10) || 600))
        // 不提交 run_at_hour：当前页面没有固定时刻控件，后端会保留已有的每日定点配置。
    };
}

// 两个域共用的事件绑定：脏标记 / 预设 / 保存 / 立即采集 / 数据源测试 / 日志刷新
function bindAcxSec(box, domain, dk, ctx) {
    const sec = box.querySelector("#acx-sec-" + dk);
    if (!sec) return;
    const { seq, load, canConfig, canRun } = ctx;
    const mark = el => {
        acxState.dirty.add(dk + ":" + (el.dataset.opt || el.id || el.value));
        syncAcxSave(box);
    };

    sec.querySelectorAll("[data-opt]").forEach(el => {
        el.addEventListener("change", () => {
            mark(el);
            if (el.classList.contains("acx-ch")) el.closest(".ac-chip")?.classList.toggle("on", el.checked);
        });
    });
    // 文本域边输入边预览标签
    if (dk === "news") {
        const kw = sec.querySelector('[data-opt="news_keywords"]');
        if (kw) kw.addEventListener("input", () => renderAcxTags(sec, kw, "acx-kw-tags", "还没有关键词，采集会退化为拉取各源最新快讯"));
    } else {
        const syms = sec.querySelector('[data-opt="metal_symbols"]');
        if (syms) syms.addEventListener("input", () => renderAcxTags(sec, syms, "acx-sym-tags", "留空表示采集全部品种"));
    }

    ["#acx-enabled", "#acx-snap-en", "#acx-quote-en", "#acx-bank-en"].forEach(sel => {
        const el = sec.querySelector(sel);
        if (el) el.addEventListener("change", () => mark(el));
    });
    ["#acx-interval", "#acx-snap-interval", "#acx-quote-interval", "#acx-bank-interval"].forEach(sel => {
        const el = sec.querySelector(sel);
        if (!el) return;
        // input 事件让用户边打字边亮起保存按钮
        el.addEventListener("input", () => mark(el));
        el.addEventListener("change", () => mark(el));
    });
    sec.querySelectorAll(".acx-src-en").forEach(el => el.addEventListener("change", () => mark(el)));

    // 立即采集 / 数据源测试 / 日志刷新：需要 market.refresh 权限
    if (canRun) {
        const runBtn = sec.querySelector("#acx-run-" + dk);
        if (runBtn) runBtn.addEventListener("click", async () => {
            if (acxState.dirty.size) { toast("配置有未保存的改动，请先保存再采集", "info"); return; }
            runBtn.disabled = true;
            const old = runBtn.innerHTML;
            runBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> 采集中…`;
            // 银行金价任务排在最后：即使 4 个官网源全部临时不可用，也不影响前两个贵金属任务已执行
            const keys = dk === "news" ? ["news_crawl"] : ["metal_snapshot", "metal_quote", "bank_gold_quote"];
            let okAll = true, msg = "";
            for (const k of keys) {
                const { ok, data } = await api("/acquire/run", "POST", { task_key: k });
                if (!ok) { okAll = false; msg = data.message || "未知错误"; break; }
                msg = data.message || msg;
            }
            runBtn.disabled = false;
            runBtn.innerHTML = old;
            if (okAll) toast("采集完成：" + msg, "success");
            else toast("采集失败：" + msg, "error");
            if (seq === routerSeq) load();
        });

        sec.querySelectorAll("[data-acx-test]").forEach(b => b.addEventListener("click", async () => {
            b.disabled = true;
            const old = b.innerHTML;
            b.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i>`;
            const { ok, data } = await api("/acquire/test", "POST", { source_key: b.dataset.acxTest });
            b.disabled = false;
            b.innerHTML = old;
            if (ok) toast(`连接正常（${data.latency_ms || 0}ms）`, "success");
            else toast("连接失败：" + (data.message || "未知错误"), "error");
        }));

    const logReload = sec.querySelector("#acx-log-reload-" + dk);
    if (logReload) logReload.addEventListener("click", e => {
        // 按钮在 details 的 summary 里，阻止冒泡避免触发折叠切换
        e.preventDefault();
        e.stopPropagation();
        loadAcxLogs(box, dk, seq);
    });
    }

    // 保存：需要 market.config 权限
    if (!canConfig) return;
    const save = async () => {
        const body = {
            sources: [...sec.querySelectorAll(".acx-src-en")].map(i => ({ source_key: i.value, enabled: i.checked })),
            tasks: dk === "news"
                ? [acxTaskBody(sec, "news_crawl", "#acx-enabled", "#acx-interval")]
                : [acxTaskBody(sec, "metal_snapshot", "#acx-snap-en", "#acx-snap-interval"),
                   acxTaskBody(sec, "metal_quote", "#acx-quote-en", "#acx-quote-interval"),
                   acxTaskBody(sec, "bank_gold_quote", "#acx-bank-en", "#acx-bank-interval")],
            options: { [dk]: readAcxOptions(sec, domain) }
        };
        const btn = sec.querySelector("#acx-save-" + dk);
        if (btn) { btn.disabled = true; btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> 保存中…`; }
        const { ok, data } = await api("/acquire/config", "POST", body);
        if (ok) {
            [...acxState.dirty].filter(k => k.startsWith(dk + ":")).forEach(k => acxState.dirty.delete(k));
            toast(`${dk === "news" ? "消息" : "贵金属"}采集配置已保存`, "success");
            if (seq === routerSeq) await load();
        } else {
            toast(data.message || "保存失败", "error");
            syncAcxSave(box);
        }
    };
    const saveBtn = sec.querySelector("#acx-save-" + dk);
    if (saveBtn) saveBtn.addEventListener("click", save);

}

async function loadAcxLogs(box, dk, seq, page) {
    const body = box.querySelector("#acx-log-body-" + dk);
    if (!body) return;
    const pg = Math.max(1, parseInt(page, 10) || 1);
    const size = acxLogSize[dk] || PAGER_SIZES[0];
    // 请求序号：换条数与翻页可能连续触发，只认最后一次的结果
    const tick = (acxLogTick[dk] = (acxLogTick[dk] || 0) + 1);
    body.innerHTML = `<tr><td colspan="7" class="empty">加载中…</td></tr>`;
    const qs = new URLSearchParams({ domain: dk, page: String(pg), page_size: String(size) });
    const { ok, data } = await api("/acquire/logs?" + qs.toString());
    if (seq !== routerSeq || tick !== acxLogTick[dk]) return;
    if (!ok) { body.innerHTML = `<tr><td colspan="7" class="empty">日志加载失败</td></tr>`; return; }
    const rows = data.rows || [];
    body.innerHTML = rows.length ? rows.map(l => {
        const st = acxStatusLabel(l.status);
        return `<tr>
            <td class="text-muted" style="font-variant-numeric:tabular-nums">${esc(fmtNewsTime(l.started_at))}</td>
            <td><span class="acx-res ${st.cls}"><i class="fa-solid ${st.icon}"></i>${st.text}</span></td>
            <td class="text-muted">${l.trigger_type === "manual" ? "手动" : "定时"}</td>
            <td class="text-right">${l.fetched || 0}</td>
            <td class="text-right" style="font-weight:600">${l.inserted || 0}</td>
            <td class="text-right text-muted">${fmtDur(l.duration_ms)}</td>
            <td class="text-muted" style="white-space:normal;max-width:420px">${esc(l.message || "")}</td>
        </tr>`;
    }).join("") : `<tr><td colspan="7" class="empty">还没有采集记录，点「立即采集」试一次</td></tr>`;
    const total = Number(data.total) || 0;
    const pages = Math.max(1, Number(data.total_pages) || 1);
    const curPage = Math.min(pages, Math.max(1, Number(data.page) || pg));
    const pager = box.querySelector("#acx-pager-" + dk);
    if (!pager) return;
    // 只有一页时也保留分页条：否则用户没法把「每页」调大去看更多历史记录
    const ctx = { cur: curPage, pages, size };
    pager.innerHTML = pagerHtml({ cur: curPage, pages, total, size });
    bindPager(pager, ctx,
        n => loadAcxLogs(box, dk, seq, n),
        sz => { acxLogSize[dk] = sz; loadAcxLogs(box, dk, seq, 1); });
}

function fmtDur(ms) {
    const n = Number(ms) || 0;
    if (n <= 0) return "—";
    if (n < 1000) return n + " ms";
    return (n / 1000).toFixed(n < 10000 ? 1 : 0) + " s";
}

function fmtCountdown(sec, overdue) {
    const n = Number(sec);
    if (overdue) return "已到期";
    if (!Number.isFinite(n) || n < 0) return "—";
    if (n < 60) return n + " 秒后";
    const m = Math.floor(n / 60);
    if (m < 60) return m + " 分钟后";
    const h = Math.floor(m / 60);
    if (h < 24) return h + " 小时 " + (m % 60) + " 分后";
    return Math.floor(h / 24) + " 天 " + (h % 24) + " 小时后";
}

function parseMetaJson(str, fallback) {
    try { const o = JSON.parse(str || ""); return o && typeof o === "object" ? o : fallback; } catch { return fallback; }
}

// ============================================================
// 消息中心
// ============================================================
const newsPage = { offset: 0, limit: 10, keyword: "", channel: "", source: "", symbol: "", days: 0, sort: "time", sentiment: "", impact: "", keyOnly: false, starredOnly: false, focusId: 0, showAll: false };
const NEWS_CH_LABELS = { equity: "股市", fund: "基金", bond: "债券", metal: "贵金属", macro: "宏观", forex: "外汇", property: "房地产", policy: "政策", ai: "AI算力", other: "综合" };
// 来源标签：后端 /api/news/meta 下发为准，本地值仅作接口异常时的兜底
const NEWS_SOURCE_LABELS_FALLBACK = { eastmoney: "东方财富", sina: "新浪财经 7×24", wscn: "华尔街见闻", manual: "手动录入" };
let NEWS_SOURCE_LABELS = { ...NEWS_SOURCE_LABELS_FALLBACK };
const NEWS_RANGE_OPTIONS = [{ v: 0, l: "全部时间" }, { v: 1, l: "今日" }, { v: 3, l: "近 3 天" }, { v: 7, l: "近 7 天" }, { v: 30, l: "近 30 天" }];
const NEWS_SORT_OPTIONS = [{ v: "time", l: "最新优先" }, { v: "oldest", l: "最早优先" }, { v: "relevance", l: "命中度优先" }, { v: "key", l: "重点优先" }];
// 情绪筛选：按标的判定后的利多 / 利空 / 中性
const NEWS_SENT_OPTIONS = [{ v: "", l: "全部消息" }, { v: "bullish", l: "只看利多" }, { v: "bearish", l: "只看利空" }, { v: "neutral", l: "只看中性" }];
// 研判方向筛选：默认全部；「有研判结论」一键筛出规则识别到影响对象的消息
const NEWS_IMPACT_OPTIONS = [{ v: "", l: "全部消息" }, { v: "researched", l: "有研判结论" }, { v: "bullish", l: "研判偏涨" }, { v: "bearish", l: "研判偏跌" }];

function fmtNewsTime(s) {
    const t = String(s || "").replace("T", " ").trim();
    return t.length >= 16 ? t.slice(5, 16) : (t || "—");
}

// 把命中关键词高亮（先切片再转义，避免破坏 HTML）
function highlightText(text, kw) {
    const raw = String(text == null ? "" : text);
    if (!kw) return esc(raw);
    const k = String(kw);
    const low = raw.toLowerCase(), lk = k.toLowerCase();
    let out = "", pos = 0, i;
    while ((i = low.indexOf(lk, pos)) >= 0) {
        out += esc(raw.slice(pos, i)) + `<mark class="nw-mark">${esc(raw.slice(i, i + k.length))}</mark>`;
        pos = i + k.length;
    }
    return out + esc(raw.slice(pos));
}

// 近 14 天消息量趋势（柱状图）
function newsTrendSvg(items) {
    if (!items || !items.length) return `<div class="empty">暂无趋势数据</div>`;
    const holder = chartSlot("vbar", { items }, 172);
    if (holder) return holder;
    const W = 660, H = 158, padL = 34, padR = 10, padT = 12, padB = 26;
    const plotW = W - padL - padR, plotH = H - padT - padB;
    const max = Math.max(1, ...items.map(i => i.count || 0));
    const slot = plotW / items.length;
    const bw = Math.max(4, Math.min(26, slot * 0.6));
    const yOf = v => padT + plotH - (v / max) * plotH;
    const bars = items.map((it, i) => {
        const x = padL + i * slot + (slot - bw) / 2;
        const v = it.count || 0;
        const h = Math.max(v > 0 ? 2 : 0, (v / max) * plotH);
        const y = padT + plotH - h;
        const d = String(it.date || "");
        const color = v > 0 ? "var(--primary)" : "var(--border)";
        return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="2" fill="${color}" opacity="${v > 0 ? .85 : 1}"><title>${esc(d)} · ${v} 条</title></rect>`
            + (i % 3 === 0 || i === items.length - 1 ? `<text x="${(x + bw / 2).toFixed(1)}" y="${H - 8}" text-anchor="middle" font-size="10" fill="var(--text-soft)">${esc(d.slice(5))}</text>` : "");
    }).join("");
    const grid = [0, 0.5, 1].map(t => {
        const y = padT + plotH * t, val = Math.round(max * (1 - t));
        return `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${y.toFixed(1)}" stroke="var(--border)" stroke-width="1" stroke-dasharray="3 3"/>`
            + `<text x="${padL - 6}" y="${(y + 4).toFixed(1)}" text-anchor="end" font-size="10" fill="var(--text-soft)">${val}</text>`;
    }).join("");
    return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto">${grid}${bars}</svg>`;
}

// 按日期分组
function newsGroupByDate(rows) {
    const groups = [];
    const today = new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
    const yest = new Date(Date.now() + 8 * 3600 * 1000 - 86400000).toISOString().slice(0, 10);
    rows.forEach(r => {
        const d = String(r.published_at || "").slice(0, 10) || "未知日期";
        let g = groups.find(x => x.date === d);
        if (!g) { g = { date: d, label: d === today ? "今天" : d === yest ? "昨天" : d, items: [] }; groups.push(g); }
        g.items.push(r);
    });
    return groups;
}

async function viewNews(container) {
    const mySeq = routerSeq;
    // 从工作台带过来的标的筛选（#news?symbol=AU0）：进入即只显示该标的相关消息
    const qSymbol = (routerQuery.get("symbol") || "").toUpperCase();
    if (qSymbol !== newsPage.symbol) { newsPage.symbol = qSymbol; newsPage.offset = 0; }
    // 从通知中心跳转过来定位某条消息（#news?focus=123）
    const qFocus = parseInt(routerQuery.get("focus"), 10) || 0;
    if (qFocus && qFocus !== newsPage.focusId) { newsPage.focusId = qFocus; newsPage.offset = 0; }
    // 深链过滤器按「本次路由显式声明」重算：从 #news?key=1 返回普通 #news 时不能残留旧筛选。
    const qKey = routerQuery.get("key") === "1";
    const qStarred = routerQuery.get("starred") === "1";
    // 定位某条消息时强制退出「只看重点」，否则目标消息可能被筛掉而看不到
    const nextKeyOnly = qFocus ? false : qKey;
    if (nextKeyOnly !== newsPage.keyOnly) { newsPage.keyOnly = nextKeyOnly; newsPage.offset = 0; }
    if (qStarred !== newsPage.starredOnly) { newsPage.starredOnly = qStarred; newsPage.offset = 0; }
    if (!state.newsMeta) { const m = await api("/news/meta"); if (m.ok) state.newsMeta = m.data; }
    if (mySeq !== routerSeq) return;
    const meta = state.newsMeta || { channels: [], sources: [], keywords: [] };
    // 代码 → 中文名（消息卡片上的标的标签与筛选条都用它）
    if (Array.isArray(meta.symbols)) {
        state.newsSymbols = {};
        meta.symbols.forEach(x => { state.newsSymbols[x.symbol] = x.name || x.symbol; });
    }
    // 来源标签由后端统一下发
    if (Array.isArray(meta.sources) && meta.sources.length) {
        const map = { ...NEWS_SOURCE_LABELS_FALLBACK };
        meta.sources.forEach(x => { if (x && x.key) map[x.key] = x.label || x.key; });
        NEWS_SOURCE_LABELS = map;
    }
    const canManage = state.user.role === "admin" || state.user.permissions.includes("news.manage");

    container.innerHTML = `
        <div class="news-filters">
            <div class="nf-row">
                <div class="nf-search">
                    <i class="fa-solid fa-magnifying-glass"></i>
                    <input id="n-keyword" placeholder="搜索标题 / 摘要 / 关键词，如：美联储、金价、碳酸锂" value="${esc(newsPage.keyword)}">
                </div>
                <button class="btn btn-primary" id="n-search"><i class="fa-solid fa-magnifying-glass"></i> 查询</button>
                <button class="btn btn-ghost" id="n-more" title="来源 / 时间范围 / 排序 / 利多利空 / 每页"><i class="fa-solid fa-sliders"></i> 更多筛选<span class="nf-count" id="n-more-count"></span></button>
                <button class="btn btn-ghost" id="n-readall" title="把通知中心里全部重点消息标记为已读（清掉点亮状态）"><i class="fa-solid fa-check-double"></i> 一键已读</button>
            </div>
            <div class="nf-chips" id="n-chips">
                ${[{ key: "", label: "全部频道" }].concat(meta.channels || []).map(c => `<button class="chip ${newsPage.channel === c.key ? "on" : ""}" data-ch="${esc(c.key)}">${esc(c.label)}</button>`).join("")}
            </div>
            <div class="adv-filters" id="n-adv">
                <input type="hidden" id="n-channel" value="${esc(newsPage.channel)}">
                <div class="field"><label>来源</label><select id="n-source"><option value="">全部来源</option>${meta.sources.map(s => `<option value="${s.key}" ${newsPage.source === s.key ? "selected" : ""}>${esc(s.label)}</option>`).join("")}</select></div>
                <div class="field"><label>时间范围</label><select id="n-days">${NEWS_RANGE_OPTIONS.map(o => `<option value="${o.v}" ${String(newsPage.days) === String(o.v) ? "selected" : ""}>${esc(o.l)}</option>`).join("")}</select></div>
                <div class="field"><label>排序</label><select id="n-sort">${NEWS_SORT_OPTIONS.map(o => `<option value="${o.v}" ${newsPage.sort === o.v ? "selected" : ""}>${esc(o.l)}</option>`).join("")}</select></div>
                <div class="field"><label>利多利空</label><select id="n-sent">${NEWS_SENT_OPTIONS.map(o => `<option value="${o.v}" ${newsPage.sentiment === o.v ? "selected" : ""}>${esc(o.l)}</option>`).join("")}</select></div>
                <div class="field"><label>研判方向</label><select id="n-impact">${NEWS_IMPACT_OPTIONS.map(o => `<option value="${o.v}" ${newsPage.impact === o.v ? "selected" : ""}>${esc(o.l)}</option>`).join("")}</select></div>
                <div class="field field-check"><label>范围</label>
                    <label class="nf-check"><input type="checkbox" id="n-key-only" ${newsPage.keyOnly ? "checked" : ""}><span>只看重点消息</span></label>
                    <label class="nf-check"><input type="checkbox" id="n-starred-only" ${newsPage.starredOnly ? "checked" : ""}><span>只看收藏</span></label>
                    <label class="nf-check"><input type="checkbox" id="n-show-all" ${newsPage.showAll ? "checked" : ""}><span>含不相关资讯</span></label>
                </div>
            </div>
        </div>
        ${newsPage.symbol ? `<div class="news-symbar"><span class="muted">关联标的</span>
            <button class="desk-chip active" id="n-sym-clear">${esc((state.newsSymbols || {})[newsPage.symbol] || newsPage.symbol)} ✕</button>
            <a class="btn btn-sm btn-ghost" href="#desk">回到工作台</a></div>` : ""}
        <div class="news-layout">
            <div id="n-list">${LOADING_HTML}</div>
        </div>`;

    // 筛选区交互：频道胶囊 / 「更多筛选」展开 / 已启用条件计数
    const syncChips = () => {
        container.querySelectorAll("#n-chips .chip").forEach(b => {
            b.classList.toggle("on", (b.dataset.ch || "") === (newsPage.channel || ""));
        });
        const n = [newsPage.source, newsPage.sentiment, newsPage.impact, newsPage.keyOnly, newsPage.starredOnly, newsPage.sort && newsPage.sort !== "time", String(newsPage.days || "0") !== "0"].filter(Boolean).length;
        const cnt = container.querySelector("#n-more-count");
        if (cnt) cnt.textContent = n ? String(n) : "";
    };
    container.querySelectorAll("#n-chips .chip").forEach(b => b.addEventListener("click", () => {
        newsPage.channel = b.dataset.ch || "";
        newsPage.offset = 0;
        const hc = container.querySelector("#n-channel");
        if (hc) hc.value = newsPage.channel;
        syncChips();
        load();
    }));
    container.querySelector("#n-more").addEventListener("click", () => {
        container.querySelector("#n-adv").classList.toggle("open");
    });
    // 一键已读：把通知中心里全部重点消息的未读点灭（普通消息不产生通知，不受影响）
    const readAllBtn = container.querySelector("#n-readall");
    if (readAllBtn) readAllBtn.addEventListener("click", async () => {
        readAllBtn.disabled = true;
        const { ok, data } = await api("/notifications", "POST", { action: "read_all", kind: "news_key" });
        readAllBtn.disabled = false;
        if (!ok) { toast(data.message || "操作失败", "error"); return; }
        toast(data.updated ? `已标记 ${data.updated} 条重点消息为已读` : "没有未读的重点消息", data.updated ? "success" : "info");
        await refreshBell();
    });
    // 已有高级条件时默认展开，避免「藏起来的筛选」让结果看起来莫名其妙
    if ([newsPage.source, newsPage.sentiment, newsPage.impact, newsPage.keyOnly, String(newsPage.days || "0") !== "0", newsPage.sort && newsPage.sort !== "time"].some(Boolean)) {
        container.querySelector("#n-adv").classList.add("open");
    }

    const buildQuery = (offset, limit) => new URLSearchParams({
        offset, limit, keyword: newsPage.keyword,
        channel: newsPage.channel, source: newsPage.source,
        symbol: newsPage.symbol || "",
        sentiment: newsPage.sentiment || "",
        impact: newsPage.impact || "",
        key: newsPage.keyOnly ? "1" : "",
        starred: newsPage.starredOnly ? "1" : "",
        days: newsPage.days || "", sort: newsPage.sort,
        // 默认只看「相关资讯」（中国政策 / 贵金属 / 金价驱动），勾上则连被过滤的历史存量一起看
        exclude: newsPage.showAll ? "0" : "1"
    }).toString();

    // 自动刷新的对比基线：总数 / 最新一条时间都不变就不重绘，避免打断阅读
    let liveSec = 10;
    let liveSig = "";
    // 请求序号：跳转输入失焦与点页码可能同时触发两次加载，只认最后一次的结果
    let loadTick = 0;
    const load = async (silent) => {
        // 视图可能已切换：DOM 已被替换，直接丢弃本次加载
        if (mySeq !== routerSeq || !$("#n-keyword")) return;
        const myTick = ++loadTick;
        newsPage.keyword = $("#n-keyword").value.trim();
        newsPage.channel = $("#n-channel").value;
        newsPage.source = $("#n-source").value;
        newsPage.days = parseInt($("#n-days").value, 10) || 0;
        newsPage.sort = $("#n-sort").value;
        newsPage.sentiment = $("#n-sent").value;
        const impactEl = $("#n-impact");
        newsPage.impact = impactEl ? impactEl.value : "";
        const keyOnlyEl = $("#n-key-only");
        newsPage.keyOnly = !!(keyOnlyEl && keyOnlyEl.checked);
        const starredOnlyEl = $("#n-starred-only");
        newsPage.starredOnly = !!(starredOnlyEl && starredOnlyEl.checked);
        const showAllEl = $("#n-show-all");
        newsPage.showAll = !!(showAllEl && showAllEl.checked);
        // 每页条数由底部翻页区的下拉直接改 newsPage.limit（见 bindPager 回调），这里不再读 DOM
        const { ok, data } = await api("/news?" + buildQuery(newsPage.offset, newsPage.limit));
        if (mySeq !== routerSeq || myTick !== loadTick) return;
        if (!ok) { $("#n-list").innerHTML = `<div class="empty">加载失败</div>`; return; }
        const rows = data.rows || [];
        const s = data.stats || {};
        liveSec = Number(data.live_sec) || liveSec;
        const sig = String(data.total || 0) + "|" + String(s.latest || "") + "|" + rows.length;
        // 静默轮询：数据没变就跳过整块重绘（统计卡 / 侧栏 / 列表都不动）
        if (silent && sig === liveSig) return;
        liveSig = sig;

        // —— 统计 / 列表 ——
        //   侧栏已按用户要求整体移除（近 14 天消息量搬去了「投资总览」，其余分布卡片此前已删）。
        //   接口仍返回 by_channel / by_source / hot_keywords / trend，需要时可按旧模板恢复。
        syncChips();

        // —— 列表 ——
        if (!rows.length) {
            $("#n-list").innerHTML = `<div class="empty">暂无消息，可到「数据采集」页点「立即采集」</div>`;
            return;
        }
        const groups = newsGroupByDate(rows);
        const kw = newsPage.keyword;
        const html = groups.map(g => `<div class="news-day">
            <div class="news-day-head"><i class="fa-regular fa-calendar"></i> ${esc(g.label)}<span class="text-muted">${g.items.length} 条</span></div>
            <div class="news-list">${g.items.map(n => {
                const label = NEWS_CH_LABELS[n.channel] || n.channel;
                const kws = String(n.keywords || "").split(",").filter(Boolean).slice(0, 5);
                let summary = String(n.summary || "").trim();
                if (summary.startsWith(n.title)) summary = summary.slice(n.title.length).trim();
                // 源摘要常写成「【标题】正文」：标题带书名号时上面那条匹配不上，这里再剥一层，
                //   否则卡片上标题会被原样重复两遍，看着像渲染出错
                const wrap = summary.match(/^【([^】]{0,160})】/);
                if (wrap && n.title && n.title.indexOf(wrap[1].trim()) >= 0) {
                    summary = summary.slice(wrap[0].length).trim();
                }
                // 去掉裁掉标题后残留的开头标点（如「。加息可能损害…」）
                summary = summary.replace(/^[。．.、，,；;：:！!？?·\s]+/, "");
                // 只剩标点的摘要视为「无摘要」，否则卡片上会孤零零出现一个「。」
                if (/^[。．.·，,；;：:、\s]*$/.test(summary)) summary = "";
                if (summary.length > 200) summary = summary.slice(0, 200) + "…";
                // 重点消息的简明摘要（服务端按「标题→方向→影响标的→事件」生成，一句话讲清）
                const brief = String(n.key_brief || "").trim();
                // 情绪：按标的判定优先（筛选单个标的时用该标的的结论），否则用整体判定
                const sm = parseSentMap(n.sentiment_map);
                const syms = String(n.symbols || "").split(",").filter(Boolean);
                const focus = newsPage.symbol ? sm[newsPage.symbol] : null;
                // 没有聚焦标的时，取分值最极端的那个标的作为整体判定依据（否则依据行永远为空）
                let peak = null;
                Object.keys(sm).forEach(sy => {
                    const v = sm[sy] || {};
                    const sc = Math.abs(Number(v.score) || 0);
                    if (sc > 0 && (!peak || sc > Math.abs(Number(peak.score) || 0))) peak = v;
                });
                const sentLabel = (focus && focus.label) || (peak && peak.label) || n.sentiment || "neutral";
                const sentScore = focus && focus.score != null ? focus.score : (peak && peak.score != null ? Number(peak.score) : 0);
                const sentHits = (focus && focus.hits && focus.hits.length) ? focus.hits : ((peak && peak.hits && peak.hits.length) ? peak.hits : []);
                // 标的标签带上该标的消息的利多利空
                const symTags = syms.map(sy => {
                    const m = sm[sy];
                    const l = (m && m.label) || "neutral";
                    return `<button class="tag tag-sym" data-sym="${esc(sy)}">${esc((state.newsSymbols || {})[sy] || sy)}${sentBadge(l, m && m.score != null ? m.score : 0)}</button>`;
                }).join("");
                return `<article class="news-item${n.starred ? " starred" : ""}${n.is_key ? " is-key" : ""}" data-id="${n.id}">
                    <div class="news-head">
                        <span class="badge ch-${esc(n.channel)}">${esc(label)}</span>
                        ${keyBadge(n)}
                        ${sentBadge(sentLabel, sentScore, sentHits)}
                        ${safeUrl(n.url) ? `<a class="news-title" href="${esc(safeUrl(n.url))}" target="_blank" rel="noopener noreferrer">${highlightText(n.title, kw)}</a>` : `<span class="news-title">${highlightText(n.title, kw)}</span>`}
                        <div class="news-actions">
                            ${canManage ? `<button class="icon-btn ${n.starred ? "on" : ""}" data-star="${n.id}" data-on="${n.starred ? 1 : 0}" title="${n.starred ? "取消收藏" : "收藏"}"><i class="fa-${n.starred ? "solid" : "regular"} fa-star"></i></button>` : ""}
                            ${canManage ? `<button class="icon-btn" data-note="${n.id}" title="添加 / 编辑备注"><i class="fa-regular fa-pen-to-square"></i></button>` : ""}
                            ${canManage ? `<button class="icon-btn danger" data-del="${n.id}" data-name="${esc(n.title)}" title="删除这条消息"><i class="fa-regular fa-trash-can"></i></button>` : ""}
                        </div>
                    </div>
                    ${(n.is_key && brief) ? `<p class="news-brief"><i class="fa-solid fa-bolt"></i><span class="nb-label">简报</span>${esc(brief)}</p>` : ""}
                    ${summary ? `<p class="news-summary${n.is_key ? " dim" : ""}">${highlightText(summary, kw)}</p>` : ""}
                    ${n.note ? `<p class="news-note"><i class="fa-solid fa-note-sticky"></i> ${esc(n.note)}</p>` : ""}
                    <div class="news-meta">
                        <span class="nm-src" title="来源"><i class="fa-solid fa-building-columns"></i> ${esc(n.platform || n.source || "—")}</span>
                        <span class="nm-time" title="发布时间"><i class="fa-regular fa-clock"></i> ${esc(fmtNewsTime(n.published_at))}</span>
                        ${kws.length ? `<span class="nm-sep"></span><span class="nm-kws">${kws.map(k => esc(k)).join(" · ")}</span>` : ""}
                    </div>
                    ${impactHtml(n, canManage)}
                    ${symTags ? `<div class="news-affect"><span class="na-label"><i class="fa-solid fa-arrow-right-long"></i> 影响标的</span>${symTags}</div>` : ""}
                </article>`;
            }).join("")}</div></div>`).join("");

        const total = data.total || 0;
        const pages = Math.max(1, Math.ceil(total / newsPage.limit));
        const cur = Math.min(pages, Math.floor(newsPage.offset / newsPage.limit) + 1);

        $("#n-list").innerHTML = html + `<div id="n-pager">${pagerHtml({ cur, pages, total, size: newsPage.limit })}</div>`;

        // —— 事件绑定 ——
        // 分页条：页码 → offset 换算在页面侧完成，组件只回传「第几页」
        bindPager($("#n-pager"), { cur, pages, size: newsPage.limit },
            n => { newsPage.offset = (n - 1) * newsPage.limit; load(); },
            size => { newsPage.limit = size; newsPage.offset = 0; load(); });
        if (canManage) {
            $("#n-list").querySelectorAll("[data-star]").forEach(b => b.addEventListener("click", async () => {
                const starredNow = b.dataset.on === "1";
                const { ok: ok2 } = await api("/news", "POST", { action: starredNow ? "unstar" : "star", id: Number(b.dataset.star) });
                if (ok2) { toast(starredNow ? "已取消收藏" : "已收藏", "success"); load(); }
                else toast("操作失败", "error");
            }));
            $("#n-list").querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", () => confirmDelete(b.dataset.name, async () => {
                const { ok: ok2 } = await api("/news", "POST", { action: "delete", id: Number(b.dataset.del) });
                toast(ok2 ? "已删除" : "删除失败", ok2 ? "success" : "error"); if (ok2) load();
            }, "消息删除后不可恢复。")));
            $("#n-list").querySelectorAll("[data-note]").forEach(b => b.addEventListener("click", () => {
                const row = rows.find(x => String(x.id) === String(b.dataset.note));
                openNewsNote(b.dataset.note, row ? row.note : "", load);
            }));
            // 研判人工改判：规则判定难免有误，人说了算；改后重算不会覆盖
            $("#n-list").querySelectorAll("[data-impact-fix]").forEach(b => b.addEventListener("click", async () => {
                const { ok: ok2 } = await api("/news", "POST", { action: "impact", id: Number(b.dataset.impactId), direction: b.dataset.impactFix });
                if (ok2) { toast("已修正研判方向", "success"); load(); }
                else toast("操作失败", "error");
            }));
        }
        // —— 从通知中心跳转定位：滚动到该条并高亮 ——
        if (newsPage.focusId) {
            const target = $("#n-list").querySelector(`.news-item[data-id="${newsPage.focusId}"]`);
            if (target) {
                target.classList.add("focus-flash");
                target.scrollIntoView({ behavior: "smooth", block: "center" });
                setTimeout(() => target.classList.remove("focus-flash"), 2600);
            }
        }

        // —— 重点消息「看过即已读」——
        //   重点消息进通知中心时是未读（点亮）状态；用户真正滚到看见它，才把对应通知标记为已读。
        //   只对重点消息生效，普通消息不产生通知，不受影响。
        stopNewsSeen();
        if (window.IntersectionObserver) {
            const seenIds = new Set();
            newsSeenObserver = new IntersectionObserver(entries => {
                const ids = [];
                entries.forEach(en => {
                    if (!en.isIntersecting) return;
                    const id = Number(en.target.dataset.id);
                    if (!id || seenIds.has(id)) return;
                    seenIds.add(id);
                    ids.push(id);
                });
                if (!ids.length) return;
                api("/notifications", "POST", { action: "read_refs", ref_type: "news", ids })
                    .then(() => refreshBell()).catch(() => {});
            }, { threshold: 0.6 });
            container.querySelectorAll(".news-item.is-key").forEach(el => newsSeenObserver.observe(el));
        }
    };

    // —— 消息卡片上的标的标签 / 清除筛选：点一下只看该标的的消息 ——
    //   只把委托挂在本页元素（#n-list / .news-symbar）上：
    //   之前挂在常驻的 #view-container 上，离开资讯中心后监听仍然存活，
    //   其它页面只要点中带 data-sym 的元素（如实时行情表格的行）就会被弹回资讯中心。
    const onNewsSymClick = e => {
        if (e.target.closest("#n-sym-clear")) {
            newsPage.symbol = "";
            newsPage.offset = 0;
            location.hash = "#news";
            return;
        }
        const tag = e.target.closest("[data-sym]");
        if (tag) {
            const next = newsPage.symbol === tag.dataset.sym ? "" : tag.dataset.sym;
            newsPage.offset = 0;
            location.hash = next ? "#news?symbol=" + next : "#news";
        }
    };
    container.querySelectorAll("#n-list, .news-symbar").forEach(root => root.addEventListener("click", onNewsSymClick));

    // —— 工具栏事件 ——
    $("#n-search").addEventListener("click", () => { newsPage.offset = 0; load(); });
    $("#n-keyword").addEventListener("keydown", e => { if (e.key === "Enter") { newsPage.offset = 0; load(); } });
    $("#n-days").addEventListener("change", () => { newsPage.offset = 0; load(); });
    $("#n-source").addEventListener("change", () => { newsPage.offset = 0; load(); });
    $("#n-sort").addEventListener("change", () => { newsPage.offset = 0; load(); });
    $("#n-sent").addEventListener("change", () => { newsPage.offset = 0; load(); });
    $("#n-impact").addEventListener("change", () => { newsPage.offset = 0; load(); });
    $("#n-key-only").addEventListener("change", () => { newsPage.offset = 0; load(); });
    $("#n-starred-only").addEventListener("change", () => { newsPage.offset = 0; load(); });
    $("#n-show-all").addEventListener("change", () => { newsPage.offset = 0; load(); });
    load();
    // 自动刷新：按服务端配置的间隔轮询（数据采集页 · 资讯页刷新间隔，默认 10 秒）。
    //   列表本身每次都会拉（保证新消息及时出现），但统计聚合在服务端缓存 3 分钟；
    //   前端最密 30 秒一轮，标签页在后台时暂停轮询。
    const newsTick = () => {
        if (mySeq !== routerSeq) return;
        // 标签页在后台不轮询（列表也没人看），回到前台最迟一个周期后自动补一次
        if (document.hidden) { viewTimer = setTimeout(newsTick, Math.max(30, liveSec) * 1000); return; }
        load(true).catch(() => {}).then(() => {
            if (mySeq !== routerSeq) return;
            viewTimer = setTimeout(newsTick, Math.max(30, liveSec) * 1000);
        });
    };
    viewTimer = setTimeout(newsTick, Math.max(30, liveSec) * 1000);
}

// 消息备注弹窗（回填已有备注，避免打开就保存导致原备注被清空）
function openNewsNote(id, currentNote, onDone) {
    const body = `<label>备注</label><textarea id="nw-note" rows="4" placeholder="记录你的观点、后续关注点或操作计划…">${esc(currentNote || "")}</textarea>`;
    const foot = `<button class="btn btn-ghost" data-close>取消</button><button class="btn btn-primary" id="nw-note-save">保存备注</button>`;
    const overlay = openModal("消息备注", body, foot, null);
    const area = overlay.querySelector("#nw-note");
    area.focus();
    area.setSelectionRange(area.value.length, area.value.length);
    overlay.querySelector("#nw-note-save").addEventListener("click", async () => {
        const val = area.value.trim();
        const { ok, data } = await api("/news", "POST", { action: "note", id: Number(id), note: val });
        if (!ok) { toast(data.message || "保存失败", "error"); return; }
        closeModal();
        toast("备注已保存", "success");
        if (onDone) onDone();
    });
}

// ---------- 用户管理 ----------
async function viewUsers(container) {
    const mySeq = routerSeq;
    const { ok, data } = await api("/users");
    if (mySeq !== routerSeq) return;
    if (!ok) { container.innerHTML = `<div class="empty">无访问权限</div>`; return; }
    const canCreate = state.user.role === "admin" || state.user.permissions.includes("users.create");
    const canEdit = state.user.role === "admin" || state.user.permissions.includes("users.edit");
    const canDelete = state.user.role === "admin" || state.user.permissions.includes("users.delete");
    container.innerHTML = `
        <div class="toolbar"><div class="field grow"></div>${canCreate ? `<div class="field"><label>&nbsp;</label><button class="btn btn-success" id="u-add"><i class="fa-solid fa-plus"></i> 新增用户</button></div>` : ""}</div>
        <div class="table-wrap"><table>
            <thead><tr><th>ID</th><th>账号</th><th>显示名</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
            <tbody>${data.map(u => `<tr>
                <td>${u.id}</td><td><b>${esc(u.username)}</b></td><td>${esc(u.display_name)}</td>
                <td><span class="badge badge-role-${u.role}">${{ admin: "管理员", user: "普通用户", visitor: "访客" }[u.role] || u.role}</span></td>
                <td>${u.enabled ? '<span class="badge badge-holding">启用</span>' : '<span class="badge badge-off">停用</span>'}</td>
                <td class="text-muted">${esc(u.created_at)}</td>
                <td><div class="row-actions">
                    ${canEdit ? `<button class="btn btn-ghost btn-sm" data-edit="${u.id}"><i class="fa-solid fa-pen"></i></button>` : ""}
                    ${canDelete && u.id !== state.user.id ? `<button class="btn btn-ghost btn-sm" data-del="${u.id}" data-name="${esc(u.username)}"><i class="fa-solid fa-trash"></i></button>` : ""}
                </div></td></tr>`).join("") || `<tr><td colspan="7" class="empty">暂无用户</td></tr>`}</tbody>
        </table></div>`;
    if (canCreate) $("#u-add").addEventListener("click", () => openUserModal());
    if (canEdit) container.querySelectorAll("[data-edit]").forEach(b => b.addEventListener("click", () => { const u = data.find(x => x.id == b.dataset.edit); openUserModal(u); }));
    if (canDelete) container.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", () => confirmDelete(b.dataset.name, async () => {
        const { ok: ok2 } = await api("/users", "POST", { action: "delete", id: Number(b.dataset.del) });
        toast(ok2 ? "已删除" : "删除失败", ok2 ? "success" : "error"); if (ok2) router();
    })));
}
async function openUserModal(u) {
    u = u || { username: "", display_name: "", role: "visitor", enabled: 1 };
    const body = `
        <div class="form-row"><div><label>账号 *</label><input id="u-username" value="${esc(u.username)}" ${u.id ? "disabled" : ""}></div>
            <div><label>显示名</label><input id="u-display" value="${esc(u.display_name)}"></div></div>
        <div class="form-row"><div><label>角色</label><select id="u-role">
                <option value="admin" ${u.role === "admin" ? "selected" : ""}>管理员</option>
                <option value="user" ${u.role === "user" ? "selected" : ""}>普通用户</option>
                <option value="visitor" ${u.role === "visitor" ? "selected" : ""}>访客</option></select></div>
            <div><label>状态</label><select id="u-enabled"><option value="1" ${u.enabled !== 0 ? "selected" : ""}>启用</option><option value="0" ${u.enabled === 0 ? "selected" : ""}>停用</option></select></div></div>
        <div class="form-row"><div class="full"><label>${u.id ? "重置密码（留空则不修改）" : "密码（至少6位）*"}</label><input type="password" id="u-password" placeholder="${u.id ? "留空保持不变" : ""}"></div></div>`;
    const foot = `<button class="btn btn-ghost" data-close>取消</button><button class="btn btn-primary" id="u-save">保存</button>`;
    openModal(u.id ? "编辑用户" : "新增用户", body, foot, async () => {
        const payload = { action: u.id ? "edit" : "create", id: u.id || undefined, username: $("#u-username").value.trim(), display_name: $("#u-display").value.trim(), role: $("#u-role").value, enabled: $("#u-enabled").value === "1", password: $("#u-password").value };
        if (!payload.username) return toast("请填写账号", "error");
        if (!u.id && (!payload.password || payload.password.length < 6)) return toast("密码至少6位", "error");
        const { ok } = await api("/users", "POST", payload);
        if (ok) { toast("已保存", "success"); closeModal(); router(); } else toast("保存失败（账号可能重复）", "error");
    });
}

// ---------- 系统设置 ----------
async function viewSettings(container) {
    const mySeq = routerSeq;
    const { ok, data } = await api("/settings");
    if (mySeq !== routerSeq) return;
    if (!ok) { container.innerHTML = `<div class="empty">无访问权限</div>`; return; }
    const canEdit = state.user.role === "admin" || state.user.permissions.includes("settings.edit");
    container.innerHTML = `
        <div class="panel"><div class="panel-head"><h3><i class="fa-solid fa-gear"></i> 基本设置</h3></div>
            <div class="panel-body"><div class="form-row">
                <div class="full"><label>系统名称</label><input id="s-name" value="${esc(data.system_name || "稀有金属投资咨询平台")}" ${canEdit ? "" : "disabled"}></div>
            </div>
            ${canEdit ? `<div style="margin-top:16px"><button class="btn btn-primary" id="s-save"><i class="fa-solid fa-floppy-disk"></i> 保存设置</button></div>` : `<p class="text-muted" style="margin-top:12px">当前账号仅可查看设置。</p>`}</div></div>
        <div class="panel"><div class="panel-head"><h3><i class="fa-solid fa-shield-halved"></i> 权限说明</h3></div>
            <div class="panel-body"><p class="text-muted">系统内置三种角色：<b>管理员</b>（全部权限）、<b>普通用户</b>（可查看与抓取资讯）、<b>访客</b>（仅查看资讯）。本平台不开放注册，账号由管理员在「用户管理」中创建。</p></div></div>`;
    if (canEdit) $("#s-save").addEventListener("click", async () => {
        const name = $("#s-name").value.trim();
        const { ok: ok2, data: d2 } = await api("/settings", "POST", { system_name: name });
        if (ok2) {
            state.brand = name || "稀有金属投资咨询平台";
            $("#brand-name").textContent = state.brand;
            toast("已保存", "success");
        } else toast(d2.message || "保存失败", "error");
    });
}

// ============================================================
// 通知中心（顶栏铃铛）
// ============================================================
let bellTimer = null;
let notifOpen = false;
// 通知列表筛选：all=全部 / unread=未读 / key=重点消息
let notifFilter = "all";

async function refreshBell() {
    try {
        const { ok, data } = await api("/notifications?limit=1");
        if (!ok) return;
        const badge = $("#bell-badge");
        if (!badge) return;
        const n = Number(data.unread || 0);
        badge.textContent = n > 99 ? "99+" : String(n);
        badge.style.display = n > 0 ? "" : "none";
        const bell = $("#bell-btn");
        if (bell) bell.title = n ? `${n} 条未读通知` : "通知中心";
    } catch {}
}
function closeNotifDrawer() {
    const d = $("#notif-drawer");
    if (d) d.remove();
    notifOpen = false;
}
async function toggleNotifDrawer() {
    if (notifOpen) return closeNotifDrawer();
    notifOpen = true;
    const drawer = el(`<div class="notif-drawer" id="notif-drawer">
        <div class="nd-head"><h4><i class="fa-solid fa-bell"></i> 通知中心<span class="nd-unread" id="nd-unread">0</span></h4>
            <button class="btn btn-ghost btn-sm" id="nd-readall" title="把所有未读通知标记为已读"><i class="fa-solid fa-check-double"></i> 一键已读</button>
            <button class="btn btn-ghost btn-sm" id="nd-readkey" title="只把重点消息标记为已读">重点已读</button>
            <button class="btn btn-ghost btn-sm" id="nd-close"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="nd-pane">
            <div class="nd-subtabs">
                <button class="nd-subtab active" data-ndfilter="all">全部</button>
                <button class="nd-subtab" data-ndfilter="unread">未读 <b id="nd-unread-n">0</b></button>
                <button class="nd-subtab" data-ndfilter="key">重点 <b id="nd-key-n">0</b></button>
            </div>
            <div class="nd-list" id="nd-list">${LOADING_HTML}</div>
        </div>
    </div>`);
    drawer.addEventListener("click", e => e.stopPropagation());
    document.body.appendChild(drawer);
    $("#nd-close").addEventListener("click", closeNotifDrawer);
    // 一键已读：全清；重点已读：只清重点消息（普通消息不产生通知，这个按钮最常用）
    const markAll = async (kind) => {
        const { ok, data } = await api("/notifications", "POST", kind ? { action: "read_all", kind } : { action: "read_all" });
        if (!ok) { toast(data.message || "操作失败", "error"); return; }
        toast(data.updated ? `已标记 ${data.updated} 条通知为已读` : "没有未读通知", data.updated ? "success" : "info");
        await renderNotifList();
        refreshBell();
    };
    $("#nd-readall").addEventListener("click", () => markAll(""));
    $("#nd-readkey").addEventListener("click", () => markAll("news_key"));
    // 子筛选：全部 / 未读 / 重点
    drawer.querySelectorAll(".nd-subtab").forEach(b => b.addEventListener("click", () => {
        notifFilter = b.dataset.ndfilter || "all";
        renderNotifList();
    }));
    await renderNotifList();
}

// 通知时间：兼容 "YYYY-MM-DD HH:mm:ss" 与 ISO
function fmtNotifTime(s) {
    const t = String(s || "").trim();
    if (!t) return "";
    return t.length >= 16 ? t.slice(5, 16) : t;
}
async function renderNotifList() {
    const box = $("#nd-list");
    if (!box) return;
    const q = notifFilter === "unread" ? "&unread=1" : notifFilter === "key" ? "&kind=news_key" : "";
    const { ok, data } = await api("/notifications?limit=50" + q);
    if (!ok) { box.innerHTML = emptyHtml("加载失败"); return; }
    const rows = data.rows || [];
    // 角标：未读总数 / 重点未读数
    const unreadN = Number(data.unread) || 0;
    const keyN = Number(data.key_unread) || 0;
    const setTxt = (sel, v) => {
        const n = document.querySelector(sel);
        if (!n) return;
        n.textContent = String(v);
        n.dataset.zero = v ? "0" : "1";
    };
    setTxt("#nd-unread", unreadN);
    setTxt("#nd-unread-n", unreadN);
    setTxt("#nd-key-n", keyN);
    document.querySelectorAll(".nd-subtab").forEach(b => b.classList.toggle("active", (b.dataset.ndfilter || "all") === notifFilter));
    if (!rows.length) {
        box.innerHTML = `<div class="nd-empty">${notifFilter === "unread" ? "没有未读通知" : notifFilter === "key" ? "暂无重点消息通知" : "暂无通知"}</div>`;
        return;
    }
    box.innerHTML = rows.map(r => {
        const isKey = r.kind === "news_key";
        // 重点消息：带跳转到资讯页对应条目的入口
        const refId = Number(r.ref_id) || 0;
        const jump = (isKey && refId) ? ` data-ref="news" data-ref-id="${refId}"` : "";
        const tag = isKey ? `<span class="nd-keytag"><i class="fa-solid fa-star"></i> 重点</span>` : "";
        const newTag = r.read ? "" : `<span class="nd-newtag">未读</span>`;
        // 重点消息：只留标题 + 时间。简报与分析正文（分数 / 传导链 / 依据）已按用户要求从通知里删除 ——
        // 标题本身即消息首句，完整研判到资讯中心原消息里看，避免通知列表冗长。
        const body = isKey ? "" : String(r.body || "");
        return `<div class="nd-item ${r.read ? "" : "unread"} ${esc(r.level || "info")}${isKey ? " nd-key" : ""}" data-id="${r.id}"${jump}>
        <span class="nd-level"></span>
        <div class="nd-main">
            <div class="nd-title">${tag}${newTag}${esc(r.title)}</div>
            ${body ? `<div class="nd-body">${esc(body)}</div>` : ""}
            <div class="nd-time">${esc(fmtNotifTime(r.created_at))}${isKey && refId ? ` · <span class="nd-jump">查看原消息</span>` : ""}</div>
        </div></div>`;
    }).join("");
    box.querySelectorAll(".nd-item").forEach(node => node.addEventListener("click", async () => {
        if (node.classList.contains("unread")) {
            await api("/notifications", "POST", { action: "read", id: Number(node.dataset.id) });
            node.classList.remove("unread");
            const nt = node.querySelector(".nd-newtag");
            if (nt) nt.remove();
            const uEl = document.querySelector("#nd-unread");
            const unEl = document.querySelector("#nd-unread-n");
            const nLeft = Math.max(0, unreadN - 1);
            if (uEl) uEl.textContent = String(nLeft);
            if (unEl) unEl.textContent = String(nLeft);
            refreshBell();
            // 当前是「未读」筛选时，这条读完就该消失
            if (notifFilter === "unread") { node.remove(); return; }
        }
        // 重点消息 → 跳到资讯页并高亮该条
        const refId = Number(node.dataset.refId) || 0;
        if (node.dataset.ref === "news" && refId) {
            closeNotifDrawer();
            location.hash = "#news?focus=" + refId;
        }
    }));
}


// ============================================================
// 通知与集成（独立菜单 #notify，原「通知推送」从系统设置拆分出来）
//   通道类型：企业微信 / 钉钉 / 飞书 / 通用 Webhook + Telegram / 微信推送(PushPlus) / Bark
// ============================================================
let NC_TYPES = [];   // 最近一次 /notify-channels 返回的类型目录（带 urlLabel / placeholder 等）

async function viewNotifications(container) {
    const mySeq = routerSeq;
    const canView = state.user.role === "admin" || state.user.permissions.includes("settings.view");
    if (!canView) { container.innerHTML = `<div class="empty">无访问权限</div>`; return; }
    const canEdit = state.user.role === "admin" || state.user.permissions.includes("settings.edit");
    container.innerHTML = `
        <div class="panel"><div class="panel-head"><h3><i class="fa-solid fa-paper-plane"></i> 通知与集成</h3></div>
            <div class="panel-body">
                <p class="text-muted">把系统里的价格预警、重点消息、财经日历推送到你的 IM 或手机。支持企业微信、钉钉、飞书、通用 Webhook，以及 Telegram、微信推送（PushPlus）、Bark —— 填好对应地址或 Token 即可，无需申请应用。</p>
                <div id="nc-list">${LOADING_HTML}</div>
                ${canEdit ? `<div class="alert-form" style="margin-top:16px">
                    <div><label>类型</label><select id="nc-type"></select></div>
                    <div id="nc-url-wrap"><label id="nc-url-label">Webhook 地址</label><input id="nc-url" placeholder="https://..."></div>
                    <div id="nc-secret-wrap" style="display:none"><label id="nc-secret-label">Secret</label><input id="nc-secret" placeholder="可选"></div>
                    <div><label>名称（可选）</label><input id="nc-name" placeholder="如：交易群"></div>
                </div>
                <div style="margin-top:10px"><label>订阅事件</label>
                    <div class="check-row">
                        <label class="check"><input type="checkbox" class="nc-ev" value="alert" checked> 价格预警</label>
                        <label class="check"><input type="checkbox" class="nc-ev" value="news_key" checked> 重点消息</label>
                        <label class="check"><input type="checkbox" class="nc-ev" value="calendar"> 财经日历</label>
                        <label class="check"><input type="checkbox" class="nc-ev" value="system"> 系统通知</label>
                        <label class="check"><input type="checkbox" class="nc-ev" value="all"> 全部</label>
                    </div>
                </div>
                <div style="margin-top:12px">
                    <button class="btn btn-primary btn-sm" id="nc-add"><i class="fa-solid fa-plus"></i> 添加通道</button>
                    <button class="btn btn-ghost btn-sm" id="nc-test" style="margin-left:8px"><i class="fa-solid fa-paper-plane"></i> 发送测试通知（全部通道）</button>
                </div>` : `<p class="text-muted" style="margin-top:12px">当前账号仅可查看通道配置。</p>`}
            </div></div>`;
    loadNotifyChannels(container, canEdit);
    bindNotifyForm(container, canEdit);
}

async function loadNotifyChannels(container, canEdit) {
    const list = container.querySelector("#nc-list");
    if (!list) return;
    const { ok, data } = await api("/notify-channels");
    if (!ok) { list.innerHTML = errorHtml(data.message || "加载失败"); return; }
    const rows = data.rows || [];
    NC_TYPES = data.types || [];
    const typeMeta = k => NC_TYPES.find(t => t.key === k) || {};
    const typeLabel = k => typeMeta(k).label || k;
    const typeIcon = k => typeMeta(k).icon || "fa-solid fa-code";
    const evLabel = e => ({ alert: "价格预警", news_key: "重点消息", calendar: "财经日历", system: "系统通知", all: "全部" }[e] || e);

    // 类型下拉只在首次渲染时填充，避免重置用户选择
    const typeSel = container.querySelector("#nc-type");
    if (typeSel && !typeSel.options.length) {
        typeSel.innerHTML = NC_TYPES.map(t => `<option value="${esc(t.key)}">${esc(t.label)}</option>`).join("");
    }

    const enabled = rows.filter(r => r.enabled).length;
    const failed = rows.filter(r => r.enabled && r.last_status === "failed").length;
    const summary = canEdit
        ? `<div class="nc-summary muted">共 ${rows.length} 个通道 · 启用 ${enabled} 个${failed ? ` · <span style="color:var(--danger)">${failed} 个推送失败</span>` : ""}</div>`
        : "";

    list.innerHTML = summary + `<div class="table-wrap"><table>
        <thead><tr><th>名称</th><th>类型</th><th>订阅</th><th>状态</th><th>最近推送</th>${canEdit ? "<th>操作</th>" : ""}</tr></thead>
        <tbody>${rows.length ? rows.map(r => {
            const st = r.enabled
                ? (r.last_status === "failed" ? '<span style="color:var(--danger)"><i class="fa-solid fa-circle-exclamation"></i> 推送失败</span>'
                    : (r.last_status === "success" ? '<span style="color:var(--success)"><i class="fa-solid fa-circle-check"></i> 正常</span>'
                        : '<span class="text-muted"><i class="fa-solid fa-circle"></i> 未推送</span>'))
                : '<span class="text-muted"><i class="fa-solid fa-circle"></i> 已停用</span>';
            return `<tr>
            <td>${esc(r.name)}</td>
            <td><i class="${esc(typeIcon(r.channel_type))} nc-ic"></i> ${esc(typeLabel(r.channel_type))}</td>
            <td class="text-muted">${esc(String(r.events || "").split(",").map(evLabel).join(" / "))}</td>
            <td>${st}</td>
            <td class="text-muted">${esc(fmtNotifTime(r.last_sent_at) || "—")}${r.last_message ? ` · ${esc(String(r.last_message).slice(0, 40))}` : ""}</td>
            ${canEdit ? `<td><div class="row-actions">
                <button class="btn btn-ghost btn-sm" data-nc-toggle="${r.id}">${r.enabled ? "停用" : "启用"}</button>
                <button class="btn btn-ghost btn-sm" data-nc-test="${r.id}"><i class="fa-solid fa-paper-plane"></i> 测试</button>
                <button class="btn btn-ghost btn-sm" data-nc-del="${r.id}">删除</button></div></td>` : ""}
        </tr>`; }).join("") : `<tr><td colspan="${canEdit ? 6 : 5}" class="text-muted">还没有推送通道，系统事件只会留在站内通知里</td></tr>`}</tbody>
    </table></div>`;

    if (!canEdit) return;
    list.querySelectorAll("[data-nc-del]").forEach(b => b.addEventListener("click", () => {
        confirmDelete("该推送通道", async () => {
            await api("/notify-channels", "POST", { action: "delete", id: Number(b.dataset.ncDel) });
            toast("已删除", "success");
            loadNotifyChannels(container, canEdit);
        });
    }));
    list.querySelectorAll("[data-nc-toggle]").forEach(b => b.addEventListener("click", async () => {
        const { ok: ok2, data: d2 } = await api("/notify-channels", "POST", { action: "toggle", id: Number(b.dataset.ncToggle) });
        if (!ok2) return toast(d2.message || "操作失败", "error");
        loadNotifyChannels(container, canEdit);
    }));
    list.querySelectorAll("[data-nc-test]").forEach(b => b.addEventListener("click", async () => {
        const { ok: ok2, data: d2 } = await api("/notify-channels", "POST", { action: "test", id: Number(b.dataset.ncTest) });
        toast(d2.message || (ok2 ? "已发送" : "发送失败"), ok2 ? "success" : "error");
        loadNotifyChannels(container, canEdit);
    }));
}

// 按所选类型动态切换「地址 / Token」字段的文案与显隐（Telegram 需要额外填 Chat ID）
function applyChannelType(container) {
    const sel = container.querySelector("#nc-type");
    const m = NC_TYPES.find(t => t.key === (sel && sel.value)) || {};
    const urlLabel = container.querySelector("#nc-url-label");
    const urlInput = container.querySelector("#nc-url");
    const secWrap = container.querySelector("#nc-secret-wrap");
    const secLabel = container.querySelector("#nc-secret-label");
    const secInput = container.querySelector("#nc-secret");
    if (urlLabel) urlLabel.textContent = m.urlLabel || "地址";
    if (urlInput) urlInput.placeholder = m.urlPlaceholder || "";
    if (secWrap && secLabel) {
        if (m.secretLabel) { secWrap.style.display = ""; secLabel.textContent = m.secretLabel; if (secInput) secInput.placeholder = m.secretPlaceholder || ""; }
        else { secWrap.style.display = "none"; if (secInput) secInput.value = ""; }
    }
}

// 表单绑定：类型切换联动、添加、全局测试（页面渲染后只绑一次）
function bindNotifyForm(container, canEdit) {
    if (!canEdit) return;
    const typeSel = container.querySelector("#nc-type");
    if (typeSel) {
        typeSel.addEventListener("change", () => applyChannelType(container));
        applyChannelType(container);
    }
    container.querySelector("#nc-add").addEventListener("click", async () => {
        const url = container.querySelector("#nc-url").value.trim();
        if (!url) return toast("请填写 " + (container.querySelector("#nc-url-label").textContent || "地址"), "error");
        const events = [...container.querySelectorAll(".nc-ev:checked")].map(i => i.value);
        if (!events.length) return toast("至少订阅一个事件", "error");
        const { ok: ok2, data: d2 } = await api("/notify-channels", "POST", {
            action: "create",
            name: container.querySelector("#nc-name").value.trim(),
            channel_type: typeSel.value,
            webhook_url: url,
            secret: container.querySelector("#nc-secret").value.trim(),
            events
        });
        if (!ok2) return toast(d2.message || "添加失败", "error");
        toast("通道已添加", "success");
        container.querySelector("#nc-url").value = "";
        container.querySelector("#nc-name").value = "";
        container.querySelector("#nc-secret").value = "";
        loadNotifyChannels(container, canEdit);
    });
    container.querySelector("#nc-test").addEventListener("click", async () => {
        const { ok: ok2, data: d2 } = await api("/alerts", "POST", { action: "test" });
        toast(d2.message || (ok2 ? "已发送" : "发送失败"), ok2 ? "success" : "error");
        loadNotifyChannels(container, canEdit);
        refreshBell();
    });
}

// ============================================================
// 价格预警（目标价 / 涨跌幅阈值）
// ============================================================
async function openAlertsDialog() {
    const canConfig = state.user.role === "admin" || state.user.permissions.includes("market.config");
    const body = `<div id="al-wrap">${LOADING_HTML}</div>`;
    const overlay = openModal("价格预警", body, `<button class="btn btn-ghost" data-close>关闭</button>`, null);
    await loadAlertsInto(overlay, canConfig);
}

async function loadAlertsInto(overlay, canConfig) {
    const wrap = overlay.querySelector("#al-wrap");
    if (!wrap) return;
    const { ok, data } = await api("/alerts");
    if (!ok) { wrap.innerHTML = errorHtml(data.message || "加载失败"); return; }
    const symbols = data.symbols || [];
    const dirs = data.directions || [];
    const rows = data.rows || [];
    const dirLabel = k => (dirs.find(d => d.key === k) || {}).label || k;
    const unitOf = s => (symbols.find(x => x.symbol === s) || {}).unit || "";
    const condText = r => `${dirLabel(r.direction)} ${r.target}${r.direction === "rise" || r.direction === "fall" ? "%" : ""}`;

    wrap.innerHTML = `
        ${canConfig ? `<div class="alert-form">
            <div><label>品种</label><select id="al-symbol">${symbols.map(s => `<option value="${esc(s.symbol)}">${esc(s.name || s.symbol)}（${esc(s.symbol)}）</option>`).join("")}</select></div>
            <div><label>触发条件</label><select id="al-dir">${dirs.map(d => `<option value="${d.key}">${d.label}</option>`).join("")}</select></div>
            <div><label>阈值</label><input type="number" id="al-target" step="0.01" placeholder="价格或百分比"></div>
            <div><label>冷却（分钟）</label><input type="number" id="al-cool" value="30" min="1" max="1440"></div>
        </div>
        <div style="margin-top:10px"><label>备注</label><input id="al-note" placeholder="可选，如：到价减仓 / 跌破止损"></div>
        <div style="margin-top:12px"><button class="btn btn-primary btn-sm" id="al-add"><i class="fa-solid fa-plus"></i> 添加预警</button>
            <span class="text-muted" style="margin-left:10px">行情刷新后自动判定；命中即写入通知中心并推送已配置的 Webhook。</span></div>` : ""}
        <div class="table-wrap" style="margin-top:14px">
            <table><thead><tr><th>品种</th><th>触发条件</th><th>状态</th><th>已触发</th><th>最近触发</th><th>备注</th>${canConfig ? "<th>操作</th>" : ""}</tr></thead>
            <tbody>${rows.length ? rows.map(r => `<tr>
                <td>${esc(r.name || r.symbol)}<span class="text-muted"> ${esc(r.symbol)}</span></td>
                <td>${esc(condText(r))}<span class="text-muted"> ${esc(unitOf(r.symbol))}</span></td>
                <td>${r.enabled ? '<span style="color:var(--success)">启用</span>' : '<span class="text-muted">停用</span>'}</td>
                <td>${r.trigger_count || 0}</td>
                <td class="text-muted">${esc(fmtNotifTime(r.last_trigger_at) || "—")}</td>
                <td class="text-muted">${esc(r.note || "—")}</td>
                ${canConfig ? `<td><div class="row-actions">
                    <button class="btn btn-ghost btn-sm" data-toggle="${r.id}">${r.enabled ? "停用" : "启用"}</button>
                    <button class="btn btn-ghost btn-sm" data-del="${r.id}">删除</button></div></td>` : ""}
            </tr>`).join("") : `<tr><td colspan="${canConfig ? 7 : 6}" class="text-muted">还没有预警，添加一条试试</td></tr>`}</tbody></table>
        </div>`;

    if (!canConfig) return;
    overlay.querySelector("#al-add").addEventListener("click", async () => {
        const payload = {
            action: "create",
            symbol: overlay.querySelector("#al-symbol").value,
            direction: overlay.querySelector("#al-dir").value,
            target: Number(overlay.querySelector("#al-target").value),
            cooldown_min: Number(overlay.querySelector("#al-cool").value) || 30,
            note: overlay.querySelector("#al-note").value.trim()
        };
        if (!(payload.target > 0)) return toast("请填写大于 0 的阈值", "error");
        const { ok: ok2, data: d2 } = await api("/alerts", "POST", payload);
        toast(d2.message || (ok2 ? "已添加" : "添加失败"), ok2 ? "success" : "error");
        if (ok2) await loadAlertsInto(overlay, canConfig);
    });
    overlay.querySelectorAll("[data-toggle]").forEach(b => b.addEventListener("click", async () => {
        await api("/alerts", "POST", { action: "toggle", id: Number(b.dataset.toggle) });
        await loadAlertsInto(overlay, canConfig);
    }));
    overlay.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async () => {
        await api("/alerts", "POST", { action: "delete", id: Number(b.dataset.del) });
        await loadAlertsInto(overlay, canConfig);
    }));
}

// ============================================================
// 持仓管理
// ============================================================
const PLAN_STATUS_LABEL = { planning: "准备中", active: "执行中", done: "已完成", cancelled: "已取消" };

async function viewPortfolio(container) {
    const mySeq = routerSeq;
    container.innerHTML = `<div id="pf-body">${LOADING_HTML}</div>`;
    const canEdit = state.user.role === "admin" || (state.user.role !== "visitor" && state.user.permissions.includes("market.view"));

    const load = async () => {
        // 三个区块互不依赖，并行取；某个失败不拖垮整页
        const [posRes, planRes, watchRes] = await Promise.all([
            api("/positions").catch(() => ({ ok: false, data: {} })),
            api("/trade-plans").catch(() => ({ ok: false, data: {} })),
            api("/watchlist").catch(() => ({ ok: false, data: {} }))
        ]);
        const box = $("#pf-body");
        if (!box || mySeq !== routerSeq) return;
        if (!posRes.ok) { box.innerHTML = errorHtml((posRes.data && posRes.data.message) || "加载失败"); return; }
        const rows = posRes.data.rows || [];
        const sm = posRes.data.summary || {};
        const symbols = posRes.data.symbols || [];
        const plans = (planRes.data && planRes.data.rows) || [];
        const watches = (watchRes.data && watchRes.data.rows) || [];
        const pnlColor = v => (v > 0 ? "var(--up)" : v > 0.0001 ? "var(--up)" : v < 0 ? "var(--down)" : "var(--text)");
        const pnl = Number(sm.pnl || 0);
        const statCard = (icon, label, main, sub, color) => `<div class="stat-card">
            <span class="stat-icon"><i class="fa-solid ${icon}"></i></span>
            <div class="stat-label">${label}</div>
            <div class="stat-value"${color ? ` style="color:${color}"` : ""}>${main}</div>
            <div class="stat-label" style="margin-top:4px">${sub}</div></div>`;
        const alloc = sm.alloc || [];
        const palette = ["#4f46e5", "#0ea5e9", "#f59e0b", "#10b981", "#ef4444", "#8b5cf6", "#14b8a6", "#f97316"];

        box.innerHTML = `
            <div class="stat-grid">
                ${statCard("fa-sack-dollar", "持仓市值", money(sm.market_value), `成本 ${money(sm.cost_value)}`)}
                ${statCard("fa-chart-line", "浮动盈亏", (pnl >= 0 ? "+" : "") + money(pnl), `${pnl >= 0 ? "+" : ""}${Number(sm.pnl_pct || 0).toFixed(2)}%`, pnlColor(pnl))}
                ${statCard("fa-layer-group", "持仓品种", `${sm.count || 0} 个`, `按 ${state.user.role === "admin" ? "全部用户" : "当前账号"} 统计`)}
            </div>

            <div class="panel"><div class="panel-head"><h3><i class="fa-solid fa-clipboard-list"></i> 建仓计划</h3>
                ${canEdit ? `<button class="btn btn-primary btn-sm" id="pf-plan-add"><i class="fa-solid fa-plus"></i> 新建计划</button>` : ""}</div>
                <div class="panel-body">
                    <div class="table-wrap"><table>
                        <thead><tr><th>品种</th><th class="num">目标价</th><th class="num">止损价</th><th class="num">现价</th><th class="num">距目标</th><th class="num">盈亏比</th><th>状态</th><th>备注</th>${canEdit ? "<th>操作</th>" : ""}</tr></thead>
                        <tbody>${plans.length ? plans.map(p => `<tr>
                            <td>${esc(p.short_name || p.name || p.symbol)}<span class="text-muted"> ${esc(p.symbol)}</span></td>
                            <td class="num">${metalNum(p.target_price)}</td>
                            <td class="num">${metalNum(p.stop_loss)}</td>
                            <td class="num">${p.price > 0 ? metalNum(p.price) : '<span class="text-muted">未采集</span>'}</td>
                            <td class="num">${p.to_target_pct != null ? `<span style="color:${p.to_target_pct >= 0 ? "var(--up)" : "var(--down)"}">${p.to_target_pct >= 0 ? "还差" : "已过"} ${Math.abs(p.to_target_pct).toFixed(1)}%</span>` : "—"}</td>
                            <td class="num">${p.risk_reward != null ? p.risk_reward : "—"}</td>
                            <td>${esc(PLAN_STATUS_LABEL[p.status] || p.status || "")}</td>
                            <td class="text-muted">${esc(p.note || "—")}</td>
                            ${canEdit ? `<td><div class="row-actions">
                                <button class="btn btn-ghost btn-sm" data-plan-edit="${p.id}">编辑</button>
                                <button class="btn btn-ghost btn-sm" data-plan-del="${p.id}">删除</button></div></td>` : ""}
                        </tr>`).join("") : `<tr><td colspan="${canEdit ? 9 : 8}" class="text-muted">还没有建仓计划。点右上角「新建计划」设定目标价、止损与分批价位。</td></tr>`}</tbody>
                    </table></div>
                </div></div>

            <div class="panel"><div class="panel-head"><h3><i class="fa-solid fa-briefcase"></i> 持仓明细</h3>
                ${canEdit ? `<button class="btn btn-primary btn-sm" id="pf-add"><i class="fa-solid fa-plus"></i> 新增持仓</button>` : ""}</div>
                <div class="panel-body">
                    <div class="table-wrap"><table>
                        <thead><tr><th>品种</th><th>数量</th><th>成本价</th><th>现价</th><th>市值</th><th>浮动盈亏</th><th>盈亏比例</th><th>建仓日</th><th>备注</th>${canEdit ? "<th>操作</th>" : ""}</tr></thead>
                        <tbody>${rows.length ? rows.map(r => {
                            const c = pnlColor(Number(r.pnl));
                            return `<tr>
                                <td>${esc(r.name || r.symbol)}<span class="text-muted"> ${esc(r.symbol)}</span></td>
                                <td>${metalNum(r.qty, 0)}</td>
                                <td>${metalNum(r.cost, 2)}</td>
                                <td>${r.price > 0 ? metalNum(r.price, 2) : '<span class="text-muted">未采集</span>'}</td>
                                <td>${r.price > 0 ? money(r.market_value) : "—"}</td>
                                <td style="color:${c};font-weight:600">${r.price > 0 ? (r.pnl >= 0 ? "+" : "") + money(r.pnl) : "—"}</td>
                                <td style="color:${c}">${r.price > 0 ? (r.pnl_pct >= 0 ? "+" : "") + Number(r.pnl_pct).toFixed(2) + "%" : "—"}</td>
                                <td class="text-muted">${esc(r.opened_at || "—")}</td>
                                <td class="text-muted">${esc(r.note || "—")}</td>
                                ${canEdit ? `<td><div class="row-actions">
                                    <button class="btn btn-ghost btn-sm" data-edit="${r.id}">编辑</button>
                                    <button class="btn btn-ghost btn-sm" data-del="${r.id}">删除</button></div></td>` : ""}
                            </tr>`; }).join("") : `<tr><td colspan="${canEdit ? 10 : 9}" class="text-muted">还没有持仓记录</td></tr>`}</tbody>
                    </table></div>
                    ${alloc.length ? `<div class="alloc-bar">${alloc.map((a, i) => `<span style="width:${a.pct}%;background:${palette[i % palette.length]}" title="${esc(a.name)} ${a.pct.toFixed(1)}%"></span>`).join("")}</div>
                    <div class="alloc-legend">${alloc.map((a, i) => `<span><i style="background:${palette[i % palette.length]}"></i>${esc(a.name)} ${a.pct.toFixed(1)}%</span>`).join("")}</div>` : ""}
                </div></div>

            <div class="panel"><div class="panel-head"><h3><i class="fa-solid fa-star"></i> 我的自选</h3></div>
                <div class="panel-body">
                    <div class="table-wrap"><table>
                        <thead><tr><th>品种</th><th class="num">现价</th><th class="num">涨跌</th><th>备注</th>${canEdit ? "<th>操作</th>" : ""}</tr></thead>
                        <tbody>${watches.length ? watches.map(w => `<tr>
                            <td>${esc(w.short_name || w.name || w.symbol)}<span class="text-muted"> ${esc(w.symbol)}</span></td>
                            <td class="num">${w.price > 0 ? metalNum(w.price) : '<span class="text-muted">未采集</span>'}</td>
                            <td class="num" style="color:${chgColor(w.change_pct)}">${w.price > 0 ? chgSign(w.change_pct) + metalPct(w.change_pct, 2) + "%" : "—"}</td>
                            <td class="text-muted">${esc(w.note || "—")}</td>
                            ${canEdit ? `<td><div class="row-actions">
                                <button class="btn btn-ghost btn-sm" data-watch-open="${esc(w.symbol)}">决策</button>
                                <button class="btn btn-ghost btn-sm" data-watch-del="${esc(w.symbol)}">移除</button></div></td>` : ""}
                        </tr>`).join("") : `<tr><td colspan="${canEdit ? 5 : 4}" class="text-muted">还没有自选标的。在「投资总览」的消息里点标的标签进入决策面板即可加入自选。</td></tr>`}</tbody>
                    </table></div>
                </div></div>`;

        if (!canEdit) return;
        $("#pf-add").addEventListener("click", () => openPositionModal(null, symbols, load));
        box.querySelectorAll("[data-edit]").forEach(b => b.addEventListener("click", () => {
            const row = rows.find(x => String(x.id) === b.dataset.edit);
            if (row) openPositionModal(row, symbols, load);
        }));
        box.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", () => {
            confirmDelete("这条持仓", async () => {
                await api("/positions", "POST", { action: "delete", id: Number(b.dataset.del) });
                toast("已删除", "success");
                load();
            });
        }));
        // —— 建仓计划 ——
        const planAdd = $("#pf-plan-add");
        if (planAdd) planAdd.addEventListener("click", async () => {
            await openPlanSymbolPicker((sym, row) => openTradePlanModal(sym, { row, onDone: load }));
        });
        box.querySelectorAll("[data-plan-edit]").forEach(b => b.addEventListener("click", () => {
            const p = plans.find(x => String(x.id) === String(b.dataset.planEdit));
            if (!p) return;
            openTradePlanModal(p.symbol, { plan: p, row: p, onDone: load });
        }));
        box.querySelectorAll("[data-plan-del]").forEach(b => b.addEventListener("click", () => {
            confirmDelete("这条建仓计划", async () => {
                const res = await api("/trade-plans", "POST", { action: "delete", id: Number(b.dataset.planDel) });
                if (!res.ok) return toast((res.data && res.data.message) || "删除失败", "error");
                toast("已删除", "success");
                load();
            });
        }));
        // —— 自选 ——
        box.querySelectorAll("[data-watch-open]").forEach(b => b.addEventListener("click", async () => {
            await openDeskDetailFor(b.dataset.watchOpen);
        }));
        box.querySelectorAll("[data-watch-del]").forEach(b => b.addEventListener("click", async () => {
            const res = await api("/watchlist", "POST", { action: "remove", symbol: b.dataset.watchDel });
            if (!res.ok) return toast((res.data && res.data.message) || "移除失败", "error");
            toast("已移出自选", "success");
            load();
        }));
    };
    await load();
}

// 新建建仓计划时先选品种：品种清单来自 /api/instruments（只读、不触发行情刷新）
async function openPlanSymbolPicker(onPick) {
    const { ok, data } = await api("/instruments");
    const rows = (data && data.rows) || [];
    if (!ok || !rows.length) return toast((data && data.message) || "品种清单加载失败", "error");
    const body = `<div class="form-row">
        <div class="full"><label>选择品种 *</label>
            <select id="pk-symbol">${rows.map(r => `<option value="${esc(r.symbol)}">${esc(r.short_name || r.name)}（${esc(r.symbol)}）${r.price > 0 ? " · 现价 " + metalNum(r.price) : ""}</option>`).join("")}</select></div>
    </div>`;
    const foot = `<button class="btn btn-ghost" data-close>取消</button><button class="btn btn-primary" id="pk-ok">下一步</button>`;
    const overlay = openModal("新建建仓计划", body, foot, null);
    overlay.querySelector("#pk-ok").addEventListener("click", () => {
        const sym = overlay.querySelector("#pk-symbol").value;
        const row = rows.find(r => r.symbol === sym) || { symbol: sym };
        closeModal();
        onPick(sym, row);
    });
}

// 从「持仓与计划」页打开标的决策面板：先补一份工作台数据（面板要行情、持仓、自选、计划）
async function openDeskDetailFor(symbol) {
    if (!deskState.data) {
        const { ok, data } = await api("/desk");
        if (!ok) return toast((data && data.message) || "工作台数据加载失败", "error");
        deskState.data = data;
    }
    openDeskDetail(symbol);
}

function openPositionModal(row, symbols, onDone) {
    const isEdit = !!row;
    const body = `<div class="form-row">
        <div class="full"><label>品种 *</label><select id="pf-symbol">${symbols.map(s => `<option value="${esc(s.symbol)}" ${isEdit && row.symbol === s.symbol ? "selected" : ""}>${esc(s.name || s.symbol)}（${esc(s.symbol)}）</option>`).join("")}</select></div>
        <div><label>数量 *</label><input type="number" id="pf-qty" step="0.01" value="${isEdit ? row.qty : ""}" placeholder="如 100"></div>
        <div><label>成本价 *</label><input type="number" id="pf-cost" step="0.01" value="${isEdit ? row.cost : ""}" placeholder="元/克 或 元/千克"></div>
        <div><label>手续费</label><input type="number" id="pf-fee" step="0.01" value="${isEdit ? row.fee : 0}"></div>
        <div><label>建仓日</label><input type="date" id="pf-date" value="${isEdit ? esc(row.opened_at || "") : ""}"></div>
        <div class="full"><label>备注</label><input id="pf-note" value="${isEdit ? esc(row.note || "") : ""}" placeholder="可选"></div>
    </div>`;
    const foot = `<button class="btn btn-ghost" data-close>取消</button><button class="btn btn-primary" id="pf-save">${isEdit ? "保存" : "添加"}</button>`;
    const overlay = openModal(isEdit ? "编辑持仓" : "新增持仓", body, foot, null);
    overlay.querySelector("#pf-save").addEventListener("click", async () => {
        const payload = {
            action: isEdit ? "update" : "create",
            id: isEdit ? row.id : undefined,
            symbol: overlay.querySelector("#pf-symbol").value,
            qty: Number(overlay.querySelector("#pf-qty").value),
            cost: Number(overlay.querySelector("#pf-cost").value),
            fee: Number(overlay.querySelector("#pf-fee").value) || 0,
            opened_at: overlay.querySelector("#pf-date").value,
            note: overlay.querySelector("#pf-note").value.trim()
        };
        if (!(payload.qty > 0)) return toast("数量必须大于 0", "error");
        if (!(payload.cost > 0)) return toast("成本价必须大于 0", "error");
        const { ok, data } = await api("/positions", "POST", payload);
        if (!ok) return toast(data.message || "保存失败", "error");
        closeModal();
        toast(data.message || "已保存", "success");
        if (onDone) onDone();
    });
}

// ============================================================
// 财经日历（经济事件日程 + 到点提醒）
// ============================================================
const calPage = { days: 14, country: "", importance: 0 };

const CAL_IMPORTANCE_COLOR = { 1: "var(--text-soft)", 2: "var(--warning)", 3: "var(--danger)" };

function calCountdown(e) {
    if (e.is_past) return `<span class="text-muted">已公布</span>`;
    const m = e.countdown_min;
    if (m == null) return "—";
    if (m <= 0) return `<span style="color:var(--danger)">即将公布</span>`;
    if (m < 60) return `<b style="color:var(--danger)">${m} 分钟后</b>`;
    if (m < 1440) return `<b style="color:var(--warning)">${Math.floor(m / 60)} 小时后</b>`;
    return `<span class="text-muted">${Math.floor(m / 1440)} 天后</span>`;
}

function calImportanceTag(lv) {
    const color = CAL_IMPORTANCE_COLOR[lv] || "var(--text-soft)";
    const label = { 1: "低", 2: "中", 3: "高" }[lv] || "中";
    const stars = "●".repeat(lv) + "○".repeat(3 - lv);
    return `<span class="cal-imp" style="color:${color}" title="重要度：${label}">${stars}</span>`;
}

async function viewCalendar(container) {
    // 与后端一致：事件维护需要 market.config（普通用户只读）
    const canEdit = state.user.role === "admin" || state.user.permissions.includes("market.config");
    const mySeq = routerSeq;
    container.innerHTML = `
        <div class="toolbar">
            <div class="field"><label>时间范围</label><select id="cal-days">
                ${[7, 14, 30, 90].map(d => `<option value="${d}" ${calPage.days === d ? "selected" : ""}>未来 ${d} 天</option>`).join("")}
            </select></div>
            <div class="field"><label>国家/地区</label><select id="cal-country"><option value="">全部</option></select></div>
            <div class="field"><label>重要度</label><select id="cal-imp">
                <option value="0">全部</option><option value="2">中等及以上</option><option value="3">仅高重要度</option>
            </select></div>
            <div class="field grow"><label>&nbsp;</label><button class="btn btn-primary" id="cal-reload"><i class="fa-solid fa-magnifying-glass"></i> 查询</button></div>
            ${canEdit ? `<div class="field"><label>&nbsp;</label><button class="btn btn-ghost" id="cal-add"><i class="fa-solid fa-plus"></i> 新增事件</button></div>` : ""}
            ${canEdit ? `<div class="field"><label>&nbsp;</label><button class="btn btn-ghost" id="cal-check" title="立即检查未来 30 分钟内的事件并推送提醒"><i class="fa-solid fa-bell"></i> 检查提醒</button></div>` : ""}
        </div>
        <div id="cal-body">${LOADING_HTML}</div>`;

    const load = async () => {
        const { ok, data } = await api(`/calendar?days=${calPage.days}${calPage.country ? "&country=" + encodeURIComponent(calPage.country) : ""}${calPage.importance ? "&importance=" + calPage.importance : ""}`);
        if (mySeq !== routerSeq) return;
        const box = $("#cal-body");
        if (!box) return;
        if (!ok) { box.innerHTML = `<div class="empty">加载失败：${esc(data.message || "无访问权限")}</div>`; return; }

        // 国家下拉首次填充
        const cs = $("#cal-country");
        if (cs && cs.options.length <= 1) {
            cs.innerHTML = `<option value="">全部</option>` + (data.countries || []).map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
            cs.value = calPage.country;
        }
        const st = data.stats || {};
        const stat = (icon, label, val, color) => `<div class="stat-card">
            <span class="stat-icon"><i class="fa-solid ${icon}"></i></span>
            <div class="stat-label">${label}</div>
            <div class="stat-value" style="font-size:20px;${color ? `color:${color}` : ""}">${val}</div></div>`;

        const rowsHtml = (data.groups || []).map(g => {
            const isToday = g.date === data.today;
            const dObj = new Date(g.date + "T00:00:00+08:00");
            const wd = "日一二三四五六"[dObj.getDay()];
            return `<div class="cal-day">
                <div class="cal-day-head">
                    <b>${esc(g.date)}</b>
                    <span class="text-muted">周${wd}${isToday ? " · 今天" : ""}</span>
                    <span class="text-muted" style="margin-left:auto">${g.items.length} 项</span>
                </div>
                <div class="table-wrap"><table>
                    <thead><tr><th style="width:64px">时间</th><th style="width:70px">地区</th><th>事件</th><th style="width:64px">重要度</th>
                        <th class="text-right" style="width:90px">前值</th><th class="text-right" style="width:90px">预期</th><th class="text-right" style="width:90px">公布</th>
                        <th style="width:96px">剩余</th>${canEdit ? "<th style='width:96px'>操作</th>" : ""}</tr></thead>
                    <tbody>${g.items.map(e => `<tr class="${e.is_past ? "cal-past" : ""}">
                        <td class="text-muted">${esc(String(e.event_at).slice(11, 16))}</td>
                        <td><span class="badge">${esc(e.country)}</span></td>
                        <td><b>${esc(e.name)}</b>${e.note ? `<div class="text-muted" style="font-size:12px">${esc(e.note)}</div>` : ""}</td>
                        <td>${calImportanceTag(e.importance)}</td>
                        <td class="text-right text-muted">${esc(e.previous || "—")}${e.unit && e.previous ? esc(e.unit) : ""}</td>
                        <td class="text-right text-muted">${esc(e.forecast || "—")}${e.unit && e.forecast ? esc(e.unit) : ""}</td>
                        <td class="text-right">${e.actual ? `<b>${esc(e.actual)}${esc(e.unit || "")}</b>` : `<span class="text-muted">待公布</span>`}</td>
                        <td>${calCountdown(e)}</td>
                        ${canEdit ? `<td><div class="row-actions">
                            <button class="btn btn-ghost btn-sm" data-cal-edit="${e.id}">编辑</button>
                            <button class="btn btn-ghost btn-sm" data-cal-del="${e.id}">删除</button></div></td>` : ""}
                    </tr>`).join("")}</tbody>
                </table></div>
            </div>`;
        }).join("");

        box.innerHTML = `<div class="stat-grid" style="margin-bottom:14px">
            ${stat("fa-calendar-check", "未来 " + data.days + " 天事件", st.total || 0)}
            ${stat("fa-fire", "高重要度", st.high || 0, "var(--danger)")}
            ${stat("fa-clock", "24 小时内", st.upcoming_24h || 0, "var(--warning)")}
            ${stat("fa-hourglass-half", "待公布", st.unconfirmed || 0)}
        </div>
        ${rowsHtml || `<div class="empty">这段时间还没有事件。<br><span class="text-muted">点「新增事件」录入，或从常用模板快速添加（非农、CPI、利率决议等）。</span></div>`}
        <p class="text-muted" style="font-size:12px;margin-top:12px">
            <i class="fa-solid fa-circle-info"></i>
            事件由管理员录入维护（金十 / 东财的日历接口目前没有稳定公开通道，接不上就不给假数据）。
            到点前 30 分钟会自动写入通知中心并按订阅推送 Webhook，同一事件只提醒一次；改时间会重新计时。
        </p>`;

        if (canEdit) {
            box.querySelectorAll("[data-cal-edit]").forEach(b => b.addEventListener("click", () => {
                const e = (data.events || []).find(x => String(x.id) === b.dataset.calEdit);
                if (e) openCalendarModal(e, data, load);
            }));
            box.querySelectorAll("[data-cal-del]").forEach(b => b.addEventListener("click", () => {
                const e = (data.events || []).find(x => String(x.id) === b.dataset.calDel);
                confirmDelete(e ? e.name : "该事件", async () => {
                    await api("/calendar", "POST", { action: "delete", id: Number(b.dataset.calDel) });
                    toast("已删除", "success");
                    load();
                });
            }));
        }
    };

    $("#cal-days").addEventListener("change", () => { calPage.days = Number($("#cal-days").value) || 14; load(); });
    $("#cal-country").addEventListener("change", () => { calPage.country = $("#cal-country").value; load(); });
    $("#cal-imp").addEventListener("change", () => { calPage.importance = Number($("#cal-imp").value) || 0; load(); });
    $("#cal-reload").addEventListener("click", load);
    if (canEdit) {
        $("#cal-add").addEventListener("click", async () => {
            const { ok, data } = await api(`/calendar?days=1`);
            openCalendarModal(null, ok ? data : { templates: [], countries: [] }, load);
        });
        $("#cal-check").addEventListener("click", async () => {
            const { ok, data } = await api("/calendar/check", "POST", {});
            if (!ok) return toast(data.message || "检查失败", "error");
            toast(data.reminded ? `已推送 ${data.reminded} 条提醒` : "未来 30 分钟没有待提醒事件", data.reminded ? "success" : "info");
            load();
        });
    }
    await load();
}

// 新增 / 编辑事件弹窗
function openCalendarModal(ev, meta, onDone) {
    const isEdit = !!ev;
    const templates = meta.templates || [];
    const countries = meta.countries && meta.countries.length ? meta.countries : ["中国", "美国", "欧元区", "日本", "英国", "其他"];
    const dtVal = ev
        ? String(ev.event_at).replace(" ", "T").slice(0, 16)
        : (() => {
            // 默认今天下一个整点
            const d = new Date(Date.now() + 8 * 3600 * 1000 + 3600 * 1000);
            return d.toISOString().slice(0, 11) + String(d.getUTCHours()).padStart(2, "0") + ":00";
        })();

    const body = `
        ${!isEdit ? `<label>从常用模板快速填充</label>
        <select id="ce-tpl"><option value="">— 选择模板（可选）—</option>
            ${templates.map((t, i) => `<option value="${i}">${esc(t.country)} · ${esc(t.name)}</option>`).join("")}
        </select>` : ""}
        <div class="form-grid">
            <div><label>时间（北京时间）</label><input type="datetime-local" id="ce-at" value="${esc(dtVal)}"></div>
            <div><label>国家/地区</label><select id="ce-country">
                ${countries.map(c => `<option value="${esc(c)}" ${ev && ev.country === c ? "selected" : ""}>${esc(c)}</option>`).join("")}
            </select></div>
            <div><label>重要度</label><select id="ce-imp">
                ${[[3, "高（三颗星）"], [2, "中"], [1, "低"]].map(([v, l]) => `<option value="${v}" ${(ev ? ev.importance : 2) === v ? "selected" : ""}>${l}</option>`).join("")}
            </select></div>
            <div><label>单位</label><input id="ce-unit" placeholder="% / 万人" value="${esc(ev ? ev.unit || "" : "")}"></div>
        </div>
        <label>事件名称</label><input id="ce-name" placeholder="如：美国 11 月非农就业人数" value="${esc(ev ? ev.name : "")}">
        <div class="form-grid">
            <div><label>前值</label><input id="ce-prev" value="${esc(ev ? ev.previous || "" : "")}"></div>
            <div><label>预期</label><input id="ce-fore" value="${esc(ev ? ev.forecast || "" : "")}"></div>
            <div><label>公布值</label><input id="ce-act" placeholder="公布后回填" value="${esc(ev ? ev.actual || "" : "")}"></div>
        </div>
        <label>备注（可选）</label><input id="ce-note" placeholder="关注点、交易计划…" value="${esc(ev ? ev.note || "" : "")}">`;

    const foot = `<button class="btn btn-ghost" data-close>取消</button><button class="btn btn-primary" id="ce-save">${isEdit ? "保存修改" : "添加事件"}</button>`;
    const overlay = openModal(isEdit ? "编辑财经事件" : "新增财经事件", body, foot, null);
    overlay.querySelector(".modal")?.classList.add("lg");

    const tplSel = overlay.querySelector("#ce-tpl");
    if (tplSel) tplSel.addEventListener("change", () => {
        const t = templates[Number(tplSel.value)];
        if (!t) return;
        overlay.querySelector("#ce-name").value = t.name;
        overlay.querySelector("#ce-country").value = t.country;
        overlay.querySelector("#ce-imp").value = String(t.importance);
        overlay.querySelector("#ce-unit").value = t.unit || "";
    });

    overlay.querySelector("#ce-save").addEventListener("click", async () => {
        const at = overlay.querySelector("#ce-at").value;
        const name = overlay.querySelector("#ce-name").value.trim();
        if (!at) return toast("请选择时间", "error");
        if (!name) return toast("请填写事件名称", "error");
        const payload = {
            action: isEdit ? "update" : "create",
            id: isEdit ? ev.id : undefined,
            event_at: at.replace("T", " "),
            country: overlay.querySelector("#ce-country").value,
            name,
            importance: Number(overlay.querySelector("#ce-imp").value) || 2,
            unit: overlay.querySelector("#ce-unit").value.trim(),
            previous: overlay.querySelector("#ce-prev").value.trim(),
            forecast: overlay.querySelector("#ce-fore").value.trim(),
            actual: overlay.querySelector("#ce-act").value.trim(),
            note: overlay.querySelector("#ce-note").value.trim()
        };
        const { ok, data } = await api("/calendar", "POST", payload);
        if (!ok) return toast(data.message || "保存失败", "error");
        closeModal();
        toast(isEdit ? "已保存" : "已添加", "success");
        if (onDone) onDone();
    });
}

// ============================================================

// ---------- 修改密码 ----------
function openChangePassword() {
    const body = `<div class="form-row"><div class="full"><label>原密码 *</label><input type="password" id="cp-old"></div></div>
        <div class="form-row"><div class="full"><label>新密码（至少6位）*</label><input type="password" id="cp-new"></div></div>`;
    const foot = `<button class="btn btn-ghost" data-close>取消</button><button class="btn btn-primary" id="cp-save">确认修改</button>`;
    openModal("修改密码", body, foot, async () => {
        const { ok } = await api("/change-password", "POST", { oldPassword: $("#cp-old").value, newPassword: $("#cp-new").value });
        if (ok) { toast("密码已修改，请重新登录", "success"); closeModal(); setTimeout(logout, 800); }
        else toast("修改失败，请检查原密码", "error");
    });
}

// ---------- 模态框 ----------
function openModal(title, bodyHtml, footHtml, onSave) {
    const root = $("#modal-root");
    const overlay = el(`<div class="modal-overlay"><div class="modal">
        <div class="modal-head"><h3>${esc(title)}</h3><button class="modal-close" data-close><i class="fa-solid fa-xmark"></i></button></div>
        <div class="modal-body">${bodyHtml}</div><div class="modal-foot">${footHtml}</div></div></div>`);
    root.appendChild(overlay);
    overlay.addEventListener("click", e => { if (e.target === overlay || e.target.closest("[data-close]")) closeModal(); });
    const saveBtn = overlay.querySelector("#u-save, #cp-save");
    if (saveBtn && onSave) saveBtn.addEventListener("click", onSave);
    return overlay;
}
function closeModal() { $("#modal-root").innerHTML = ""; }
function confirmDelete(name, onConfirm, hint) {
    const body = `<p>确定要删除 <b>${esc(name)}</b> 吗？${esc(hint || "此操作不可撤销。")}</p>`;
    const foot = `<button class="btn btn-ghost" data-close>取消</button><button class="btn btn-danger" id="cd-yes">删除</button>`;
    const overlay = openModal("确认删除", body, foot, null);
    overlay.querySelector("#cd-yes").addEventListener("click", async () => { closeModal(); await onConfirm(); });
}

// ============================================================
// 通用小组件：涨跌徽标 / 迷你走势线 / 时间格式化
// ============================================================
function pctBadge(v, digits) {
    const n = Number(v) || 0;
    return `<span class="pct-badge ${n > 0 ? "up" : n < 0 ? "down" : "flat"}">${chgSign(n)}${metalPct(n, digits == null ? 2 : digits)}%</span>`;
}
// 迷你走势线（无坐标轴，只表达方向与幅度）
function sparkSvg(points, opts = {}) {
    const pts = (points || []).map(p => Number(p.c != null ? p.c : p)).filter(v => Number.isFinite(v));
    if (pts.length < 2) return `<span class="spark-empty">—</span>`;
    const W = opts.width || 96, H = opts.height || 26, pad = 2;
    const min = Math.min(...pts), max = Math.max(...pts), span = (max - min) || 1;
    const d = pts.map((v, i) => `${(pad + i / (pts.length - 1) * (W - pad * 2)).toFixed(1)},${(H - pad - (v - min) / span * (H - pad * 2)).toFixed(1)}`).join(" ");
    const up = pts[pts.length - 1] >= pts[0];
    const color = opts.color || (up ? "var(--up)" : "var(--down)");
    return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><polyline points="${d}" fill="none" stroke="${color}" stroke-width="1.6" stroke-linejoin="round"/></svg>`;
}
function shortTime(v) {
    const s = String(v || "");
    return s.length >= 16 ? s.slice(5, 16) : s;
}
// 数据库默认时间戳（SQLite CURRENT_TIMESTAMP 为 UTC 无时区字符串）→ 北京时间 MM-DD HH:mm
//   行情表的 updated_at 走这条；应用写入的北京时间字符串（如 last_* / published_at）不要用它。
function dbUtcTime(v) {
    const s = String(v || "").trim();
    if (!s) return "";
    // 已带时区标记的按原样解析
    const iso = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(s);
    const ms = iso ? Date.parse(s.replace(" ", "T")) : Date.parse(s.replace(" ", "T") + "Z");
    if (!Number.isFinite(ms)) return shortTime(s);
    return new Date(ms + 8 * 3600 * 1000).toISOString().slice(5, 16).replace("T", " ");
}
// 财经日历用：入参是「还有多少分钟」（分钟数而非时间戳）
function countdownMinText(mins) {
    const m = Number(mins);
    if (!Number.isFinite(m)) return "—";
    if (m < 0) return "已公布";
    if (m < 60) return `${m} 分钟后`;
    if (m < 1440) return `${Math.floor(m / 60)} 小时 ${m % 60} 分后`;
    return `${Math.floor(m / 1440)} 天后`;
}

// ============================================================
// 投资工作台（#desk）：一个页面装下「总览 / 实时行情 / 稀有金属」
//   过去「实时行情」「稀有金属」「消息中心」「持仓」是四张互不相干的页面，
//   用户得自己在脑子里拼：这条消息影响哪个品种？这个品种我现在有没有仓？要不要加自选？
//   现在全部收进工作台：左侧菜单切换子页，下方同一套标的池、消息面贯穿始终。
//   子标签通过 URL 表达（#desk?tab=quote），刷新 / 分享 / 前进后退都能对上。
// ============================================================
const DESK_TABS = [
    { key: "overview", label: "投资总览", icon: "fa-compass-drafting", title: "消息面总览" },
    { key: "quote", label: "实时行情", icon: "fa-chart-line", title: "贵金属报价 · 涨跌幅" },
    { key: "rare", label: "稀有金属研究", icon: "fa-gem", title: "稀有报价 · 材料联想" }
];
const deskState = { newsSymbol: "", data: null, tab: "overview" };

// 消息影响研判：默认只占一行（方向 + 影响标的 + 强度），展开才看传导链 / 依据 / 风险提示。
//   涨红跌绿沿用 A 股习惯；这是消息面规则推演，不是价格预测，不输出股价或涨跌幅。
const IMPACT_DIR_LABEL = { bullish: "偏涨", bearish: "偏跌", neutral: "方向不明" };
function parseImpactSafe(raw) {
    try { const o = JSON.parse(String(raw || "")); return (o && typeof o === "object") ? o : null; }
    catch (e) { return null; }
}
// 重点标记：算法判定的高重要性消息，在标题前点亮
function keyBadge(n) {
    if (!n.is_key) return "";
    const kp = parseImpactSafe(n.key_reasons);
    const rs = (kp && Array.isArray(kp.reasons)) ? kp.reasons : [];
    const tip = rs.length ? rs.join("；") : "综合评分达重点阈值";
    const score = Number(n.key_score) || 0;
    return `<span class="key-badge" title="重点消息 · 综合分 ${score}｜${esc(tip)}"><i class="fa-solid fa-star"></i>重点 ${score}</span>`;
}
function impactHtml(n, canManage) {
    const p = parseImpactSafe(n.impact);
    // 未命中规则的消息不加噪音；但人工改判过的必须显示，否则用户看不到自己的修正结果
    if (!p || ((!p.scope || p.scope === "none") && !p.manual)) return "";
    const dir = ["bullish", "bearish", "neutral"].includes(p.direction) ? p.direction : "neutral";
    const tone = dir === "bullish" ? "up" : dir === "bearish" ? "down" : "flat";
    const targets = (Array.isArray(p.targets) ? p.targets : []).map(x => x && x.name ? x.name : "").filter(Boolean);
    const chains = (Array.isArray(p.chains) ? p.chains : []).filter(Boolean);
    const hits = (Array.isArray(p.hits) ? p.hits : []).filter(Boolean);
    const manual = p.manual ? `<span class="ni-manual" title="已人工改判">人工</span>` : "";
    const fixBtns = canManage ? `<div class="ni-fix">
        <button class="ni-fix-btn" data-impact-fix="bullish" data-impact-id="${n.id}">改判偏涨</button>
        <button class="ni-fix-btn" data-impact-fix="bearish" data-impact-id="${n.id}">改判偏跌</button>
        <button class="ni-fix-btn" data-impact-fix="neutral" data-impact-id="${n.id}">方向不明</button>
    </div>` : "";
    return `<details class="news-impact ni-${tone}">
        <summary>
            <i class="fa-solid fa-chart-line"></i><span class="ni-label">研判</span>
            <span class="ni-dir">${esc(IMPACT_DIR_LABEL[dir])}</span>
            ${targets.length ? `<span class="ni-targets">${targets.map(t => esc(t)).join(" · ")}</span>` : ""}
            ${p.strength && p.strength !== "—" ? `<span class="ni-strength">${esc(p.strength)}</span>` : ""}
            ${manual}
        </summary>
        <div class="ni-body">
            ${p.event ? `<p><b>事件</b>：${esc(p.event)}</p>` : ""}
            ${chains.map(c => `<p><b>传导链</b>：${esc(c)}</p>`).join("")}
            ${!chains.length ? `<p><b>说明</b>：${p.manual ? "规则未识别到明确方向催化，方向由人工指定。" : "消息为中性陈述，未识别到明确方向催化，不强行给出涨跌结论。"}</p>` : ""}
            ${hits.length ? `<p><b>判定依据</b>：${esc(hits.join("、"))}</p>` : ""}
            ${n.is_key ? `<p><b>为何列为重点</b>：${esc(((parseImpactSafe(n.key_reasons) || {}).reasons || []).join("；") || "综合评分达重点阈值")}</p>` : ""}
            <p class="ni-warn">规则推演，仅反映消息面倾向；消息可能已被市场提前定价，不构成投资建议，也不代表实际价格走势。</p>
            ${fixBtns}
        </div>
    </details>`;
}

// 情绪标签：利多=红（涨），利空=绿（跌），与 A 股习惯一致
const SENT_LABEL = { bullish: "利多", bearish: "利空", neutral: "中性" };
function sentBadge(label, score, hits) {
    const l = SENT_LABEL[label] ? label : "neutral";
    const tip = score != null ? `（强度 ${Math.abs(score)}）` : "";
    const basis = (hits && hits.length) ? `｜判定依据：${hits.join("、")}` : "";
    const icon = l === "bullish" ? "fa-arrow-trend-up" : l === "bearish" ? "fa-arrow-trend-down" : "fa-minus";
    return `<span class="sent-tag sent-${l}" title="${SENT_LABEL[l]}${tip}${basis}"><i class="fa-solid ${icon}"></i>${SENT_LABEL[l]}</span>`;
}

// 相关消息：每条消息下方的标的标签。
//   标的池大表格删掉后，这里就是「从消息进入某个标的」的唯一入口 —— 点标签直接开决策面板。
//   排序：有关联标的的排前面（标的池删掉后，未关联标的的消息在总览里价值最低），
//   同组内仍按时间倒序，避免打乱时序感。
function deskNewsHtml(data) {
    const q = deskState.newsSymbol;
    const all = data.news || [];
    const list = q ? all.filter(n => (n.symbols || []).some(s => s.symbol === q)) : all;
    if (!list.length) return `<li class="desk-empty muted">${q ? "该标的近期没有关联消息" : "近期暂无消息，去「数据采集」页抓一次"}</li>`;
    const sorted = q ? list : list.slice().sort((a, b) => {
        const ta = (a.symbols || []).length ? 1 : 0;
        const tb = (b.symbols || []).length ? 1 : 0;
        return tb - ta;
    });
    return sorted.slice(0, 16).map(n => {
        const url = safeUrl(n.url);
        const title = url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(n.title)}</a>` : esc(n.title);
        // 标的标签带上「这条消息对该标的是利多还是利空」
        const tags = (n.symbols || []).slice(0, 3).map(s => `<button class="desk-tag" data-tag="${esc(s.symbol)}" data-name="${esc(s.name)}" title="打开 ${esc(s.name)} 的标的决策面板">${esc(s.name)}${sentBadge(s.sentiment, s.sentiment_score)}</button>`).join("");
        return `<li class="desk-news-item">
            <div class="dn-time">${esc(shortTime(n.published_at))}<span class="dn-src">${esc(n.platform || n.source || "")}</span></div>
            <div class="dn-title">${title}</div>
            <div class="dn-tags">${tags || `<span class="muted">未关联标的</span>`}</div>
        </li>`;
    }).join("");
}

// 我的关注：自选 / 有持仓 / 有建仓计划的品种，缩成一排可点的卡片。
//   标的池表格删除后，这是「没有相关消息但我仍在盯的品种」的入口。
function deskFocusHtml(data) {
    const inst = (data.instruments || []);
    const focus = inst.filter(r => r.watching || r.plan || r.position);
    if (!focus.length) {
        return `<div class="muted df-empty">还没有自选、持仓或建仓计划。在右侧消息里点标的标签进入决策面板，即可加自选 / 记持仓 / 建计划。</div>`;
    }
    return focus.map(r => {
        const marks = [];
        if (r.watching) marks.push("自选");
        if (r.position) marks.push("持仓");
        if (r.plan) marks.push("计划");
        const dir = r.change_pct > 0 ? "up" : r.change_pct < 0 ? "down" : "";
        return `<button class="desk-focus" data-open="${esc(r.symbol)}" title="打开 ${esc(r.name || r.short_name)} 的标的决策面板">
            <b>${esc(r.short_name)}</b>
            <span class="df-px ${dir}">${r.price ? metalNum(r.price) : "—"}</span>
            <small class="muted">${marks.join(" · ")}</small>
        </button>`;
    }).join("");
}

// 系统概览：把本系统各张统计表的「总体数字」汇总成一排卡片。
//   数据来自 /api/desk 的 overview 字段（消息库 / 消息面 / 行情 / 我的账本 / 日程预警），
//   口径与资讯中心完全一致（屏蔽词 + 四类相关性白名单），不会出现卡片与列表对不上。
function deskOverviewHtml(d) {
    const ov = d.overview || {};
    const st = d.stats || {};
    const sent = ov.sentiment || {};
    const sentTotal = (sent.bullish || 0) + (sent.bearish || 0) + (sent.neutral || 0);
    const bullPct = sentTotal ? Math.round((sent.bullish || 0) / sentTotal * 100) : 0;
    const bearPct = sentTotal ? Math.round((sent.bearish || 0) / sentTotal * 100) : 0;
    const pos = st.positions || {};
    const pnl = Number(pos.pnl || 0);
    const metal = st.metal || {};
    const rare = st.rare || {};
    const card = (icon, label, value, sub, tone, extra) => `<div class="stat-card ov-card">
        <span class="stat-icon"><i class="fa-solid ${icon}"></i></span>
        <div class="stat-label">${label}</div>
        <div class="stat-value"${tone ? ` style="color:${tone}"` : ""}>${value}</div>
        <div class="stat-sub">${sub}</div>
        ${extra || ""}
    </div>`;

    // 消息面分布条：利多（红）/ 中性（灰）/ 利空（绿），一眼看出整体倾向
    const dist = `<div class="ov-dist" title="全库消息面倾向：利多 ${sent.bullish || 0} · 利空 ${sent.bearish || 0} · 中性 ${sent.neutral || 0}">
        <span class="ov-dist-b" style="width:${bullPct}%"></span>
        <span class="ov-dist-n" style="width:${Math.max(0, 100 - bullPct - bearPct)}%"></span>
        <span class="ov-dist-s" style="width:${bearPct}%"></span>
    </div>
    <div class="ov-dist-legend muted"><span class="up">利多 ${sent.bullish || 0}</span><span>中性 ${sent.neutral || 0}</span><span class="down">利空 ${sent.bearish || 0}</span></div>`;

    // 涨跌分布条：涨 / 平 / 跌
    const scopeDist = (s, label) => {
        const up = s.up || 0, down = s.down || 0, flat = Math.max(0, (s.quoted || 0) - up - down);
        const tot = (s.quoted || 0) || 1;
        return `<div class="ov-dist" title="${label}：涨 ${up} · 平 ${flat} · 跌 ${down}">
            <span class="ov-dist-b" style="width:${up / tot * 100}%"></span>
            <span class="ov-dist-n" style="width:${flat / tot * 100}%"></span>
            <span class="ov-dist-s" style="width:${down / tot * 100}%"></span>
        </div>
        <div class="ov-dist-legend muted"><span class="up">涨 ${up}</span><span>平 ${flat}</span><span class="down">跌 ${down}</span></div>`;
    };

    return `<div class="ov-grid">
        ${card("fa-newspaper", "消息库", (ov.news_total || 0).toLocaleString(), `今日新增 <b class="ov-hl">${ov.news_today || 0}</b> 条`, "", `
            <div class="ov-chips">
                <a class="ov-chip" href="#news?key=1"><i class="fa-solid fa-star"></i>重点 ${ov.key_count || 0}</a>
                <a class="ov-chip" href="#news?starred=1"><i class="fa-solid fa-bookmark"></i>收藏 ${ov.starred || 0}</a>
            </div>`)}
        ${card("fa-chart-simple", "消息面倾向", bullPct >= bearPct ? `偏多 ${bullPct}%` : `偏空 ${bearPct}%`, `全库 ${sentTotal} 条的利多 / 利空占比`, bullPct >= bearPct ? "var(--up)" : "var(--down)", dist)}
        ${card("fa-coins", "贵金属", `${metal.up || 0} 涨 / ${metal.down || 0} 跌`, `${metal.quoted || 0} 个品种有报价 · 均幅 ${(metal.avg_pct || 0) > 0 ? "+" : ""}${(metal.avg_pct || 0).toFixed(2)}%`, (metal.avg_pct || 0) > 0 ? "var(--up)" : (metal.avg_pct || 0) < 0 ? "var(--down)" : "", scopeDist(metal, "贵金属"))}
        ${card("fa-gem", "稀有金属", `${rare.up || 0} 涨 / ${rare.down || 0} 跌`, `${rare.quoted || 0} 个品种有报价 · 均幅 ${(rare.avg_pct || 0) > 0 ? "+" : ""}${(rare.avg_pct || 0).toFixed(2)}%`, (rare.avg_pct || 0) > 0 ? "var(--up)" : (rare.avg_pct || 0) < 0 ? "var(--down)" : "", scopeDist(rare, "稀有金属"))}
        ${card("fa-briefcase", "我的账本", money(pos.market_value || 0), `浮动盈亏 ${pnl >= 0 ? "+" : ""}${money(pnl)} · ${st.positions && st.positions.count || 0} 个持仓`, pnl > 0 ? "var(--up)" : pnl < 0 ? "var(--down)" : "", `
            <div class="ov-chips">
                <a class="ov-chip" href="#portfolio"><i class="fa-solid fa-star"></i>自选 ${st.watch || 0}</a>
                <a class="ov-chip" href="#portfolio"><i class="fa-solid fa-clipboard-list"></i>计划 ${st.plans || 0}</a>
            </div>`)}
        ${card("fa-calendar-check", "日程与预警", `${ov.calendar_24h || 0} 个`, `24 小时内 ${ov.calendar_total || 0} 个财经事件 · 高重要度 ${ov.calendar_high || 0}`, "", `
            <div class="ov-chips">
                <a class="ov-chip" href="#calendar"><i class="fa-solid fa-bell"></i>预警 ${ov.alerts_active || 0}${ov.alerts_triggered ? ` · 今日 ${ov.alerts_triggered}` : ""}</a>
            </div>`)}
    </div>
    <div class="ov-foot muted">
        <i class="fa-solid fa-circle-info"></i>
        消息采集于 ${esc(shortTime(ov.last_news_refresh) || "—")} · 行情刷新于 ${esc(shortTime(ov.last_metal_refresh) || "—")} · 统计口径与资讯中心一致（四类相关 + 屏蔽词）
    </div>`;
}

// 重点信息：系统判定为「重点」的消息（按综合分排序）+ 即将到来的重要财经事件。
//   这是投资总览的「重点信息」栏 —— 让用户一眼看到今天最该看的那几条。
function deskKeyHtml(d) {
    const list = d.key_news || [];
    const evs = d.upcoming_events || [];
    const keyItems = list.length ? list.map(n => {
        const url = safeUrl(n.url);
        const title = url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(n.title)}</a>` : esc(n.title);
        const im = parseImpactSafe(n.impact);
        const dir = im && ["bullish", "bearish", "neutral"].includes(im.direction) ? im.direction : "";
        const tone = dir === "bullish" ? "up" : dir === "bearish" ? "down" : "";
        const dirLabel = dir ? IMPACT_DIR_LABEL[dir] : "";
        const targets = (im && Array.isArray(im.targets) ? im.targets : []).map(t => t && t.name ? t.name : "").filter(Boolean);
        const strength = im && im.strength && im.strength !== "—" ? im.strength : "";
        // 消息自带的标的标签（点击直接进决策面板）—— 与「相关消息」面板同一套入口
        const symTags = (n.symbols || []).slice(0, 3).map(s => {
            const sym = typeof s === "string" ? s : (s && s.symbol);
            const nm = typeof s === "string" ? s : (s && s.name);
            if (!sym) return "";
            return `<button class="desk-tag" data-tag="${esc(sym)}" data-name="${esc(nm || sym)}" title="打开 ${esc(nm || sym)} 的标的决策面板">${esc(nm || sym)}</button>`;
        }).join("");
        // 简报里已经包含标题（"标题 → 偏跌（影响 X） · 事件"），这里只取箭头后的结论部分，避免与标题重复
        const briefRaw = String(n.key_brief || "").trim();
        const brief = briefRaw.includes("→") ? briefRaw.split("→").slice(1).join("→").trim() : "";
        return `<li class="ov-key-item">
            <div class="ov-key-top">
                <span class="key-badge"><i class="fa-solid fa-star"></i>重点 ${Number(n.key_score) || 0}</span>
                ${dirLabel ? `<span class="ov-dir ${tone}">${esc(dirLabel)}</span>` : ""}
                ${strength ? `<span class="ov-strength">${esc(strength)}</span>` : ""}
                ${targets.length ? `<span class="ov-targets">${esc(targets.join(" · "))}</span>` : ""}
                <span class="ov-key-time muted">${esc(shortTime(n.published_at))}</span>
            </div>
            <div class="ov-key-title">${title}</div>
            ${symTags ? `<div class="dn-tags">${symTags}</div>` : ""}
            ${brief ? `<div class="ov-key-brief muted">${esc(brief)}</div>` : ""}
        </li>`;
    }).join("") : `<li class="ov-empty muted">暂无重点消息</li>`;

    const evItems = evs.length ? evs.map(e => {
        const imp = Number(e.importance) || 0;
        const impLabel = imp === 3 ? "高" : imp === 2 ? "中" : "低";
        const t = String(e.event_at || "");
        const md = t.length >= 16 ? t.slice(5, 16) : t;
        return `<li class="ov-ev-item">
            <span class="ov-ev-time">${esc(md)}</span>
            <span class="ov-ev-imp imp-${imp}">${impLabel}</span>
            <span class="ov-ev-name">${esc(e.name || "")}</span>
            <span class="ov-ev-country muted">${esc(e.country || "")}</span>
        </li>`;
    }).join("") : `<li class="ov-empty muted">未来 7 天暂无事件</li>`;

    return `<section class="panel desk-keyside">
        <div class="panel-head">
            <h3><i class="fa-solid fa-bolt"></i> 重点信息</h3>
            <small class="muted">重点消息 ${(d.overview || {}).key_count || 0} 条</small>
        </div>
        <div class="panel-body">
            <div class="ov-sub-head">重点消息</div>
            <ul class="ov-key-list">${keyItems}</ul>
            <div class="ov-sub-head">未来 7 天重要日程</div>
            <ul class="ov-ev-list">${evItems}</ul>
        </div>
    </section>`;
}

// 相关消息面板头部的状态位：被 ?symbol= 深链筛选时给一个可取消的标签
function deskNewsMetaHtml(data) {
    if (!deskState.newsSymbol) return `<span class="muted">全部标的</span>`;
    const hit = (data.instruments || []).find(r => r.symbol === deskState.newsSymbol);
    const name = hit ? (hit.short_name || hit.name) : deskState.newsSymbol;
    return `<button class="desk-chip active" data-clear="1" title="取消按标的筛选">只看 ${esc(name)} ✕</button>`;
}

function deskHtml(d) {
    const st = d.stats || {};
    const trend = d.news_trend || [];
    const trendTotal = trend.reduce((s, x) => s + (Number(x.count) || 0), 0);

    return `
    ${deskOverviewHtml(d)}
    <div class="desk-grid">
        <div class="desk-col">
            <section class="panel desk-main">
                <div class="panel-head">
                    <h3><i class="fa-solid fa-chart-column"></i> 近 14 天消息量</h3>
                    <small class="muted">近 14 天 ${trendTotal} 条 · 今日 ${st.news_today || 0} 条</small>
                </div>
                <div class="panel-body">
                    <div id="desk-trend">${newsTrendSvg(trend)}</div>
                    <div class="desk-focus-head"><span>我的关注</span><small class="muted">自选 / 持仓 / 建仓计划</small></div>
                    <div class="desk-focus-list" id="desk-focus">${deskFocusHtml(d)}</div>
                </div>
            </section>
            ${deskKeyHtml(d)}
        </div>
        <div class="desk-col">
            <section class="panel desk-side">
                <div class="panel-head"><h3><i class="fa-solid fa-newspaper"></i> 相关消息</h3>
                    <span id="desk-news-meta">${deskNewsMetaHtml(d)}</span></div>
                <div class="panel-body"><ul class="desk-news" id="desk-news">${deskNewsHtml(d)}</ul></div>
            </section>
        </div>
    </div>
    <div class="dash-foot muted">生成于 ${esc(d.generated_at)} · 行情刷新后自动更新（90 秒轮询）</div>`;
}

function refreshDeskParts(container) {
    const d = deskState.data;
    if (!d) return;
    const news = container.querySelector("#desk-news");
    if (news) news.innerHTML = deskNewsHtml(d);
    const meta = container.querySelector("#desk-news-meta");
    if (meta) meta.innerHTML = deskNewsMetaHtml(d);
    const focus = container.querySelector("#desk-focus");
    if (focus) focus.innerHTML = deskFocusHtml(d);
}

function bindDesk(container) {
    // 幂等绑定：reloadDeskData 会复用同一个 pane 反复调用本函数，
    // 若直接 addEventListener，委托会越叠越多，点一次标的就会弹出多个决策面板。
    if (container.__deskClickHandler) container.removeEventListener("click", container.__deskClickHandler);
    const handler = async e => {
        if (e.target.closest("[data-clear]")) { deskState.newsSymbol = ""; refreshDeskParts(container); return; }
        // 消息里的标的标签 → 直接进决策面板（行情 / 该标的消息 / 加自选 / 预警 / 持仓 / 建仓计划）
        const tag = e.target.closest("[data-tag]");
        if (tag) { openDeskDetail(tag.dataset.tag, tag.dataset.name); return; }
        const open = e.target.closest("[data-open]");
        if (open) { openDeskDetail(open.dataset.open); return; }
    };
    container.__deskClickHandler = handler;
    container.addEventListener("click", handler);
}

// 子页面（总览 / 行情 / 稀有金属）切换已迁移到左侧菜单（#desk?tab=…），
// 页面内不再渲染顶部标签栏；DESK_TABS 仅用于标题与 tab 参数校验。

function deskTabFromQuery() {
    const t = String(routerQuery.get("tab") || "overview").toLowerCase();
    return DESK_TABS.some(x => x.key === t) ? t : "overview";
}

async function viewDesk(container) {
    const seq = routerSeq;
    deskState.tab = deskTabFromQuery();
    // 从消息中心跳过来时可带 symbol，直接筛到该标的
    const sym = String(routerQuery.get("symbol") || "").toUpperCase();
    if (sym) deskState.newsSymbol = sym;
    const meta = DESK_TABS.find(t => t.key === deskState.tab);
    // 子页面切换已由左侧菜单（#desk?tab=…）承担，页面内不再渲染重复的标签栏
    $("#view-title").textContent = meta ? meta.label : "投资总览";

    container.innerHTML = `<div id="desk-pane"></div>`;
    const pane = container.querySelector("#desk-pane");
    if (!pane) return;

    // —— 实时行情标签：直接复用原「实时行情」页的渲染 ——
    if (deskState.tab === "quote") {
        await viewMetalsQuote(pane);
        return;
    }
    // —— 稀有金属标签：复用「稀有金属研究」页 ——
    if (deskState.tab === "rare") {
        await viewRare(pane);
        return;
    }

    // —— 投资总览 ——
    async function render(silent) {
        const { ok, data } = await api("/desk");
        if (seq !== routerSeq) return;
        if (!ok) { if (!silent) pane.innerHTML = errorHtml(data.message || "工作台加载失败"); return; }
        deskState.data = data;
        const y = window.scrollY;
        pane.innerHTML = deskHtml(data);
        if (!silent) bindDesk(pane);
        else window.scrollTo(0, y);
    }
    await render(false).catch(e => { if (seq === routerSeq) pane.innerHTML = errorHtml(e.message); });
    // 自动刷新：与行情页同源配置（数据采集 → 贵金属数据区 → 行情页刷新间隔，默认 10 秒）；
    // 总览要做持仓 / 消息 / 预警的聚合计算，最密 30 秒一次（服务端聚合已缓存 3 分钟），
    //   再快也只是重复读缓存，纯属浪费请求配额；标签页在后台时暂停轮询。
    const refreshMs = () => Math.max(30, Number((deskState.data || {}).live_sec) || 10) * 1000;
    const tick = () => {
        if (seq !== routerSeq) return;
        // 标签页在后台 / 窗口最小化时不轮询（回来最多等一个周期就会补上），
        //   否则「网页挂着不看」会白烧一天的读配额。
        if (document.hidden) { viewTimer = setTimeout(tick, refreshMs()); return; }
        render(true).catch(() => {}).then(() => {
            if (seq !== routerSeq) return;
            viewTimer = setTimeout(tick, refreshMs());
        });
    };
    stopViewTimer();
    viewTimer = setTimeout(tick, refreshMs());
}

// 标的决策面板：行情 + 该标的的消息（带利多利空判定与人工修正）+ 建仓计划 + 动作
//   标的池表格删除后，入口有两个：投资总览「相关消息」里的标的标签、以及「我的关注」卡片。
//   nameHint 用于消息里出现但不在品种池里的标的（如历史遗留代码），这时没有行情数据。
async function openDeskDetail(symbol, nameHint) {
    const d = deskState.data || {};
    const found = (d.instruments || []).find(x => x.symbol === symbol);
    const r = found || {
        symbol,
        name: nameHint || symbol,
        short_name: nameHint || symbol,
        scope: "", kind: "", market: "", chain: "", unit: "",
        price: 0, change: 0, change_pct: 0, amplitude: 0,
        quote_time: "", updated_at: "",
        news_count: (d.news || []).filter(n => (n.symbols || []).some(s => s.symbol === symbol)).length,
        news_sentiment: null,
        watching: false, alert_count: 0, plan: null, position: null
    };
    const pos = r.position;
    const canConfig = state.user.role === "admin" || state.user.permissions.includes("market.config");
    const canManageNews = state.user.role === "admin" || state.user.permissions.includes("news.manage");
    const plan = r.plan;
    const ns = r.news_sentiment;
    const sentLine = ns
        ? `<div><span>消息面</span><b class="sent-sum">
            <span class="sent-tag sent-bullish">利多 ${ns.bullish || 0}</span>
            <span class="sent-tag sent-bearish">利空 ${ns.bearish || 0}</span>
            <span class="sent-tag sent-neutral">中性 ${ns.neutral || 0}</span>
           </b></div>`
        : "";
    const planLine = plan ? `<div><span>建仓计划</span><b>目标 ${metalNum(plan.target_price)} / 止损 ${metalNum(plan.stop_loss)}</b>
        <small class="muted">${plan.to_target_pct != null ? `距目标 ${plan.to_target_pct >= 0 ? "" : "已过"}${Math.abs(plan.to_target_pct).toFixed(1)}%` : ""}${plan.risk_reward ? ` · 盈亏比 ${plan.risk_reward}` : ""}</small></div>` : "";
    const body = `<div class="dd-wrap">
        <div class="dd-head">
            <div>
                <b class="dd-name">${esc(r.name || r.short_name)}</b>
                <span class="muted">${esc(r.symbol)} · ${esc(r.market || "")} · ${esc(r.kind || "")}${r.chain ? " · " + esc(r.chain) : ""}</span>
            </div>
            <div class="dd-price">
                <b>${r.price ? metalNum(r.price) : "—"}</b>
                <span class="muted">${esc(r.unit || "")}</span>
                ${pctBadge(r.change_pct)}
            </div>
        </div>
        <div class="dd-metrics">
            <div><span>日内振幅</span><b>${r.price ? metalPct(r.amplitude, 2) + "%" : "—"}</b></div>
            <div><span>涨跌额</span><b style="color:${chgColor(r.change)}">${chgSign(r.change)}${metalNum(r.change)}</b></div>
            <div><span>相关消息</span><b>${r.news_count || 0} 条</b></div>
            ${sentLine}
            <div><span>我的持仓</span><b style="color:${pos ? chgColor(pos.pnl) : "inherit"}">${pos ? `${metalNum(pos.qty, 0)} · ${chgSign(pos.pnl_pct)}${metalPct(pos.pnl_pct, 2)}%` : "未建仓"}</b></div>
            ${planLine}
            <div><span>报价时间</span><b>${esc(r.quote_time || dbUtcTime(r.updated_at) || "—")}</b></div>
        </div>
        <div class="dd-actions">
            ${state.user && state.user.role !== "visitor" ? `<button class="btn btn-sm ${r.watching ? "" : "btn-primary"}" id="dd-star"><i class="fa-${r.watching ? "solid" : "regular"} fa-star"></i> ${r.watching ? "已在自选，点击移出" : "加入自选"}</button>
            <button class="btn btn-sm ${plan ? "" : "btn-primary"}" id="dd-plan"><i class="fa-solid fa-clipboard-list"></i> ${plan ? "编辑建仓计划" : "建仓计划"}</button>` : ""}
            ${canConfig ? `<button class="btn btn-sm" id="dd-alert"><i class="fa-solid fa-bell"></i> 设价格预警</button>` : ""}
            ${state.user && state.user.role !== "visitor" ? `<button class="btn btn-sm" id="dd-pos"><i class="fa-solid fa-plus"></i> 记一笔持仓</button>` : ""}
            <a class="btn btn-sm btn-ghost" href="#desk?tab=quote">完整行情</a>
        </div>
        <div class="dd-alert" id="dd-alert-box" hidden>
            <div class="form-row">
                <div><label>触发条件</label><select id="dd-dir">
                    <option value="above">价格上破</option><option value="below">价格下破</option>
                    <option value="rise">涨幅达到</option><option value="fall">跌幅达到</option>
                </select></div>
                <div><label>阈值</label><input type="number" id="dd-target" step="0.01" placeholder="${r.price ? metalNum(r.price) : "价格"}"></div>
            </div>
            <div class="dd-alert-foot"><button class="btn btn-primary btn-sm" id="dd-alert-save">保存预警</button>
                <span class="muted">到价后写入通知中心，并推送到已配置的 Webhook</span></div>
        </div>
        <div class="dd-section-title">这条标的的消息
            <small class="muted">${canManageNews ? "点右侧的利多/利空可人工修正（规则判定难免有误，人说了算）" : "利多利空由系统按标的自动判定"}</small></div>
        <ul class="desk-news dd-news" id="dd-news"><li class="muted">加载中…</li></ul>
        <div class="dd-more" id="dd-more"></div>
    </div>`;
    const overlay = openModal("标的决策 · " + (r.short_name || r.symbol), body, `<button class="btn btn-ghost" data-close>关闭</button>`, null);

    const starBtn = overlay.querySelector("#dd-star");
    if (starBtn) starBtn.addEventListener("click", async (ev) => {
        const btn = ev.currentTarget;
        const { ok, data } = await api("/watchlist", "POST", { action: "toggle", symbol: r.symbol });
        if (!ok) return toast(data.message || "操作失败", "error");
        r.watching = !!data.watching;
        btn.className = `btn btn-sm${r.watching ? "" : " btn-primary"}`;
        btn.innerHTML = `<i class="fa-${r.watching ? "solid" : "regular"} fa-star"></i> ${r.watching ? "已在自选，点击移出" : "加入自选"}`;
        toast(data.message || "已更新", "success");
        refreshDeskIfOverview();
    });

    const planBtn = overlay.querySelector("#dd-plan");
    if (planBtn) planBtn.addEventListener("click", () => {
        closeModal();
        openTradePlanModal(symbol);
    });

    const alertBtn = overlay.querySelector("#dd-alert");
    if (alertBtn) {
        alertBtn.addEventListener("click", () => {
            const box = overlay.querySelector("#dd-alert-box");
            box.hidden = !box.hidden;
            if (!box.hidden) overlay.querySelector("#dd-target").focus();
        });
        overlay.querySelector("#dd-alert-save").addEventListener("click", async () => {
            const target = Number(overlay.querySelector("#dd-target").value);
            if (!(target > 0)) return toast("请填写大于 0 的阈值", "error");
            const { ok, data } = await api("/alerts", "POST", {
                action: "create", symbol: r.symbol, direction: overlay.querySelector("#dd-dir").value, target, cooldown_min: 30
            });
            if (!ok) return toast(data.message || "保存失败", "error");
            toast(data.message || "预警已创建", "success");
            overlay.querySelector("#dd-alert-box").hidden = true;
        });
    }

    const posBtn = overlay.querySelector("#dd-pos");
    if (posBtn) posBtn.addEventListener("click", () => {
        closeModal();
        openPositionModal(null, [{ symbol: r.symbol, name: r.name || r.short_name, unit: r.unit }], () => {
            refreshDeskIfOverview();
        });
    });

    const { ok, data } = await api("/news?symbol=" + encodeURIComponent(r.symbol) + "&limit=8&days=30");
    const ul = overlay.querySelector("#dd-news");
    if (!ul) return;
    if (!ok) { ul.innerHTML = `<li class="muted">消息加载失败</li>`; return; }
    const rows = data.rows || [];
    ul.innerHTML = rows.length ? rows.map(n => {
        const url = safeUrl(n.url);
        // 该消息对当前标的的判定：优先取按标的的明细，其次回退到整体判定
        const sm = parseSentMap(n.sentiment_map);
        const me = sm[r.symbol] || null;
        const label = (me && me.label) || n.sentiment || "neutral";
        const score = me && me.score != null ? me.score : 0;
        const hits = (me && me.hits && me.hits.length) ? me.hits : [];
        const fix = canManageNews ? `<span class="sent-fix">
            <button class="sent-mini sent-bullish${label === "bullish" ? " on" : ""}" data-fix="bullish" title="判定为利多">利多</button>
            <button class="sent-mini sent-bearish${label === "bearish" ? " on" : ""}" data-fix="bearish" title="判定为利空">利空</button>
            <button class="sent-mini sent-neutral${label === "neutral" ? " on" : ""}" data-fix="neutral" title="中性 / 不明确">中性</button>
        </span>` : "";
        return `<li class="desk-news-item" data-news-id="${n.id}">
            <div class="dn-time">${esc(shortTime(n.published_at))}<span class="dn-src">${esc(n.platform || n.source || "")}</span>${sentBadge(label, score)}${hits.length ? `<span class="sent-hits">命中：${esc(hits.join("、"))}</span>` : ""}</div>
            <div class="dn-title">${url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(n.title)}</a>` : esc(n.title)}</div>
            ${fix}
        </li>`;
    }).join("") : `<li class="muted">近 30 天没有命中该标的的消息</li>`;

    // 人工修正利多利空：改后写入 manual 标记，重算规则不会覆盖
    if (canManageNews) {
        ul.querySelectorAll("[data-fix]").forEach(b => b.addEventListener("click", async () => {
            const li = b.closest("[data-news-id]");
            const id = li && li.dataset.newsId;
            if (!id) return;
            const { ok: ok2, data: d2 } = await api("/news", "POST", { action: "sentiment", id: Number(id), symbol: r.symbol, label: b.dataset.fix });
            if (!ok2) return toast(d2.message || "修正失败", "error");
            toast(d2.message || "已修正", "success");
            // 面板内即时更新
            ul.querySelectorAll("[data-fix]").forEach(x => x.classList.toggle("on", x.dataset.fix === b.dataset.fix));
            const bd = ul.querySelector(`[data-news-id="${id}"] .sent-tag`);
            if (bd) { bd.className = "sent-tag sent-" + b.dataset.fix; bd.textContent = SENT_LABEL[b.dataset.fix] || "中性"; }
            refreshDeskIfOverview();
        }));
    }

    // 消息多了不在弹窗里翻页，直接跳到消息中心并带上标的筛选
    const more = overlay.querySelector("#dd-more");
    if (more) {
        const total = data.total || rows.length;
        more.innerHTML = total > rows.length
            ? `<a class="btn btn-sm btn-ghost" href="#news?symbol=${encodeURIComponent(r.symbol)}">查看全部 ${total} 条消息 →</a>`
            : "";
    }
}

// 解析 sentiment_map（前端也要能容忍脏数据）
function parseSentMap(raw) {
    if (!raw) return {};
    if (typeof raw === "object") return raw;
    try {
        const o = JSON.parse(String(raw));
        return (o && typeof o === "object" && !Array.isArray(o)) ? o : {};
    } catch { return {}; }
}

// 工作台在总览标签时才刷新（其它标签由各自的渲染器负责）
function refreshDeskIfOverview() {
    if (deskState.tab !== "overview") return;
    const pane = document.querySelector("#desk-pane");
    if (pane && deskState.data) refreshDeskParts(pane);
}

// 建仓计划弹窗：目标价 / 止损价 / 分批价位
//   分批用「价位 + 占比」表达：比如 3 笔各占 30/30/40，
//   占比合计必须 100%，避免「到底买多少」说不清。
//   ctx 可传 { plan, row, onDone }：从「持仓与计划」页打开时，
//   工作台数据（deskState.data）里没有这个标的，要由调用方把计划与行情带进来。
// ============================================================
function openTradePlanModal(symbol, ctx) {
    const c = ctx || {};
    const d = deskState.data || {};
    const inst = (d.instruments || []).find(x => x.symbol === symbol);
    const plan = c.plan || (inst && inst.plan) || null;
    const r = inst || c.row || {
        symbol,
        short_name: (plan && (plan.short_name || plan.name)) || symbol,
        kind: (plan && plan.kind) || "",
        unit: (plan && plan.unit) || "",
        price: (plan && Number(plan.price)) || 0,
        change_pct: 0
    };
    const price = r.price || 0;
    const tranches = (plan && plan.tranches && plan.tranches.length)
        ? plan.tranches
        : [{ price: 0, pct: 50 }, { price: 0, pct: 50 }];
    const body = `<div class="tp-wrap">
        <div class="tp-head">
            <div><b>${esc(r.short_name)}</b><span class="muted">${esc(r.symbol)} · ${esc(r.kind || "")}</span></div>
            <div class="tp-now">现价 <b>${price ? metalNum(price) : "—"}</b>${r.unit ? `<small class="muted"> ${esc(r.unit)}</small>` : ""} ${pctBadge(r.change_pct)}</div>
        </div>
        <div class="form-row">
            <div><label>目标价（止盈）*</label><input type="number" id="tp-target" step="0.01" value="${plan ? plan.target_price : ""}" placeholder="${price ? metalNum(price) : "目标价"}"></div>
            <div><label>止损价 *</label><input type="number" id="tp-stop" step="0.01" value="${plan ? plan.stop_loss : ""}" placeholder="${price ? metalNum(price) : "止损价"}"></div>
            <div><label>计划均价（参考）</label><input type="number" id="tp-entry" step="0.01" value="${plan ? plan.entry_price : ""}" placeholder="可选"></div>
            <div><label>状态</label><select id="tp-status">
                <option value="planning"${plan && plan.status === "planning" ? " selected" : ""}>准备中</option>
                <option value="active"${plan && plan.status === "active" ? " selected" : ""}>执行中</option>
                <option value="done"${plan && plan.status === "done" ? " selected" : ""}>已完成</option>
                <option value="cancelled"${plan && plan.status === "cancelled" ? " selected" : ""}>已取消</option>
            </select></div>
        </div>
        <div class="tp-batches">
            <div class="tp-batches-head"><label>分批建仓价位</label>
                <button class="btn btn-sm btn-ghost" id="tp-add"><i class="fa-solid fa-plus"></i> 加一批</button></div>
            <div class="tp-batch-rows" id="tp-rows">
                ${tranches.map((t, i) => tpBatchRowHtml(t, i)).join("")}
            </div>
            <p class="muted tp-tip">占比合计需为 100%。价位留 0 表示「到价再定」，系统会按现价从上到下提示哪一批可以下手。</p>
        </div>
        <div class="form-row">
            <div class="full"><label>备注</label><input type="text" id="tp-note" value="${plan ? esc(plan.note || "") : ""}" placeholder="如：等非农数据落地再动手"></div>
        </div>
        <div class="tp-live" id="tp-live"></div>
    </div>`;
    const foot = `<button class="btn btn-ghost" data-close>取消</button>
        ${plan ? `<button class="btn btn-danger" id="tp-del">删除计划</button>` : ""}
        <button class="btn btn-primary" id="tp-save">保存计划</button>`;
    const overlay = openModal("建仓计划 · " + (r.short_name || r.symbol), body, foot, null);

    const rowsBox = overlay.querySelector("#tp-rows");
    const liveBox = overlay.querySelector("#tp-live");
    // 分批价位的占比合计 + 现价对照
    const refreshLive = () => {
        const rows = readTpRows(rowsBox);
        const sum = rows.reduce((s, t) => s + (Number(t.pct) || 0), 0);
        const filled = rows.filter(t => Number(t.price) > 0).sort((a, b) => b.price - a.price);
        const ready = price > 0 ? filled.filter(t => price <= t.price) : [];
        const wait = price > 0 ? filled.filter(t => price > t.price) : [];
        liveBox.innerHTML = `<div class="tp-live-row">
            <span class="${Math.abs(sum - 100) < 0.5 ? "ok" : "warn"}">占比合计 ${sum.toFixed(0)}%${Math.abs(sum - 100) < 0.5 ? " ✓" : "（需为 100%）"}</span>
            <span class="muted">可下手 ${ready.length} 批 · 待触发 ${wait.length} 批</span>
        </div>` + (filled.length ? `<ul class="tp-live-list">${filled.map((t, i) => `<li class="${price > 0 && price <= t.price ? "hit" : ""}">
            <span>第 ${i + 1} 批</span><b>${metalNum(t.price)}</b><span class="muted">${Math.round(t.pct || 0)}%</span>
            <span class="muted">${price <= 0 ? "暂无现价" : (price <= t.price ? "现价已到，可下手" : `距触发还差 ${(((price - t.price) / price) * 100).toFixed(1)}%`)}</span>
        </li>`).join("")}</ul>` : "");
    };
    rowsBox.addEventListener("input", refreshLive);
    overlay.querySelector("#tp-add").addEventListener("click", () => {
        const rows = readTpRows(rowsBox);
        rows.push({ price: 0, pct: 0 });
        rowsBox.innerHTML = rows.map((t, i) => tpBatchRowHtml(t, i)).join("");
        refreshLive();
    });
    rowsBox.addEventListener("click", e => {
        const del = e.target.closest("[data-del-row]");
        if (!del) return;
        const rows = readTpRows(rowsBox);
        if (rows.length <= 1) return toast("至少保留一批", "error");
        rows.splice(Number(del.dataset.delRow), 1);
        rowsBox.innerHTML = rows.map((t, i) => tpBatchRowHtml(t, i)).join("");
        refreshLive();
    });
    refreshLive();

    overlay.querySelector("#tp-save").addEventListener("click", async () => {
        const rows = readTpRows(rowsBox);
        const sum = rows.reduce((s, t) => s + (Number(t.pct) || 0), 0);
        if (Math.abs(sum - 100) > 0.5) return toast(`分批占比合计需为 100%（当前 ${sum.toFixed(1)}%）`, "error");
        const body2 = {
            action: "save",
            id: plan ? plan.id : 0,
            symbol: r.symbol,
            target_price: Number(overlay.querySelector("#tp-target").value),
            stop_loss: Number(overlay.querySelector("#tp-stop").value),
            entry_price: Number(overlay.querySelector("#tp-entry").value),
            status: overlay.querySelector("#tp-status").value,
            note: overlay.querySelector("#tp-note").value,
            tranches: rows
        };
        const { ok, data } = await api("/trade-plans", "POST", body2);
        if (!ok) return toast(data.message || "保存失败", "error");
        toast(data.message || "已保存", "success");
        closeModal();
        await reloadDeskData();
        if (c.onDone) c.onDone();
    });

    const delBtn = overlay.querySelector("#tp-del");
    if (delBtn) delBtn.addEventListener("click", async () => {
        const { ok, data } = await api("/trade-plans", "POST", { action: "delete", id: plan.id });
        if (!ok) return toast(data.message || "删除失败", "error");
        toast(data.message || "已删除", "success");
        closeModal();
        await reloadDeskData();
        if (c.onDone) c.onDone();
    });
}

function tpBatchRowHtml(t, i) {
    return `<div class="tp-batch-row" data-row="${i}">
        <span class="tp-bi muted">第 ${i + 1} 批</span>
        <input type="number" step="0.01" class="tp-bp" data-f="price" value="${t.price || ""}" placeholder="价位">
        <span class="muted">元</span>
        <input type="number" step="1" min="0" max="100" class="tp-bp" data-f="pct" value="${t.pct != null ? t.pct : ""}" placeholder="占比">
        <span class="muted">%</span>
        <button class="icon-btn danger" data-del-row="${i}" title="删除这一批"><i class="fa-solid fa-trash"></i></button>
    </div>`;
}

function readTpRows(rowsBox) {
    return Array.from(rowsBox.querySelectorAll(".tp-batch-row")).map(row => ({
        price: Number(row.querySelector('[data-f="price"]').value) || 0,
        pct: Number(row.querySelector('[data-f="pct"]').value) || 0
    }));
}

// 重新拉一次工作台数据并重绘（建仓计划 / 自选变更后调用）
async function reloadDeskData() {
    if (deskState.tab !== "overview") return;
    const pane = document.querySelector("#desk-pane");
    if (!pane) return;
    const { ok, data } = await api("/desk");
    if (!ok) return;
    deskState.data = data;
    pane.innerHTML = deskHtml(data);
    bindDesk(pane);
}

// ============================================================
// 稀有金属（#rare）：报价 + 材料联想
// ============================================================
// —— 稀有金属品种管理：库驱动，增删改后采集 / 推演同步生效 ——
async function openRareInstrumentManager(onSaved, prefill) {
    const { ok, data } = await api("/rare/instruments");
    if (!ok) return toast(data.message || "品种列表加载失败", "error");
    const st = { rows: data.rows || [], editing: "" };
    const prefixes = data.prefixes || [];
    const kinds = data.kinds || [], markets = data.markets || [];

    const body = `<div class="ri-wrap">
        <p class="ri-intro muted">品种由数据库驱动：这里增删改后，<b>行情采集、技术面指标</b>会同步变化。内置品种可停用但不可删除；「检测」会同时验证新浪行情与东财 K 线。</p>
        <div class="ri-form" id="ri-form">
            <div class="ri-form-title" id="ri-form-title">新增品种</div>
            <div class="form-row">
                <div><label>品种代码</label><input id="ri-symbol" placeholder="如 AO0、CU0、LC0" autocomplete="off"></div>
                <div><label>行情前缀</label><select id="ri-prefix">${prefixes.map(p => `<option value="${esc(p.value)}" title="${esc(p.hint || "")}">${esc(p.label)}</option>`).join("")}</select></div>
                <div><label>名称</label><input id="ri-name" placeholder="如 氧化铝主连" autocomplete="off"></div>
                <div><label>简称</label><input id="ri-short" placeholder="留空自动截取" autocomplete="off"></div>
                <div><label>市场</label><input id="ri-market" list="ri-markets" placeholder="上期所 / 广期所" autocomplete="off"><datalist id="ri-markets">${markets.map(m => `<option value="${esc(m)}"></option>`).join("")}</datalist></div>
                <div><label>类别</label><input id="ri-kind" list="ri-kinds" placeholder="锂 / 镍 / 锡 / 铝" autocomplete="off"><datalist id="ri-kinds">${kinds.map(k => `<option value="${esc(k)}"></option>`).join("")}</datalist></div>
                <div><label>单位</label><input id="ri-unit" placeholder="元/吨" autocomplete="off"></div>
                <div><label>东财 secid <span class="muted">（K 线 / 技术面用，可留空）</span></label><input id="ri-em" placeholder="如 113.AOM" autocomplete="off"></div>
                <div class="full"><label>产业链</label><input id="ri-chain" placeholder="如 电解铝/铝土" autocomplete="off"></div>
            </div>
            <div class="ri-form-foot">
                <label class="ri-check"><input type="checkbox" id="ri-enabled" checked> 启用（停用则不采集、页面不展示）</label>
                <div class="ri-form-actions">
                    <span class="ri-test-out" id="ri-test-out"></span>
                    <button class="btn btn-ghost btn-sm" id="ri-test"><i class="fa-solid fa-vial"></i> 检测</button>
                    <button class="btn btn-primary btn-sm" id="ri-save"><i class="fa-solid fa-check"></i> 保存</button>
                    <button class="btn btn-ghost btn-sm" id="ri-reset">清空</button>
                </div>
            </div>
        </div>
        <div class="table-wrap ri-table"><table>
            <thead><tr><th>代码</th><th>名称</th><th>类别</th><th>市场</th><th>行情代码</th><th>最新价</th><th>状态</th><th>操作</th></tr></thead>
            <tbody id="ri-rows"></tbody>
        </table></div>
        <div class="ri-sum muted" id="ri-sum"></div>
    </div>`;

    const overlay = openModal("稀有金属品种管理", body, `<button class="btn btn-ghost" data-close>关闭</button>`, null);
    overlay.querySelector(".modal").classList.add("lg");
    const q = s => overlay.querySelector(s);
    const val = id => (q("#" + id) || {}).value || "";

    function fillForm(r) {
        st.editing = r ? r.symbol : "";
        q("#ri-form-title").textContent = r ? `编辑 ${r.symbol}` : "新增品种";
        q("#ri-symbol").value = r ? r.symbol : "";
        q("#ri-symbol").disabled = !!r;   // 代码是主键，编辑时不允许改
        const p = r && r.sina ? String(r.sina).split("_")[0] : "nf";
        q("#ri-prefix").value = ["nf", "hf", "gds"].includes(p) ? p : "nf";
        q("#ri-name").value = r ? r.name : "";
        q("#ri-short").value = r ? (r.short_name || "") : "";
        q("#ri-market").value = r ? (r.market || "") : "";
        q("#ri-kind").value = r ? (r.kind || "") : "";
        q("#ri-unit").value = r ? (r.unit || "") : "";
        q("#ri-em").value = r ? (r.em || "") : "";
        q("#ri-chain").value = r ? (r.chain || "") : "";
        q("#ri-enabled").checked = r ? !!r.enabled : true;
        q("#ri-test-out").innerHTML = "";
    }

    function renderRows() {
        const tb = q("#ri-rows");
        tb.innerHTML = st.rows.map(r => `<tr>
            <td><b>${esc(r.symbol)}</b></td>
            <td>${esc(r.name)}${r.builtin ? `<span class="ri-badge">内置</span>` : ""}</td>
            <td>${esc(r.kind || "—")}</td>
            <td>${esc(r.market || "—")}</td>
            <td><code class="ri-code">${esc(r.sina)}</code></td>
            <td class="num">${r.quote ? `${metalNum(r.quote.price)} ${pctBadge(r.quote.change_pct)}` : `<span class="muted">未采集</span>`}</td>
            <td><span class="ri-state ${r.enabled ? "on" : "off"}">${r.enabled ? "启用" : "停用"}</span></td>
            <td class="ri-ops">
                <button class="btn btn-ghost btn-sm" data-edit="${esc(r.symbol)}">编辑</button>
                <button class="btn btn-ghost btn-sm" data-test="${esc(r.symbol)}">检测</button>
                <button class="btn btn-ghost btn-sm" data-toggle="${esc(r.symbol)}">${r.enabled ? "停用" : "启用"}</button>
                ${r.builtin ? "" : `<button class="btn btn-ghost btn-sm ac-danger" data-del="${esc(r.symbol)}">删除</button>`}
            </td>
        </tr>`).join("") || `<tr><td colspan="8" class="empty">还没有配置品种</td></tr>`;
        const on = st.rows.filter(r => r.enabled).length;
        const sum = q("#ri-sum");
        if (sum) sum.textContent = `共 ${st.rows.length} 个品种 · 启用 ${on} 个 · 停用 ${st.rows.length - on} 个`;
    }

    async function reload() {
        const { ok: ok2, data: d2 } = await api("/rare/instruments");
        if (!ok2) return;
        st.rows = d2.rows || [];
        renderRows();
    }

    async function doTest(payload) {
        const out = q("#ri-test-out");
        out.innerHTML = `<span class="ri-sub"><i class="fa-solid fa-spinner fa-spin"></i> 检测中…</span>`;
        const { ok: ok2, data: res } = await api("/rare/instruments/test", "POST", payload);
        if (!ok2) { out.innerHTML = `<span class="ri-bad">检测请求失败</span>`; return null; }
        if (!res.success) {
            out.innerHTML = `<span class="ri-bad"><i class="fa-solid fa-xmark"></i> ${esc(res.message)}</span>`;
            return res;
        }
        const qt = res.quote || {};
        const k = res.kline;
        out.innerHTML = `<span class="ri-ok"><i class="fa-solid fa-check"></i> ${esc(qt.name || res.sina)} ${metalNum(qt.price)}</span>
            <span class="ri-sub">昨收 ${metalNum(qt.prev_close)}</span>
            ${pctBadge(qt.change_pct)}
            <span class="ri-sub ${k && !k.ok ? "ri-bad" : ""}">${k ? (k.ok ? `K 线 ✓ ${k.bars} 根` : esc(k.message)) : "未填 secid，无 K 线"}</span>`;
        return res;
    }

    function payloadFromForm() {
        return {
            symbol: val("ri-symbol").toUpperCase(),
            prefix: val("ri-prefix"),
            name: val("ri-name"),
            short_name: val("ri-short"),
            market: val("ri-market"),
            kind: val("ri-kind"),
            unit: val("ri-unit"),
            em: val("ri-em"),
            chain: val("ri-chain"),
            enabled: q("#ri-enabled").checked
        };
    }

    q("#ri-test").addEventListener("click", async () => {
        const p = payloadFromForm();
        if (!p.symbol) return toast("先填品种代码，如 AO0", "error");
        const res = await doTest({ symbol: p.symbol, prefix: p.prefix, em: p.em });
        // 名称空着时顺手回填接口返回的中文名，少打一遍字
        if (res && res.success && !val("ri-name") && res.quote && res.quote.name) q("#ri-name").value = res.quote.name;
        if (res && res.success && !val("ri-unit")) q("#ri-unit").value = p.prefix === "hf" ? "美元/盎司" : "元/吨";
    });

    q("#ri-save").addEventListener("click", async () => {
        const p = payloadFromForm();
        if (!p.symbol) return toast("品种代码不能为空", "error");
        if (!p.name) return toast("品种名称不能为空", "error");
        const { ok: ok2, data: res } = await api("/rare/instruments", "POST", p);
        if (!ok2) return toast(res.message || "保存失败", "error");
        toast(res.message || "已保存", "success");
        fillForm(null);
        await reload();
        if (onSaved) onSaved();
    });

    q("#ri-reset").addEventListener("click", () => fillForm(null));

    q("#ri-rows").addEventListener("click", async e => {
        const b = e.target.closest("button");
        if (!b) return;
        const sym = b.dataset.edit || b.dataset.test || b.dataset.toggle || b.dataset.del;
        const row = st.rows.find(r => r.symbol === sym);
        if (!row) return;
        if (b.dataset.edit) { fillForm(row); q("#ri-symbol").scrollIntoView({ block: "center" }); return; }
        if (b.dataset.test) {
            fillForm(row);
            await doTest({ symbol: sym, prefix: String(row.sina).split("_")[0], em: row.em });
            return;
        }
        if (b.dataset.toggle) {
            const { ok: ok2, data: res } = await api("/rare/instruments", "POST", {
                symbol: row.symbol, prefix: String(row.sina).split("_")[0], name: row.name,
                short_name: row.short_name, market: row.market, kind: row.kind, unit: row.unit,
                em: row.em, chain: row.chain, enabled: !row.enabled
            });
            toast(ok2 ? (res.message || "已更新") : (res.message || "更新失败"), ok2 ? "success" : "error");
            if (ok2) { await reload(); if (onSaved) onSaved(); }
            return;
        }
        if (b.dataset.del) {
            if (!confirm(`删除品种 ${row.symbol}（${row.name}）？会同时清掉它的报价与历史轨迹。`)) return;
            const { ok: ok2, data: res } = await api("/rare/instruments/delete", "POST", { symbol: row.symbol });
            toast(ok2 ? "已删除" : (res.message || "删除失败"), ok2 ? "success" : "error");
            if (ok2) { await reload(); if (onSaved) onSaved(); }
        }
    });

    renderRows();
    fillForm(null);
    // 从「材料联想 · 手动接入」进来：把材料名、类别、用途先填好，用户只需要补行情代码
    if (prefill && prefill.name) {
        q("#ri-form-title").textContent = `接入材料：${prefill.name}`;
        q("#ri-short").value = prefill.name;
        q("#ri-kind").value = prefill.cat || prefill.name;
        q("#ri-unit").value = prefill.unit || "元/吨";
        // 产业链填短标签就行，填整句会把报价表的「产业链」列撑开
        q("#ri-chain").value = [prefill.cat, prefill.name].filter(Boolean).join("/").slice(0, 20);
        if (prefill.reason) {
            q(".ri-intro").innerHTML = `<b>${esc(prefill.name)}</b>${prefill.cat ? `（${esc(prefill.cat)}）` : ""} 目前没有可用的免费连续报价，所以没有行情可自动接入。`
                + `如果它有公开报价代码（新浪 nf_ / hf_ / gds_ 任一通道），在这里填上「代码 + 前缀」点「检测」即可；没有就建议先不加，避免出现永远不更新的空品种。`
                + `<br><span class="muted">用途参考：${esc(prefill.reason)}</span>`;
        }
        q("#ri-symbol").focus();
        q("#ri-form").scrollIntoView({ block: "start" });
    }
}

// ============================================================
// 材料联想（#material）：独立菜单页
//   ① 场景 → 材料：输入行业 / 场景词，反查最相关的金属与材料（支持「AI 液冷」这类组合查询）
//   ② 材料 → 场景：点材料名，反查它用在哪、属于哪些产业链、配套材料是谁
//   ③ 一键接入：材料有真实报价代码的才能「+ 监测」；没有的转「手动接入」，绝不伪造价格
//   数据全部来自本地知识库 + 库内真实资讯统计，可解释、不预测价格。
// ============================================================
const MAT_EXAMPLES = ["AI", "算力中心", "液冷", "光伏", "新能源车", "固态电池", "人形机器人", "半导体", "军工", "商业航天", "氢能", "稀土"];

const matState = {
    q: "AI", data: null, topics: null, sort: "rel",
    onlyTraded: false, onlyNews: false, sel: "", detail: null
};

function matShellHtml() {
    return `<div class="mat-grid">
        <aside class="mat-side">
            <section class="panel mat-panel">
                <div class="panel-head"><h3><i class="fa-solid fa-diagram-project"></i> 场景目录</h3>
                    <small class="muted" id="mat-scene-meta">—</small></div>
                <div class="panel-body">
                    <input id="mat-scene-filter" class="mat-filter" type="search" placeholder="筛选场景…" autocomplete="off">
                    <ul class="mat-list" id="mat-scenes"></ul>
                </div>
            </section>
            <section class="panel mat-panel">
                <div class="panel-head"><h3><i class="fa-solid fa-link"></i> 材料链</h3>
                    <small class="muted" id="mat-chain-meta">—</small></div>
                <div class="panel-body"><ul class="mat-list" id="mat-chains"></ul></div>
            </section>
            <section class="panel mat-panel">
                <div class="panel-head"><h3><i class="fa-solid fa-layer-group"></i> 材料类别</h3></div>
                <div class="panel-body"><div class="mat-cats" id="mat-cats"></div></div>
            </section>
        </aside>
        <div class="mat-main">
            <section class="panel">
                <div class="panel-head">
                    <h3><i class="fa-solid fa-wand-magic-sparkles"></i> 材料联想</h3>
                    <small class="muted">说一个行业或场景，反查最相关的材料；直接输入材料名则反查它的用途与配套材料</small>
                </div>
                <div class="panel-body">
                    <div class="rm-search">
                        <i class="fa-solid fa-magnifying-glass"></i>
                        <input id="mat-q" type="search" value="${esc(matState.q)}" placeholder="例如：AI、算力中心、光伏、碳酸锂，或「AI 液冷」组合查询" autocomplete="off">
                        <button class="btn btn-primary btn-sm" id="mat-go">联想</button>
                    </div>
                    <div class="rm-chips" id="mat-chips"></div>
                    <div class="mat-toolbar" id="mat-toolbar"></div>
                    <div class="rm-sum" id="mat-summary"></div>
                </div>
            </section>
            <section class="panel mat-detail-panel" id="mat-detail-panel" hidden>
                <div class="panel-head"><h3 id="mat-detail-title"><i class="fa-solid fa-diagram-project"></i> 材料详情</h3>
                    <button class="btn btn-ghost btn-sm" id="mat-detail-close"><i class="fa-solid fa-xmark"></i> 收起</button></div>
                <div class="panel-body" id="mat-detail-body"></div>
            </section>
            <section class="panel">
                <div class="panel-head"><h3><i class="fa-solid fa-list-ul"></i> 联想结果</h3>
                    <small class="muted" id="mat-result-meta"></small></div>
                <div class="panel-body"><div id="mat-result"></div></div>
            </section>
        </div>
    </div>`;
}

// 左侧目录：场景 / 材料链 / 材料类别
function renderMatSide(container) {
    const t = matState.topics || {};
    const scenes = t.topics || [];
    const sceneMeta = document.querySelector("#mat-scene-meta");
    if (sceneMeta) sceneMeta.textContent = `${scenes.length} 个场景 · ${t.total_materials || 0} 种材料`;

    const ul = document.querySelector("#mat-scenes");
    if (ul) {
        ul.innerHTML = scenes.map(s => `<li class="mat-scene-item${matState.q === s.label ? " active" : ""}" data-scene="${esc(s.label)}">
            <span class="mat-scene-name">${esc(s.label)}</span>
            <span class="mat-scene-num" title="关联材料数">${s.count}</span>
            <span class="mat-scene-news${s.news_7d ? " hot" : ""}" title="近 7 天库内提到该场景的消息条数">${s.news_7d || 0}</span>
        </li>`).join("") || `<li class="muted">场景加载中…</li>`;
    }

    const chainMeta = document.querySelector("#mat-chain-meta");
    const chains = t.chains || [];
    if (chainMeta) chainMeta.textContent = `${chains.length} 条链`;
    const cl = document.querySelector("#mat-chains");
    if (cl) {
        cl.innerHTML = chains.map(c => `<li class="mat-chain-item" data-chain="${esc(c.key)}">
            <span class="mat-scene-name">${esc(c.name)}</span>
            <span class="mat-scene-num" title="链上材料数">${c.count}</span>
            <div class="mat-chain-mem">${(c.members || []).slice(0, 8).map(m => `<button type="button" class="chip-btn" data-q="${esc(m)}">${esc(m)}</button>`).join("")}</div>
        </li>`).join("") || `<li class="muted">材料链加载中…</li>`;
    }

    const cats = document.querySelector("#mat-cats");
    if (cats) {
        cats.innerHTML = (t.categories || []).map(c => `<button type="button" class="chip-btn${matState.q === c.name ? " active" : ""}" data-cat="${esc(c.name)}" title="${esc(c.members.join("、"))}">${esc(c.name)}<small>${c.count}</small></button>`).join("");
    }
}

// 排序 + 筛选工具条
function renderMatToolbar(container) {
    const box = document.querySelector("#mat-toolbar");
    if (!box) return;
    box.innerHTML = `<div class="mat-toolbar-left">
            <span class="muted">排序</span>
            <select id="mat-sort">
                <option value="rel"${matState.sort === "rel" ? " selected" : ""}>相关度</option>
                <option value="news"${matState.sort === "news" ? " selected" : ""}>近 7 天资讯热度</option>
                <option value="cat"${matState.sort === "cat" ? " selected" : ""}>类别</option>
            </select>
        </div>
        <div class="mat-toolbar-right">
            <label class="rm-check"><input type="checkbox" id="mat-only-traded"${matState.onlyTraded ? " checked" : ""}> 只看已接入行情</label>
            <label class="rm-check"><input type="checkbox" id="mat-only-news"${matState.onlyNews ? " checked" : ""}> 只看有资讯</label>
        </div>`;
}

// 结果表
function matResultHtml(d, canConfig) {
    const items = d.items || [];
    if (!items.length) {
        const ex = (d.examples || MAT_EXAMPLES).map(e => `<button type="button" class="rm-inline-q" data-q="${esc(e)}">${esc(e)}</button>`).join("、");
        return `<div class="rm-empty muted">没有匹配到「${esc(d.q || "")}」相关的材料。换个更常见的行业说法试试，例如：${ex}</div>`;
    }
    const maxNews = Math.max(1, ...items.map(x => Number(x.news_7d) || 0));
    const rows = items.map(it => {
        const rel = Number(it.relevance) || 0;
        const price = (it.tradable && it.quoted)
            ? `${metalNum(it.price)} ${pctBadge(it.change_pct)}`
            : (it.tradable ? `<span class="muted">待采集</span>`
                : (it.can_add ? `<span class="muted">未接入</span>` : `<span class="muted">无行情源</span>`));
        let op = "";
        if (canConfig) {
            if (it.tradable) {
                op = `<span class="rm-on" title="${esc(it.symbol || "")}"><i class="fa-solid fa-circle-check"></i> 监测中</span>`;
            } else if (it.can_add) {
                op = `<button type="button" class="rm-add" data-add="${esc(it.name)}" title="接入 ${esc((it.hint || {}).name || "")}"><i class="fa-solid fa-plus"></i> 监测</button>`;
            } else {
                op = `<button type="button" class="rm-manual" data-manual="${esc(it.name)}" data-cat="${esc(it.cat || "")}" data-reason="${esc(it.reason || "")}" title="该材料暂无公开连续报价，可手动接入"><i class="fa-solid fa-pen-to-square"></i> 手动接入</button>`;
            }
        }
        const n = Number(it.news_7d) || 0;
        const newsCell = n > 0
            ? `<div class="rm-rel" title="近 7 天库内资讯中提及该材料的条数"><div class="rm-bar"><i style="width:${Math.max(6, Math.round((n / maxNews) * 100))}%"></i></div><b>${n}<small> 条</small></b></div>`
            : `<span class="muted" title="近 7 天库内资讯没有提及该材料">0 条</span>`;
        const scenes = (it.topics || []).map(t => `<span class="rm-topic">${esc(t)}</span>`).join("");
        const chains = (it.chains || []).map(c => `<span class="rm-topic chain" title="${esc(c.role || "")}">${esc(c.name)}</span>`).join("");
        const tips = (it.why || []).length ? `<i class="fa-solid fa-circle-question rm-why-tip" title="${esc((it.why || []).join("；"))}"></i>` : "";
        return `<tr class="mat-row${matState.sel === it.name ? " sel" : ""}" data-name="${esc(it.name)}">
            <td class="rm-rank">${it.rank}</td>
            <td class="mat-cell-name"><b class="mat-name" data-open="${esc(it.name)}">${esc(it.name)}</b>${it.symbol ? ` <small class="muted">${esc(it.symbol)} · ${esc(it.instrument || "")}</small>` : ""}
                <span class="rm-cat">${esc(it.cat || "—")}</span>${it.direct ? `<span class="rm-cat mat-direct">直接命中</span>` : ""}</td>
            <td class="mat-rel"><div class="rm-bar" title="相关度 ${rel}"><i style="width:${Math.max(4, rel)}%"></i></div><b>${rel}</b></td>
            <td class="mat-cell-why">${scenes}${chains}<div class="rm-why">${esc(it.reason || "—")}${tips}</div></td>
            <td>${newsCell}</td>
            <td class="num rm-quote">${price}${op ? `<div class="rm-op">${op}</div>` : ""}</td>
        </tr>`;
    }).join("");
    const nameList = items.map(it => it.name).join("、");
    const addable = items.filter(it => !it.tradable && it.can_add).length;
    const sum = d.summary || {};
    const winNote = sum.news_win_from ? `自 ${esc(sum.news_win_from)} 起` : "近 7 天";
    const sceneTxt = (d.matched || []).map(m => m.label).join(" · ");
    const chainTxt = (sum.chains || []).join(" · ");
    return `<div class="rm-sum">
        <span>共 <b>${items.length}</b> 种材料${sceneTxt ? ` · 识别为：<b>${esc(sceneTxt)}</b>` : ""}${chainTxt ? ` · 牵动材料链：<b>${esc(chainTxt)}</b>` : ""}</span>
        <div class="rm-sum-ops">
            ${canConfig && addable ? `<button type="button" class="btn btn-primary btn-sm" data-add-all><i class="fa-solid fa-circle-plus"></i> 加入全部可接入（${addable}）</button>` : ""}
            <button type="button" class="btn btn-ghost btn-sm rm-copy" data-copy="${esc(nameList)}"><i class="fa-regular fa-copy"></i> 复制名单</button>
        </div>
    </div>
    <div class="table-wrap"><table class="data-table rm-table mat-table">
        <thead><tr><th>#</th><th>材料 / 类别</th><th>相关度</th><th>命中场景 · 用途 / 关联逻辑</th><th>近 7 天资讯</th><th>行情</th></tr></thead>
        <tbody>${rows}</tbody>
    </table></div>
    <p class="rm-note muted">相关度来自「场景—材料」知识库的关联强弱（用量 × 不可替代性），只表示关联强弱，不代表价格涨跌；点材料名可反查它的场景与配套材料。「近 7 天资讯」是库内实际抓到的消息中提及该材料的条数（${winNote}，库内存量 ${Number(sum.news_rows) || 0} 条），没有命中就显示 0 条，不估算、不编造。点「+ 监测」会把该材料对应的期货品种直接加入稀有金属采集（行情与 K 线立刻可用）；显示「手动接入」的材料目前没有稳定的免费连续报价，不会伪造价格。</p>`;
}

// 材料详情：反查场景 / 材料链 / 配套材料
function matDetailHtml(d, canConfig) {
    if (!d || !d.name) return `<div class="rm-empty muted">没有识别到这个材料</div>`;
    const allScenes = d.scenes || [];
    const showScenes = allScenes.slice(0, 8);
    const scenes = showScenes.map(s => `<li>
        <div class="mat-scene-row"><span class="mat-scene-label">${esc(s.label)}</span>
            <div class="rm-bar"><i style="width:${Math.max(4, Number(s.weight) || 0)}%"></i></div>
            <b>${Number(s.weight) || 0}</b></div>
        <small class="muted">${esc(s.reason || "")}</small></li>`).join("");
    const allChains = d.chains || [];
    const chains = allChains.slice(0, 6).map(c => `<div class="mat-chain-box">
        <div class="mat-chain-head"><b>${esc(c.name)}</b><span class="rm-cat">${esc(c.role || "—")}</span></div>
        <small class="muted">${esc(c.note || "")}</small>
        <div class="mat-chain-mem">${(c.siblings || []).map(s => `<button type="button" class="chip-btn" data-q="${esc(s.name)}" title="${esc(s.role || "")}">${esc(s.name)}</button>`).join("")}</div>
    </div>`).join("");
    const related = (d.related || []).slice(0, 14).map(r => `<button type="button" class="chip-btn" data-q="${esc(r.name)}" title="${esc(r.chains.join(" / "))}">${esc(r.name)}<small>${esc(r.role || r.chains[0] || "")}</small></button>`).join("");
    let quote = "";
    if (d.tradable) {
        quote = `<div class="mat-quote"><b>${d.price != null ? metalNum(d.price) : "—"}</b> ${pctBadge(d.change_pct)}
            <small class="muted">${esc(d.instrument || "")} ${esc(d.symbol || "")} ${esc(d.unit || "")}</small></div>`;
    } else if (d.can_add) {
        quote = `<button type="button" class="btn btn-primary btn-sm" data-add="${esc(d.name)}"><i class="fa-solid fa-plus"></i> 加入监测</button>`;
    } else if (canConfig) {
        quote = `<button type="button" class="btn btn-ghost btn-sm" data-manual="${esc(d.name)}" data-cat="${esc(d.cat || "")}" data-reason="${esc((d.scenes[0] || {}).reason || "")}"><i class="fa-solid fa-pen-to-square"></i> 手动接入</button>`;
    }
    return `<div class="mat-detail-grid">
        <div class="mat-detail-main">
            <div class="mat-detail-head">
                <div><b>${esc(d.name)}</b><span class="rm-cat">${esc(d.cat || "—")}</span>
                    ${(d.aliases || []).length ? `<small class="muted">别名：${esc(d.aliases.join(" / "))}</small>` : ""}</div>
                <div class="mat-detail-ops">
                    ${quote}
                    <button type="button" class="btn btn-ghost btn-sm" data-q="${esc(d.name)}"><i class="fa-solid fa-magnifying-glass"></i> 以它为起点再联想</button>
                </div>
            </div>
            <div class="mat-detail-block">
                <div class="mat-block-title">用在哪（场景关联强度，共 ${allScenes.length} 个）</div>
                <ul class="mat-scene-list">${scenes || `<li class="muted">知识库里还没有登记它的场景</li>`}</ul>
                ${allScenes.length > showScenes.length ? `<small class="muted">另有 ${allScenes.length - showScenes.length} 个关联场景未展开（强度更低）</small>` : ""}
            </div>
            <div class="mat-detail-block">
                <div class="mat-block-title">所属材料链（共 ${allChains.length} 条）</div>
                ${chains || `<div class="muted">未归入材料链</div>`}
                ${allChains.length > 6 ? `<small class="muted">另有 ${allChains.length - 6} 条材料链未展开</small>` : ""}
            </div>
        </div>
        <div class="mat-detail-side">
            <div class="mat-block-title">配套材料（常一起出现）</div>
            <div class="mat-chain-mem">${related || `<span class="muted">暂无</span>`}</div>
        </div>
    </div>`;
}

// 排序 + 过滤（纯前端，不重新请求）
function matApplyView(items) {
    let list = items.slice();
    if (matState.onlyTraded) list = list.filter(i => i.tradable);
    if (matState.onlyNews) list = list.filter(i => (Number(i.news_7d) || 0) > 0);
    if (matState.sort === "news") list.sort((a, b) => (Number(b.news_7d) || 0) - (Number(a.news_7d) || 0) || (Number(b.relevance) || 0) - (Number(a.relevance) || 0));
    else if (matState.sort === "cat") list.sort((a, b) => String(a.cat || "").localeCompare(String(b.cat || ""), "zh") || (Number(b.relevance) || 0) - (Number(a.relevance) || 0));
    else list.sort((a, b) => (Number(b.relevance) || 0) - (Number(a.relevance) || 0));
    return list;
}

async function viewMaterial(container) {
    const seq = routerSeq;
    // 支持 #material?q=碳酸锂 深链（从别处分享 / 收藏进来直接看到结果）
    const deepQ = String(routerQuery.get("q") || "").trim();
    if (deepQ) matState.q = deepQ.slice(0, 40);
    container.innerHTML = matShellHtml();

    const canConfig = !!(state.user && (state.user.role === "admin" || state.user.permissions.includes("market.config")));
    const chips = document.querySelector("#mat-chips");
    if (chips) {
        chips.innerHTML = `<span class="rm-chip-label">常搜：</span>` +
            MAT_EXAMPLES.map(e => `<button type="button" class="chip-btn" data-q="${esc(e)}">${esc(e)}</button>`).join("") +
            `<span class="rm-chip-label" style="margin-left:8px">组合：</span>` +
            ["AI 液冷", "光伏 硅", "新能源车 磁材"].map(e => `<button type="button" class="chip-btn" data-q="${esc(e)}">${esc(e)}</button>`).join("");
    }
    renderMatToolbar(container);

    // 场景目录 / 材料链 / 类别：一次性拉取
    const { ok: tokOk, data: tok } = await api("/rare/topics");
    if (seq !== routerSeq) return;
    if (tokOk && tok) { matState.topics = tok; renderMatSide(container); }

    // 执行一次联想
    const input = document.querySelector("#mat-q");
    let runSeq = 0, timer = null;

    async function run(q, keepFilters) {
        const query = String(q == null ? (input ? input.value : "") : q).trim();
        matState.q = query;
        const out = document.querySelector("#mat-result");
        const meta = document.querySelector("#mat-result-meta");
        if (!query) {
            if (out) out.innerHTML = `<div class="rm-empty muted">输入一个行业或场景词（例如「AI」「算力中心」「光伏」），或直接输入材料名（例如「碳酸锂」「钨」）。</div>`;
            if (meta) meta.textContent = "";
            return;
        }
        // 换了查询语境（点场景 / 类别 / 材料）时先清掉上一轮的过滤条件，
        // 否则会出现「点了稀土却一条都不显示」这种让人以为坏了的结果；手动打字不算换语境，保留过滤。
        if (!keepFilters && (matState.onlyTraded || matState.onlyNews)) {
            matState.onlyTraded = false;
            matState.onlyNews = false;
            renderMatToolbar(container);
            const t = document.querySelector("#mat-only-traded"), n = document.querySelector("#mat-only-news");
            if (t) t.checked = false;
            if (n) n.checked = false;
        }
        const my = ++runSeq;
        if (out) out.innerHTML = `<div class="rm-empty muted"><i class="fa-solid fa-spinner fa-spin"></i> 正在匹配「${esc(query)}」…</div>`;
        const { ok, data } = await api("/rare/match?q=" + encodeURIComponent(query) + "&limit=14");
        if (my !== runSeq || seq !== routerSeq) return;
        if (!ok) { if (out) out.innerHTML = `<div class="rm-empty">匹配失败：${esc(data.message || "请稍后再试")}</div>`; return; }
        matState.data = data;
        renderResult();
    }

    function renderResult() {
        const d = matState.data;
        if (!d) return;
        const out = document.querySelector("#mat-result");
        const meta = document.querySelector("#mat-result-meta");
        const list = matApplyView(d.items || []);
        const all = d.items || [];
        if (meta) meta.textContent = `命中 ${all.length} 种 · 显示 ${list.length} 种`;
        if (!out) return;
        if (!list.length) {
            out.innerHTML = `<div class="rm-empty muted">当前筛选下没有材料。取消「只看已接入行情 / 只看有资讯」再看看。</div>`;
            return;
        }
        // 排序后重新编号，序号保持连续
        const shown = list.map((it, i) => Object.assign({}, it, { rank: i + 1 }));
        const tmp = Object.assign({}, d, { items: shown });
        out.innerHTML = matResultHtml(tmp, canConfig);
    }

    async function reload() {
        const { ok, data } = await api("/rare/match?q=" + encodeURIComponent(matState.q) + "&limit=14");
        if (seq !== routerSeq) return;
        if (ok) { matState.data = data; renderResult(); }
    }

    async function showDetail(name) {
        matState.sel = name;
        const panel = document.querySelector("#mat-detail-panel");
        const body = document.querySelector("#mat-detail-body");
        const title = document.querySelector("#mat-detail-title");
        if (!panel || !body) return;
        panel.hidden = false;
        if (title) title.innerHTML = `<i class="fa-solid fa-diagram-project"></i> 材料详情 · ${esc(name)}`;
        body.innerHTML = `<div class="rm-empty muted"><i class="fa-solid fa-spinner fa-spin"></i> 正在反查…</div>`;
        const { ok, data } = await api("/rare/match/reverse?name=" + encodeURIComponent(name));
        if (seq !== routerSeq) return;
        if (!ok) { body.innerHTML = `<div class="rm-empty">反查失败：${esc(data.message || "请稍后再试")}</div>`; return; }
        matState.detail = data;
        body.innerHTML = matDetailHtml(data, canConfig);
        panel.scrollIntoView({ block: "nearest", behavior: "smooth" });
        document.querySelectorAll(".mat-row").forEach(tr => tr.classList.toggle("sel", tr.dataset.name === name));
    }

    async function addOne(name, btn) {
        const old = btn ? btn.innerHTML : "";
        if (btn) { btn.disabled = true; btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i>`; }
        const { ok, data } = await api("/rare/instruments/quick-add", "POST", { name });
        if (seq !== routerSeq) return;
        if (!ok) { toast(data.message || "加入失败", "error"); if (btn) { btn.disabled = false; btn.innerHTML = old; } return; }
        const r = (data.results || [])[0] || {};
        if (!r.success) {
            toast(r.message || "加入失败", "error");
            if (btn) { btn.disabled = false; btn.innerHTML = old; }
            return;
        }
        toast(r.exists ? `${name} 已在监测（${r.instrument}）` : `已加入监测：${name} → ${r.instrument || r.symbol}`, "success");
        await reload();
        if (matState.sel) await showDetail(matState.sel);
    }

    // —— 事件绑定 ——
    const onClick = async e => {
        const qBtn = e.target.closest("[data-q]");
        if (qBtn) {
            const q = qBtn.dataset.q;
            if (input) input.value = q;
            if (timer) clearTimeout(timer);
            await run(q);
            return;
        }
        const scene = e.target.closest("[data-scene]");
        if (scene) { if (input) input.value = scene.dataset.scene; await run(scene.dataset.scene); return; }
        const cat = e.target.closest("[data-cat]");
        if (cat) { if (input) input.value = cat.dataset.cat; await run(cat.dataset.cat); return; }
        const open = e.target.closest("[data-open]");
        if (open) { await showDetail(open.dataset.open); return; }
        const cp = e.target.closest("[data-copy]");
        if (cp) {
            try { await navigator.clipboard.writeText(cp.dataset.copy || ""); toast("已复制材料名单", "success"); }
            catch (err) { toast("复制失败，可手动选中表格文字", "error"); }
            return;
        }
        const add = e.target.closest("[data-add]");
        if (add) { await addOne(add.dataset.add, add); return; }
        const all = e.target.closest("[data-add-all]");
        if (all) {
            const names = [...document.querySelectorAll("#mat-result [data-add]")].map(n => n.dataset.add);
            if (!names.length) { toast("当前结果没有可一键接入的材料", "info"); return; }
            all.disabled = true;
            all.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> 正在接入 ${names.length} 个…`;
            const { ok, data } = await api("/rare/instruments/quick-add", "POST", { names });
            if (seq !== routerSeq) return;
            all.disabled = false;
            if (!ok) { toast(data.message || "批量接入失败", "error"); return; }
            const created = (data.results || []).filter(r => r.created);
            toast(data.message + (created.length ? `：${created.map(r => r.instrument).join("、")}` : ""), created.length ? "success" : "info");
            await reload();
            return;
        }
        const man = e.target.closest("[data-manual]");
        if (man) {
            openRareInstrumentManager(async () => { await reload(); }, {
                name: man.dataset.manual, cat: man.dataset.cat, reason: man.dataset.reason
            });
            return;
        }
    };
    container.addEventListener("click", onClick);

    if (input) {
        input.addEventListener("input", () => {
            if (timer) clearTimeout(timer);
            timer = setTimeout(() => run(input.value, true), 320);   // 输入即查：防抖，避免每敲一个字打一次接口
        });
        input.addEventListener("keydown", e => {
            if (e.key === "Enter") { e.preventDefault(); if (timer) clearTimeout(timer); run(input.value, true); }
        });
    }
    const go = document.querySelector("#mat-go");
    if (go) go.addEventListener("click", () => { if (timer) clearTimeout(timer); run(input ? input.value : "", true); });
    const closeBtn = document.querySelector("#mat-detail-close");
    if (closeBtn) closeBtn.addEventListener("click", () => {
        const panel = document.querySelector("#mat-detail-panel");
        if (panel) panel.hidden = true;
        matState.sel = "";
        document.querySelectorAll(".mat-row").forEach(tr => tr.classList.remove("sel"));
    });
    const sceneFilter = document.querySelector("#mat-scene-filter");
    if (sceneFilter) sceneFilter.addEventListener("input", () => {
        const kw = sceneFilter.value.trim().toLowerCase();
        document.querySelectorAll("#mat-scenes .mat-scene-item").forEach(li => {
            li.style.display = !kw || li.dataset.scene.toLowerCase().indexOf(kw) >= 0 ? "" : "none";
        });
    });
    container.addEventListener("change", e => {
        if (e.target.id === "mat-sort") { matState.sort = e.target.value; renderResult(); return; }
        if (e.target.id === "mat-only-traded") { matState.onlyTraded = e.target.checked; renderResult(); return; }
        if (e.target.id === "mat-only-news") { matState.onlyNews = e.target.checked; renderResult(); return; }
    });

    await run(matState.q);
}

async function viewRare(container) {
    const seq = routerSeq;

    async function load() {
        const [bRes, sRes] = await Promise.all([api("/rare"), api("/rare/scenarios?days=21")]);
        if (seq !== routerSeq) return;
        if (!bRes.ok) { container.innerHTML = errorHtml(bRes.data.message || "稀有金属数据加载失败"); return; }
        const b = bRes.data;
        const items = (sRes.ok && sRes.data.items) || [];
        const scBy = {};
        items.forEach(it => { scBy[it.symbol] = it; });
        const canRefresh = !!(state.user && (state.user.role === "admin" || state.user.permissions.includes("market.refresh")));
        const canConfig = !!(state.user && (state.user.role === "admin" || state.user.permissions.includes("market.config")));
        const insts = b.instruments || [];

        const rows = (b.quotes || []).map(q => {
            const sc = scBy[q.symbol];
            return `<tr>
                <td><b>${esc(q.short_name)}</b><br><small class="muted">${esc(q.symbol)} · ${esc(q.market || "—")}${q.kind ? ` · ${esc(q.kind)}` : ""}</small></td>
                <td>${esc((insts.find(i => i.symbol === q.symbol) || {}).chain || "—")}</td>
                <td class="num">${metalNum(q.price)}<br><small class="muted">${esc(q.unit || "")}</small></td>
                <td class="num">${pctBadge(q.change_pct)}</td>
                <td class="num">${metalPct(q.amplitude, 2)}%</td>
                <td class="num">${q.open_interest ? metalNum(q.open_interest, 0) : "—"}</td>
                <td class="num">${q.volume ? metalNum(q.volume, 0) : "—"}</td>
                <td>${sc && sc.tech ? esc(sc.tech.ma20_state.replace("价格在 ", "")) : "—"}</td>
                <td class="num">${sc ? sparkSvg(sc.kline_points, { width: 88, height: 24 }) : "—"}</td>
                <td>${sc
                    ? `<button class="btn btn-ghost btn-sm" data-kline="${esc(q.symbol)}" title="K 线 / 技术指标 / 分时"><i class="fa-solid fa-chart-column"></i></button>`
                    : `<span class="muted" title="未配置东财 secid，取不到历史 K 线">—</span>`}</td>
            </tr>`;
        }).join("");

        container.innerHTML = `
        <section class="panel">
            <div class="panel-head"><h3><i class="fa-solid fa-gem"></i> 稀有 / 战略金属报价</h3>
                <small class="muted">${insts.length} 个品种 · 可自行增删（广期所 / 上期所等）</small>
                <a class="btn btn-sm btn-ghost" href="#material" title="输入行业或场景，反查相关材料"><i class="fa-solid fa-wand-magic-sparkles"></i> 材料联想</a>
                ${canConfig ? `<button class="btn btn-sm btn-ghost" id="rare-mgr"><i class="fa-solid fa-sliders"></i> 品种管理</button>` : ""}
                ${canRefresh ? `<button class="btn btn-sm btn-primary" id="rare-refresh"><i class="fa-solid fa-rotate"></i> 刷新行情</button>` : ""}
            </div>
            <div class="panel-body">
                <div class="table-wrap"><table class="data-table">
                    <thead><tr><th>品种</th><th>产业链</th><th>现价</th><th>涨跌</th><th>振幅</th><th>持仓量</th><th>成交量</th><th>MA20</th><th>近 60 日</th><th>K 线</th></tr></thead>
                    <tbody>${rows || `<tr><td colspan="10">${emptyHtml(insts.length ? "暂无报价，点「刷新行情」试试" : "还没有品种，点「品种管理」添加")}</td></tr>`}</tbody>
                </table></div>
            </div>
        </section>`;

        const btn = container.querySelector("#rare-refresh");
        // K 线入口：与实时行情共用同一套「详细数据」弹窗（多周期 + 技术指标 + 分时）
        container.querySelectorAll("[data-kline]").forEach(b => b.addEventListener("click", () => openMetalDetail(b.dataset.kline)));
        if (btn) btn.addEventListener("click", async () => {
            btn.disabled = true;
            const { ok, data } = await api("/rare/refresh", "POST", {});
            toast(ok ? `已刷新 ${data.updated || 0} 个品种` : (data.message || "刷新失败"), ok ? "success" : "error");
            btn.disabled = false;
            if (ok) await load();
        });
        // 品种管理：增删改后整页重载，报价 / 情景卡片同步刷新
        const mgr = container.querySelector("#rare-mgr");
        if (mgr) mgr.addEventListener("click", () => openRareInstrumentManager(async () => { await load(); }));
    }

    await load().catch(e => { if (seq === routerSeq) container.innerHTML = errorHtml(e.message); });
}

// ---------- 启动 ----------
setupAuthEvents();
startup();
