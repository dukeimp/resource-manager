// 功能修复回归测试：分批解析 / 日历日期校验 / 时间戳换算 / 任务间隔与下次执行
//   全部为纯函数，worker.js 源码按函数名切片后在 vm 沙箱里跑，不依赖 D1。
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "worker.js"), "utf8");

function extractFn(name) {
    const idx = src.indexOf("function " + name + "(");
    if (idx < 0) throw new Error("worker.js 里找不到函数 " + name);
    const start = src.indexOf("{", idx);
    let depth = 0, quote = null;
    for (let p = start; p < src.length; p++) {
        const ch = src[p];
        if (quote) {
            if (ch === "\\") { p++; continue; }
            if (ch === quote) quote = null;
            continue;
        }
        if (ch === '"' || ch === "'" || ch === "`") { quote = ch; continue; }
        if (ch === "{") depth++;
        else if (ch === "}") { depth--; if (depth === 0) return src.slice(src.slice(Math.max(0, idx - 6), idx) === 'async ' ? idx - 6 : idx, p + 1); }
    }
    throw new Error("函数 " + name + " 的大括号没配平");
}

const sandbox = { console, URL, TextEncoder, TextDecoder, crypto: require("crypto").webcrypto, btoa, atob };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext([
    extractFn("bytesToB64"),
    extractFn("hmacSign"),
    extractFn("isPrivateHost"),
    extractFn("safeWebhook"),
    extractFn("webhookBody"),
    extractFn("buildChannelRequest"),
    extractFn("maskSecretValue"),
    extractFn("parseTranches"),
    extractFn("normalizeEventAt"),
    extractFn("epochOf"),
    extractFn("epochOfUtcDb"),
    extractFn("taskIntervalSec"),
    extractFn("beijingStamp"),
    extractFn("nextRunStamp")
].join("\n"), sandbox, { filename: "fixes.js" });

const S = sandbox;
let pass = 0, fail = 0;
function t(name, fn) {
    try { fn(); pass++; console.log("PASS " + name); }
    catch (e) { fail++; console.log("FAIL " + name + " -> " + e.message); }
}
function eq(a, b, msg) {
    const x = JSON.stringify(a), y = JSON.stringify(b);
    if (x !== y) throw new Error((msg || "") + " 期望 " + y + " 实际 " + x);
}

// —— 分批价位：价位 0 但占比 > 0 必须保留（「到价再定」）——
t("零价分批按占比保留", () => {
    const r = S.parseTranches([{ price: 0, pct: 50 }, { price: 0, pct: 50 }]);
    eq(r.length, 2);
    eq(r[0].pct, 50);
});
t("零价零量零占比被丢弃", () => {
    eq(S.parseTranches([{ price: 0, qty: 0, pct: 0 }]).length, 0);
});
t("混合零价与有价分批都保留", () => {
    const r = S.parseTranches([{ price: 0, pct: 40 }, { price: 500, pct: 60 }]);
    eq(r.length, 2);
    eq(r[1].price, 500);
});
t("JSON 字符串分批可解析", () => {
    eq(S.parseTranches('[{"price":0,"pct":100}]').length, 1);
});
t("非法 JSON 返回空数组", () => {
    eq(S.parseTranches("{bad json").length, 0);
});
t("占比上限夹到 100", () => {
    eq(S.parseTranches([{ price: 1, pct: 250 }])[0].pct, 100);
});

// —— 日历日期校验：真实年月日 + 闰年 ——
t("合法日期归一化", () => {
    eq(S.normalizeEventAt("2026-11-05 20:30"), "2026-11-05 20:30");
});
t("省略时分补 00:00", () => {
    eq(S.normalizeEventAt("2026-11-05"), "2026-11-05 00:00");
});
t("2 月 31 日被拒绝", () => {
    eq(S.normalizeEventAt("2026-02-31 20:30"), "");
});
t("4 月 31 日被拒绝", () => {
    eq(S.normalizeEventAt("2026-04-31"), "");
});
t("闰年 2 月 29 日合法", () => {
    eq(S.normalizeEventAt("2028-02-29"), "2028-02-29 00:00");
});
t("平年 2 月 29 日被拒绝", () => {
    eq(S.normalizeEventAt("2026-02-29"), "");
});
t("非法月份被拒绝", () => {
    eq(S.normalizeEventAt("2026-13-01"), "");
});
t("非法小时被拒绝", () => {
    eq(S.normalizeEventAt("2026-11-05 24:00"), "");
});
t("尾部多余字符被拒绝", () => {
    eq(S.normalizeEventAt("2026-11-05 20:30 尾巴"), "");
});
t("斜杠日期可解析", () => {
    eq(S.normalizeEventAt("2026/11/05"), "2026-11-05 00:00");
});

// —— 时间戳换算：北京时间字符串 vs SQLite UTC ——
t("北京时间字符串按 +08:00 解析", () => {
    eq(S.epochOf("2026-11-16 08:00:00"), Date.UTC(2026, 10, 16, 0, 0, 0));
});
t("SQLite UTC 字符串按 UTC 解析", () => {
    eq(S.epochOfUtcDb("2026-11-16 00:00:00"), Date.UTC(2026, 10, 16, 0, 0, 0));
});
t("两种口径相差 8 小时", () => {
    eq(S.epochOf("2026-11-16 08:00:00") - S.epochOfUtcDb("2026-11-16 00:00:00"), 0);
});
t("带 Z 的 ISO 按显式时区解析", () => {
    eq(S.epochOf("2026-11-16T00:00:00Z"), Date.UTC(2026, 10, 16, 0, 0, 0));
});

// —— 任务间隔与下次执行 ——
t("interval_sec 优先于 interval_min", () => {
    eq(S.taskIntervalSec({ interval_sec: 90, interval_min: 30 }), 90);
});
t("interval_sec 缺失时回退分钟", () => {
    eq(S.taskIntervalSec({ interval_min: 10 }), 600);
});
t("固定时刻任务：0 点合法", () => {
    const base = Date.UTC(2026, 10, 16, 3, 0, 0); // 北京时间 11:00
    const next = S.nextRunStamp({ run_at_hour: 0 }, base);
    // 下一个北京 0 点 = 次日 0 点
    eq(next, Date.UTC(2026, 10, 16, 16, 0, 0));
});
t("固定时刻任务：未到点用当天", () => {
    const base = Date.UTC(2026, 10, 15, 20, 0, 0); // 北京时间 04:00
    const next = S.nextRunStamp({ run_at_hour: 8 }, base);
    eq(next, Date.UTC(2026, 10, 16, 0, 0, 0)); // 当天北京 08:00
});
t("间隔任务：无上次执行时按当前时间起步", () => {
    const base = Date.UTC(2026, 10, 16, 3, 0, 0);
    eq(S.nextRunStamp({ interval_sec: 600 }, base), base + 600000);
});

// —— Webhook SSRF 防护与敏感凭证脱敏 ——
t("safeWebhook 拦截本地回环与内网 IP", () => {
    eq(S.safeWebhook("http://127.0.0.1:8080/hook"), "");
    eq(S.safeWebhook("http://localhost/hook"), "");
    eq(S.safeWebhook("http://169.254.169.254/latest/meta-data/"), "");
    eq(S.safeWebhook("http://192.168.1.10/api"), "");
    eq(S.safeWebhook("http://10.0.0.1/api"), "");
    eq(S.safeWebhook("http://172.16.5.4/api"), "");
});
t("safeWebhook 放行合法公网 Webhook", () => {
    eq(S.safeWebhook("https://oapi.dingtalk.com/robot/send?access_token=abc"), "https://oapi.dingtalk.com/robot/send?access_token=abc");
});
t("maskSecretValue 正确脱敏敏感字段", () => {
    eq(S.maskSecretValue("SEC1234567890abcdef"), "SEC1****cdef");
    eq(S.maskSecretValue("short"), "****");
    eq(S.maskSecretValue(""), "");
});

// —— 钉钉加签异步构建与 Bark SSRF 校验 ——
(async () => {
    try {
        const dtReq = await S.buildChannelRequest({
            channel_type: "dingtalk",
            webhook_url: "https://oapi.dingtalk.com/robot/send?access_token=testtoken",
            secret: "SECtestsecret123456"
        }, "预警标题", "预警正文");
        if (!dtReq || !dtReq.url.includes("timestamp=") || !dtReq.url.includes("sign=")) {
            throw new Error("钉钉加签 URL 缺少 timestamp 或 sign 参数: " + (dtReq && dtReq.url));
        }
        pass++;
        console.log("PASS 钉钉机器人加签生成 timestamp 与 sign 参数");
    } catch (e) {
        fail++;
        console.log("FAIL 钉钉机器人加签生成 timestamp 与 sign 参数 -> " + e.message);
    }

    try {
        const barkBad = await S.buildChannelRequest({
            channel_type: "bark",
            webhook_url: "http://127.0.0.1:8080/ push"
        }, "标题", "正文");
        eq(barkBad, null, "Bark 内网地址应被拦截");
        pass++;
        console.log("PASS Bark 自定义 URL 同样受 SSRF 内网拦截保护");
    } catch (e) {
        fail++;
        console.log("FAIL Bark 自定义 URL 同样受 SSRF 内网拦截保护 -> " + e.message);
    }

    console.log("\n通过 " + pass + " / " + (pass + fail));
    process.exit(fail ? 1 : 0);
})();
