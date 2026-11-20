// 重点消息「简明摘要」与通知文案单测
//   覆盖：briefKeyNews（摘要生成）、pickKeyNews 返回值、keyNotifyText（通知文案结构）
//   均为纯函数，不依赖 D1；worker.js 源码按函数名切片后在 vm 沙箱里跑。
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

const ROOT = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "worker.js"), "utf8");

// —— 从源码里精确切出一个函数（含大括号配平）——
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
        else if (ch === "}") { depth--; if (depth === 0) return src.slice(idx, p + 1); }
    }
    throw new Error("函数 " + name + " 的大括号没配平");
}

const sandbox = { console };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
// 重点引擎整段（briefKeyNews + pickKeyNews 都在这段里）
const S = "// ==== KEY_PICK_ENGINE_START ====";
const E = "// ==== KEY_PICK_ENGINE_END ====";
vm.runInContext(src.slice(src.indexOf(S), src.indexOf(E)), sandbox, { filename: "keypick.js" });
// 通知文案函数单独切出来，依赖的两个 JSON 解析器用等价实现补上
vm.runInContext([
    "function parseKeyPick(raw){try{const o=JSON.parse(String(raw||''));return (o&&typeof o==='object')?o:null;}catch(e){return null;}}",
    "function parseImpact(raw){try{const o=JSON.parse(String(raw||''));return (o&&typeof o==='object')?o:null;}catch(e){return null;}}",
    extractFn("keyNotifyText")
].join("\n"), sandbox, { filename: "keynotify.js" });

const { briefKeyNews, pickKeyNews } = sandbox;
const { keyNotifyText } = sandbox;

let pass = 0, fail = 0;
function t(name, fn) {
    try { fn(); pass++; console.log("  ✓ " + name); }
    catch (e) { fail++; console.log("  ✗ " + name + " → " + e.message); }
}

console.log("briefKeyNews · 重点消息简明摘要");

t("方向 + 标的 + 事件：摘要里三样都要有", () => {
    const b = briefKeyNews("美联储宣布加息25个基点", "美联储…",
        { direction: "bearish", strength: "强", scope: "metal", event: "宏观·利率", targets: [{ name: "沪金" }, { name: "沪银" }] });
    assert.ok(b.includes("偏跌"), "应含方向偏跌，实际：" + b);
    assert.ok(b.includes("沪金"), "应含影响标的，实际：" + b);
    assert.ok(b.includes("宏观·利率"), "应含事件类型，实际：" + b);
    assert.ok(b.startsWith("美联储宣布加息25个基点"), "应以标题开头，实际：" + b);
});

t("偏涨方向写「偏涨」不写「偏跌」", () => {
    const b = briefKeyNews("英伟达业绩超预期", "", { direction: "bullish", targets: [{ name: "英伟达" }] });
    assert.ok(b.includes("偏涨"), b);
    assert.ok(!b.includes("偏跌"), b);
});

t("多空交织标成「多空分歧」，不给单向结论", () => {
    const b = briefKeyNews("多重因素支撑黄金中长期配置价值仍存", "", { direction: "mixed", strength: "分歧", targets: [] });
    assert.ok(b.includes("多空分歧"), b);
    assert.ok(!b.includes("偏涨") && !b.includes("偏跌"), b);
});

t("没有研判就不硬凑方向", () => {
    const b = briefKeyNews("某地举办稀土产业推介会", "", null);
    assert.ok(!b.includes("偏涨") && !b.includes("偏跌") && !b.includes("方向不明"), b);
});

t("影响标的最多列 2 个", () => {
    const b = briefKeyNews("测试", "", { direction: "bullish", targets: [{ name: "A" }, { name: "B" }, { name: "C" }, { name: "D" }] });
    assert.ok(b.includes("A、B"), b);
    assert.ok(!b.includes("C"), b);
});

t("摘要长度不超过 70 字（超长要截断）", () => {
    const long = "重".repeat(120);
    const b = briefKeyNews(long, "", { direction: "bullish", targets: [{ name: "沪金" }] });
    assert.ok(b.length <= 71, "实际长度 " + b.length);
    assert.ok(b.includes("…"), b);
});

t("标题缺失时用摘要兜底，不编造", () => {
    const b = briefKeyNews("", "这是原始摘要内容", null);
    assert.ok(b.includes("这是原始摘要内容"), b);
});

t("标题与摘要都空 → 返回空串", () => {
    assert.strictEqual(briefKeyNews("", "", null), "");
});

t("摘要去掉句末标点，不留尾巴", () => {
    const b = briefKeyNews("金价快速回落。", "", null);
    assert.ok(!b.endsWith("。"), b);
});

console.log("");
console.log("pickKeyNews · 返回值带简明摘要");

t("pickKeyNews 返回 brief 字段且与 briefKeyNews 一致", () => {
    const imp = { direction: "bearish", strength: "强", event: "宏观·利率", scope: "metal", targets: [{ name: "沪金" }] };
    const kp = pickKeyNews("美联储加息25个基点", "正文", "macro", imp, "wscn", "2026-11-13 10:00:00", Date.parse("2026-11-13T10:30:00+08:00"));
    assert.ok(typeof kp.brief === "string" && kp.brief.length > 0, "brief 应为非空字符串");
    assert.strictEqual(kp.brief, briefKeyNews("美联储加息25个基点", "正文", imp));
});

t("非重点消息也会生成 brief（规则变化后可直接点亮）", () => {
    const kp = pickKeyNews("某地举办稀土产业推介会", "正文", "other", null, "sina", "2026-11-13 10:00:00", Date.now());
    assert.ok(typeof kp.brief === "string", "brief 应存在");
    assert.ok(kp.brief.length > 0, "brief 应非空");
});

console.log("");
console.log("keyNotifyText · 通知中心文案结构");

t("body 第一行是简明摘要，末行是风险提示", () => {
    const r = {
        title: "美联储加息25个基点", key_brief: "美联储加息25个基点 → 偏跌（影响 沪金）",
        key_score: 78, impact: JSON.stringify({ direction: "bearish", targets: [{ name: "沪金" }], chains: ["实际利率上行→美元走强→金价承压"] }),
        key_reasons: JSON.stringify({ reasons: ["方向偏跌（强度强）", "影响 沪金（直击贵金属）"] })
    };
    const out = keyNotifyText(r);
    const lines = out.body.split("\n");
    assert.strictEqual(lines[0], "美联储加息25个基点 → 偏跌（影响 沪金）", lines[0]);
    assert.ok(lines[1].includes("重点 78 分"), lines[1]);
    assert.ok(lines[1].includes("偏跌"), lines[1]);
    assert.ok(out.body.includes("传导链："), out.body);
    assert.ok(out.body.includes("规则推演，非投资建议"), out.body);
    assert.ok(out.title.startsWith("【重点】"), out.title);
});

t("没有 key_brief 时回退到重点理由里的 brief，再退到标题", () => {
    const r1 = { title: "标题甲", key_brief: "", key_reasons: JSON.stringify({ brief: "来自理由的简报" }) };
    assert.strictEqual(keyNotifyText(r1).body.split("\n")[0], "来自理由的简报");
    const r2 = { title: "标题乙", key_brief: "", key_reasons: "" };
    assert.strictEqual(keyNotifyText(r2).body.split("\n")[0], "标题乙");
});

t("多空分歧的通知写「多空分歧」", () => {
    const r = { title: "分歧稿", key_brief: "分歧稿 → 多空分歧", key_score: 60, impact: JSON.stringify({ direction: "mixed", strength: "分歧", targets: [] }), key_reasons: "" };
    assert.ok(keyNotifyText(r).body.includes("多空分歧"), keyNotifyText(r).body);
});

console.log("");
console.log("通过 " + pass + " / " + (pass + fail));
if (fail) process.exit(1);
