// 重点消息自动挑选算法单测：按起止标记从 worker.js 切片，不依赖 D1 / 网络
//   覆盖：高分重点命中、低分噪音降权、时效性、来源权重、阈值边界、跨维联动。
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "worker.js"), "utf8");
const START = "// ==== KEY_PICK_ENGINE_START ===";
const END = "// ==== KEY_PICK_ENGINE_END ===";
const i = src.indexOf(START), j = src.indexOf(END, i);
if (i < 0 || j < 0) throw new Error("key pick engine markers missing");

const sandbox = { console };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(src.slice(i, j), sandbox, { filename: "key-pick-part.js" });

const { pickKeyNews } = sandbox;
let pass = 0, fail = 0;
function check(name, actual, expected) {
    const ok = actual === expected;
    if (ok) pass++; else fail++;
    console.log(`${ok ? "PASS" : "FAIL"} ${name} -> ${actual}${ok ? "" : ` (期望 ${expected})`}`);
}

// 固定「现在」为 2026-11-13 16:00（北京），保证时效性断言稳定
const NOW = Date.parse("2026-11-13T16:00:00+08:00");
// 构造 impact 结果
const IMP = (direction, strength, targets, event, scope) => ({
    direction, strength, targets: (targets || []).map(n => ({ key: n, name: n })),
    event: event || "", scope: scope || "none"
});
// 便捷调用
const K = (title, summary = "", channel = "macro", impact = null, source = "sina", publishedAt = "2026-11-13 15:30:00") =>
    pickKeyNews(title, summary, channel, impact, source, publishedAt, NOW);

// —— ① 高重要性消息应被判为重点（用户场景：加息→黄金偏跌 / 英伟达消息→股票涨跌）——
check("美联储加息+金价影响 -> 重点", K("美联储宣布加息25个基点，美元指数走强", "", "macro",
    IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal")).isKey, true);
check("加息消息 -> 综合分 >= 55", K("美联储宣布加息25个基点，美元指数走强", "", "macro",
    IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal")).score >= 55, true);
check("英伟达业绩超预期 -> 重点", K("英伟达业绩超预期，数据中心营收激增", "", "ai",
    IMP("bullish", "强", ["英伟达", "AI算力"], "公司业绩", "ai")).isKey, true);
check("出口管制升级 -> 重点", K("英伟达遭出口管制升级，A股算力硬件股集体下挫", "高端GPU出货受限", "ai",
    IMP("bearish", "强", ["英伟达", "AI算力", "AI芯片"], "政策监管", "ai")).isKey, true);
check("重点消息会给出挑选理由", K("美联储宣布加息25个基点", "", "macro",
    IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal")).reasons.length > 0, true);

// —— ② 噪音 / 低价值内容不得点亮 ——
check("研报解读 -> 不点亮", K("【风口研报】AI算力板块投资策略解读", "", "ai",
    IMP("neutral", "弱", [], "", "none"), "eastmoney").isKey, false);
check("问答类 -> 不点亮", K("算力板块是否值得关注？", "投资者提问", "ai",
    IMP("neutral", "弱", [], "", "none")).isKey, false);
check("指数日常震荡 -> 不点亮", K("今日A股三大指数小幅震荡", "", "equity",
    IMP("neutral", "弱", [], "", "none")).isKey, false);
check("无研判无信号 -> 不点亮", K("某公司发布新产品公告", "", "other",
    IMP("neutral", "弱", [], "", "none")).isKey, false);
check("研报含降权理由", K("【风口研报】AI算力板块投资策略解读", "", "ai",
    IMP("neutral", "弱", [], "", "none"), "eastmoney").reasons.some(r => r.includes("信息量偏低")), true);

// —— ③ 事件类型权重：能改变预期的事件更重 ——
const rateEvent = K("某政策落地", "", "macro", IMP("bullish", "中", ["金价/银价"], "宏观·利率", "metal")).score;
const perfEvent = K("某政策落地", "", "macro", IMP("bullish", "中", ["金价/银价"], "市场表现", "metal")).score;
check("宏观利率事件权重 > 市场表现事件", rateEvent > perfEvent, true);

// —— ④ 影响范围：直击贵金属核心品种加权 ——
const coreHit = K("消息", "", "macro", IMP("bullish", "中", ["金价/银价"], "宏观·利率", "metal")).score;
const noHit = K("消息", "", "macro", IMP("bullish", "中", [], "宏观·利率", "metal")).score;
check("影响标的数越多分越高", coreHit > noHit, true);
check("多标的比单标的分高", K("消息", "", "ai", IMP("bullish", "中", ["英伟达", "AI算力", "AI芯片"], "公司业绩", "ai")).score
    > K("消息", "", "ai", IMP("bullish", "中", ["英伟达"], "公司业绩", "ai")).score, true);

// —— ⑤ 时效性：同样的消息，刚发布的分更高 ——
const fresh = K("美联储加息25个基点", "", "macro", IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal"), "sina", "2026-11-13 15:50:00").score;
const old = K("美联储加息25个基点", "", "macro", IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal"), "sina", "2026-11-12 15:50:00").score;
check("刚发布的消息分更高", fresh > old, true);

// —— ⑥ 来源权威度：华尔街见闻 > 东方财富 ——
const wscn = K("美联储加息25个基点", "", "macro", IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal"), "wscn").score;
const em = K("美联储加息25个基点", "", "macro", IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal"), "eastmoney").score;
check("华尔街见闻分高于东方财富", wscn > em, true);

// —— ⑦ 阈值边界：score 达标但无方向也无信号 → 不点亮 ——
check("无方向无信号即使分高也不点亮", K("某公司发布新产品公告", "", "other", null, "wscn", "2026-11-13 15:55:00").isKey, false);

// —— ⑦' 多空交织稿不点亮（分歧本身不是方向催化）——
check("多空交织分析稿 -> 不点亮", K("多重因素支撑 黄金中长期配置价值仍存",
    "实际利率上行会抬升持有无息资产的机会成本，压制黄金的投机需求。但一旦市场开始计价2027年紧缩力度不及预期，这一因素就会转为利多黄金的变量。 央行购金构成了强有力的底部支撑。",
    "metal", IMP("neutral", "分歧", ["金价/银价"], "宏观·利率", "metal")).isKey, false);
check("多空交织稿 -> 分数明显低于单向强信号",
    K("多重因素支撑 黄金中长期配置价值仍存",
        "实际利率上行会抬升持有无息资产的机会成本，压制黄金的投机需求。但一旦市场开始计价2027年紧缩力度不及预期，这一因素就会转为利多黄金的变量。 央行购金构成了强有力的底部支撑。",
        "metal", IMP("neutral", "分歧", ["金价/银价"], "宏观·利率", "metal")).score
    < K("美联储宣布加息25个基点，美元指数走强", "", "macro", IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal")).score, true);

// —— ⑧ 输出结构完整 ——
const r = K("美联储宣布加息25个基点", "", "macro", IMP("bearish", "强", ["金价/银价"], "宏观·利率", "metal"));
check("返回含 score", typeof r.score === "number", true);
check("返回含 isKey", typeof r.isKey === "boolean", true);
check("返回含 reasons 数组", Array.isArray(r.reasons), true);
check("返回含 dims 分项", r.dims && typeof r.dims.impact === "number", true);
check("分数在 0-100 之间", r.score >= 0 && r.score <= 100, true);
check("空消息不报错", (() => { try { pickKeyNews("", "", "", null, "", "", NOW); return true; } catch (e) { return false; } })(), true);

console.log(`\n通过 ${pass} / ${pass + fail}`);
if (fail) process.exit(1);
