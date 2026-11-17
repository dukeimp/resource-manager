// 情绪判定引擎的单元测试：直接从 worker.js 里抽出函数跑，不依赖 D1
const fs = require("fs");
const vm = require("vm");

const path = require("path");
const src = fs.readFileSync(path.join(__dirname, "..", "worker.js"), "utf8");

// 抽出需要的常量与函数（按 worker.js 中的真实边界切片，勿重叠）
function grab(startMark, endMark) {
    const i = src.indexOf(startMark);
    const j = src.indexOf(endMark, i);
    if (i < 0 || j < 0) throw new Error("extract failed: " + startMark + " -> " + endMark);
    return src.slice(i, j);
}
const code = [
    // 起点前移到 AI_COMPUTE_TERMS：相关性白名单里引用了它，单测沙箱必须一并带入
    grab("const AI_COMPUTE_TERMS = [", "const NEWS_ALIAS_KIND = {"),
    grab("const NEWS_ALIAS_KIND = {", "function tagNewsSymbols(text, instruments) {"), // 含 NEWS_MACRO_ALIASES
    grab("function tagNewsSymbols(text, instruments) {", "const SENTIMENT_WORDS = ["),
    grab("const SENTIMENT_WORDS = [", "function nowBeijing() {") // 含 MACRO_SUBJECTS / judgeSentiment
].join("\n");

const sandbox = { console, TextEncoder, TextDecoder, crypto: require("crypto").webcrypto };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: "sent-part.js" });

// 构造一份最小品种表（与真实库结构一致）
const INSTRUMENTS = [
    { symbol: "AU0", name: "沪金主连", short_name: "沪金", kind: "黄金", scope: "metal", enabled: 1 },
    { symbol: "AG0", name: "沪银主连", short_name: "沪银", kind: "白银", scope: "metal", enabled: 1 },
    { symbol: "LC0", name: "碳酸锂主连", short_name: "碳酸锂", kind: "锂", scope: "rare", enabled: 1 },
    { symbol: "CU0", name: "沪铜主连", short_name: "沪铜", kind: "铜", scope: "rare", enabled: 1 },
    { symbol: "NI0", name: "沪镍主连", short_name: "沪镍", kind: "镍", scope: "rare", enabled: 1 },
    { symbol: "SI0", name: "工业硅主连", short_name: "工业硅", kind: "硅", scope: "rare", enabled: 1 },
    { symbol: "PS0", name: "多晶硅主连", short_name: "多晶硅", kind: "硅", scope: "rare", enabled: 1 }
];

let pass = 0, fail = 0;
// expectLabel 为 null 表示「该标的不应出现在 map 里（未打标 → 与我们无关）」
function check(title, text, expectSym, expectLabel, expectOverall) {
    const syms = sandbox.tagNewsSymbols(text, INSTRUMENTS);
    const j = sandbox.judgeSentiment(text, INSTRUMENTS, syms, null);
    const m = j.map[expectSym];
    const gotLabel = m ? m.label : "(无条目)";
    const gotOverall = j.sentiment;
    const ok = (expectLabel === null ? !m : gotLabel === expectLabel) &&
        (!expectOverall || gotOverall === expectOverall);
    if (ok) {
        pass++;
        console.log("  PASS", title, "->", expectSym + ":" + gotLabel, "整体:" + gotOverall,
            "| score:" + (m ? m.score : "-"), "依据:" + (m ? (m.hits || []).join("/") : "-"),
            "| 打标:" + syms.join(","));
    } else {
        fail++;
        console.log("  FAIL", title);
        console.log("      期望:", expectSym, expectLabel, "整体", expectOverall || "-");
        console.log("      实际:", gotLabel, "整体", gotOverall);
        console.log("      标的:", syms.join(","), "| map:", JSON.stringify(j.map));
    }
}

console.log("\n=== 情绪判定测试 ===\n");

// —— 一、方向与主语配对 ——
check("金价上涨 -> 沪金利多",
    "沪金主力合约今日大幅上涨，金价突破关键点位", "AU0", "bullish", "bullish");

check("现货黄金重返4000 -> 沪金利多",
    "直线拉升！现货黄金重返4000美元/盎司", "AU0", "bullish", "bullish");

check("铜价下跌 -> 沪铜利空",
    "今日沪铜价格大幅下跌，跌破支撑位", "CU0", "bearish", "bearish");

check("锂矿减产 -> 碳酸锂利多",
    "受锂矿减产影响，碳酸锂供应偏紧，锂价上涨", "LC0", "bullish");

// —— 二、宏观主体：方向取反 ——
check("美联储加息 -> 黄金利空（宏观）",
    "美联储宣布加息25个基点，美元指数走强", "AU0", "bearish", "bearish");

check("美联储降息 -> 黄金利多（宏观）",
    "美联储释放降息信号，市场预期年内降息两次", "AU0", "bullish", "bullish");

check("避险升温 -> 黄金利多",
    "地缘局势紧张，市场避险情绪升温，黄金走强", "AU0", "bullish", "bullish");

// —— 三、否定词反向 ——
check("未上涨 -> 反向为利空",
    "现货黄金价格未上涨，市场情绪谨慎", "AU0", "bearish", "bearish");

// —— 四、无关消息不参与判定（不打标的标的不该出现在 map 里）——
check("锂价下跌与黄金无关 -> 沪金无条目",
    "碳酸锂期货今日大跌，锂价跌穿成本线", "AU0", null);

check("美股评级消息 -> 黄金无条目",
    "德意志银行将苹果评级下调至卖出，目标价180美元", "AU0", null);

check("光伏需求 -> 黄金无条目（只影响硅）",
    "光伏需求增长带动多晶硅价格上行", "AU0", null);

check("光伏需求 -> 多晶硅利多",
    "光伏需求增长带动多晶硅价格上行", "PS0", "bullish");

// —— 五、供需语义 ——
check("产量不及预期 -> 利空",
    "白银矿产量不及预期，供应承压", "AG0", "bearish", "bearish");

check("供应中断 -> 镍利多",
    "印尼镍矿供应中断，镍价跳涨", "NI0", "bullish", "bullish");

// —— 六、此前判错的真实样本 ——
check("真实样本A 黄金股ETF涨停潮 -> 利多",
    "金价收复4000美元，黄金股ETF华夏（159562）持仓股现涨停潮", "AU0", "bullish", "bullish");

check("真实样本B 美元指数下跌 -> 黄金利多",
    "美元指数2日下跌，累计跌幅达0.6%", "AU0", "bullish", "bullish");

// —— 七、同句内两个品种方向相反，不能互相污染 ——
check("沪金跌/黄金涨 -> 沪金利空（黄金逆势上涨不再单独打标）",
    "沪金主力合约今日大幅下跌，但现货黄金逆势上涨", "AU0", "bearish");

// （原「伦敦金利多、整体相抵为中性」用例随伦敦金品种删除一并移除 —— 对冲场景已不存在）

// —— 八、噪声/歧义防护（真实数据里踩过的坑）——
check("成语真金白银 -> 不打标白银",
    "产业资本真金白银回购彰显信心，回调后基本面支撑明确", "AG0", null);

check("美联储逆回购 -> 黄金中性（回购不是利多词）",
    "美联储隔夜逆回购协议周二使用规模为4.27亿美元", "AU0", "neutral", "neutral");

check("不愿降息 -> 黄金利空（否定词隔一字）",
    "特朗普表示：美联储不愿降息", "AU0", "bearish", "bearish");

check("并列主语 金价银价 -> 金银都利多",
    "油价，大跌！金价银价，大涨", "AU0", "bullish", "bullish");

check("并列主语 金价银价 -> 银也利多",
    "油价，大跌！金价银价，大涨", "AG0", "bullish");

// —— 九、贵金属泛称与干扰主语 ——
check("贵金属板块走强 -> 黄金利多",
    "期市收评 | 商品期货跌多涨少 贵金属涨幅居前", "AU0", "bullish", "bullish");

check("贵金属走强 -> 白银也利多",
    "有色/贵金属 | 民主党横扫国会 流动性好转拉升贵金属", "AG0", "bullish");

check("油价暴跌不该算成黄金利空",
    "黄金时间·每日论金：油价暴跌缓解通胀压力 黄金超跌反弹", "AU0", "bullish", "bullish");

check("A股大反攻不该算成黄金利多（与我们无关）",
    "A股午后大反攻：沪指大涨2.16%，创指怒涨6.4%", "AU0", null);

// —— 十、人工修正不被覆盖 ——
(function manualCase() {
    const syms = sandbox.tagNewsSymbols("现货黄金重返4000美元", INSTRUMENTS);
    const prev = { XAU: { label: "bearish", score: -2, hits: ["人工"], manual: 1 } };
    const j = sandbox.judgeSentiment("现货黄金重返4000美元", INSTRUMENTS, syms, prev);
    if (j.map.XAU && j.map.XAU.label === "bearish" && j.map.XAU.manual === 1) {
        pass++;
        console.log("  PASS 人工修正保留 -> 覆盖自动判定为利多", "| 实际:", j.map.XAU.label, "manual:" + j.map.XAU.manual);
    } else {
        fail++;
        console.log("  FAIL 人工修正保留 ->", JSON.stringify(j.map));
    }
})();

console.log("\n通过 " + pass + " / " + (pass + fail));
if (fail) process.exit(1);
