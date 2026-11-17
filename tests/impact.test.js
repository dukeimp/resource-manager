// 消息影响研判引擎单测：按起止标记从 worker.js 切片，不依赖 D1 / 网络
//   覆盖两类用户场景：宏观变量 → 金价、AI 事件 → 板块 / 公司；以及易误伤边界。
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "worker.js"), "utf8");
const START = "// ==== IMPACT_ENGINE_START ===";
const END = "// ==== IMPACT_ENGINE_END ===";
const i = src.indexOf(START), j = src.indexOf(END, i);
if (i < 0 || j < 0) throw new Error("impact engine markers missing");

const sandbox = { console };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(src.slice(i, j), sandbox, { filename: "impact-part.js" });

const { judgeImpact, parseImpact } = sandbox;
let pass = 0, fail = 0;
function check(name, actual, expected) {
    const ok = actual === expected;
    if (ok) pass++; else fail++;
    console.log(`${ok ? "PASS" : "FAIL"} ${name} -> ${actual}${ok ? "" : ` (期望 ${expected})`}`);
}
const J = (title, summary = "", channel = "") => judgeImpact(title, summary, channel);

// —— ① 宏观变量 → 金价（用户例子：美元加息，未来黄金会跌）——
check("美联储加息 -> 金价偏跌", J("美联储宣布加息25个基点", "", "macro").direction, "bearish");
check("美联储加息 -> 影响金价/银价", J("美联储宣布加息25个基点", "", "macro").targets.some(t => t.key === "GOLD"), true);
check("美联储加息 -> 传导链含实际利率", J("美联储宣布加息25个基点", "", "macro").chains[0].includes("实际利率"), true);
check("美联储降息 -> 金价偏涨", J("美联储降息预期升温", "", "macro").direction, "bullish");
check("美元走强 -> 金价偏跌", J("美元指数走强突破105", "", "macro").direction, "bearish");
check("美元走弱 -> 金价偏涨", J("美元指数走弱", "", "macro").direction, "bullish");
check("实际利率上行 -> 偏跌", J("实际利率上行", "", "macro").direction, "bearish");
check("避险升温 -> 偏涨", J("地缘紧张局势升级，避险情绪升温", "", "macro").direction, "bullish");
check("美联储不加息 -> 否定词反向为偏涨", J("美联储不加息", "", "macro").direction, "bullish");

// —— ② 易误伤边界（2026-11-12 定稿口径）——
check("日本央行加息 -> 不误判金价", J("日本央行加息", "", "macro").scope, "none");
check("欧洲央行加息 -> 不误判金价", J("欧洲央行加息", "", "macro").scope, "none");
check("3亿美元收购 -> 不误判美元", J("某公司3亿美元收购AI初创企业", "", "ai").direction, "neutral");
check("英文 said/air/email -> 不被裸 ai 误伤", J("said he would chair the air quality email", "", "ai").scope, "none");
check("普通闲聊 -> 无研判", J("今日天气晴", "", "other").scope, "none");

// —— ③ AI 事件 → 板块 / 公司（用户例子：英伟达因某条消息未来股票涨跌）——
check("英伟达出口管制 -> 偏跌", J("英伟达遭美国出口管制升级", "高端GPU出货受限", "ai").direction, "bearish");
check("英伟达出口管制 -> 点名英伟达", J("英伟达遭美国出口管制升级", "", "ai").targets.some(t => t.key === "NVDA"), true);
check("出口管制 -> 传导链含出货受限", J("英伟达遭美国出口管制升级", "", "ai").chains[0].includes("出货受限"), true);
check("英伟达业绩超预期 -> 偏涨", J("英伟达业绩超预期，数据中心营收激增", "", "ai").direction, "bullish");
check("业绩不及预期 -> 偏跌", J("某芯片公司业绩不及预期", "", "ai").direction, "bearish");
check("砍单 -> 偏跌", J("AI芯片大客户砍单，需求走弱", "", "ai").direction, "bearish");
check("政策扶持国产替代 -> 偏涨", J("政策扶持国产替代，算力产业链受益", "", "ai").direction, "bullish");
check("供不应求涨价 -> 偏涨", J("HBM供不应求，厂商提价", "", "ai").direction, "bullish");
check("AI频道未点名标的 -> AI板块兜底", J("算力产业链订单激增", "", "ai").targets.some(t => t.key === "AI" || t.key === "COMPUTE"), true);
check("强催化分级", J("英伟达业绩超预期且获大单，产能满载", "", "ai").strength, "强");

// —— ③' 真实快讯抽样校准（2026-11-13，防止误判 / 漏判回归）——
check("反对滥用出口管制 -> 不误判偏跌", J("外交部：中方一贯反对滥用出口管制措施，扰乱全球产供链的稳定", "", "ai").direction, "neutral");
check("收紧数据中心审批 -> 不误判偏涨", J("如果美国、欧洲多地收紧大型数据中心新建审批，对公司是否有影响？", "", "ai").direction, "neutral");
check("增收不增利 -> 偏跌", J("领益智造加码AI服务器液冷赛道！公司前三季度增收不增利", "", "ai").direction, "bearish");
check("算力硬件股集体下挫 -> 偏跌", J("收评：创业板指高开低走跌3.32% 算力硬件股集体下挫", "", "ai").direction, "bearish");
check("发布在即/销量增 -> 偏涨", J("华为云具身世界模型发布在即!双十一销量增700% 人形机器人板块再迎催化", "", "ai").direction, "bullish");
check("市场表现类传导链标注非预测", J("算力硬件股集体下挫", "", "ai").chains[0].includes("非未来预测"), true);

// —— ③'' 多空交织 / 误挂标的回归（2026-11-13 重点挑选实测发现）——
check("多空交织分析稿 -> 不强给方向", J("多重因素支撑 黄金中长期配置价值仍存",
    "实际利率上行会抬升持有无息资产的机会成本，压制黄金的投机需求。但一旦市场开始计价2027年紧缩力度不及预期，这一因素就会转为利多黄金的变量。 央行购金构成了强有力的底部支撑。",
    "metal").direction, "neutral");
check("多空交织 -> 标记 mixed", J("多重因素支撑 黄金中长期配置价值仍存",
    "实际利率上行会抬升持有无息资产的机会成本，压制黄金的投机需求。但一旦市场开始计价2027年紧缩力度不及预期，这一因素就会转为利多黄金的变量。 央行购金构成了强有力的底部支撑。",
    "metal").mixed, 1);
check("多空交织 -> 强度标为分歧", J("多重因素支撑 黄金中长期配置价值仍存",
    "实际利率上行会抬升持有无息资产的机会成本，压制黄金的投机需求。但一旦市场开始计价2027年紧缩力度不及预期，这一因素就会转为利多黄金的变量。 央行购金构成了强有力的底部支撑。",
    "metal").strength, "分歧");
check("金属频道消息不被错挂 AI板块", J("多重因素支撑 黄金中长期配置价值仍存",
    "实际利率上行会抬升持有无息资产的机会成本，压制黄金的投机需求。但一旦市场开始计价2027年紧缩力度不及预期，这一因素就会转为利多黄金的变量。 央行购金构成了强有力的底部支撑。",
    "metal").targets.some(t => t.key === "AI"), false);
check("宏观语境的不及预期 -> 不归为公司业绩", J("多重因素支撑 黄金中长期配置价值仍存",
    "实际利率上行会抬升持有无息资产的机会成本，压制黄金的投机需求。但一旦市场开始计价2027年紧缩力度不及预期，这一因素就会转为利多黄金的变量。 央行购金构成了强有力的底部支撑。",
    "metal").event, "宏观·利率");
check("业绩不及预期 -> 仍归为公司业绩", J("英伟达业绩不及预期，营收下滑", "", "ai").event, "公司业绩");

// —— ④ 输出结构与容错 ——
const r = J("美联储加息", "", "macro");
check("版本号写入", typeof r.v === "string" && r.v.length > 0, true);
check("人工标记默认 0", r.manual, 0);
check("依据词非空", r.hits.length > 0, true);
check("scope 为 metal", r.scope, "metal");
check("坏 JSON 不抛异常", parseImpact("{bad json"), null);
check("空值解析为 null", parseImpact(""), null);
check("合法 JSON 可解析", parseImpact(JSON.stringify(r)).direction, "bearish");

console.log(`\n通过 ${pass} / ${pass + fail}`);
if (fail) process.exit(1);
