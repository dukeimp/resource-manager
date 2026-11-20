// 材料联想引擎单测：按起止标记从 worker.js 切片，不依赖 D1 / 网络
//   覆盖：场景命中、组合查询、直接命中、材料链联动、反向查询、热度加权、知识库自洽性。
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "worker.js"), "utf8");
const START = "// ==== MATERIAL_ENGINE_START ====";
const END = "// ==== MATERIAL_ENGINE_END ====";
const i = src.indexOf(START), j = src.indexOf(END, i);
if (i < 0 || j < 0) throw new Error("material engine markers missing");

const sandbox = { console };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(src.slice(i, j), sandbox, { filename: "material-part.js" });

const { matchMaterials, matchMaterialReverse } = sandbox;
let pass = 0, fail = 0;
function check(name, actual, expected) {
    const ok = actual === expected;
    if (ok) pass++; else fail++;
    console.log(`${ok ? "PASS" : "FAIL"} ${name} -> ${actual}${ok ? "" : ` (期望 ${expected})`}`);
}
const names = r => (r.items || []).map(x => x.name);
const byName = (r, n) => (r.items || []).find(x => x.name === n) || null;

// —— ① 场景 → 材料 ——
const ai = matchMaterials("AI", 10);
check("AI -> 命中 AI / 算力中心", (ai.matched[0] || {}).label, "AI / 算力中心");
check("AI -> 铜排第一", names(ai)[0], "铜");
check("AI -> 每项都有相关度", ai.items.every(x => typeof x.relevance === "number" && x.relevance > 0), true);
check("AI -> 每项都有用途说明", ai.items.every(x => !!(x.reason || "").length), true);
check("AI -> 每项都有可解释理由", ai.items.every(x => Array.isArray(x.why) && x.why.length > 0), true);

// —— ② 组合查询：一次问两个场景 ——
const combo = matchMaterials("AI 液冷", 10);
check("组合查询 -> 命中两个场景", combo.matched.length >= 2, true);
check("组合查询 -> 场景标签带上第二个", combo.items[0].topics.join("/").includes("液冷"), true);
check("组合查询 -> 词元被拆分", combo.tokens.length, 2);
check("组合查询 -> 铜仍在前列", names(combo).indexOf("铜") <= 1, true);

// —— ③ 直接命中材料名 ——
const li = matchMaterials("碳酸锂", 10);
check("直接命中 -> 锂排第一", names(li)[0], "锂");
check("直接命中 -> 标记 direct", (byName(li, "锂") || {}).direct, true);
check("直接命中 -> 带上场景标签", (byName(li, "锂") || {}).topics.length > 0, true);

// —— ④ 材料链联动：查材料能带出配套材料 ——
check("材料链 -> 带出同链材料（镍）", names(li).includes("镍"), true);
check("材料链 -> 标注所属材料链", ((byName(li, "镍") || {}).chains || []).some(c => c.name === "锂电材料链"), true);
check("材料链 -> 给出链上角色", ((byName(li, "镍") || {}).chains || [])[0].role.length > 0, true);

// —— ⑤ 反向查询：材料 → 场景 / 材料链 / 配套材料 ——
const rev = matchMaterialReverse("碳酸锂");
check("反向 -> 归一到材料名", rev.name, "锂");
check("反向 -> 给出类别", rev.cat, "稀有金属");
check("反向 -> 列出使用场景", rev.scenes.some(s => s.label.includes("动力电池")), true);
check("反向 -> 场景带强度权重", rev.scenes[0].weight > 0, true);
check("反向 -> 给出材料链", rev.chains.some(c => c.name === "锂电材料链"), true);
check("反向 -> 链上角色可读", rev.chains[0].role.length > 0, true);
check("反向 -> 配套材料含镍", rev.related.some(r => r.name === "镍"), true);
const revAu = matchMaterialReverse("黄金");
check("反向 -> 别名可归一", revAu.name, "金");
check("反向 -> 未知材料不报错", matchMaterialReverse("不存在的材料xyz").name, "不存在的材料xyz");

// —— ⑥ 类别直查 ——
const cat = matchMaterials("稀土", 12);
check("类别 -> 识别为稀土", cat.category, "稀土");
check("类别 -> 列全部成员", cat.items.length, Math.min(12, 7));
check("类别 -> 成员属于该类别", cat.items.every(x => x.cat === "稀土"), true);

// —— ⑦ 资讯热度只影响排序，不凭空造分 ——
const plain = matchMaterials("AI", 10);
const hot = matchMaterials("AI", 10, { heat: { 银: 40 } });
check("热度 -> 有热度的材料排前面", names(hot)[0], "银");
check("热度 -> 不改变命中集合", names(hot).length, names(plain).length);
check("热度 -> 给出提及条数", (byName(hot, "银") || {}).heat, 40);

// —— ⑧ 边界 ——
check("空查询不报错", matchMaterials("", 10).items.length, 0);
check("空查询返回示例", matchMaterials("", 10).examples.length > 0, true);
check("特殊字符不报错", (() => { try { matchMaterials("%%%^^&", 10); return true; } catch (e) { return false; } })(), true);
check("limit 生效", matchMaterials("AI", 3).items.length, 3);
check("结果条数不超过 limit", matchMaterials("AI", 5).items.length <= 5, true);

// —— ⑨ 知识库自洽：场景 / 材料链引用的材料必须都在目录里 ——
const idx = vm.runInContext("[...MATERIAL_INDEX.keys()]", sandbox);
const catNames = vm.runInContext("Object.keys(MATERIAL_CATALOG)", sandbox);
const topics = vm.runInContext("MATERIAL_TOPICS", sandbox);
const chains = vm.runInContext("MATERIAL_CHAINS", sandbox);
const missingInTopics = [];
topics.forEach(t => t.items.forEach(it => { if (!idx.includes(it[0])) missingInTopics.push(`${t.key}:${it[0]}`); }));
check("场景引用的材料都在目录里", missingInTopics.join(","), "");
const missingInChains = [];
chains.forEach(c => c.members.forEach(m => { if (!idx.includes(m[0])) missingInChains.push(`${c.key}:${m[0]}`); }));
check("材料链引用的材料都在目录里", missingInChains.join(","), "");
check("材料目录有材料", idx.length > 40, true);
check("场景数量达到 30+", topics.length >= 30, true);
check("材料链数量达到 10+", chains.length >= 10, true);
check("类别清单非空", catNames.length >= 5, true);

console.log(`\n通过 ${pass} / ${pass + fail}`);
if (fail) process.exit(1);
