// 资讯相关性 / 屏蔽词单测（2026-11-19）
//   覆盖：newsBlacklistHit / newsRelevantFlag（入库标记）与 newsRelevanceFilter（查询条件）。
//   重点验证：屏蔽词已经烘进 relevant 之后，默认查询路径只剩 `relevant = 1`，
//   不再拼 N 个 NOT LIKE 全表扫描；只有关掉相关性 / 带关键词搜索时才回退 LIKE。
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

const ROOT = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "worker.js"), "utf8");

const sandbox = { console, Map, RegExp, String, Object, Array, Number };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

// 词表 + termMatches + 两个标记函数是一段连续的源码，直接整段执行
//   （AI_COMPUTE_TERMS 被 NEWS_RELEVANCE_TERMS.ai_compute 引用，先单独切出来）
const aiS = "const AI_COMPUTE_TERMS = [";
const aiE = "];";
const aiStart = src.indexOf(aiS);
if (aiStart < 0) throw new Error("worker.js 里找不到 AI_COMPUTE_TERMS");
vm.runInContext(src.slice(aiStart, src.indexOf(aiE, aiStart) + aiE.length), sandbox, { filename: "ai-terms.js" });

const S = "const AI_TERM_RE_CACHE = new Map();";
const E = "// 词表版本：改了 NEWS_RELEVANCE_TERMS";
if (src.indexOf(S) < 0 || src.indexOf(E) < 0) throw new Error("worker.js 里找不到相关性词表片段");
vm.runInContext(src.slice(src.indexOf(S), src.indexOf(E)), sandbox, { filename: "relevance.js" });

// newsRelevanceFilter 依赖 splitList / acquireOption，用最小等价实现补上
vm.runInContext([
    "function splitList(raw, max){const list=String(raw||'').split(/[,，;；\\s]+/).map(s=>s.trim()).filter(Boolean);const uniq=[...new Set(list)];return max?uniq.slice(0,max):uniq;}",
    (() => {
        const idx = src.indexOf("async function newsRelevanceFilter(");
        const start = src.indexOf("{", idx);
        let depth = 0, quote = null;
        for (let p = start; p < src.length; p++) {
            const ch = src[p];
            if (quote) { if (ch === "\\") { p++; continue; } if (ch === quote) quote = null; continue; }
            if (ch === '"' || ch === "'" || ch === "`") { quote = ch; continue; }
            if (ch === "{") depth++;
            else if (ch === "}") { depth--; if (depth === 0) return src.slice(idx, p + 1); }
        }
        throw new Error("newsRelevanceFilter 大括号没配平");
    })()
].join("\n"), sandbox, { filename: "relevance-filter.js" });

const { newsBlacklistHit, newsRelevantFlag, newsRelevanceFilter } = sandbox;

// —— 入库标记：白名单 + 屏蔽词合成一个 relevant 位 ——
assert.strictEqual(newsRelevantFlag({ title: "金价大涨再创新高" }, []), 1, "命中白名单应保留");
assert.strictEqual(newsRelevantFlag({ title: "某上市公司董事辞职" }, []), 0, "未命中四类白名单应过滤");
assert.strictEqual(
    newsRelevantFlag({ title: "黄金价格走高", summary: "某公司董事辞职" }, ["董事"]),
    0, "命中屏蔽词应过滤（即使标题命中白名单）"
);
assert.strictEqual(
    newsRelevantFlag({ title: "黄金价格走高", keywords: "董事,辞职" }, ["董事"]),
    0, "keywords 字段里的屏蔽词也要算命中"
);
assert.strictEqual(newsRelevantFlag({ title: "黄金价格走高" }, ["比特币"]), 1, "未命中屏蔽词应保留");

// —— 屏蔽词判定：大小写不敏感、空值安全 ——
assert.strictEqual(newsBlacklistHit(["ai"], { title: "AI 芯片出货量创新高" }), true);
assert.strictEqual(newsBlacklistHit([], { title: "任意标题" }), false);
assert.strictEqual(newsBlacklistHit(["董事"], null), false);

// —— 查询条件：默认只判 relevant=1，不再拼 LIKE ——
(async () => {
    const envWith = (opts) => ({
        DB: {},
        __opts: opts
    });
    const fakeAcquire = async (_env, _domain, key, fallback) => {
        const v = _env.__opts[key];
        return v === undefined || v === null || v === "" ? fallback : v;
    };
    sandbox.acquireOption = fakeAcquire;

    const def = await newsRelevanceFilter(envWith({ news_blacklist: "董事,比特币" }), {});
    assert.strictEqual(def.cond, "(relevant = 1)", "默认路径只应有 relevant = 1");
    assert.strictEqual(JSON.stringify(def.params), "[]", "默认路径不应有绑定参数");

    const search = await newsRelevanceFilter(envWith({ news_blacklist: "董事" }), { keyword: "金价" });
    assert.ok(search.cond.includes("NOT ("), "关键词搜索回退 LIKE 屏蔽词");
    assert.ok(!search.cond.includes("relevant = 1"), "关键词搜索不判 relevant（主动查询不空手而归）");
    assert.strictEqual(JSON.stringify(search.params), '["%董事%"]');

    const all = await newsRelevanceFilter(envWith({ news_blacklist: "董事" }), { skipFilter: true });
    assert.strictEqual(all.cond, "", "看全量时不过滤");
    assert.strictEqual(JSON.stringify(all.params), "[]");

    const noRelevance = await newsRelevanceFilter(envWith({ news_blacklist: "董事", news_relevance_only: "0" }), {});
    assert.ok(noRelevance.cond.includes("NOT ("), "关掉相关性后仍要按屏蔽词过滤");
    assert.ok(!noRelevance.cond.includes("relevant = 1"));

    console.log("通过：资讯相关性 / 屏蔽词 12 项断言");
})().catch(e => { console.error(e); process.exit(1); });
