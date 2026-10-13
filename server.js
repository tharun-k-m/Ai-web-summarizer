require("dotenv").config();
const express = require("express");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const net = require("net");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const KEY = process.env.GROQ_API_KEY;
const MODEL = process.env.GROQ_MODEL || "openai/gpt-oss-20b";
const MAX_CHARS = 12000;
const MAX_CHATS = 3;

// ---- analytics config (all optional: without SUPABASE_* the app works, it just doesn't record) ----
const SB_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SB_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const IP_SALT = process.env.IP_SALT || "gist-default-salt-change-me";
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 90);
const TRACKING = !!(SB_URL && SB_KEY);

app.set("trust proxy", true);
app.use(express.json({ limit: "200kb" }));
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Headers", "Content-Type, x-visitor, x-session, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.static(path.join(__dirname, "public")));
app.get("/admin", (req, res) => { res.set("X-Robots-Tag", "noindex"); res.sendFile(path.join(__dirname, "public", "admin.html")); });

// ======================= analytics =======================
const COLS = ["created_at", "type", "visitor_id", "session_id", "ip_hash", "country", "device", "browser", "os", "language", "browser_lang",
  "referrer_domain", "utm_source", "utm_medium", "utm_campaign", "page", "screen_w", "screen_h", "viewport_w", "viewport_h", "dpr",
  "timezone", "connection", "color_scheme", "reduced_motion", "touch", "is_new", "domain", "success", "duration_ms", "value", "error", "meta", "consent"];
const EVENT_TYPES = new Set(["page_view", "perf", "session_end", "url_focus", "url_paste", "summarize_click", "result_view", "language_change",
  "chat_toggle", "chat_send", "tab_switch", "export", "visit_click", "result_link_click", "intro", "js_error", "consent"]);

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const clip = (v, n = 200) => (v === null || v === undefined ? null : String(v).slice(0, n));
const num = (v) => (v !== null && v !== "" && v !== undefined && Number.isFinite(Number(v)) ? Number(v) : null);
const validId = (s) => typeof s === "string" && /^[a-zA-Z0-9-]{8,64}$/.test(s);
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const cleanLang = (l) => String(l || "English").replace(/[^\p{L} ()-]/gu, "").slice(0, 30) || "English";

function parseUA(ua = "") {
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad|iPod/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "Other";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\/|Opera/.test(ua) ? "Opera" : /SamsungBrowser/.test(ua) ? "Samsung Internet" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\/|CriOS/.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Other";
  const device = /iPad|Tablet/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua)) ? "Tablet" : /Mobi|iPhone|Android/.test(ua) ? "Mobile" : "Desktop";
  return { os, browser, device, bot: /bot|crawl|spider|slurp|headless|lighthouse|monitor|preview/i.test(ua) };
}
const clientIp = (req) => String(req.get("cf-connecting-ip") || req.get("x-forwarded-for") || req.ip || "").split(",")[0].trim();
function enrich(req) {            // privacy: the raw IP is never stored, only a salted one-way hash
  const p = parseUA(req.get("user-agent") || ""), ip = clientIp(req), c = String(req.get("cf-ipcountry") || "");
  return { ip_hash: ip ? sha(ip + IP_SALT).slice(0, 16) : null, country: /^[A-Za-z]{2}$/.test(c) ? c.toUpperCase() : null, device: p.device, browser: p.browser, os: p.os };
}

const queue = [];
function push(row) {
  const r = {};
  for (const c of COLS) r[c] = row[c] === undefined ? null : row[c];
  r.created_at = r.created_at || new Date().toISOString();
  queue.push(r);
  if (queue.length >= 25) flush();
}
async function sb(q, opts = {}) {
  const res = await fetch(`${SB_URL}/rest/v1/${q}`, {
    ...opts,
    headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, "Content-Type": "application/json", ...(opts.headers || {}) },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res;
}
let flushing = false;
async function flush() {
  if (!TRACKING || flushing || !queue.length) return;
  flushing = true;
  const batch = queue.splice(0, 200);
  try { await sb("events", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify(batch) }); }
  catch (e) { console.error("track flush failed:", e.message); }   // analytics must never break the app
  finally { flushing = false; }
}
setInterval(flush, 3000).unref();
process.on("SIGTERM", async () => { await flush(); process.exit(0); });

// server-side events (summaries, translations, chat). Visitor/session ids are only attached if the browser sent them (= user consented).
function track(req, row) {
  if (!TRACKING) return;
  try {
    if (parseUA(req.get("user-agent") || "").bot) return;
    const vid = req.get("x-visitor"), sid = req.get("x-session"), consent = validId(vid) && validId(sid);
    push({ ...(consent ? { ...enrich(req), visitor_id: vid, session_id: sid } : {}), consent, ...row });
  } catch {}
}

async function purgeOld() {        // data retention
  if (!TRACKING) return;
  try { await sb(`events?created_at=lt.${encodeURIComponent(new Date(Date.now() - RETENTION_DAYS * 864e5).toISOString())}`, { method: "DELETE" }); }
  catch (e) { console.error("purge failed:", e.message); }
}
purgeOld(); setInterval(purgeOld, 864e5).unref();

const hits = new Map();
function limited(key, max, ms) {
  const now = Date.now(), h = (hits.get(key) || []).filter((t) => now - t < ms);
  h.push(now); hits.set(key, h);
  if (hits.size > 5000) hits.clear();
  return h.length > max;
}
function cleanMeta(m) {
  if (!m || typeof m !== "object") return null;
  const out = {};
  for (const k of Object.keys(m).slice(0, 10)) { const v = m[k]; if (["string", "number", "boolean"].includes(typeof v)) out[String(k).slice(0, 30)] = typeof v === "string" ? v.slice(0, 120) : v; }
  return Object.keys(out).length ? out : null;
}

// browser events (sent with navigator.sendBeacon; plain text body so no CORS pre-flight is needed)
app.post("/api/track", express.text({ type: "*/*", limit: "100kb" }), (req, res) => {
  res.sendStatus(204);             // never make the page wait
  if (!TRACKING) return;
  try {
    if (parseUA(req.get("user-agent") || "").bot || limited("track:" + clientIp(req), 240, 60000)) return;
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
    const c = body.ctx || {}, events = Array.isArray(body.events) ? body.events.slice(0, 25) : [];
    const consented = body.consent === true && validId(c.vid) && validId(c.sid);
    const who = consented ? enrich(req) : {};
    for (const e of events) {
      if (!e || !EVENT_TYPES.has(e.type) || (!consented && e.type !== "consent")) continue;
      const at = Number(e.at), ts = Number.isFinite(at) && Math.abs(Date.now() - at) < 36e5 ? new Date(at) : new Date();
      push({
        created_at: ts.toISOString(), type: e.type, consent: consented, value: num(e.v), meta: cleanMeta(e.m),
        ...(consented ? {
          ...who, visitor_id: c.vid, session_id: c.sid, language: clip(c.ui, 30), browser_lang: clip(c.bl, 20), referrer_domain: clip(c.ref, 100),
          utm_source: clip(c.utm && c.utm.source, 60), utm_medium: clip(c.utm && c.utm.medium, 60), utm_campaign: clip(c.utm && c.utm.campaign, 60),
          page: clip(c.page, 100), screen_w: num(c.sw), screen_h: num(c.sh), viewport_w: num(c.vw), viewport_h: num(c.vh), dpr: num(c.dpr),
          timezone: clip(c.tz, 60), connection: clip(c.conn, 10), color_scheme: clip(c.cs, 10), reduced_motion: !!c.rm, touch: !!c.touch, is_new: !!c.isNew,
        } : {}),
      });
    }
  } catch {}
});

// "Delete my data": removes every event linked to the visitor id stored in that browser
app.post("/api/privacy/delete", async (req, res) => {
  try {
    const vid = (req.body || {}).vid;
    if (!validId(vid)) return res.status(400).json({ error: "Invalid ID." });
    if (TRACKING) { await flush(); await sb(`events?visitor_id=eq.${encodeURIComponent(vid)}`, { method: "DELETE" }); }
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: "Could not delete." }); }
});

// ---------- admin dashboard API ----------
const fails = new Map();
function adminAuth(req, res, next) {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Set ADMIN_PASSWORD on the server first." });
  const ip = clientIp(req) || "x", now = Date.now(), recent = (fails.get(ip) || []).filter((t) => now - t < 15 * 60000);
  if (recent.length >= 10) return res.status(429).json({ error: "Too many wrong passwords. Try again later." });
  const given = (req.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const a = crypto.createHash("sha256").update(given).digest(), b = crypto.createHash("sha256").update(ADMIN_PASSWORD).digest();
  if (!crypto.timingSafeEqual(a, b)) { recent.push(now); fails.set(ip, recent); return res.status(401).json({ error: "Wrong password." }); }
  next();
}
async function loadRows(days) {
  const since = encodeURIComponent(new Date(Date.now() - days * 864e5).toISOString()), rows = [];
  for (let off = 0; off < 30000; off += 1000) {
    const r = await (await sb(`events?select=*&created_at=gte.${since}&order=created_at.desc&limit=1000&offset=${off}`)).json();
    rows.push(...r);
    if (r.length < 1000) break;
  }
  return rows;
}
function aggregate(rows, days, tzOff) {
  const ofType = (t) => rows.filter((r) => r.type === t);
  const top = (list, f, n = 8) => {
    const m = new Map();
    for (const r of list) { const k = f(r); if (k === null || k === undefined || k === "") continue; m.set(k, (m.get(k) || 0) + 1); }
    return [...m].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ k: String(k), v }));
  };
  const uniq = (list, f) => new Set(list.map(f).filter(Boolean)).size;
  const avg = (a) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : 0);
  const med = (a) => (a.length ? [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)] : 0);
  const nums = (list, f) => list.map(f).filter((v) => typeof v === "number" && Number.isFinite(v));
  const meta = (r) => r.meta || {};
  const consented = rows.filter((r) => r.consent && r.visitor_id);
  const views = ofType("page_view"), sums = ofType("summarize"), good = sums.filter((r) => r.success);
  const sessionsWith = (types) => uniq(consented.filter((r) => types.includes(r.type)), (r) => r.session_id);

  const visitors = uniq(consented, (r) => r.visitor_id), newVisitors = uniq(views.filter((r) => r.is_new), (r) => r.visitor_id);
  const spent = new Map(), scroll = new Map();
  for (const r of ofType("session_end")) {
    if (!r.session_id) continue;
    spent.set(r.session_id, (spent.get(r.session_id) || 0) + (r.value || 0));
    scroll.set(r.session_id, Math.max(scroll.get(r.session_id) || 0, Number(meta(r).scroll) || 0));
  }
  const dayKey = (iso) => new Date(new Date(iso).getTime() - tzOff * 60000).toISOString().slice(0, 10);
  const keys = [];
  for (let i = days - 1; i >= 0; i--) keys.push(new Date(Date.now() - i * 864e5 - tzOff * 60000).toISOString().slice(0, 10));
  const idx = new Map(keys.map((k, i) => [k, i])), series = keys.map((day) => ({ day, views: 0, summaries: 0, visitors: new Set() })), hours = Array(24).fill(0);
  for (const r of rows) {
    if (r.type !== "page_view" && r.type !== "summarize") continue;
    const i = idx.get(dayKey(r.created_at));
    if (i === undefined) continue;
    if (r.type === "page_view") { series[i].views++; if (r.visitor_id) series[i].visitors.add(r.visitor_id); } else series[i].summaries++;
    hours[new Date(new Date(r.created_at).getTime() - tzOff * 60000).getUTCHours()]++;
  }
  series.forEach((s) => (s.visitors = s.visitors.size));
  const intro = ofType("intro"), choices = ofType("consent").map((r) => meta(r).choice);
  const bucket = (r) => (r.viewport_w < 600 ? "Phone-size" : r.viewport_w < 1024 ? "Tablet-size" : "Desktop-size");

  return {
    range: { days }, generated: new Date().toISOString(), totalRows: rows.length,
    kpi: {
      visitors, sessions: uniq(consented, (r) => r.session_id), views: views.length, newVisitors, returning: Math.max(0, visitors - newVisitors),
      avgSessionMs: avg([...spent.values()]), avgScroll: avg([...scroll.values()].filter((v) => v > 0)),
      summaries: sums.length, successRate: sums.length ? Math.round((good.length / sums.length) * 100) : 0,
      avgSummarizeMs: avg(nums(good, (r) => r.duration_ms)), medSummarizeMs: med(nums(good, (r) => r.duration_ms)),
      chats: ofType("chat").filter((r) => r.success).length, exports: ofType("export").length, translations: ofType("translate").filter((r) => r.success).length,
      consentYes: choices.filter((c) => c === "yes").length, consentNo: choices.filter((c) => c === "no").length,
    },
    series, hours,
    funnel: [
      { k: "Visited", v: sessionsWith(["page_view"]) }, { k: "Clicked the URL box", v: sessionsWith(["url_focus"]) },
      { k: "Pressed Summarize", v: sessionsWith(["summarize_click"]) }, { k: "Got a summary", v: uniq(good.filter((r) => r.session_id), (r) => r.session_id) },
      { k: "Explored the results", v: sessionsWith(["chat_send", "export", "tab_switch", "visit_click", "result_link_click", "language_change"]) },
    ],
    audience: {
      devices: top(views, (r) => r.device), browsers: top(views, (r) => r.browser), os: top(views, (r) => r.os), countries: top(views, (r) => r.country, 10),
      screens: top(views, bucket), connection: top(views, (r) => r.connection), colorScheme: top(views, (r) => r.color_scheme),
      timezones: top(views, (r) => r.timezone), browserLangs: top(views, (r) => r.browser_lang),
    },
    sources: { referrers: top(views, (r) => r.referrer_domain || "Direct"), utm: top(views, (r) => r.utm_source), campaigns: top(views, (r) => r.utm_campaign) },
    usage: {
      domains: top(sums, (r) => r.domain, 10), targetLangs: top(sums, (r) => r.language), translations: top(ofType("translate"), (r) => r.language),
      exports: top(ofType("export"), (r) => meta(r).format), tabs: top(ofType("tab_switch"), (r) => meta(r).tab),
      links: top(ofType("result_link_click"), (r) => meta(r).kind), visitClicks: ofType("visit_click").length,
      avgPageChars: avg(nums(good, (r) => Number(meta(r).chars))), avgQuestionLen: avg(nums(ofType("chat"), (r) => r.value)),
      emailsFound: avg(nums(good, (r) => Number(meta(r).emails))), linksFound: avg(nums(good, (r) => Number(meta(r).internal) + Number(meta(r).external))),
    },
    health: {
      jsErrors: top(ofType("js_error"), (r) => meta(r).msg), failures: top(sums.filter((r) => !r.success), (r) => r.error),
      loadAvgMs: avg(nums(ofType("perf"), (r) => r.value)), ttfbAvgMs: avg(nums(ofType("perf"), (r) => Number(meta(r).ttfb))),
      introDone: intro.filter((r) => !meta(r).skipped && !meta(r).reduced).length, introSkipped: intro.filter((r) => meta(r).skipped).length, introReduced: intro.filter((r) => meta(r).reduced).length,
      reducedMotionUsers: views.filter((r) => r.reduced_motion).length, touchViews: views.filter((r) => r.touch).length,
    },
    recent: rows.slice(0, 150).map((r) => ({ t: r.created_at, type: r.type, s: r.session_id ? r.session_id.slice(0, 6) : "", country: r.country, device: r.device, browser: r.browser, domain: r.domain, language: r.language, ok: r.success, ms: r.duration_ms, v: r.value, err: r.error })),
  };
}
app.get("/api/admin/stats", adminAuth, async (req, res) => {
  try {
    if (!TRACKING) return res.status(503).json({ error: "Supabase is not configured on the server." });
    await flush();
    const days = clamp(Number(req.query.days) || 7, 1, 90);
    res.json(aggregate(await loadRows(days), days, Number(req.query.tz) || 0));
  } catch (e) { console.error(e.message); res.status(500).json({ error: "Could not load stats." }); }
});
app.get("/api/admin/export.csv", adminAuth, async (req, res) => {
  try {
    if (!TRACKING) return res.status(503).json({ error: "Supabase is not configured on the server." });
    await flush();
    const rows = await loadRows(clamp(Number(req.query.days) || 30, 1, 90));
    const cell = (v) => { if (v === null || v === undefined) return ""; const s = typeof v === "object" ? JSON.stringify(v) : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    res.set("Content-Type", "text/csv");
    res.send([COLS.join(","), ...rows.map((r) => COLS.map((c) => cell(r[c])).join(","))].join("\n"));
  } catch (e) { console.error(e.message); res.status(500).json({ error: "Could not export." }); }
});

// ======================= scraping + AI (unchanged) =======================
function isPrivateIp(ip) {
  if (net.isIPv6(ip)) return ip === "::1" || /^f[cd]/i.test(ip) || /^fe80/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}
async function assertPublic(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error("Please enter a valid URL."); }
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Only http(s) links are supported.");
  const { address } = await dns.lookup(u.hostname).catch(() => { throw new Error("Could not find that website."); });
  if (isPrivateIp(address)) throw new Error("That address is not allowed.");
  return u.href;
}

const SOCIALS = ["linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com", "github.com", "wa.me", "t.me"];
const uniqList = (a) => [...new Set(a)];

async function scrape(url) {
  const res = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (compatible; AISummarizerBot/1.0)" }, signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`The website returned status ${res.status}.`);
  if (!(res.headers.get("content-type") || "").includes("text/html")) throw new Error("That URL is not an HTML page.");
  const html = await res.text();
  const base = new URL(res.url);
  const $ = cheerio.load(html);

  const internal = new Map(), external = new Map();
  const emails = new Set(), phones = new Set(), socials = new Set();
  $("a[href]").each((_, el) => {
    const href = ($(el).attr("href") || "").trim();
    const label = $(el).text().replace(/\s+/g, " ").trim().slice(0, 80);
    if (href.startsWith("mailto:")) return emails.add(href.slice(7).split("?")[0].trim().toLowerCase());
    if (href.startsWith("tel:")) return phones.add(decodeURIComponent(href.slice(4)).trim());
    let u;
    try { u = new URL(href, base); } catch { return; }
    if (!["http:", "https:"].includes(u.protocol)) return;
    u.hash = "";
    const host = u.hostname.replace(/^www\./, "");
    if (SOCIALS.some((s) => host === s || host.endsWith("." + s))) socials.add(u.href);
    const map = u.hostname === base.hostname ? internal : external;
    if (!map.has(u.href)) map.set(u.href, label);
  });

  const body = $("body").text();
  (html.match(/[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}/gi) || [])
    .filter((e) => !/\.(png|jpe?g|gif|svg|webp|css|js)$/i.test(e)).forEach((e) => emails.add(e.toLowerCase()));
  const phoneRe = /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,5}\)|\d{2,5})[\s.-]\d{3,5}(?:[\s.-]\d{2,5})?/g;
  (body.match(phoneRe) || []).forEach((p) => { const d = p.replace(/\D/g, "").length; if (d >= 10 && d <= 13) phones.add(p.trim()); });
  const addresses = [];
  $("address").each((_, el) => addresses.push($(el).text().replace(/\s+/g, " ").trim()));

  const toList = (m) => [...m].slice(0, 100).map(([url, text]) => ({ url, text }));
  const description = $('meta[name="description"]').attr("content") || "";

  $("script, style, noscript, nav, footer, header, aside, form, iframe, svg").remove();
  const root = $("article").length ? $("article") : $("main").length ? $("main") : $("body");
  const text = root.text().replace(/\s+/g, " ").trim();
  if (text.length < 100) throw new Error("Not enough text found. The page may need JavaScript to load.");

  return {
    url: base.href, title: $("title").first().text().trim() || base.hostname, description, text: text.slice(0, MAX_CHARS),
    contacts: { emails: uniqList([...emails]).slice(0, 20), phones: uniqList([...phones]).slice(0, 20), socials: [...socials].slice(0, 20), addresses: uniqList(addresses).filter(Boolean).slice(0, 5) },
    links: { internal: toList(internal), external: toList(external) },
  };
}

async function ai(messages, json = false) {
  if (!KEY) throw new Error("Server is missing GROQ_API_KEY.");
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${KEY}` },
    body: JSON.stringify({ model: MODEL, temperature: 0.3, messages, ...(json && { response_format: { type: "json_object" } }) }),
  });
  if (!res.ok) { console.error("Groq error:", res.status, await res.text()); throw new Error(`AI service error (${res.status}). Try again in a moment.`); }
  return (await res.json()).choices[0].message.content;
}
const parseJson = (s) => JSON.parse(s.replace(/^```(?:json)?|```$/g, "").trim());

const SHAPE = `Return ONLY JSON in this shape:
{"summary": "3-4 sentence summary", "takeaways": ["3 short key takeaways"],
 "keywords": {"about": "what the page is about, max 6 words", "industry": "sector or industry, or empty string",
 "companies": [], "people": [], "locations": [], "topics": ["3-5 topic keywords"]}}
In "summary" and "takeaways", wrap the 2-4 most important phrases in ==double equals== to highlight them (e.g. ==launched a free plan==). Only highlight short phrases.`;

const summarize = async (page, language) =>
  parseJson(await ai([
    { role: "system", content: `You analyse web pages. Write every text value in ${language}. Keep JSON keys in English. ${SHAPE}` },
    { role: "user", content: `Title: ${page.title}\nDescription: ${page.description}\n\n${page.text}` },
  ], true));

// ======================= routes =======================
const wrap = (fn) => async (req, res) => {
  try { res.json(await fn(req.body || {}, req)); }
  catch (e) { console.error(e.message); res.status(e.status || 400).json({ error: e.message || "Something went wrong." }); }
};

app.post("/api/summarize", wrap(async ({ url, language }, req) => {
  language = cleanLang(language);
  const t0 = Date.now();
  let domain = null;
  try {
    const safe = await assertPublic(String(url || ""));
    domain = new URL(safe).hostname.replace(/^www\./, "");
    const page = await scrape(safe);
    const result = await summarize(page, language);
    const id = remember({ title: page.title, url: page.url, text: page.text });
    track(req, { type: "summarize", success: true, domain, language, duration_ms: Date.now() - t0,
      meta: { chars: page.text.length, emails: page.contacts.emails.length, phones: page.contacts.phones.length, socials: page.contacts.socials.length, internal: page.links.internal.length, external: page.links.external.length } });
    return { id, url: page.url, title: page.title, ...result, contacts: page.contacts, links: page.links };
  } catch (e) {
    track(req, { type: "summarize", success: false, domain, language, duration_ms: Date.now() - t0, error: clip(e.message, 120) });
    throw e;
  }
}));

app.post("/api/translate", wrap(async ({ data, language }, req) => {
  language = cleanLang(language);
  const t0 = Date.now();
  try {
    if (!data || !data.summary) throw new Error("Nothing to translate.");
    const out = parseJson(await ai([
      { role: "system", content: `Translate the JSON values into ${language}. Keep keys and the ==highlight== markers unchanged. Keep names of people and companies as they are. Return ONLY JSON.` },
      { role: "user", content: JSON.stringify({ summary: data.summary, takeaways: data.takeaways, keywords: data.keywords }) },
    ], true));
    track(req, { type: "translate", success: true, language, duration_ms: Date.now() - t0 });
    return out;
  } catch (e) { track(req, { type: "translate", success: false, language, duration_ms: Date.now() - t0, error: clip(e.message, 120) }); throw e; }
}));

app.post("/api/chat", wrap(async ({ id, question, language }, req) => {
  language = cleanLang(language);
  const t0 = Date.now();
  try {
    const page = pages.get(id);
    if (!page) throw new Error("This session expired. Summarize the page again.");
    if (!question || !String(question).trim()) throw new Error("Type a question first.");
    if (page.chats >= MAX_CHATS) throw new Error("You've used all follow-up questions for this page.");
    page.chats++;
    const answer = await ai([
      { role: "system", content: `Answer questions about the web page below using only its content. If the answer is not on the page, say so. Keep it under 3 sentences. Reply in ${language}.\n\nTitle: ${page.title}\nURL: ${page.url}\n\n${page.text}` },
      { role: "user", content: String(question).slice(0, 500) },
    ]);
    track(req, { type: "chat", success: true, language, value: String(question).length, duration_ms: Date.now() - t0, meta: { remaining: MAX_CHATS - page.chats } });   // the question text itself is never stored
    return { answer, remaining: MAX_CHATS - page.chats };
  } catch (e) { track(req, { type: "chat", success: false, language, duration_ms: Date.now() - t0, error: clip(e.message, 120) }); throw e; }
}));

// in-memory page cache so follow-up chat can use the page text (expires after 1 hour)
const pages = new Map();
function remember(data) {
  const id = crypto.randomUUID();
  pages.set(id, { ...data, chats: 0, at: Date.now() });
  for (const [k, v] of pages) if (Date.now() - v.at > 3600e3 || pages.size > 100) pages.delete(k);
  return id;
}

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}${TRACKING ? " (analytics on)" : " (analytics off)"}`));
