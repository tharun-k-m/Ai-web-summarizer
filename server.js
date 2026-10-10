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

app.use(express.json({ limit: "200kb" }));
app.use(express.static(path.join(__dirname, "public")));

// In-memory page cache so follow-up chat can use the page text (expires after 1 hour)
const pages = new Map();
function remember(data) {
  const id = crypto.randomUUID();
  pages.set(id, { ...data, chats: 0, at: Date.now() });
  for (const [k, v] of pages) if (Date.now() - v.at > 3600e3 || pages.size > 100) pages.delete(k);
  return id;
}

// ---------- safety: only public http(s) hosts ----------
function isPrivateIp(ip) {
  if (net.isIPv6(ip)) return ip === "::1" || /^f[cd]/i.test(ip) || /^fe80/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}
async function assertPublic(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error("Please enter a valid URL."); }
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Only http(s) links are supported.");
  const { address } = await dns.lookup(u.hostname).catch(() => { throw new Error("Could not find that website."); });
  if (isPrivateIp(address)) throw new Error("That address is not allowed.");
  return u.href;
}

// ---------- scraping ----------
const SOCIALS = ["linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com", "github.com", "wa.me", "t.me"];
const uniq = (a) => [...new Set(a)];

async function scrape(url) {
  const res = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; AISummarizerBot/1.0)" },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`The website returned status ${res.status}.`);
  if (!(res.headers.get("content-type") || "").includes("text/html")) throw new Error("That URL is not an HTML page.");
  const html = await res.text();
  const base = new URL(res.url);
  const $ = cheerio.load(html);

  // Links + contacts are read BEFORE removing nav/footer (that's where contacts usually live)
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
  (body.match(phoneRe) || []).forEach((p) => {
    const d = p.replace(/\D/g, "").length;
    if (d >= 10 && d <= 13) phones.add(p.trim());
  });
  const addresses = [];
  $("address").each((_, el) => addresses.push($(el).text().replace(/\s+/g, " ").trim()));

  const toList = (m) => [...m].slice(0, 100).map(([url, text]) => ({ url, text }));
  const description = $('meta[name="description"]').attr("content") || "";

  $("script, style, noscript, nav, footer, header, aside, form, iframe, svg").remove();
  const root = $("article").length ? $("article") : $("main").length ? $("main") : $("body");
  const text = root.text().replace(/\s+/g, " ").trim();
  if (text.length < 100) throw new Error("Not enough text found. The page may need JavaScript to load.");

  return {
    url: base.href,
    title: $("title").first().text().trim() || base.hostname,
    description,
    text: text.slice(0, MAX_CHARS),
    contacts: {
      emails: uniq([...emails]).slice(0, 20),
      phones: uniq([...phones]).slice(0, 20),
      socials: [...socials].slice(0, 20),
      addresses: uniq(addresses).filter(Boolean).slice(0, 5),
    },
    links: { internal: toList(internal), external: toList(external) },
  };
}

// ---------- AI ----------
async function ai(messages, json = false) {
  if (!KEY) throw new Error("Server is missing GROQ_API_KEY.");
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${KEY}` },
    body: JSON.stringify({
      model: MODEL, temperature: 0.3, messages,
      ...(json && { response_format: { type: "json_object" } }),
    }),
  });
  if (!res.ok) {
    console.error("Groq error:", res.status, await res.text());
    throw new Error(`AI service error (${res.status}). Try again in a moment.`);
  }
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

// ---------- routes ----------
const wrap = (fn) => async (req, res) => {
  try { res.json(await fn(req.body || {})); }
  catch (e) { console.error(e.message); res.status(e.status || 400).json({ error: e.message || "Something went wrong." }); }
};

app.post("/api/summarize", wrap(async ({ url, language = "English" }) => {
  const page = await scrape(await assertPublic(String(url || "")));
  const result = await summarize(page, language);
  const id = remember({ title: page.title, url: page.url, text: page.text });
  return { id, url: page.url, title: page.title, ...result, contacts: page.contacts, links: page.links };
}));

app.post("/api/translate", wrap(async ({ data, language = "English" }) => {
  if (!data || !data.summary) throw new Error("Nothing to translate.");
  return parseJson(await ai([
    { role: "system", content: `Translate the JSON values into ${language}. Keep keys and the ==highlight== markers unchanged. Keep names of people and companies as they are. Return ONLY JSON.` },
    { role: "user", content: JSON.stringify({ summary: data.summary, takeaways: data.takeaways, keywords: data.keywords }) },
  ], true));
}));

app.post("/api/chat", wrap(async ({ id, question, language = "English" }) => {
  const page = pages.get(id);
  if (!page) throw new Error("This session expired. Summarize the page again.");
  if (!question || !String(question).trim()) throw new Error("Type a question first.");
  if (page.chats >= MAX_CHATS) throw new Error("You've used all follow-up questions for this page.");
  page.chats++;
  const answer = await ai([
    { role: "system", content: `Answer questions about the web page below using only its content. If the answer is not on the page, say so. Keep it under 3 sentences. Reply in ${language}.\n\nTitle: ${page.title}\nURL: ${page.url}\n\n${page.text}` },
    { role: "user", content: String(question).slice(0, 500) },
  ]);
  return { answer, remaining: MAX_CHATS - page.chats };
}));

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
